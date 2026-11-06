import pytest
from unittest.mock import AsyncMock, patch
from src.threat_intel import ThreatIntelManager, HIGH_RISK_PORTS
from src.server import lookup_threat_intel, triage_threat_actors, investigate_indicator


def test_ip_public_private_detection():
    manager = ThreatIntelManager()
    assert manager.is_public_ip("8.8.8.8") is True
    assert manager.is_public_ip("1.1.1.1") is True
    assert manager.is_public_ip("142.250.190.46") is True
    assert manager.is_public_ip("10.0.0.1") is False
    assert manager.is_public_ip("172.16.0.1") is False
    assert manager.is_public_ip("127.0.0.1") is False
    assert manager.is_public_ip("not-an-ip") is False


def test_indicator_type_detection():
    manager = ThreatIntelManager()
    assert manager.detect_indicator_type("198.51.100.1") == "ipv4"
    assert manager.detect_indicator_type("2001:db8::1") == "ipv6"
    assert manager.detect_indicator_type("d41d8cd98f00b204e9800998ecf8427e") == "md5"
    assert manager.detect_indicator_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"
    assert manager.detect_indicator_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "sha256"
    assert manager.detect_indicator_type("evil-domain.com") == "domain"


@pytest.mark.asyncio
async def test_lookup_abuseipdb_unconfigured():
    manager = ThreatIntelManager(abuseipdb_api_key=None)
    res = await manager.lookup_abuseipdb("198.51.100.1")
    assert res["configured"] is False
    assert "not configured" in res["message"]


@pytest.mark.asyncio
async def test_lookup_abuseipdb_private_ip():
    manager = ThreatIntelManager(abuseipdb_api_key="mock_key")
    res = await manager.lookup_abuseipdb("10.0.0.20")
    assert res["configured"] is True
    assert res["is_public"] is False


@pytest.mark.asyncio
async def test_lookup_abuseipdb_success():
    manager = ThreatIntelManager(abuseipdb_api_key="mock_key")
    mock_payload = {
        "data": {
            "abuseConfidenceScore": 85,
            "totalReports": 42,
            "numDistinctUsers": 12,
            "countryCode": "US",
            "isp": "Malicious Hosting LLC",
            "usageType": "Data Center/Web Hosting/Transit",
            "isWhitelisted": False,
            "lastReportedAt": "2026-11-05T12:00:00+00:00",
        }
    }
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_resp = AsyncMock()
        mock_resp.status_code = 200
        mock_resp.json = lambda: mock_payload
        mock_get.return_value = mock_resp

        res = await manager.lookup_abuseipdb("1.1.1.1")
        assert res["status"] == "success"
        assert res["abuse_confidence_score"] == 85
        assert res["total_reports"] == 42
        assert res["country_code"] == "US"


@pytest.mark.asyncio
async def test_compute_local_heuristics_high_severity():
    mock_es = AsyncMock()
    # Mock UniFi drops: 1200 drops across ports 22, 23, 8080
    mock_unifi_res = {
        "hits": {"total": {"value": 1200}},
        "aggregations": {
            "distinct_ports": {
                "buckets": [
                    {"key": 22, "doc_count": 800},
                    {"key": 23, "doc_count": 300},
                    {"key": 8080, "doc_count": 100},
                ]
            }
        },
    }
    # Mock Sysmon endpoint events: 1 matching connection
    mock_sysmon_res = {
        "hits": {"total": {"value": 1}}
    }

    mock_client = AsyncMock()
    mock_client.search = AsyncMock(side_effect=[mock_unifi_res, mock_sysmon_res])
    mock_es.get_client = lambda: mock_client

    manager = ThreatIntelManager(es_manager=mock_es)
    res = await manager.compute_local_behavioral_heuristics("198.51.100.22", hours_back=24)

    assert res["score"] >= 80
    assert res["severity"] == "Critical"
    assert "High-frequency flood" in res["risk_factors"][0]
    assert "CRITICAL: Active internal endpoint contact detected" in " ".join(res["risk_factors"])


@pytest.mark.asyncio
async def test_lookup_threat_intel_tool():
    with patch("src.server.threat_intel.evaluate_indicator", new_callable=AsyncMock) as mock_eval:
        mock_eval.return_value = {
            "indicator": "198.51.100.10",
            "indicator_type": "ipv4",
            "verdict": {"combined_score": 75, "severity": "High"},
        }
        res = await lookup_threat_intel("198.51.100.10")
        assert res["indicator"] == "198.51.100.10"
        assert res["verdict"]["severity"] == "High"


@pytest.mark.asyncio
async def test_investigate_indicator_tool_with_threat_intel():
    mock_search_res = {
        "hits": {
            "total": {"value": 1},
            "hits": [
                {
                    "_source": {
                        "@timestamp": "2026-11-05T18:00:00Z",
                        "event": {"action": "firewall-drop"},
                        "source": {"ip": "198.51.100.10"},
                    }
                }
            ],
        }
    }
    mock_client = AsyncMock()
    mock_client.search = AsyncMock(return_value=mock_search_res)

    mock_eval = {
        "indicator": "198.51.100.10",
        "verdict": {"combined_score": 60, "severity": "High"},
    }

    with patch("src.server.es_manager.get_client", return_value=mock_client), \
         patch("src.server.threat_intel.evaluate_indicator", new_callable=AsyncMock, return_value=mock_eval):
        res = await investigate_indicator("198.51.100.10")
        assert res["indicator"] == "198.51.100.10"
        assert res["total_occurrences"] == 1
        assert res["threat_assessment"]["verdict"]["severity"] == "High"


@pytest.mark.asyncio
async def test_triage_threat_actors_tool():
    mock_unifi_triage = {
        "total_drops": 500,
        "top_attacker_ips": [{"key": "198.51.100.99", "doc_count": 300}],
    }
    mock_eval = {
        "indicator": "198.51.100.99",
        "verdict": {"combined_score": 70, "severity": "High", "profile": "SSH Brute-Force Bot"},
        "local_heuristics": {"telemetry": {"firewall_drops": 300, "ports": [22]}},
    }
    mock_ai_res = {
        "status": "success",
        "model": "llama3.2:3b",
        "latency_ms": 520.0,
        "tokens_per_second": 105.0,
        "completion": "1. SSH scan campaign.\n2. 198.51.100.99 is critical.\n3. Drop at WAN edge.",
        "audit_id": "audit_secops_1",
    }

    with patch("src.server.triage_unifi_firewall", new_callable=AsyncMock, return_value=mock_unifi_triage), \
         patch("src.server.threat_intel.evaluate_indicator", new_callable=AsyncMock, return_value=mock_eval), \
         patch("src.server.ai_harness.execute_and_audit", new_callable=AsyncMock, return_value=mock_ai_res):

        res = await triage_threat_actors(hours_back=12, top_n=1, generate_ai_summary=True)
        assert res["status"] == "success"
        assert res["total_firewall_drops"] == 500
        assert len(res["top_actors"]) == 1
        assert res["top_actors"][0]["indicator"] == "198.51.100.99"
        assert "ai_assessment" in res
        assert res["ai_assessment"]["model"] == "llama3.2:3b"
        assert "SSH scan campaign" in res["ai_assessment"]["summary"]


@pytest.mark.asyncio
async def test_internal_lan_false_positive_exclusion():
    manager = ThreatIntelManager()
    # Internal workstation / LAN IPs must never be scored as external threats
    for internal_ip in ["10.0.0.15", "10.0.0.70", "10.0.0.186", "172.16.0.15", "127.0.0.1"]:
        assert manager.is_internal_lan_ip(internal_ip) is True
        res = await manager.compute_local_behavioral_heuristics(internal_ip)
        assert res["score"] == 0
        assert res["severity"] == "Benign"
        assert res["is_internal_asset"] is True
        assert "Trusted Internal Asset" in res["profile"]


@pytest.mark.asyncio
async def test_triage_threat_actors_excludes_internal_lan_ips():
    mock_unifi_triage = {
        "total_drops": 1200,
        "top_attacker_ips": [
            {"key": "10.0.0.15", "doc_count": 600},
            {"key": "10.0.0.186", "doc_count": 400},
            {"key": "198.51.100.44", "doc_count": 200},
        ],
    }
    mock_eval = {
        "indicator": "198.51.100.44",
        "verdict": {"combined_score": 80, "severity": "Critical", "profile": "Telnet / IoT Botnet Scanner"},
        "local_heuristics": {"telemetry": {"firewall_drops": 200, "ports": [23], "country": "Kazakhstan", "as_org": "AO ALMAZ"}},
    }

    with patch("src.server.triage_unifi_firewall", new_callable=AsyncMock, return_value=mock_unifi_triage), \
         patch("src.server.threat_intel.evaluate_indicator", new_callable=AsyncMock, return_value=mock_eval) as mock_eval_fn:

        res = await triage_threat_actors(hours_back=24, top_n=5, generate_ai_summary=False)
        assert res["status"] == "success"
        # Only the external IP 198.51.100.44 should be evaluated; internal IPs are excluded
        assert res["actors_evaluated_count"] == 1
        assert res["top_actors"][0]["indicator"] == "198.51.100.44"
        mock_eval_fn.assert_called_once_with("198.51.100.44", hours_back=24)
