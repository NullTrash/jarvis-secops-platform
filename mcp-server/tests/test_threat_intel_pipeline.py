"""Unit tests for the Jarvis Threat Intel, Asset Vulnerability, and Identity OSINT Pipeline."""

from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from src.asset_inventory import AssetInventoryManager
from src.threat_feeds import (
    ThreatFeedPipeline,
    extract_actors_and_vendors,
    extract_iocs_from_text,
    refang,
    resolve_publisher,
)
from src.vuln_scanner import AssetVulnerabilityScanner
from src.identity_osint import IdentityExposureMonitor, mask_email


def test_refang_and_extract_iocs():
    """Verify defanged URLs, IPs, CVEs, MITRE T-IDs, and hashes are extracted cleanly."""
    sample_text = (
        "Volt Typhoon exploited CVE-2024-21887 and CVE-2025-12345 on Ubiquiti UniFi Dream Router "
        "via C2 198[.]51[.]100[.]44 and hxxps://evil[.]example[.]com/payload. "
        "Observed SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
        "and technique T1190 / T1071.001."
    )
    assert refang("198[.]51[.]100[.]44") == "198.51.100.44"
    assert refang("hxxps://evil[.]example[.]com") == "https://evil.example.com"

    iocs = extract_iocs_from_text(sample_text)
    assert "CVE-2024-21887" in iocs["cve"]
    assert "CVE-2025-12345" in iocs["cve"]
    assert "198.51.100.44" in iocs["ipv4"]
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in iocs["sha256"]
    assert "T1190" in iocs["mitre_attack"]
    assert "T1071.001" in iocs["mitre_attack"]

    actors, vendors, labels = extract_actors_and_vendors(sample_text)
    assert "Volt Typhoon" in actors
    assert "Ubiquiti" in vendors
    assert "unifi" in labels
    assert "network-perimeter" in labels


def test_resolve_publisher():
    """Verify Admiralty reliability and confidence scoring for known CTI publishers."""
    pub, conf, rel = resolve_publisher("https://www.cisa.gov/cybersecurity-advisories/all.xml")
    assert pub == "CISA"
    assert conf == 90
    assert rel == "A"

    pub_fb, conf_fb, rel_fb = resolve_publisher("https://feeds.feedburner.com/TheDfirReport")
    assert pub_fb == "The DFIR Report"
    assert conf_fb == 85
    assert rel_fb == "A"


def test_environment_relevance_scoring():
    """Verify environment-profile.json boosts Ubiquiti UniFi Dream Router and Proxmox reports."""
    inv = AssetInventoryManager()
    score, matches = inv.score_environment_relevance(
        title="Critical Firewall Advisory for Ubiquiti UniFi Dream Router and Proxmox VE",
        description="Active exploitation by Volt Typhoon targeting edge gateways.",
        labels=["unifi", "proxmox"],
        vendors=["Ubiquiti", "Proxmox"],
        threat_actors=["Volt Typhoon"],
    )
    assert score == 100
    assert any("Ubiquiti" in m for m in matches)
    assert any("Proxmox" in m for m in matches)
    assert any("Volt Typhoon" in m for m in matches)


@pytest.mark.asyncio
async def test_asset_inventory_sync():
    """Verify hybrid asset inventory discovery and Elasticsearch indexing."""
    mock_es = MagicMock()
    mock_client = AsyncMock()
    mock_client.search.return_value = {
        "hits": {"total": {"value": 500}},
        "aggregations": {
            "hosts": {"buckets": [{"key": "UDR"}]},
            "hostnames": {"buckets": [{"key": "Workstation-01"}]},
            "os_names": {"buckets": [{"key": "Windows 11 Pro"}]},
            "os_versions": {"buckets": [{"key": "10.0.22631"}]},
        },
    }
    mock_client.index.return_value = {"_id": "asset-udr-gateway-01", "result": "created"}
    mock_es.get_client.return_value = mock_client

    mock_pve = AsyncMock()
    mock_pve.is_configured = MagicMock(return_value=True)
    mock_pve.get_nodes.return_value = [{"node": "pve", "status": "online"}]
    mock_pve.get_node_status.return_value = {"pveversion": "pve-manager/8.2.4", "kversion": "Linux 6.8.8-2-pve"}
    mock_pve.get_cluster_resources.return_value = [{"vmid": 100, "name": "orchestrator", "status": "running", "node": "pve"}]

    inv = AssetInventoryManager(es_manager=mock_es, proxmox_manager=mock_pve)
    res = await inv.sync_asset_inventory(run_active_scan=False)

    assert res["status"] == "success"
    assert res["total_assets"] >= 4
    assert res["indexed_to_es"] == res["total_assets"]
    pve_asset = next(a for a in res["assets"] if a["asset_id"] == "proxmox-pve-01")
    assert pve_asset["version"] == "pve-manager/8.2.4"


@pytest.mark.asyncio
async def test_rss_parsing_and_retroactive_siem_match():
    """Verify RSS parsing and 90-day retroactive SIEM matching against UniFi/Sysmon logs."""
    mock_es = MagicMock()
    mock_client = AsyncMock()
    # Mock retroactive match finding 12 hits for 198.51.100.77
    mock_client.search.return_value = {
        "aggregations": {
            "src_hits": {"buckets": [{"key": "198.51.100.77", "doc_count": 12}]},
            "dst_hits": {"buckets": []},
        }
    }
    mock_es.get_client.return_value = mock_client

    pipeline = ThreatFeedPipeline(es_manager=mock_es)
    sample_rss = """<?xml version="1.0" encoding="UTF-8" ?>
    <rss version="2.0">
      <channel>
        <title>CISA Advisories</title>
        <item>
          <title>Ubiquiti UniFi Dream Router RCE (CVE-2025-9999)</title>
          <link>https://www.cisa.gov/advisory/cve-2025-9999</link>
          <description>Exploitation from 198.51.100.77 using technique T1190 by Volt Typhoon.</description>
          <pubDate>Wed, 18 Nov 2026 12:00:00 GMT</pubDate>
        </item>
      </channel>
    </rss>"""

    items = pipeline._parse_rss_xml(sample_rss, "https://www.cisa.gov/cybersecurity-advisories/all.xml")
    assert len(items) == 1
    scored = pipeline.score_item(items[0])
    assert scored["environment_score"] > 50
    assert scored["priority_score"] >= 80

    retro = await pipeline.retroactive_siem_match(items, lookback_days=90)
    assert retro["items_with_siem_hits"] == 1
    assert retro["total_siem_event_matches"] == 12
    assert items[0]["retro_classification"] == "high_confidence_siem_match"
    assert items[0]["priority_score"] == 100


@pytest.mark.asyncio
async def test_cisa_kev_and_asset_vuln_scanner():
    """Verify CISA KEV matching against UniFi Dream Router and Proxmox assets."""
    mock_es = MagicMock()
    mock_client = AsyncMock()
    mock_client.index.return_value = {"_id": "vuln-1", "result": "created"}
    mock_es.get_client.return_value = mock_client

    scanner = AssetVulnerabilityScanner(es_manager=mock_es)
    sample_kev = [
        {
            "cveID": "CVE-2024-0001",
            "vendorProject": "Ubiquiti",
            "product": "UniFi OS / Dream Router",
            "vulnerabilityName": "Ubiquiti UniFi Command Injection",
            "shortDescription": "Ubiquiti UniFi Dream Router contains a remote command injection flaw.",
            "dateAdded": "2026-10-01",
            "requiredAction": "Upgrade UniFi OS firmware.",
            "knownRansomwareCampaignUse": "Known",
        }
    ]
    udr_asset = {
        "asset_id": "udr-gateway-01",
        "name": "Ubiquiti UniFi Dream Router (UDR)",
        "ip": "10.0.0.1",
        "vendor": "Ubiquiti",
        "product": "UniFi Dream Router",
        "version": "4.0+",
        "internet_facing": True,
        "search_keywords": ["Ubiquiti UniFi", "UniFi Dream Router"],
    }
    matches = scanner.match_cisa_kev_to_asset(sample_kev, udr_asset)
    assert len(matches) == 1
    assert matches[0]["cve_id"] == "CVE-2024-0001"
    assert matches[0]["in_cisa_kev"] is True
    prio = scanner.calculate_vuln_priority(matches[0], udr_asset)
    assert prio >= 90


@pytest.mark.asyncio
async def test_identity_exposure_monitor():
    """Verify email masking and identity OSINT scan aggregation."""
    assert mask_email("secops-admin@example.com") == "se***n@example.com"
    assert mask_email("ab@example.com") == "a*@example.com"

    mock_es = MagicMock()
    mock_client = AsyncMock()
    mock_client.index.return_value = {"_id": "id-1", "result": "created"}
    mock_es.get_client.return_value = mock_client

    monitor = IdentityExposureMonitor(es_manager=mock_es)
    with patch.object(
        monitor,
        "check_hudsonrock_email",
        new=AsyncMock(return_value={"source": "HudsonRock Cavalier", "compromised": False, "stealer_count": 0, "severity": "LOW", "priority_score": 10}),
    ), patch.object(
        monitor,
        "check_xposedornot_email",
        new=AsyncMock(return_value={"source": "XposedOrNot Breach Database", "exposed": True, "breach_count": 2, "breaches": ["Canva", "LinkedIn"], "severity": "MEDIUM", "priority_score": 60}),
    ), patch.object(
        monitor,
        "check_github_public_exposure",
        new=AsyncMock(return_value={"source": "GitHub Public Commit OSINT", "total_public_mentions": 3, "sample_repositories": ["NullTrash/jarvis-secops-platform"], "severity": "MEDIUM", "priority_score": 45}),
    ), patch.object(
        monitor,
        "check_hudsonrock_username",
        new=AsyncMock(return_value={"source": "HudsonRock Cavalier", "compromised": False, "stealer_count": 0, "severity": "LOW", "priority_score": 10}),
    ), patch.object(
        monitor,
        "check_wan_ip_shodan_internetdb",
        new=AsyncMock(return_value={"source": "Shodan InternetDB", "wan_ip_masked": "203.0.x.x", "open_ports": [], "vulns": [], "severity": "LOW", "priority_score": 5}),
    ):
        res = await monitor.scan_identity_exposures(
            names=["SecOps Admin"],
            emails=["secops-admin@example.com"],
            usernames=["NullTrash"],
            check_wan_footprint=True,
        )
        assert res["status"] == "success"
        assert res["total_checks_run"] == 6
        assert res["indexed_to_es"] == 6
