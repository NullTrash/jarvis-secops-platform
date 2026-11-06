import pytest
from unittest.mock import AsyncMock, patch
from src.server import get_cluster_health, search_security_events, triage_unifi_firewall, investigate_indicator


@pytest.mark.asyncio
async def test_get_cluster_health_success():
    mock_health = {
        "status": "green",
        "cluster_name": "jarvis-siem-cluster",
        "number_of_nodes": 1,
        "active_primary_shards": 5,
    }
    mock_indices = [
        {"index": "logs-network.unifi-default", "docs.count": "1500", "store.size": "12mb", "health": "green"}
    ]

    mock_client = AsyncMock()
    mock_client.cluster.health = AsyncMock(return_value=mock_health)
    mock_client.cat.indices = AsyncMock(return_value=mock_indices)

    with patch("src.server.es_manager.get_client", return_value=mock_client):
        res = await get_cluster_health()
        assert res["status"] == "green"
        assert res["cluster_name"] == "jarvis-siem-cluster"
        assert res["indices_count"] == 1


@pytest.mark.asyncio
async def test_search_security_events():
    mock_search_response = {
        "hits": {
            "total": {"value": 2},
            "hits": [
                {"_source": {"@timestamp": "2026-08-19T10:00:00Z", "event": {"action": "firewall-drop"}}},
                {"_source": {"@timestamp": "2026-08-19T10:05:00Z", "event": {"action": "firewall-drop"}}},
            ],
        }
    }

    mock_client = AsyncMock()
    mock_client.search = AsyncMock(return_value=mock_search_response)

    with patch("src.server.es_manager.get_client", return_value=mock_client):
        res = await search_security_events(query="event.action: firewall-drop")
        assert res["total_matches"] == 2
        assert len(res["events"]) == 2


@pytest.mark.asyncio
async def test_triage_unifi_firewall():
    mock_agg_response = {
        "hits": {"total": {"value": 45}},
        "aggregations": {
            "top_source_ips": {"buckets": [{"key": "198.51.100.22", "doc_count": 30}]},
            "top_targeted_ports": {"buckets": [{"key": 22, "doc_count": 30}]},
            "top_rules_triggered": {"buckets": [{"key": "WAN_LOCAL-drop", "doc_count": 45}]},
        },
    }

    mock_client = AsyncMock()
    mock_client.search = AsyncMock(return_value=mock_agg_response)

    with patch("src.server.es_manager.get_client", return_value=mock_client):
        res = await triage_unifi_firewall(hours_back=12)
        assert res["total_drops"] == 45
        assert res["top_attacker_ips"][0]["key"] == "198.51.100.22"
        assert res["top_targeted_ports"][0]["key"] == 22
