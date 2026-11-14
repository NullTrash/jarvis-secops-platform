from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
import pytest

from src.detection_rules import DetectionRuleCurator


def test_extract_query_fields_ignores_quoted_exe_strings():
    query = '''
    process where host.os.type == "windows" and event.type == "start" and
      process.name : ("powershell.exe", "dns.exe") and
      process.command_line : "*Invoke-Mimikatz*"
    '''
    fields = DetectionRuleCurator.extract_query_fields(query)
    assert "host.os.type" in fields
    assert "event.type" in fields
    assert "process.name" in fields
    assert "process.command_line" in fields
    assert "powershell.exe" not in fields
    assert "dns.exe" not in fields


def test_extract_query_event_codes():
    query = 'event.code : ("4624", "4625") and winlog.event_id == "1"'
    codes = DetectionRuleCurator.extract_query_event_codes(query)
    assert "4624" in codes
    assert "4625" in codes
    assert "1" in codes


def test_kql_to_lucene_conversion():
    kql = 'event.category : "process" and process.name : ("cmd.exe", "powershell.exe") and not user.name : "SYSTEM"'
    lucene = DetectionRuleCurator._kql_to_lucene(kql)
    assert "AND" in lucene
    assert "NOT" in lucene
    assert 'process.name:("cmd.exe" OR "powershell.exe")' in lucene


def test_evaluate_rule_compatibility_tier1_vs_defend(tmp_path: Path):
    curator = DetectionRuleCurator(upstream_rules_dir=tmp_path, jarvis_rules_dir=tmp_path / "jarvis")
    mock_telemetry = {
        "indexed_fields_set": {
            "host.os.type",
            "event.type",
            "event.code",
            "process.name",
            "process.command_line",
            "process.executable",
        },
        "event_codes": {"1": 5000, "4688": 1200},
    }

    # 1. Compatible Sysmon/Winlogbeat rule
    good_toml = tmp_path / "windows" / "good_rule.toml"
    good_toml.parent.mkdir(parents=True, exist_ok=True)
    good_toml.write_text(
        '''
[rule]
name = "Suspicious PowerShell"
rule_id = "rule-111"
language = "eql"
type = "eql"
severity = "high"
risk_score = 73
index = ["winlogbeat-*", "logs-windows.sysmon_operational-*"]
tags = ["Data Source: Sysmon"]
query = 'process where host.os.type == "windows" and process.name == "powershell.exe" and process.command_line : "*-enc*"'
''',
        encoding="utf-8",
    )
    res_good = curator.evaluate_rule_compatibility(good_toml, mock_telemetry)
    assert res_good["compatible"] is True
    assert res_good["tier"] == "tier_1_ready_candidate"
    assert res_good["field_coverage_ratio"] == 1.0

    # 2. Incompatible Elastic Defend-only rule
    defend_toml = tmp_path / "windows" / "defend_only.toml"
    defend_toml.write_text(
        '''
[rule]
name = "Defend Only Rule"
rule_id = "rule-222"
language = "eql"
type = "eql"
severity = "medium"
risk_score = 47
index = ["logs-endpoint.events.process-*"]
tags = ["Data Source: Elastic Defend"]
query = 'process where process.Ext.memory_region.AllocationProtect == "PAGE_EXECUTE_READWRITE"'
''',
        encoding="utf-8",
    )
    res_defend = curator.evaluate_rule_compatibility(defend_toml, mock_telemetry)
    assert res_defend["compatible"] is False
    assert "Elastic Defend" in res_defend["reason"]


@pytest.mark.asyncio
async def test_dry_run_liveness_blind_spot_detection(tmp_path: Path):
    mock_es_client = MagicMock()
    mock_es_client.eql.search = AsyncMock(return_value={"hits": {"total": {"value": 0}, "events": []}})
    mock_es_mgr = MagicMock()
    mock_es_mgr.get_client.return_value = mock_es_client

    curator = DetectionRuleCurator(es_manager=mock_es_mgr, upstream_rules_dir=tmp_path, jarvis_rules_dir=tmp_path / "jarvis")

    # Telemetry where Event Code 10 (ProcessAccess) is NOT collected (0 docs)
    telemetry_missing_eid10 = {
        "indexed_fields_set": {"host.os.type", "event.code", "process.name"},
        "categories": {"process": 40000},
        "event_codes": {"1": 15000, "3": 5000},
    }

    rule_toml = tmp_path / "windows" / "lsass_access.toml"
    rule_toml.parent.mkdir(parents=True, exist_ok=True)
    rule_toml.write_text(
        '''
[rule]
name = "LSASS Process Access"
rule_id = "rule-333"
language = "eql"
type = "eql"
severity = "critical"
risk_score = 99
index = ["winlogbeat-*"]
query = 'process where host.os.type == "windows" and event.code == "10" and process.name == "lsass.exe"'
''',
        encoding="utf-8",
    )

    res = await curator.dry_run_single_rule(rule_toml, telemetry_missing_eid10, hours_back=24)
    assert res["liveness"]["status"] == "TELEMETRY_BLIND_SPOT"
    assert res["assessment"]["noise_profile"] == "BLIND_SPOT_NO_TELEMETRY"

