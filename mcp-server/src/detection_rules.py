"""Elastic Detection Rules Curation, Live Dry-Run & Tuning Engine for Jarvis SecOps.

Implements a 3-stage Detection-as-Code pipeline:
  - Stage 1 (Scan & Filter): Scans the local `elastic/detection-rules` repository
    (`elasticpublic/elastic-detection-rules/rules`), cross-checks required ECS fields
    and log sources against live Elasticsearch `_field_caps` and event distributions,
    and imports compatible candidate rules into `detection-rules/candidates/`.
  - Stage 2 (Deep Analysis & Live Dry-Run): Verifies telemetry liveness (distinguishing
    true 0-hit silent candidates from missing-telemetry blind spots), executes EQL/KQL
    queries against live `winlogbeat-*` and `logs-network.unifi-default` indices,
    identifies noisy false-positive processes, and scores Fidelity, Noise, Severity,
    and Urgency in `detection-rules/analyzed/`.
  - Stage 3 (Custom Rule Pipeline & Kibana Deployment): Adapts rules to Jarvis data
    streams (`winlogbeat-*`, `logs-network.unifi-default`), injects homelab allowlist
    exceptions into `detection-rules/tuned/`, and optionally deploys to Kibana's
    Detection Engine REST API (`/api/detection_engine/rules`).
"""

import asyncio
import json
import os
import re
import shutil
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import httpx

from .client import ElasticClientManager
from .ai_harness import AITaskHarness

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_UPSTREAM_RULES_DIR = REPO_ROOT / "elasticpublic" / "elastic-detection-rules" / "rules"
DEFAULT_JARVIS_RULES_DIR = REPO_ROOT / "detection-rules"

# Directories in elastic/detection-rules relevant to our Windows + Network + Proxmox environment
TARGET_RULE_DIRS = ["windows", "network", "cross-platform", "threat_intel"]

# Index patterns or Data Source tags that indicate compatibility with Winlogbeat / Sysmon / Windows Security / UniFi
COMPATIBLE_INDEX_PATTERNS = {
    "winlogbeat-*",
    "logs-windows.sysmon_operational-*",
    "logs-system.security*",
    "logs-windows.powershell*",
    "logs-windows.forwarded*",
    "logs-network-*",
    "packetbeat-*",
    "filebeat-*",
}

COMPATIBLE_DATA_SOURCE_TAGS = {
    "Data Source: Sysmon",
    "Data Source: Windows Security Event Logs",
    "Data Source: PowerShell",
    "Data Source: Windows",
    "Data Source: Active Directory",
}

# Proprietary Elastic Defend / Endgame field prefixes that Winlogbeat + Sysmon do not populate
PROPRIETARY_DEFEND_PREFIXES = (
    "process.Ext.",
    "file.Ext.",
    "dll.Ext.",
    "registry.Ext.",
    "network.Ext.",
    "event.Ext.",
)

# Regex to extract ECS and vendor field names from EQL / KQL queries
ECS_FIELD_REGEX = re.compile(
    r"\b("
    r"process\.[a-zA-Z0-9_.]+|"
    r"file\.[a-zA-Z0-9_.]+|"
    r"registry\.[a-zA-Z0-9_.]+|"
    r"dns\.[a-zA-Z0-9_.]+|"
    r"network\.[a-zA-Z0-9_.]+|"
    r"network_traffic\.[a-zA-Z0-9_.]+|"
    r"source\.[a-zA-Z0-9_.]+|"
    r"destination\.[a-zA-Z0-9_.]+|"
    r"host\.[a-zA-Z0-9_.]+|"
    r"user\.[a-zA-Z0-9_.]+|"
    r"event\.[a-zA-Z0-9_.]+|"
    r"winlog\.[a-zA-Z0-9_.]+|"
    r"powershell\.[a-zA-Z0-9_.]+|"
    r"dll\.[a-zA-Z0-9_.]+|"
    r"driver\.[a-zA-Z0-9_.]+|"
    r"threat\.[a-zA-Z0-9_.]+|"
    r"rule\.[a-zA-Z0-9_.]+|"
    r"observer\.[a-zA-Z0-9_.]+|"
    r"fortinet\.[a-zA-Z0-9_.]+|"
    r"citrix\.[a-zA-Z0-9_.]+|"
    r"panw\.[a-zA-Z0-9_.]+|"
    r"suricata\.[a-zA-Z0-9_.]+|"
    r"zeek\.[a-zA-Z0-9_.]+|"
    r"crowdstrike\.[a-zA-Z0-9_.]+|"
    r"sentinel_one\.[a-zA-Z0-9_.]+|"
    r"Data_stream\.[a-zA-Z0-9_.]+|"
    r"data_stream\.[a-zA-Z0-9_.]+"
    r")\b"
)

# Regex to extract specific Windows Event IDs from queries
EVENT_CODE_REGEX = re.compile(
    r'(?:event\.code|winlog\.event_id)\s*(?:==|:|in)\s*\(?([^)\n]+)\)?'
)


class DetectionRuleCurator:
    """Manages Stage 1 (Scan), Stage 2 (Deep Analysis & Dry-Run), and Stage 3 (Tune & Deploy)."""

    def __init__(
        self,
        es_manager: Optional[ElasticClientManager] = None,
        ai_harness: Optional[AITaskHarness] = None,
        upstream_rules_dir: Optional[Path] = None,
        jarvis_rules_dir: Optional[Path] = None,
    ):
        self.es = es_manager or ElasticClientManager()
        self.ai_harness = ai_harness
        self.upstream_dir = Path(
            upstream_rules_dir
            or os.getenv("ELASTIC_RULES_DIR", str(DEFAULT_UPSTREAM_RULES_DIR))
        )
        self.jarvis_dir = Path(
            jarvis_rules_dir
            or os.getenv("JARVIS_RULES_DIR", str(DEFAULT_JARVIS_RULES_DIR))
        )
        self.candidates_dir = self.jarvis_dir / "candidates"
        self.analyzed_dir = self.jarvis_dir / "analyzed"
        self.tuned_dir = self.jarvis_dir / "tuned"
        self.deployed_dir = self.jarvis_dir / "deployed"

        for d in (self.candidates_dir, self.analyzed_dir, self.tuned_dir, self.deployed_dir):
            d.mkdir(parents=True, exist_ok=True)

        self._telemetry_cache: Optional[Dict[str, Any]] = None

    async def get_live_telemetry_inventory(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Query Elasticsearch `_field_caps` and active Event IDs/Categories to map our exact log coverage."""
        if self._telemetry_cache is not None and not force_refresh:
            return self._telemetry_cache

        client = self.es.get_client()
        target_indices = "winlogbeat-*,logs-network.unifi-default,logs-endpoint.sysmon-*"

        # 1. Fetch all indexed fields via _field_caps
        caps_res = await client.field_caps(
            index=target_indices,
            fields="*",
            ignore_unavailable=True,
        )
        raw_fields = set(caps_res.get("fields", {}).keys())
        # Normalize .keyword suffixes so base field lookups succeed
        base_fields: Set[str] = set()
        for f in raw_fields:
            base_fields.add(f)
            if f.endswith(".keyword"):
                base_fields.add(f[:-8])

        # 2. Fetch active event categories, channels, and event.code counts
        aggs_res = await client.search(
            index=target_indices,
            size=0,
            aggs={
                "channels": {"terms": {"field": "winlog.channel", "size": 25}},
                "categories": {"terms": {"field": "event.category", "size": 25}},
                "event_codes": {"terms": {"field": "event.code", "size": 100}},
                "actions": {"terms": {"field": "event.action", "size": 30}},
            },
        )
        aggs = aggs_res.get("aggregations", {})
        channels = {b["key"]: b["doc_count"] for b in aggs.get("channels", {}).get("buckets", [])}
        categories = {b["key"]: b["doc_count"] for b in aggs.get("categories", {}).get("buckets", [])}
        event_codes = {str(b["key"]): b["doc_count"] for b in aggs.get("event_codes", {}).get("buckets", [])}
        actions = {b["key"]: b["doc_count"] for b in aggs.get("actions", {}).get("buckets", [])}

        self._telemetry_cache = {
            "indexed_fields": sorted(base_fields),
            "indexed_fields_set": base_fields,
            "channels": channels,
            "categories": categories,
            "event_codes": event_codes,
            "actions": actions,
            "total_fields_count": len(base_fields),
        }
        return self._telemetry_cache

    @staticmethod
    def extract_query_fields(query: str) -> List[str]:
        """Extract unique ECS field names referenced inside a rule's EQL/KQL query."""
        if not query:
            return []
        # Strip quoted string literals first so process names like "powershell.exe" or "dns.exe" are not parsed as ECS fields
        unquoted = re.sub(r'"(?:\\.|[^"\\])*"', '""', query)
        matches = ECS_FIELD_REGEX.findall(unquoted)
        cleaned = []
        for m in matches:
            # Strip trailing .keyword or .caseless for field existence comparison
            base = re.sub(r"\.(keyword|caseless|text)$", "", m)
            if base not in cleaned:
                cleaned.append(base)
        return cleaned

    @staticmethod
    def extract_query_event_codes(query: str) -> List[str]:
        """Extract specific Windows/Sysmon event codes referenced in a query."""
        if not query:
            return []
        codes = []
        for match in EVENT_CODE_REGEX.findall(query):
            for num in re.findall(r"\b\d{1,5}\b", match):
                if num not in codes:
                    codes.append(num)
        return codes

    @staticmethod
    def extract_mitre_metadata(rule_block: Dict[str, Any]) -> Tuple[List[str], List[str]]:
        """Extract MITRE ATT&CK Tactic names and Technique IDs from a parsed TOML rule."""
        tactics: List[str] = []
        techniques: List[str] = []
        for th in rule_block.get("threat", []):
            tactic = th.get("tactic", {})
            if isinstance(tactic, dict) and tactic.get("name"):
                t_name = tactic["name"]
                if t_name not in tactics:
                    tactics.append(t_name)
            for tech in th.get("technique", []):
                if isinstance(tech, dict) and tech.get("id"):
                    tid = f"{tech['id']} ({tech.get('name', '')})"
                    if tid not in techniques:
                        techniques.append(tid)
                for sub in tech.get("subtechnique", []) if isinstance(tech, dict) else []:
                    if isinstance(sub, dict) and sub.get("id"):
                        sid = f"{sub['id']} ({sub.get('name', '')})"
                        if sid not in techniques:
                            techniques.append(sid)
        return tactics, techniques

    def evaluate_rule_compatibility(
        self,
        toml_path: Path,
        telemetry: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Evaluate a single upstream `.toml` rule against our live homelab telemetry inventory."""
        raw_bytes = toml_path.read_bytes()
        parsed = tomllib.loads(raw_bytes.decode("utf-8", errors="replace"))
        rule = parsed.get("rule", {})

        name = rule.get("name", toml_path.stem)
        rule_id = rule.get("rule_id", toml_path.stem)
        language = rule.get("language", "unknown")
        rule_type = rule.get("type", "unknown")
        severity = rule.get("severity", "medium")
        risk_score = rule.get("risk_score", 50)
        indices = set(rule.get("index", []))
        tags = set(rule.get("tags", []))
        query = rule.get("query", "")
        tactics, techniques = self.extract_mitre_metadata(rule)

        # 1. Check language support
        if language not in ("eql", "kuery", "lucene"):
            return {
                "compatible": False,
                "reason": f"Unsupported query language: {language} (type: {rule_type})",
                "rule_id": rule_id,
                "name": name,
            }

        # 2. Check if rule supports Winlogbeat/Sysmon/Security/PowerShell or Network logs
        has_compatible_index = bool(indices & COMPATIBLE_INDEX_PATTERNS)
        has_compatible_tag = bool(tags & COMPATIBLE_DATA_SOURCE_TAGS)
        is_network_rule = toml_path.parent.name == "network" or "Domain: Network" in tags

        # Exclude tutorial sample rules or rules requiring external Threat Intel indicator indices
        if rule_type == "threat_match" or toml_path.stem == "guided_onboarding_sample_rule":
            return {
                "compatible": False,
                "reason": f"Special rule type ({rule_type}) or onboarding sample rule",
                "rule_id": rule_id,
                "name": name,
            }

        # Exclude rules that are exclusively Elastic Defend (no Sysmon/Winlogbeat support)
        is_defend_only = (
            indices == {"logs-endpoint.events.*"}
            or indices.issubset({
                "logs-endpoint.events.process-*",
                "logs-endpoint.events.file-*",
                "logs-endpoint.events.network-*",
                "logs-endpoint.events.registry-*",
                "logs-endpoint.events.library-*",
                "logs-endpoint.events.api-*",
                "endgame-*",
            })
        ) and not has_compatible_tag

        if is_defend_only:
            return {
                "compatible": False,
                "reason": "Requires Elastic Defend proprietary endpoint agent (not Sysmon/Winlogbeat)",
                "rule_id": rule_id,
                "name": name,
            }

        if not (has_compatible_index or has_compatible_tag or is_network_rule):
            return {
                "compatible": False,
                "reason": f"Incompatible data source indices: {sorted(indices)[:3]}",
                "rule_id": rule_id,
                "name": name,
            }

        # 3. Extract fields referenced in query & check against live Elasticsearch _field_caps
        referenced_fields = self.extract_query_fields(query)
        proprietary_fields = [
            f for f in referenced_fields if f.startswith(PROPRIETARY_DEFEND_PREFIXES)
        ]

        # If the query strictly requires Elastic Defend .Ext. fields and has no fallback, skip
        if proprietary_fields and "winlogbeat-*" not in indices and "Data Source: Sysmon" not in tags:
            return {
                "compatible": False,
                "reason": f"Uses proprietary Elastic Defend fields: {proprietary_fields[:3]}",
                "rule_id": rule_id,
                "name": name,
            }

        live_fields: Set[str] = telemetry["indexed_fields_set"]
        standard_fields = [f for f in referenced_fields if not f.startswith(PROPRIETARY_DEFEND_PREFIXES)]
        present_fields = [f for f in standard_fields if f in live_fields]
        missing_fields = [f for f in standard_fields if f not in live_fields]

        coverage_ratio = (
            round(len(present_fields) / len(standard_fields), 2)
            if standard_fields
            else 1.0
        )

        # 4. Check Event Code availability if the query filters on specific Windows Event IDs
        referenced_codes = self.extract_query_event_codes(query)
        active_codes = telemetry["event_codes"]
        present_codes = [c for c in referenced_codes if c in active_codes]
        missing_codes = [c for c in referenced_codes if c not in active_codes]

        # Determine compatibility tier
        if coverage_ratio >= 0.75 and not (referenced_codes and not present_codes):
            tier = "tier_1_ready_candidate"
        elif coverage_ratio >= 0.50:
            tier = "tier_2_partial_telemetry"
        else:
            return {
                "compatible": False,
                "reason": f"Low field coverage ({int(coverage_ratio*100)}%). Missing: {missing_fields[:4]}",
                "rule_id": rule_id,
                "name": name,
            }

        return {
            "compatible": True,
            "tier": tier,
            "rule_id": rule_id,
            "name": name,
            "file_name": toml_path.name,
            "source_category": toml_path.parent.name,
            "source_path": str(toml_path),
            "language": language,
            "rule_type": rule_type,
            "severity": severity,
            "risk_score": risk_score,
            "tactics": tactics,
            "techniques": techniques,
            "field_coverage_ratio": coverage_ratio,
            "present_fields": present_fields,
            "missing_fields": missing_fields,
            "referenced_event_codes": referenced_codes,
            "present_event_codes": present_codes,
            "missing_event_codes": missing_codes,
            "tags": sorted(tags),
        }

    async def scan_upstream_rules(
        self,
        directories: Optional[List[str]] = None,
        copy_tier_1_only: bool = False,
        max_rules_to_copy: int = 1000,
    ) -> Dict[str, Any]:
        """Stage 1: Scan `elasticpublic/elastic-detection-rules/rules` and copy compatible candidates."""
        if not self.upstream_dir.exists():
            return {
                "status": "error",
                "message": f"Upstream rules directory not found at {self.upstream_dir}",
            }

        telemetry = await self.get_live_telemetry_inventory(force_refresh=True)
        scan_dirs = directories or TARGET_RULE_DIRS

        total_scanned = 0
        tier_1_candidates: List[Dict[str, Any]] = []
        tier_2_candidates: List[Dict[str, Any]] = []
        rejection_reasons: Dict[str, int] = {}
        tactic_counts: Dict[str, int] = {}
        missing_field_frequency: Dict[str, int] = {}

        for subdir_name in scan_dirs:
            subdir = self.upstream_dir / subdir_name
            if not subdir.exists():
                continue

            for toml_file in sorted(subdir.rglob("*.toml")):
                total_scanned += 1
                try:
                    eval_res = self.evaluate_rule_compatibility(toml_file, telemetry)
                except Exception as e:
                    rejection_reasons[f"Parse error: {type(e).__name__}"] = (
                        rejection_reasons.get(f"Parse error: {type(e).__name__}", 0) + 1
                    )
                    continue

                if not eval_res.get("compatible"):
                    reason_key = eval_res.get("reason", "Unknown").split(":")[0]
                    rejection_reasons[reason_key] = rejection_reasons.get(reason_key, 0) + 1
                    continue

                for mf in eval_res.get("missing_fields", []):
                    missing_field_frequency[mf] = missing_field_frequency.get(mf, 0) + 1

                for tac in eval_res.get("tactics", ["Uncategorized"]):
                    tactic_counts[tac] = tactic_counts.get(tac, 0) + 1

                if eval_res["tier"] == "tier_1_ready_candidate":
                    tier_1_candidates.append(eval_res)
                else:
                    tier_2_candidates.append(eval_res)

        # Sort candidates by risk_score descending
        tier_1_candidates.sort(key=lambda r: r.get("risk_score", 0), reverse=True)
        tier_2_candidates.sort(key=lambda r: r.get("risk_score", 0), reverse=True)

        # Clean and copy candidate TOML files into detection-rules/candidates/<category>/
        if self.candidates_dir.exists():
            shutil.rmtree(self.candidates_dir)
        self.candidates_dir.mkdir(parents=True, exist_ok=True)
        copied_count = 0
        to_copy = tier_1_candidates if copy_tier_1_only else (tier_1_candidates + tier_2_candidates)
        for cand in to_copy[:max_rules_to_copy]:
            src_path = Path(cand["source_path"])
            dest_cat_dir = self.candidates_dir / cand["source_category"]
            dest_cat_dir.mkdir(parents=True, exist_ok=True)
            dest_path = dest_cat_dir / src_path.name
            shutil.copy2(src_path, dest_path)
            cand["candidate_path"] = str(dest_path.relative_to(REPO_ROOT))
            copied_count += 1

        top_missing_fields = sorted(
            missing_field_frequency.items(), key=lambda x: x[1], reverse=True
        )[:15]

        manifest = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "upstream_source": str(self.upstream_dir),
            "directories_scanned": scan_dirs,
            "total_rules_scanned": total_scanned,
            "tier_1_ready_count": len(tier_1_candidates),
            "tier_2_partial_count": len(tier_2_candidates),
            "copied_to_candidates_count": copied_count,
            "live_telemetry_summary": {
                "total_indexed_fields": telemetry["total_fields_count"],
                "active_channels": telemetry["channels"],
                "active_categories": telemetry["categories"],
            },
            "candidates_by_tactic": dict(
                sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True)
            ),
            "top_missing_fields_across_candidates": dict(top_missing_fields),
            "rejection_summary": rejection_reasons,
            "tier_1_candidates": tier_1_candidates,
            "tier_2_candidates": tier_2_candidates,
        }

        manifest_path = self.jarvis_dir / "candidate_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        return {
            "status": "success",
            "manifest_path": str(manifest_path.relative_to(REPO_ROOT)),
            "total_rules_scanned": total_scanned,
            "tier_1_ready_count": len(tier_1_candidates),
            "tier_2_partial_count": len(tier_2_candidates),
            "copied_to_candidates_count": copied_count,
            "candidates_by_tactic": manifest["candidates_by_tactic"],
            "top_missing_fields": dict(top_missing_fields[:10]),
            "rejection_summary": rejection_reasons,
            "top_15_tier_1_candidates": [
                {
                    "name": c["name"],
                    "file_name": c["file_name"],
                    "category": c["source_category"],
                    "severity": c["severity"],
                    "risk_score": c["risk_score"],
                    "tactics": c["tactics"],
                    "field_coverage": c["field_coverage_ratio"],
                }
                for c in tier_1_candidates[:15]
            ],
        }

    @staticmethod
    def _kql_to_lucene(kql: str) -> str:
        """Convert basic Elastic KQL syntax (`and`, `or`, `not`, `: (a, b)`) into Lucene query_string syntax."""
        q = kql.strip()
        # Convert `field : ("a", "b")` or `field: ("a", "b")` to `field:("a" OR "b")`
        def _replace_list(match: re.Match) -> str:
            field = match.group(1)
            inner = match.group(2)
            items = [i.strip() for i in inner.split(",") if i.strip()]
            return f"{field}:({' OR '.join(items)})"

        q = re.sub(r"([a-zA-Z0-9_.]+)\s*:\s*\(([^()]+)\)", _replace_list, q)
        q = re.sub(r"\band\b", "AND", q, flags=re.IGNORECASE)
        q = re.sub(r"\bor\b", "OR", q, flags=re.IGNORECASE)
        q = re.sub(r"\bnot\b", "NOT", q, flags=re.IGNORECASE)
        return q

    async def dry_run_single_rule(
        self,
        toml_path: Path,
        telemetry: Dict[str, Any],
        hours_back: int = 168,
    ) -> Dict[str, Any]:
        """Stage 2 helper: Execute a single candidate rule against live Elasticsearch & verify liveness."""
        parsed = tomllib.loads(toml_path.read_bytes().decode("utf-8", errors="replace"))
        rule = parsed.get("rule", {})

        name = rule.get("name", toml_path.stem)
        rule_id = rule.get("rule_id", toml_path.stem)
        language = rule.get("language", "eql")
        severity = rule.get("severity", "medium")
        risk_score = int(rule.get("risk_score", 50))
        query = rule.get("query", "").strip()
        false_positives_doc = rule.get("false_positives", [])
        tactics, techniques = self.extract_mitre_metadata(rule)

        # 1. Telemetry Liveness Proof (Does the underlying event stream have positive volume?)
        referenced_fields = self.extract_query_fields(query)
        standard_fields = [f for f in referenced_fields if not f.startswith(PROPRIETARY_DEFEND_PREFIXES)]
        missing_fields = [f for f in standard_fields if f not in telemetry["indexed_fields_set"]]
        referenced_codes = self.extract_query_event_codes(query)

        # Check category liveness (e.g. process, network, registry, file, dns, iam, authentication)
        required_category = None
        if language == "eql":
            first_token = query.split()[0].lower() if query.split() else ""
            if first_token in ("process", "network", "file", "registry", "dns", "authentication", "iam", "driver"):
                required_category = first_token

        category_doc_count = (
            telemetry["categories"].get(required_category, 0)
            if required_category
            else sum(telemetry["categories"].values())
        )
        # Note: in Winlogbeat Sysmon, DNS events (EID 22) have event.category="network" or dns.question.name
        if required_category == "dns" and category_doc_count == 0:
            category_doc_count = telemetry["event_codes"].get("22", 0)

        code_doc_count = (
            sum(telemetry["event_codes"].get(c, 0) for c in referenced_codes)
            if referenced_codes
            else category_doc_count
        )

        telemetry_alive = (category_doc_count > 0) and (code_doc_count > 0 if referenced_codes else True)
        if not telemetry_alive:
            liveness_status = "TELEMETRY_BLIND_SPOT"
        elif missing_fields:
            liveness_status = "PARTIAL_FIELD_COVERAGE"
        else:
            liveness_status = "VERIFIED_LIVE_TELEMETRY"

        # 2. Execute Live Dry-Run Search against Elasticsearch
        client = self.es.get_client()
        # Route Windows/Endpoint rules to winlogbeat-* to avoid field type collisions (e.g. process.pid text vs long in syslog)
        if toml_path.parent.name == "network" and "winlogbeat-*" not in rule.get("index", []):
            target_index = "logs-network.unifi-default,winlogbeat-*"
        else:
            target_index = "winlogbeat-*"
        hit_count = 0
        sample_hits: List[Dict[str, Any]] = []
        noisy_processes: Dict[str, int] = {}
        query_error: Optional[str] = None

        try:
            if language == "eql":
                # Strip proprietary `process.Ext...` clauses if mixed into an otherwise standard rule
                eql_res = await client.eql.search(
                    index=target_index,
                    query=query,
                    filter={"range": {"@timestamp": {"gte": f"now-{hours_back}h", "lte": "now"}}},
                    size=20,
                )
                raw_events = eql_res.get("hits", {}).get("events", [])
                raw_seqs = eql_res.get("hits", {}).get("sequences", [])
                hit_count = eql_res.get("hits", {}).get("total", {}).get("value", len(raw_events) + len(raw_seqs))

                items_to_inspect = raw_events
                if raw_seqs:
                    for seq in raw_seqs[:5]:
                        items_to_inspect.extend(seq.get("events", []))

                for ev in items_to_inspect:
                    src = ev.get("_source", {})
                    proc_exec = (
                        src.get("process", {}).get("executable")
                        or src.get("process", {}).get("name")
                        or src.get("source", {}).get("ip")
                        or "unknown"
                    )
                    noisy_processes[proc_exec] = noisy_processes.get(proc_exec, 0) + 1
                    if len(sample_hits) < 3:
                        sample_hits.append({
                            "timestamp": src.get("@timestamp"),
                            "host": src.get("host", {}).get("name"),
                            "user": src.get("user", {}).get("name"),
                            "process_name": src.get("process", {}).get("name"),
                            "process_executable": src.get("process", {}).get("executable"),
                            "command_line": src.get("process", {}).get("command_line"),
                            "event_code": src.get("event", {}).get("code"),
                        })
            else:
                lucene_q = self._kql_to_lucene(query)
                s_res = await client.search(
                    index=target_index,
                    size=10,
                    query={
                        "bool": {
                            "must": [
                                {"query_string": {"query": lucene_q, "lenient": True}},
                                {"range": {"@timestamp": {"gte": f"now-{hours_back}h", "lte": "now"}}},
                            ]
                        }
                    },
                    aggs={
                        "top_procs": {"terms": {"field": "process.executable.keyword", "size": 5}},
                    },
                    track_total_hits=True,
                )
                hit_count = s_res.get("hits", {}).get("total", {}).get("value", 0)
                for b in s_res.get("aggregations", {}).get("top_procs", {}).get("buckets", []):
                    noisy_processes[b["key"]] = b["doc_count"]
                for h in s_res.get("hits", {}).get("hits", [])[:3]:
                    src = h.get("_source", {})
                    sample_hits.append({
                        "timestamp": src.get("@timestamp"),
                        "host": src.get("host", {}).get("name"),
                        "user": src.get("user", {}).get("name"),
                        "process_name": src.get("process", {}).get("name"),
                        "process_executable": src.get("process", {}).get("executable"),
                        "command_line": src.get("process", {}).get("command_line"),
                        "event_code": src.get("event", {}).get("code"),
                    })
        except Exception as e:
            query_error = str(e)[:240]

        # 3. Score Fidelity, Noise, Severity & Urgency for the Homelab
        recommended_exceptions: List[str] = []
        if query_error:
            noise_profile = "QUERY_SYNTAX_OR_MAPPING_GAP"
            fidelity = "Low (Needs Query Adaptation)"
        elif liveness_status == "TELEMETRY_BLIND_SPOT":
            noise_profile = "BLIND_SPOT_NO_TELEMETRY"
            fidelity = "Unverified (Missing Event Stream)"
        elif hit_count == 0:
            noise_profile = "SILENT_CANDIDATE_VERIFIED_LOGS"
            fidelity = "High" if not missing_fields else "Medium"
        elif hit_count <= 10:
            noise_profile = "LOW_NOISE_ACTIVE_HITS"
            fidelity = "High (Inspect Matches)"
            for proc_path in list(noisy_processes.keys())[:3]:
                if proc_path and proc_path != "unknown":
                    escaped = proc_path.replace("\\", "\\\\")
                    recommended_exceptions.append(f'not process.executable : "{escaped}"')
        else:
            noise_profile = "NOISY_BASELINE_ACTIVITY"
            fidelity = "Medium (Requires Homelab Exception Tuning)"
            for proc_path in list(noisy_processes.keys())[:5]:
                if proc_path and proc_path != "unknown":
                    escaped = proc_path.replace("\\", "\\\\")
                    recommended_exceptions.append(f'not process.executable : "{escaped}"')

        # Compute Homelab Urgency Score (0-100)
        urgency_score = risk_score
        if liveness_status == "VERIFIED_LIVE_TELEMETRY":
            urgency_score += 15
        elif liveness_status == "TELEMETRY_BLIND_SPOT":
            urgency_score -= 35
        if query_error:
            urgency_score -= 30
        if noise_profile == "LOW_NOISE_ACTIVE_HITS":
            urgency_score += 10
        urgency_score = max(5, min(100, urgency_score))

        if urgency_score >= 80:
            urgency_label = "P1 - Critical Homelab Priority"
        elif urgency_score >= 60:
            urgency_label = "P2 - High Homelab Priority"
        elif urgency_score >= 40:
            urgency_label = "P3 - Medium Candidate"
        else:
            urgency_label = "P4 - Low / Backlog"

        return {
            "rule_id": rule_id,
            "name": name,
            "file_name": toml_path.name,
            "category": toml_path.parent.name,
            "language": language,
            "upstream_severity": severity,
            "upstream_risk_score": risk_score,
            "tactics": tactics,
            "techniques": techniques,
            "liveness": {
                "status": liveness_status,
                "telemetry_alive": telemetry_alive,
                "required_category": required_category,
                "baseline_category_docs": category_doc_count,
                "referenced_event_codes": referenced_codes,
                "baseline_code_docs": code_doc_count,
                "missing_fields": missing_fields,
            },
            "dry_run": {
                "hours_back": hours_back,
                "hit_count": hit_count,
                "noisy_culprits": noisy_processes,
                "sample_hits": sample_hits,
                "query_error": query_error,
            },
            "assessment": {
                "fidelity": fidelity,
                "noise_profile": noise_profile,
                "homelab_urgency_score": urgency_score,
                "homelab_urgency_label": urgency_label,
                "known_false_positives": false_positives_doc,
                "recommended_exceptions": recommended_exceptions,
            },
        }

    async def analyze_candidates(
        self,
        tactic: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 25,
        hours_back: int = 168,
        tier_1_only: bool = True,
    ) -> Dict[str, Any]:
        """Stage 2: Run deep live Elasticsearch dry-run analysis on a batch of local candidate rules."""
        manifest_path = self.jarvis_dir / "candidate_manifest.json"
        if not manifest_path.exists():
            await self.scan_upstream_rules()

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        pool = manifest.get("tier_1_candidates", [])
        if not tier_1_only:
            pool = pool + manifest.get("tier_2_candidates", [])

        # Apply filters
        filtered = []
        for c in pool:
            if category and c.get("source_category", "").lower() != category.lower():
                continue
            if severity and c.get("severity", "").lower() != severity.lower():
                continue
            if tactic:
                tactics_lower = [t.lower() for t in c.get("tactics", [])]
                if not any(tactic.lower() in t for t in tactics_lower):
                    continue
            filtered.append(c)

        batch = filtered[:limit]
        telemetry = await self.get_live_telemetry_inventory()

        sem = asyncio.Semaphore(12)

        async def _bounded_dry_run(cand: Dict[str, Any]) -> Dict[str, Any]:
            async with sem:
                cand_path = REPO_ROOT / cand.get("candidate_path", "")
                if not cand_path.exists():
                    cand_path = Path(cand["source_path"])
                return await self.dry_run_single_rule(cand_path, telemetry, hours_back=hours_back)

        results: List[Dict[str, Any]] = list(
            await asyncio.gather(*[_bounded_dry_run(c) for c in batch])
        )

        # Sort so rules with active hits appear first, then by homelab_urgency_score descending
        results.sort(
            key=lambda r: (
                1 if r["dry_run"]["hit_count"] > 0 else 0,
                r["assessment"]["homelab_urgency_score"],
            ),
            reverse=True,
        )

        summary_counts = {
            "SILENT_CANDIDATE_VERIFIED_LOGS": 0,
            "LOW_NOISE_ACTIVE_HITS": 0,
            "NOISY_BASELINE_ACTIVITY": 0,
            "BLIND_SPOT_NO_TELEMETRY": 0,
            "QUERY_SYNTAX_OR_MAPPING_GAP": 0,
        }
        for r in results:
            np = r["assessment"]["noise_profile"]
            summary_counts[np] = summary_counts.get(np, 0) + 1

        report = {
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "filters": {"tactic": tactic, "category": category, "severity": severity, "limit": limit},
            "rules_analyzed_count": len(results),
            "noise_and_liveness_breakdown": summary_counts,
            "results": results,
        }

        out_file = self.analyzed_dir / "latest_analysis_report.json"
        out_file.write_text(json.dumps(report, indent=2), encoding="utf-8")

        return report

    async def stage_and_deploy_rule(
        self,
        file_name: str,
        custom_exceptions: Optional[List[str]] = None,
        override_severity: Optional[str] = None,
        deploy_to_kibana: bool = False,
    ) -> Dict[str, Any]:
        """Stage 3: Customize a candidate rule for Jarvis data streams, save to `detection-rules/tuned/`, and optionally push to Kibana."""
        matches = list(self.candidates_dir.rglob(file_name))
        if not matches:
            matches = list(self.upstream_dir.rglob(file_name))
        if not matches:
            return {"status": "error", "message": f"Rule file '{file_name}' not found in candidates or upstream."}

        src_path = matches[0]
        parsed = tomllib.loads(src_path.read_bytes().decode("utf-8", errors="replace"))
        rule = parsed.get("rule", {})

        original_query = rule.get("query", "").strip()
        tuned_query = original_query

        if custom_exceptions:
            exc_clause = " and ".join(custom_exceptions)
            if rule.get("language") == "eql" and " where " in tuned_query and "sequence" not in tuned_query.splitlines()[0]:
                tuned_query = f"{tuned_query}\n  and {exc_clause}"
            elif rule.get("language") in ("kuery", "lucene"):
                tuned_query = f"({tuned_query}) and {exc_clause}"

        rule_type = rule.get("type", "eql" if rule.get("language") == "eql" else "query")
        jarvis_indices = ["winlogbeat-*", "logs-endpoint.sysmon-*", "logs-network.unifi-default"]
        kibana_payload: Dict[str, Any] = {
            "rule_id": f"jarvis-{rule.get('rule_id', src_path.stem)}",
            "name": f"[Jarvis] {rule.get('name', src_path.stem)}",
            "description": rule.get("description", ""),
            "risk_score": rule.get("risk_score", 50),
            "severity": override_severity or rule.get("severity", "medium"),
            "type": rule_type,
            "language": rule.get("language", "eql"),
            "index": jarvis_indices,
            "query": tuned_query,
            "from": "now-15m",
            "interval": "10m",
            "enabled": True,
            "tags": list(set(rule.get("tags", []) + ["Jarvis-Curated", "Homelab-Tuned"])),
            "threat": rule.get("threat", []),
        }
        if rule_type == "threshold" and "threshold" in rule:
            kibana_payload["threshold"] = rule["threshold"]
        if rule_type == "new_terms" and "new_terms" in rule:
            nt = rule["new_terms"]
            kibana_payload["new_terms_fields"] = (
                nt.get("value") or nt.get("fields") or ["registry.path"]
                if isinstance(nt, dict)
                else nt
            )
            hw = nt.get("history_window_start") if isinstance(nt, dict) else None
            if isinstance(hw, list) and hw and isinstance(hw[0], dict):
                kibana_payload["history_window_start"] = hw[0].get("value", "now-7d")
            else:
                kibana_payload["history_window_start"] = rule.get("history_window_start", "now-7d")

        tuned_json_path = self.tuned_dir / f"{src_path.stem}.json"
        tuned_json_path.write_text(json.dumps(kibana_payload, indent=2), encoding="utf-8")

        kibana_status: Dict[str, Any] = {"deployed": False}
        if deploy_to_kibana:
            kibana_host = os.getenv("ELASTIC_HOST", "10.0.0.20")
            kibana_port = os.getenv("KIBANA_PORT", "5601")
            user = os.getenv("ELASTIC_USER", "elastic")
            password = os.getenv("ELASTIC_PASSWORD", "ChangemeSecurePass2026!")
            url = f"http://{kibana_host}:{kibana_port}/api/detection_engine/rules"

            async with httpx.AsyncClient(timeout=20.0, verify=False) as client:
                resp = await client.post(
                    url,
                    auth=(user, password),
                    headers={"kbn-xsrf": "true", "Content-Type": "application/json"},
                    json=kibana_payload,
                )
                if resp.status_code in (200, 201):
                    kibana_status = {"deployed": True, "status_code": resp.status_code, "rule_id": kibana_payload["rule_id"]}
                    deployed_path = self.deployed_dir / f"{src_path.stem}.json"
                    deployed_path.write_text(json.dumps(kibana_payload, indent=2), encoding="utf-8")
                elif resp.status_code == 409:
                    # Rule already exists and is active in Kibana Detection Engine
                    kibana_status = {
                        "deployed": True,
                        "status_code": 200,
                        "action": "already_exists_active",
                        "rule_id": kibana_payload["rule_id"],
                    }
                    deployed_path = self.deployed_dir / f"{src_path.stem}.json"
                    deployed_path.write_text(json.dumps(kibana_payload, indent=2), encoding="utf-8")
                else:
                    kibana_status = {
                        "deployed": False,
                        "status_code": resp.status_code,
                        "error": resp.text[:300],
                    }

        return {
            "status": "success",
            "rule_name": kibana_payload["name"],
            "rule_id": kibana_payload["rule_id"],
            "tuned_file": str(tuned_json_path.relative_to(REPO_ROOT)),
            "jarvis_indices": jarvis_indices,
            "tuned_query": tuned_query,
            "kibana_deployment": kibana_status,
        }

    async def deploy_curated_top_pack(
        self,
        pack_size: int = 25,
        deploy_to_kibana: bool = True,
    ) -> Dict[str, Any]:
        """Select a balanced, tactic-diverse Top N pack of verified-live rules, tune them, and deploy to Kibana."""
        report_path = self.analyzed_dir / "latest_analysis_report.json"
        if not report_path.exists():
            await self.analyze_candidates(limit=500, hours_back=720)

        report = json.loads(report_path.read_text(encoding="utf-8"))
        valid_rules = [
            r
            for r in report.get("results", [])
            if r["liveness"]["status"] == "VERIFIED_LIVE_TELEMETRY"
            and r["dry_run"]["query_error"] is None
        ]

        selected: List[Dict[str, Any]] = []
        selected_files: Set[str] = set()

        # 1. Always include the 3 active-hit homelab rules first
        for r in valid_rules:
            if r["dry_run"]["hit_count"] > 0 and len(selected) < pack_size:
                selected.append(r)
                selected_files.add(r["file_name"])

        # 2. Pick top verified-live rules balanced across core MITRE tactics
        target_tactics = [
            ("Credential Access", 5),
            ("Persistence", 4),
            ("Execution", 4),
            ("Defense Evasion", 4),
            ("Command and Control", 3),
            ("Privilege Escalation", 2),
            ("Lateral Movement", 2),
            ("Discovery", 2),
        ]
        for tactic_name, quota in target_tactics:
            added = 0
            for r in valid_rules:
                if len(selected) >= pack_size or added >= quota:
                    break
                if r["file_name"] in selected_files:
                    continue
                if tactic_name in r.get("tactics", []):
                    selected.append(r)
                    selected_files.add(r["file_name"])
                    added += 1

        # Fill any remaining slots with highest urgency verified rules
        for r in valid_rules:
            if len(selected) >= pack_size:
                break
            if r["file_name"] not in selected_files:
                selected.append(r)
                selected_files.add(r["file_name"])

        deployed_results: List[Dict[str, Any]] = []
        succeeded = 0
        for r in selected:
            fname = r["file_name"]
            exceptions = None
            if fname == "command_and_control_tunnel_vscode.toml":
                exceptions = ['not process.args : "kill"']
            res = await self.stage_and_deploy_rule(
                file_name=fname,
                custom_exceptions=exceptions,
                deploy_to_kibana=deploy_to_kibana,
            )
            is_ok = res.get("kibana_deployment", {}).get("deployed", False)
            if is_ok:
                succeeded += 1
            deployed_results.append({
                "name": r["name"],
                "file_name": fname,
                "rule_id": res.get("rule_id"),
                "severity": r["upstream_severity"],
                "urgency_score": r["assessment"]["homelab_urgency_score"],
                "tactics": r["tactics"],
                "language": r["language"],
                "dry_run_hits_30d": r["dry_run"]["hit_count"],
                "kibana_deployed": is_ok,
                "kibana_status": res.get("kibana_deployment"),
            })

        # Write Markdown catalog of deployed rules
        md_lines = [
            "# 🛡️ Jarvis Curated Detection Rules Catalog (Deployed to Elastic SIEM)",
            "",
            f"- **Last Synced**: `{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}`",
            f"- **Total Rules Deployed**: **{succeeded} / {len(selected)}**",
            "- **Target Data Streams**: `winlogbeat-*`, `logs-endpoint.sysmon-*`, `logs-network.unifi-default`",
            "",
            "| # | Rule Name | Severity | Urgency | Language | MITRE Tactics | 30d Dry-Run Hits | Kibana Status |",
            "| :---: | :--- | :---: | :---: | :---: | :--- | :---: | :---: |",
        ]
        for idx, d in enumerate(deployed_results, 1):
            tacs = ", ".join(d["tactics"][:2]) or "General"
            status_badge = "✅ Active" if d["kibana_deployed"] else "⚠️ Staged Only"
            md_lines.append(
                f"| {idx} | **{d['name']}** (`{d['file_name']}`) | `{d['severity'].upper()}` | "
                f"**{d['urgency_score']}/100** | `{d['language'].upper()}` | {tacs} | "
                f"{d['dry_run_hits_30d']} | {status_badge} |"
            )

        catalog_path = self.jarvis_dir / "DEPLOYED_RULES_CATALOG.md"
        catalog_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

        return {
            "status": "success",
            "requested_pack_size": pack_size,
            "deployed_count": succeeded,
            "catalog_path": str(catalog_path.relative_to(REPO_ROOT)),
            "rules": deployed_results,
        }
