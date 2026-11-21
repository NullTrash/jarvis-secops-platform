"""Asset-Specific Vulnerability & CVE Correlator for Jarvis SecOps.

Matches inventoried homelab assets (Ubiquiti UniFi Dream Router, Proxmox VE,
Windows 11 Workstation Workstation-01, Elasticsearch/Kibana/Logstash 8.17, Ollama)
against:
1. CISA Known Exploited Vulnerabilities (KEV) Catalog (live JSON feed, no API key).
2. NIST NVD CVE API v2 (https://services.nvd.nist.gov/rest/json/cves/2.0).
3. Local Ollama GPU synthesis (`llama3.2:3b`) for tailored remediation guidance.
4. Direct indexing into Elasticsearch (`logs-threat_intel.vulnerabilities-default`).
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set
import httpx

from src.ai_harness import AITaskHarness
from src.asset_inventory import AssetInventoryManager
from src.client import ElasticClientManager

VULNS_INDEX = "logs-threat_intel.vulnerabilities-default"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class AssetVulnerabilityScanner:
    """Correlates live asset inventory against CISA KEV and NVD CVE feeds."""

    def __init__(
        self,
        es_manager: Optional[ElasticClientManager] = None,
        inventory_manager: Optional[AssetInventoryManager] = None,
        ai_harness: Optional[AITaskHarness] = None,
    ):
        self.es = es_manager or ElasticClientManager()
        self.inventory = inventory_manager or AssetInventoryManager(es_manager=self.es)
        self.ai_harness = ai_harness

    async def fetch_cisa_kev(self) -> List[Dict[str, Any]]:
        """Fetch CISA's Known Exploited Vulnerabilities (KEV) catalog."""
        try:
            async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
                resp = await client.get(CISA_KEV_URL)
                if resp.status_code == 200:
                    return resp.json().get("vulnerabilities", [])
        except Exception:
            pass
        return []

    async def fetch_nvd_cves_for_keyword(
        self, keyword: str, max_results: int = 8
    ) -> List[Dict[str, Any]]:
        """Query NIST NVD CVE API v2 for recent vulnerabilities matching an asset keyword."""
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": str(max_results),
        }
        headers = {"User-Agent": "Jarvis-SecOps-VulnScanner/1.0"}
        results: List[Dict[str, Any]] = []
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(NVD_API_URL, params=params, headers=headers)
                if resp.status_code == 200:
                    vulns = resp.json().get("vulnerabilities", [])
                    for v in vulns:
                        cve_obj = v.get("cve", {})
                        cve_id = cve_obj.get("id")
                        if not cve_id:
                            continue
                        # Extract English description
                        descriptions = cve_obj.get("descriptions", [])
                        desc = next(
                            (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
                            "",
                        )
                        # Extract CVSS v3.1 / v3.0 / v2 score
                        metrics = cve_obj.get("metrics", {})
                        cvss_score = 0.0
                        severity = "MEDIUM"
                        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                            m_list = metrics.get(metric_key, [])
                            if m_list:
                                cvss_data = m_list[0].get("cvssData", {})
                                cvss_score = float(cvss_data.get("baseScore", 0.0))
                                severity = cvss_data.get("baseSeverity") or m_list[0].get("baseSeverity", "MEDIUM")
                                break

                        results.append(
                            {
                                "cve_id": cve_id,
                                "published": cve_obj.get("published", ""),
                                "description": desc[:600],
                                "cvss_score": cvss_score,
                                "severity": severity.upper(),
                                "source": "NVD API v2",
                                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                            }
                        )
        except Exception:
            pass
        return results

    def match_cisa_kev_to_asset(
        self, kev_list: List[Dict[str, Any]], asset: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Match CISA KEV entries against a specific homelab asset by vendor and product keywords."""
        vendor = (asset.get("vendor") or "").lower()
        keywords = [k.lower() for k in asset.get("search_keywords", [])]
        matched: List[Dict[str, Any]] = []

        for entry in kev_list:
            kev_vendor = (entry.get("vendorProject") or "").lower()
            kev_product = (entry.get("product") or "").lower()
            kev_name = (entry.get("vulnerabilityName") or "").lower()
            kev_desc = (entry.get("shortDescription") or "").lower()
            combined = f"{kev_vendor} {kev_product} {kev_name} {kev_desc}"

            is_match = False
            if vendor and vendor in kev_vendor:
                # For broad vendors like Microsoft, require a product keyword match (e.g., Windows)
                if vendor == "microsoft":
                    is_match = any(
                        w in combined for w in ("windows 11", "windows 10", "mshtml", "win32k", "ntlm", "kerberos", "smb")
                    )
                else:
                    is_match = True
            elif any(kw in combined for kw in keywords if len(kw) > 4):
                is_match = True

            if is_match:
                cve_id = entry.get("cveID", "")
                matched.append(
                    {
                        "cve_id": cve_id,
                        "title": entry.get("vulnerabilityName", cve_id),
                        "published": entry.get("dateAdded", ""),
                        "description": entry.get("shortDescription", ""),
                        "required_action": entry.get("requiredAction", "Apply vendor patch immediately."),
                        "cvss_score": 8.8,  # KEV entries are confirmed actively exploited high/critical flaws
                        "severity": "CRITICAL",
                        "in_cisa_kev": True,
                        "ransomware_use": entry.get("knownRansomwareCampaignUse", "Unknown"),
                        "source": "CISA KEV",
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    }
                )

        # Sort by dateAdded descending so newest actively-exploited vulnerabilities surface first
        matched.sort(key=lambda x: x.get("published", ""), reverse=True)
        return matched[:8]

    def calculate_vuln_priority(self, vuln: Dict[str, Any], asset: Dict[str, Any]) -> int:
        """Calculate Operational Priority Score (0-100) for a vulnerability on an asset."""
        cvss = float(vuln.get("cvss_score") or 5.0)
        base = int(cvss * 6.0)  # up to 60 pts from CVSS
        kev_bonus = 25 if vuln.get("in_cisa_kev") else 0
        wan_bonus = 15 if asset.get("internet_facing") else 5
        return min(100, base + kev_bonus + wan_bonus)

    async def scan_all_assets(
        self,
        query_nvd: bool = True,
        generate_ai_advisory: bool = True,
        max_per_asset: int = 8,
    ) -> Dict[str, Any]:
        """Correlate all inventoried assets against CISA KEV and NVD CVEs, and index into Elasticsearch."""
        now_iso = datetime.now(timezone.utc).isoformat()
        assets = await self.inventory.get_cached_or_live_assets()
        kev_catalog = await self.fetch_cisa_kev()

        all_findings: List[Dict[str, Any]] = []
        asset_summaries: List[Dict[str, Any]] = []

        for asset in assets:
            asset_id = asset.get("asset_id", "unknown")
            asset_name = asset.get("name", asset_id)
            seen_cves: Set[str] = set()
            asset_vulns: List[Dict[str, Any]] = []

            # 1. Match CISA KEV
            kev_matches = self.match_cisa_kev_to_asset(kev_catalog, asset)
            for km in kev_matches[:max_per_asset]:
                seen_cves.add(km["cve_id"])
                km["priority_score"] = self.calculate_vuln_priority(km, asset)
                asset_vulns.append(km)

            # 2. Query NVD API v2 for primary search keyword if requested
            if query_nvd and asset.get("search_keywords"):
                primary_kw = asset["search_keywords"][0]
                nvd_matches = await self.fetch_nvd_cves_for_keyword(primary_kw, max_results=5)
                for nm in nvd_matches:
                    cid = nm["cve_id"]
                    if cid in seen_cves:
                        continue
                    seen_cves.add(cid)
                    nm["title"] = f"{asset.get('vendor')} {asset.get('product')}: {cid}"
                    nm["in_cisa_kev"] = False
                    nm["required_action"] = f"Verify {asset_name} version ({asset.get('version')}) against vendor advisory for {cid}."
                    nm["priority_score"] = self.calculate_vuln_priority(nm, asset)
                    asset_vulns.append(nm)

            asset_vulns.sort(key=lambda x: x.get("priority_score", 0), reverse=True)
            asset_vulns = asset_vulns[:max_per_asset]

            for v in asset_vulns:
                v["asset_id"] = asset_id
                v["asset_name"] = asset_name
                v["asset_ip"] = asset.get("ip")
                v["asset_vendor"] = asset.get("vendor")
                v["asset_product"] = asset.get("product")
                v["asset_version"] = asset.get("version")
                v["internet_facing"] = asset.get("internet_facing", False)
                all_findings.append(v)

            asset_summaries.append(
                {
                    "asset_id": asset_id,
                    "asset_name": asset_name,
                    "ip": asset.get("ip"),
                    "vendor": asset.get("vendor"),
                    "product": asset.get("product"),
                    "version": asset.get("version"),
                    "vulnerabilities_found": len(asset_vulns),
                    "cisa_kev_count": sum(1 for v in asset_vulns if v.get("in_cisa_kev")),
                    "top_cves": [v["cve_id"] for v in asset_vulns[:5]],
                }
            )

        # Optional local GPU LLM synthesis
        ai_advisory: Optional[Dict[str, Any]] = None
        if generate_ai_advisory and self.ai_harness and all_findings:
            top_vulns = sorted(all_findings, key=lambda x: x.get("priority_score", 0), reverse=True)[:8]
            prompt_lines = [
                "You are the Jarvis SecOps Vulnerability Management Agent. Analyze these asset-specific CVEs discovered against our homelab inventory (including our WAN-facing Ubiquiti UniFi Dream Router, Proxmox VE hypervisor, Windows 11 workstation, and Elastic SIEM stack):"
            ]
            for v in top_vulns:
                kev_tag = " [CISA KEV - ACTIVELY EXPLOITED]" if v.get("in_cisa_kev") else ""
                prompt_lines.append(
                    f"- {v['cve_id']}{kev_tag} on {v['asset_name']} ({v['asset_ip']}) | "
                    f"Priority: {v['priority_score']}/100 | CVSS: {v['cvss_score']} | {v['description'][:180]}"
                )
            prompt_lines.append(
                "\nProvide a concise 3-point vulnerability remediation brief:\n"
                "1. Highest-Risk Perimeter & Hypervisor Exposures (focus on UniFi Dream Router & Proxmox VE)\n"
                "2. Version Verification & Patching Order\n"
                "3. Compensating Controls in UniFi Firewall & Sysmon Detection Engine."
            )
            ai_res = await self.ai_harness.execute_and_audit(
                prompt="\n".join(prompt_lines),
                task_type="asset-vulnerability-triage",
                model="llama3.2:3b",
                agent_id="vuln-scanner-subagent",
                temperature=0.3,
                max_tokens=450,
            )
            ai_advisory = {
                "status": ai_res.get("status"),
                "model": ai_res.get("model"),
                "latency_ms": ai_res.get("latency_ms"),
                "tokens_per_second": ai_res.get("tokens_per_second"),
                "summary": ai_res.get("completion"),
                "audit_id": ai_res.get("audit_id"),
            }

        # Index all findings into Elasticsearch (`logs-threat_intel.vulnerabilities-default`)
        indexed_count = 0
        es_errors: List[str] = []
        try:
            client = self.es.get_client()
            for v in all_findings:
                doc_id = f"vuln-{v['asset_id']}-{v['cve_id']}"
                doc = {
                    "@timestamp": now_iso,
                    "event": {
                        "kind": "alert",
                        "category": ["vulnerability"],
                        "type": ["info"],
                        "dataset": "threat_intel.vulnerabilities",
                    },
                    "vulnerability": {
                        "id": v["cve_id"],
                        "title": v.get("title"),
                        "description": v.get("description"),
                        "severity": v.get("severity", "HIGH"),
                        "score": {"base": v.get("cvss_score", 0.0)},
                        "in_cisa_kev": v.get("in_cisa_kev", False),
                        "ransomware_campaign": v.get("ransomware_use", "Unknown"),
                        "required_action": v.get("required_action"),
                        "reference_url": v.get("url"),
                        "published_date": v.get("published"),
                        "scanner_source": v.get("source"),
                    },
                    "asset": {
                        "id": v["asset_id"],
                        "name": v["asset_name"],
                        "ip": v["asset_ip"],
                        "vendor": v["asset_vendor"],
                        "product": v["asset_product"],
                        "version": v["asset_version"],
                        "internet_facing": v["internet_facing"],
                    },
                    "threat": {
                        "priority_score": v["priority_score"],
                        "disposition": "unreviewed",
                    },
                }
                await client.index(
                    index=VULNS_INDEX,
                    document=doc,
                    op_type="create",
                )
                indexed_count += 1
        except Exception as e:
            es_errors.append(str(e))

        return {
            "status": "success" if not es_errors else "partial",
            "timestamp": now_iso,
            "assets_scanned": len(assets),
            "cisa_kev_catalog_size": len(kev_catalog),
            "total_vulnerabilities_matched": len(all_findings),
            "indexed_to_es": indexed_count,
            "index_name": VULNS_INDEX,
            "asset_breakdown": asset_summaries,
            "top_vulnerabilities": sorted(all_findings, key=lambda x: x.get("priority_score", 0), reverse=True)[:12],
            "ai_advisory": ai_advisory,
            "errors": es_errors,
        }
