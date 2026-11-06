"""Threat Intelligence & Behavioral Reputation Engine for Jarvis SecOps.

Provides automated threat reputation lookups across external threat feeds
(AbuseIPDB, VirusTotal) with fallback to local SIEM behavioral heuristics
derived from UniFi firewall drops and Sysmon endpoint telemetry.
"""

import ipaddress
import os
from pathlib import Path
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import httpx
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
load_dotenv()

# RFC 1918, Loopback, Link-Local, and IPv6 Private CIDR blocks excluded from external threat triage
INTERNAL_PRIVATE_CIDRS = [
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "0.0.0.0/8",
    "fe80::/10",
    "fc00::/7",
    "::1/128",
]

INTERNAL_PRIVATE_NETWORKS = [ipaddress.ip_network(cidr) for cidr in INTERNAL_PRIVATE_CIDRS]

# Known internal homelab / enterprise infrastructure assets (excluded from false-positive triage)
KNOWN_INTERNAL_ASSETS = {
    "10.0.0.1": "Ubiquiti UniFi Dream Router (Gateway)",
    "10.0.0.15": "Workstation-01 (Monitored Windows Endpoint)",
    "10.0.0.10": "Proxmox VE Hypervisor Host (pve)",
    "10.0.0.20": "Jarvis Elastic SIEM & GPU Compute Node",
    "127.0.0.1": "Localhost Loopback",
}

# Critical ports commonly targeted by automated worms, brute-forcers, and exploit kits
HIGH_RISK_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    137: "NetBIOS",
    139: "NetBIOS-SSN",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    8006: "Proxmox-API",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
}


class ThreatIntelManager:
    """Manages external and local threat intelligence enrichment."""

    def __init__(
        self,
        abuseipdb_api_key: Optional[str] = None,
        virustotal_api_key: Optional[str] = None,
        es_manager: Optional[Any] = None,
    ):
        self.abuseipdb_api_key = abuseipdb_api_key or os.getenv("ABUSEIPDB_API_KEY")
        self.virustotal_api_key = virustotal_api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self.es_manager = es_manager

    def is_public_ip(self, ip_str: str) -> bool:
        """Check if an IP string is a valid, globally routable public IPv4/IPv6 address."""
        try:
            addr = ipaddress.ip_address(ip_str.strip())
            return not (
                addr.is_private
                or addr.is_loopback
                or addr.is_reserved
                or addr.is_link_local
                or addr.is_multicast
            )
        except ValueError:
            return False

    def is_internal_lan_ip(self, ip_str: str) -> bool:
        """Check if an IP belongs to RFC 1918 private LAN, loopback, or link-local space."""
        try:
            addr = ipaddress.ip_address(ip_str.strip())
            return any(addr in net for net in INTERNAL_PRIVATE_NETWORKS)
        except ValueError:
            return False

    def detect_indicator_type(self, indicator: str) -> str:
        """Infer indicator type: ipv4, ipv6, md5, sha1, sha256, or domain."""
        ind = indicator.strip()
        try:
            addr = ipaddress.ip_address(ind)
            return "ipv4" if addr.version == 4 else "ipv6"
        except ValueError:
            pass

        if re.match(r"^[a-fA-F0-9]{32}$", ind):
            return "md5"
        if re.match(r"^[a-fA-F0-9]{40}$", ind):
            return "sha1"
        if re.match(r"^[a-fA-F0-9]{64}$", ind):
            return "sha256"

        return "domain"

    async def lookup_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Query AbuseIPDB API v2 for IP reputation and abuse score."""
        if not self.abuseipdb_api_key:
            return {
                "configured": False,
                "message": "AbuseIPDB API key not configured (set ABUSEIPDB_API_KEY)",
            }

        if not self.is_public_ip(ip):
            return {
                "configured": True,
                "is_public": False,
                "message": "Private or non-routable IP address ignored for external lookup",
            }

        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": True}
        headers = {
            "Key": self.abuseipdb_api_key,
            "Accept": "application/json",
            "User-Agent": "Jarvis-SecOps-Platform/1.0",
        }

        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                resp = await client.get(url, params=params, headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    return {
                        "configured": True,
                        "status": "success",
                        "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                        "total_reports": data.get("totalReports", 0),
                        "distinct_users": data.get("numDistinctUsers", 0),
                        "country_code": data.get("countryCode"),
                        "isp": data.get("isp"),
                        "usage_type": data.get("usageType"),
                        "is_whitelisted": data.get("isWhitelisted", False),
                        "last_reported_at": data.get("lastReportedAt"),
                    }
                else:
                    return {
                        "configured": True,
                        "status": "error",
                        "status_code": resp.status_code,
                        "error": resp.text[:200],
                    }
        except Exception as e:
            return {"configured": True, "status": "error", "error": str(e)}

    async def lookup_virustotal(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """Query VirusTotal API v3 for IP, domain, or hash reputation."""
        if not self.virustotal_api_key:
            return {
                "configured": False,
                "message": "VirusTotal API key not configured (set VIRUSTOTAL_API_KEY)",
            }

        headers = {
            "x-apikey": self.virustotal_api_key,
            "Accept": "application/json",
            "User-Agent": "Jarvis-SecOps-Platform/1.0",
        }

        endpoint_map = {
            "ipv4": f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}",
            "ipv6": f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}",
            "domain": f"https://www.virustotal.com/api/v3/domains/{indicator}",
            "md5": f"https://www.virustotal.com/api/v3/files/{indicator}",
            "sha1": f"https://www.virustotal.com/api/v3/files/{indicator}",
            "sha256": f"https://www.virustotal.com/api/v3/files/{indicator}",
        }

        url = endpoint_map.get(indicator_type)
        if not url:
            return {"configured": True, "status": "error", "error": f"Unsupported indicator type: {indicator_type}"}

        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    attr = resp.json().get("data", {}).get("attributes", {})
                    stats = attr.get("last_analysis_stats", {})
                    return {
                        "configured": True,
                        "status": "success",
                        "malicious_count": stats.get("malicious", 0),
                        "suspicious_count": stats.get("suspicious", 0),
                        "harmless_count": stats.get("harmless", 0),
                        "undetected_count": stats.get("undetected", 0),
                        "reputation": attr.get("reputation", 0),
                        "network": attr.get("network"),
                        "as_owner": attr.get("as_owner"),
                    }
                else:
                    return {
                        "configured": True,
                        "status": "error",
                        "status_code": resp.status_code,
                        "error": resp.text[:200],
                    }
        except Exception as e:
            return {"configured": True, "status": "error", "error": str(e)}

    async def compute_local_behavioral_heuristics(
        self, indicator: str, hours_back: int = 24
    ) -> Dict[str, Any]:
        """Compute threat score (0-100) and attacker profiling using live SIEM telemetry."""
        # Exclude internal RFC 1918 LAN hosts & known trusted assets (e.g., Workstation-01 PC) from false-positive scoring
        if self.is_internal_lan_ip(indicator):
            asset_label = KNOWN_INTERNAL_ASSETS.get(indicator.strip(), "Internal RFC 1918 LAN Host")
            return {
                "score": 0,
                "severity": "Benign",
                "is_internal_asset": True,
                "asset_name": asset_label,
                "profile": f"Trusted Internal Asset ({asset_label})",
                "recommended_action": "Excluded from external threat scoring (Internal LAN / RFC 1918 host).",
                "risk_factors": [],
                "telemetry": {
                    "firewall_drops": 0,
                    "unique_ports_targeted": 0,
                    "ports": [],
                    "endpoint_events": 0,
                    "time_window_hours": hours_back,
                },
            }

        if not self.es_manager:
            return {
                "score": 0,
                "severity": "Unknown",
                "profile": "No SIEM connection",
                "details": {},
            }

        try:
            client = self.es_manager.get_client()

            # 1. Query perimeter drops in UniFi logs (size=1 to also extract GeoIP & ASN metadata)
            unifi_query = {
                "bool": {
                    "must": [
                        {"term": {"source.ip": indicator}},
                        {"range": {"@timestamp": {"gte": f"now-{hours_back}h", "lte": "now"}}},
                    ]
                }
            }
            unifi_aggs = {
                "distinct_ports": {"terms": {"field": "destination.port", "size": 30}},
                "top_rules": {"terms": {"field": "rule.name", "size": 5}},
            }

            unifi_res = await client.search(
                index="logs-network.unifi-*",
                query=unifi_query,
                size=1,
                aggs=unifi_aggs,
            )

            drop_count = unifi_res.get("hits", {}).get("total", {}).get("value", 0)
            port_buckets = unifi_res.get("aggregations", {}).get("distinct_ports", {}).get("buckets", [])
            targeted_ports = [b["key"] for b in port_buckets]
            unique_port_count = len(targeted_ports)

            # Extract GeoIP & ASN enrichment if present on the UniFi document
            geo_country = None
            asn_org = None
            asn_number = None
            hits_list = unifi_res.get("hits", {}).get("hits", [])
            if hits_list:
                sample_src = hits_list[0].get("_source", {}).get("source", {})
                geo_country = sample_src.get("geo", {}).get("country_name")
                as_info = sample_src.get("as", {})
                asn_org = as_info.get("organization_name") or as_info.get("organization", {}).get("name")
                asn_number = as_info.get("asn") or as_info.get("number")

            # 2. Query endpoint telemetry (Sysmon / Winlogbeat)
            endpoint_query = {
                "bool": {
                    "must": [
                        {
                            "multi_match": {
                                "query": indicator,
                                "fields": ["source.ip", "destination.ip", "dns.question.name", "hash.*"],
                            }
                        },
                        {"range": {"@timestamp": {"gte": f"now-{hours_back}h", "lte": "now"}}},
                    ]
                }
            }

            endpoint_res = await client.search(
                index="logs-endpoint.*,winlogbeat*",
                query=endpoint_query,
                size=5,
            )
            endpoint_count = endpoint_res.get("hits", {}).get("total", {}).get("value", 0)

            # 3. Calculate Risk Heuristic Score (0 - 100)
            score = 0
            risk_factors: List[str] = []

            # Volume scoring
            if drop_count > 1000:
                score += 45
                risk_factors.append(f"High-frequency flood ({drop_count} dropped packets)")
            elif drop_count > 200:
                score += 35
                risk_factors.append(f"Elevated drop volume ({drop_count} packets)")
            elif drop_count > 50:
                score += 25
                risk_factors.append(f"Moderate drop activity ({drop_count} packets)")
            elif drop_count > 5:
                score += 15
                risk_factors.append(f"Repeated drop attempts ({drop_count} packets)")

            # Port scanning breadth
            if unique_port_count >= 10:
                score += 30
                risk_factors.append(f"Horizontal sweep: probed {unique_port_count} distinct ports")
            elif unique_port_count >= 3:
                score += 15
                risk_factors.append(f"Multi-port probing: probed {unique_port_count} distinct ports")

            # High-risk target ports
            critical_hits = [p for p in targeted_ports if p in HIGH_RISK_PORTS]
            if critical_hits:
                score += 20
                service_names = [f"{p}/{HIGH_RISK_PORTS[p]}" for p in critical_hits[:4]]
                risk_factors.append(f"Targeted high-risk service ports: {', '.join(service_names)}")

            # Critical endpoint involvement
            if endpoint_count > 0:
                score += 40
                risk_factors.append(f"CRITICAL: Active internal endpoint contact detected ({endpoint_count} Sysmon events)")

            score = min(score, 100)

            # Severity Classification
            if score >= 80:
                severity = "Critical"
                recommended_action = "Immediate WAN edge block; inspect internal endpoints for lateral movement"
            elif score >= 55:
                severity = "High"
                recommended_action = "Enforce automated temporary ban; verify internal firewall drop rules"
            elif score >= 25:
                severity = "Medium"
                recommended_action = "Monitor scan velocity; rate-limit if recurrence continues"
            else:
                severity = "Low"
                recommended_action = "Routine internet background noise; no action required"

            # Profile classification
            if unique_port_count >= 5 and drop_count > 50:
                profile = "Horizontal Port Scanner / Recon Bot"
            elif 22 in targeted_ports and drop_count > 30:
                profile = "SSH Brute-Force Bot"
            elif 23 in targeted_ports and drop_count > 30:
                profile = "Telnet / IoT Botnet Scanner"
            elif 3389 in targeted_ports or 445 in targeted_ports:
                profile = "Windows Admin / SMB Exploiter"
            elif drop_count > 500:
                profile = "Volumetric DoS / Flooder"
            elif drop_count > 0:
                profile = "Opportunistic Probe"
            else:
                profile = "Inactive in current window"

            return {
                "score": score,
                "severity": severity,
                "profile": profile,
                "recommended_action": recommended_action,
                "risk_factors": risk_factors,
                "telemetry": {
                    "firewall_drops": drop_count,
                    "unique_ports_targeted": unique_port_count,
                    "ports": targeted_ports[:10],
                    "endpoint_events": endpoint_count,
                    "country": geo_country,
                    "asn": asn_number,
                    "as_org": asn_org,
                    "time_window_hours": hours_back,
                },
            }

        except Exception as e:
            return {
                "score": 0,
                "severity": "Error",
                "profile": f"Heuristics evaluation error: {str(e)}",
                "details": {},
            }

    async def evaluate_indicator(
        self, indicator: str, hours_back: int = 24
    ) -> Dict[str, Any]:
        """Comprehensive evaluation combining external feeds with local behavioral telemetry."""
        ind_type = self.detect_indicator_type(indicator)
        result: Dict[str, Any] = {
            "indicator": indicator,
            "indicator_type": ind_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # 1. Local SIEM Behavioral Evaluation
        local_eval = await self.compute_local_behavioral_heuristics(indicator, hours_back=hours_back)
        result["local_heuristics"] = local_eval

        # 2. AbuseIPDB
        if ind_type in {"ipv4", "ipv6"}:
            result["abuseipdb"] = await self.lookup_abuseipdb(indicator)

        # 3. VirusTotal
        result["virustotal"] = await self.lookup_virustotal(indicator, ind_type)

        # 4. Synthesize Combined Verdict
        abuse_score = result.get("abuseipdb", {}).get("abuse_confidence_score")
        vt_malicious = result.get("virustotal", {}).get("malicious_count")
        local_score = local_eval.get("score", 0)

        # Effective Combined Score
        if abuse_score is not None:
            combined_score = max(local_score, abuse_score)
        elif vt_malicious is not None and vt_malicious > 0:
            combined_score = max(local_score, min(vt_malicious * 15, 100))
        else:
            combined_score = local_score

        result["verdict"] = {
            "combined_score": combined_score,
            "severity": local_eval.get("severity", "Low") if combined_score <= local_score else (
                "Critical" if combined_score >= 80 else ("High" if combined_score >= 55 else "Medium")
            ),
            "profile": local_eval.get("profile", "Unknown"),
            "recommended_action": local_eval.get("recommended_action", "Monitor"),
        }

        return result
