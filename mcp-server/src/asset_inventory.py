"""Hybrid Asset Inventory & Environment Relevance Engine for Jarvis SecOps.

Combines:
1. Declarative environment profile & weighted relevance scoring (inspired by
   matt-snyder-stuff/threat-intel's operations/context.py & environment-profile.json).
2. Live telemetry auto-discovery from Proxmox VE API, UniFi Firewall syslog streams,
   and Windows Sysmon/Winlogbeat endpoint logs.
3. Active asynchronous TCP port & banner discovery across configured homelab hosts.
4. Direct indexing into Elasticsearch (`logs-threat_intel.assets-default`).
"""

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.client import ElasticClientManager
from src.proxmox import ProxmoxClientManager

DEFAULT_PROFILE_PATH = Path(__file__).resolve().parent.parent / "config" / "environment-profile.json"
ASSETS_INDEX = "logs-threat_intel.assets-default"

# Common administrative & service ports for active LAN probing
PROBE_PORTS: Dict[int, str] = {
    22: "SSH",
    53: "DNS",
    80: "HTTP",
    135: "msrpc",
    443: "HTTPS",
    445: "SMB",
    514: "Syslog",
    3389: "RDP",
    5044: "Beats",
    5601: "Kibana",
    8006: "Proxmox-VE-API",
    8443: "UniFi-Controller-HTTPS",
    9200: "Elasticsearch-REST",
    11434: "Ollama-LLM-API",
}


class AssetInventoryManager:
    """Manages environment profiles, asset discovery, and SIEM inventory indexing."""

    def __init__(
        self,
        es_manager: Optional[ElasticClientManager] = None,
        proxmox_manager: Optional[ProxmoxClientManager] = None,
        profile_path: Optional[Path] = None,
    ):
        self.es = es_manager or ElasticClientManager()
        self.proxmox = proxmox_manager or ProxmoxClientManager()
        env_profile_override = os.getenv("ENVIRONMENT_PROFILE")
        if profile_path:
            self.profile_path = Path(profile_path)
        elif env_profile_override:
            self.profile_path = Path(env_profile_override)
        else:
            self.profile_path = DEFAULT_PROFILE_PATH
        self._profile_cache: Optional[Dict[str, Any]] = None

    def load_environment_profile(self) -> Dict[str, Any]:
        """Load and validate the environment relevance profile and baseline assets."""
        if self._profile_cache is not None:
            return self._profile_cache

        if not self.profile_path.exists():
            self._profile_cache = {
                "name": "Default Jarvis Environment",
                "priorities": {"labels": {}, "vendors": {}, "threat_actors": {}, "keywords": {}},
                "baseline_assets": [],
            }
            return self._profile_cache

        with open(self.profile_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        self._profile_cache = data
        return data

    def score_environment_relevance(
        self,
        title: str,
        description: str = "",
        labels: Optional[List[str]] = None,
        vendors: Optional[List[str]] = None,
        threat_actors: Optional[List[str]] = None,
    ) -> Tuple[int, List[str]]:
        """Score a threat report or CVE (0-100) against the local Jarvis environment profile.

        Adapted from matt-snyder-stuff/threat-intel/operations/context.py.
        """
        profile = self.load_environment_profile()
        priorities = profile.get("priorities", {})

        candidates = {
            "labels": labels or [],
            "vendors": vendors or [],
            "threat_actors": threat_actors or [],
        }

        score = 0
        matches: List[str] = []

        for category, values in candidates.items():
            configured = priorities.get(category, {})
            for val in values:
                for target, weight in configured.items():
                    if val.lower() == target.lower():
                        score += int(weight)
                        matches.append(f"{category}:{target}")

        combined_text = f"{title or ''} {description or ''}".lower()
        for keyword, weight in priorities.get("keywords", {}).items():
            if keyword.lower() in combined_text:
                score += int(weight)
                matches.append(f"keywords:{keyword}")

        # Also check baseline asset vendors and product names
        for asset in profile.get("baseline_assets", []):
            vendor = asset.get("vendor", "")
            if vendor and vendor.lower() in combined_text and f"vendors:{vendor}" not in matches:
                v_weight = priorities.get("vendors", {}).get(vendor, 20)
                score += int(v_weight)
                matches.append(f"asset_vendor:{vendor}")

        return min(score, 100), sorted(set(matches))

    async def probe_tcp_port(self, ip: str, port: int, timeout: float = 0.75) -> Optional[Dict[str, Any]]:
        """Asynchronously probe a single TCP port and attempt lightweight banner/HTTP header grab."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            banner = ""
            try:
                if port in {80, 5601, 9200, 11434}:
                    writer.write(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode("ascii"))
                    await writer.drain()
                raw = await asyncio.wait_for(reader.read(256), timeout=0.4)
                if raw:
                    first_line = raw.decode("utf-8", errors="ignore").splitlines()[0].strip()
                    banner = first_line[:120]
            except Exception:
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

            return {
                "port": port,
                "service": PROBE_PORTS.get(port, "tcp"),
                "state": "open",
                "banner": banner,
            }
        except Exception:
            return None

    async def probe_host_ports(
        self, ip: str, ports: Optional[List[int]] = None, timeout: float = 0.75
    ) -> List[Dict[str, Any]]:
        """Probe multiple TCP ports on a target host concurrently."""
        target_ports = ports or list(PROBE_PORTS.keys())
        tasks = [self.probe_tcp_port(ip, p, timeout=timeout) for p in target_ports]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]

    async def discover_from_proxmox(self) -> Dict[str, Any]:
        """Pull live hypervisor version, kernel, and virtual machine metadata from Proxmox VE."""
        discovered: Dict[str, Any] = {"host_info": {}, "vms": []}
        if not self.proxmox or not self.proxmox.is_configured():
            return discovered

        try:
            nodes = await self.proxmox.get_nodes()
            if nodes:
                node_name = nodes[0].get("node", "pve")
                detailed = await self.proxmox.get_node_status(node_name)
                discovered["host_info"] = {
                    "node": node_name,
                    "pveversion": detailed.get("pveversion"),
                    "kversion": detailed.get("kversion"),
                    "cpu_model": detailed.get("cpuinfo", {}).get("model"),
                    "status": nodes[0].get("status", "online"),
                }
            vms = await self.proxmox.get_cluster_resources(resource_type="vm")
            for vm in vms:
                discovered["vms"].append(
                    {
                        "vmid": vm.get("vmid"),
                        "name": vm.get("name"),
                        "status": vm.get("status"),
                        "node": vm.get("node"),
                    }
                )
        except Exception:
            pass
        return discovered

    async def discover_from_siem_telemetry(self) -> Dict[str, Any]:
        """Inspect Elastic SIEM logs for active UniFi gateway and Windows Sysmon endpoint metadata."""
        telemetry_info: Dict[str, Any] = {
            "unifi_active": False,
            "unifi_event_count": 0,
            "unifi_hosts": [],
            "sysmon_active": False,
            "sysmon_event_count": 0,
            "endpoints": [],
        }
        try:
            client = self.es.get_client()

            # 1. Check UniFi logs
            unifi_res = await client.search(
                index="logs-network.unifi-*",
                size=1,
                sort=[{"@timestamp": {"order": "desc"}}],
                aggs={"hosts": {"terms": {"field": "host.name", "size": 5}}},
            )
            unifi_total = unifi_res.get("hits", {}).get("total", {}).get("value", 0)
            telemetry_info["unifi_active"] = unifi_total > 0
            telemetry_info["unifi_event_count"] = unifi_total
            host_buckets = unifi_res.get("aggregations", {}).get("hosts", {}).get("buckets", [])
            telemetry_info["unifi_hosts"] = [b["key"] for b in host_buckets]

            # 2. Check Sysmon / Winlogbeat endpoint logs
            ep_res = await client.search(
                index="logs-endpoint.*,winlogbeat*",
                size=1,
                sort=[{"@timestamp": {"order": "desc"}}],
                aggs={
                    "hostnames": {"terms": {"field": "host.name", "size": 5}},
                    "os_names": {"terms": {"field": "host.os.name", "size": 5}},
                    "os_versions": {"terms": {"field": "host.os.version", "size": 5}},
                },
            )
            ep_total = ep_res.get("hits", {}).get("total", {}).get("value", 0)
            telemetry_info["sysmon_active"] = ep_total > 0
            telemetry_info["sysmon_event_count"] = ep_total
            ep_hosts = [b["key"] for b in ep_res.get("aggregations", {}).get("hostnames", {}).get("buckets", [])]
            os_names = [b["key"] for b in ep_res.get("aggregations", {}).get("os_names", {}).get("buckets", [])]
            os_versions = [b["key"] for b in ep_res.get("aggregations", {}).get("os_versions", {}).get("buckets", [])]
            telemetry_info["endpoints"] = [
                {
                    "hostname": h,
                    "os_name": os_names[0] if os_names else "Windows 11",
                    "os_version": os_versions[0] if os_versions else "10.0.22631",
                }
                for h in ep_hosts
            ]
        except Exception:
            pass

        return telemetry_info

    async def sync_asset_inventory(
        self,
        run_active_scan: bool = True,
        extra_ips: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Synchronize the hybrid asset inventory and index all assets into Elasticsearch."""
        now_iso = datetime.now(timezone.utc).isoformat()
        profile = self.load_environment_profile()
        baseline_assets = profile.get("baseline_assets", [])

        proxmox_data, siem_data = await asyncio.gather(
            self.discover_from_proxmox(),
            self.discover_from_siem_telemetry(),
        )

        assets: List[Dict[str, Any]] = []
        for base in baseline_assets:
            asset = dict(base)
            asset_id = asset["asset_id"]
            ip = asset.get("ip", "")
            discovery_sources = ["environment-profile"]

            # Enrich with live Proxmox telemetry
            if "proxmox" in asset_id and proxmox_data.get("host_info"):
                pve_info = proxmox_data["host_info"]
                if pve_info.get("pveversion"):
                    asset["version"] = pve_info["pveversion"]
                if pve_info.get("kversion"):
                    asset["kernel_version"] = pve_info["kversion"]
                asset["running_vms"] = [v.get("name") for v in proxmox_data.get("vms", []) if v.get("status") == "running"]
                discovery_sources.append("proxmox-api")

            # Enrich UniFi gateway with live SIEM log status
            if "udr" in asset_id and siem_data.get("unifi_active"):
                asset["telemetry_events_ingested"] = siem_data.get("unifi_event_count", 0)
                discovery_sources.append("unifi-syslog-telemetry")

            # Enrich Windows workstation with live Sysmon telemetry
            if "workstation" in asset_id and siem_data.get("sysmon_active"):
                asset["telemetry_events_ingested"] = siem_data.get("sysmon_event_count", 0)
                eps = siem_data.get("endpoints", [])
                if eps:
                    asset["os_version_build"] = eps[0].get("os_version", "")
                    asset["os_family"] = eps[0].get("os_name", asset.get("os_family"))
                discovery_sources.append("sysmon-winlogbeat-telemetry")

            # Enrich SIEM & GPU node
            if "siem-gpu" in asset_id:
                discovery_sources.append("elasticsearch-cluster-api")

            # Active network port & banner scan
            open_ports_info: List[Dict[str, Any]] = []
            if run_active_scan and ip:
                ports_to_check = sorted(set(list(PROBE_PORTS.keys()) + asset.get("expected_ports", [])))
                open_ports_info = await self.probe_host_ports(ip, ports=ports_to_check)
                if open_ports_info:
                    discovery_sources.append("active-lan-port-scan")

            asset["open_ports"] = [p["port"] for p in open_ports_info]
            asset["service_banners"] = [
                f"{p['port']}/{p['service']}" + (f" ({p['banner']})" if p.get("banner") else "")
                for p in open_ports_info
            ]
            asset["discovery_sources"] = discovery_sources
            asset["status"] = "online" if (len(discovery_sources) > 1 or open_ports_info) else "configured"
            asset["last_synced"] = now_iso
            assets.append(asset)

        # Probe any additional user-supplied IPs not already in baseline
        known_ips = {a.get("ip") for a in assets}
        if run_active_scan and extra_ips:
            for extra_ip in extra_ips:
                if extra_ip in known_ips:
                    continue
                open_ports_info = await self.probe_host_ports(extra_ip)
                if open_ports_info:
                    assets.append(
                        {
                            "asset_id": f"discovered-{extra_ip.replace('.', '-')}",
                            "name": f"Discovered LAN Host ({extra_ip})",
                            "ip": extra_ip,
                            "hostname": extra_ip,
                            "role": "discovered-network-host",
                            "criticality": "medium",
                            "criticality_weight": 15,
                            "internet_facing": False,
                            "vendor": "Unknown",
                            "product": "Network Appliance / Host",
                            "version": "unknown",
                            "os_family": "Unknown",
                            "cpe_patterns": [],
                            "search_keywords": [],
                            "open_ports": [p["port"] for p in open_ports_info],
                            "service_banners": [
                                f"{p['port']}/{p['service']}" + (f" ({p['banner']})" if p.get("banner") else "")
                                for p in open_ports_info
                            ],
                            "discovery_sources": ["active-lan-port-scan"],
                            "status": "online",
                            "last_synced": now_iso,
                        }
                    )

        # Index each asset into Elasticsearch
        indexed_count = 0
        es_errors: List[str] = []
        try:
            client = self.es.get_client()
            for asset in assets:
                doc = {
                    "@timestamp": now_iso,
                    "event": {
                        "kind": "state",
                        "category": ["host", "configuration"],
                        "type": ["info"],
                        "action": "asset_inventory_sync",
                        "dataset": "threat_intel.assets",
                    },
                    "host": {
                        "ip": asset.get("ip"),
                        "name": asset.get("hostname") or asset.get("name"),
                        "os": {
                            "family": asset.get("os_family"),
                            "version": asset.get("version"),
                            "kernel": asset.get("kernel_version", ""),
                        },
                    },
                    "asset": asset,
                }
                await client.index(
                    index=ASSETS_INDEX,
                    document=doc,
                    op_type="create",
                )
                indexed_count += 1
        except Exception as e:
            es_errors.append(str(e))

        return {
            "status": "success" if not es_errors else "partial",
            "timestamp": now_iso,
            "environment_name": profile.get("name"),
            "total_assets": len(assets),
            "indexed_to_es": indexed_count,
            "index_name": ASSETS_INDEX,
            "active_scan_performed": run_active_scan,
            "assets": assets,
            "errors": es_errors,
        }

    async def get_cached_or_live_assets(self) -> List[Dict[str, Any]]:
        """Retrieve assets from Elasticsearch if populated, otherwise return baseline assets."""
        try:
            client = self.es.get_client()
            res = await client.search(
                index=ASSETS_INDEX,
                size=50,
                sort=[{"@timestamp": {"order": "desc"}}],
            )
            hits = res.get("hits", {}).get("hits", [])
            if hits:
                seen_ids = set()
                deduped = []
                for h in hits:
                    a = h.get("_source", {}).get("asset", {})
                    aid = a.get("asset_id")
                    if aid and aid not in seen_ids:
                        seen_ids.add(aid)
                        deduped.append(a)
                if deduped:
                    return deduped
        except Exception:
            pass

        return self.load_environment_profile().get("baseline_assets", [])
