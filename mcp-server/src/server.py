"""Jarvis Elastic FastMCP Server.

Exposes standard MCP tools for AI assistants and orchestrators to query,
triage, and investigate security data across Elastic SIEM, UniFi Dream Router,
and Windows endpoint Sysmon logs.
"""

import asyncio
from typing import Annotated, Any, Dict, List, Optional
from fastmcp import FastMCP
from pydantic import Field

from src.client import ElasticClientManager
from src.proxmox import ProxmoxClientManager
from src.ollama import OllamaClientManager
from src.ai_harness import AITaskHarness
from src.threat_intel import ThreatIntelManager, INTERNAL_PRIVATE_CIDRS
from src.detection_rules import DetectionRuleCurator
from src.asset_inventory import AssetInventoryManager
from src.threat_feeds import ThreatFeedPipeline
from src.vuln_scanner import AssetVulnerabilityScanner
from src.identity_osint import IdentityExposureMonitor

# Initialize FastMCP Server
mcp = FastMCP("jarvis-elastic-siem")
es_manager = ElasticClientManager()
proxmox_manager = ProxmoxClientManager()
ollama_manager = OllamaClientManager()
ai_harness = AITaskHarness(
    ollama_manager=ollama_manager,
    es_manager=es_manager,
    proxmox_manager=proxmox_manager,
)
threat_intel = ThreatIntelManager(es_manager=es_manager)
rule_curator = DetectionRuleCurator(es_manager=es_manager, ai_harness=ai_harness)
asset_inventory = AssetInventoryManager(es_manager=es_manager, proxmox_manager=proxmox_manager)
threat_feeds = ThreatFeedPipeline(es_manager=es_manager, inventory_manager=asset_inventory)
vuln_scanner = AssetVulnerabilityScanner(
    es_manager=es_manager,
    inventory_manager=asset_inventory,
    ai_harness=ai_harness,
)
identity_monitor = IdentityExposureMonitor(es_manager=es_manager)


@mcp.tool(
    name="get_cluster_health",
    description="Check the operational health, node counts, and status of the Elastic SIEM cluster on Proxmox.",
)
async def get_cluster_health() -> Dict[str, Any]:
    """Retrieve cluster health and index stats."""
    client = es_manager.get_client()
    try:
        health = await client.cluster.health()
        indices = await client.cat.indices(format="json")
        return {
            "status": health.get("status"),
            "cluster_name": health.get("cluster_name"),
            "number_of_nodes": health.get("number_of_nodes"),
            "active_primary_shards": health.get("active_primary_shards"),
            "indices_count": len(indices),
            "indices_summary": [
                {
                    "index": idx.get("index"),
                    "docs_count": idx.get("docs.count"),
                    "store_size": idx.get("store.size"),
                    "health": idx.get("health"),
                }
                for idx in indices[:15]
            ],
        }
    except Exception as e:
        return {"error": f"Failed to connect to Elasticsearch: {str(e)}"}


@mcp.tool(
    name="search_security_events",
    description="Search security events in Elastic SIEM using Lucene queries, index patterns, and time filters.",
)
async def search_security_events(
    query: Annotated[str, Field(description="Lucene query string (e.g. 'event.action: firewall-drop' or 'process.name: powershell.exe')")],
    index_pattern: Annotated[str, Field(description="Index or Data Stream pattern to search (e.g. 'logs-network.*', 'logs-endpoint.*', 'winlogbeat*')")] = "logs-*,winlogbeat*",
    hours_back: Annotated[int, Field(description="How many hours back from now to search")] = 24,
    limit: Annotated[int, Field(description="Maximum number of hits to return (max 100)")] = 20,
) -> Dict[str, Any]:
    """Query Elasticsearch logs."""
    client = es_manager.get_client()
    time_filter = {
        "range": {
            "@timestamp": {
                "gte": f"now-{hours_back}h",
                "lte": "now",
            }
        }
    }
    search_query = {
        "bool": {
            "must": [
                {"query_string": {"query": query}},
                time_filter,
            ]
        }
    }

    try:
        response = await client.search(
            index=index_pattern,
            query=search_query,
            size=min(limit, 100),
            sort=[{"@timestamp": {"order": "desc"}}],
        )
        hits = response["hits"]["hits"]
        return {
            "total_matches": response["hits"]["total"]["value"],
            "returned_count": len(hits),
            "events": [hit["_source"] for hit in hits],
        }
    except Exception as e:
        return {"error": f"Search failed: {str(e)}"}


@mcp.tool(
    name="triage_unifi_firewall",
    description="Aggregate UniFi Dream Router firewall drops to discover top blocked external attacker IPs and targeted ports.",
)
async def triage_unifi_firewall(
    hours_back: Annotated[int, Field(description="Time window in hours to analyze")] = 24,
    top_n: Annotated[int, Field(description="Top N attackers/ports to return")] = 10,
    external_only: Annotated[bool, Field(description="Exclude internal RFC 1918 LAN/workstation IPs to prevent false positives")] = True,
) -> Dict[str, Any]:
    """Aggregate blocked incoming connection attempts from UDR."""
    client = es_manager.get_client()
    bool_clause: Dict[str, Any] = {
        "must": [
            {"term": {"event.action": "firewall-drop"}},
            {"range": {"@timestamp": {"gte": f"now-{hours_back}h", "lte": "now"}}},
        ]
    }
    if external_only:
        bool_clause["must_not"] = [
            {"terms": {"source.ip": INTERNAL_PRIVATE_CIDRS}}
        ]

    agg_query = {"bool": bool_clause}
    aggs = {
        "top_source_ips": {
            "terms": {"field": "source.ip", "size": top_n}
        },
        "top_targeted_ports": {
            "terms": {"field": "destination.port", "size": top_n}
        },
        "top_rules_triggered": {
            "terms": {"field": "rule.name", "size": top_n}
        },
        "top_countries": {
            "terms": {"field": "source.geo.country_name", "size": top_n}
        },
    }

    try:
        response = await client.search(
            index="logs-network.unifi-*",
            query=agg_query,
            size=0,
            aggs=aggs,
        )
        aggregations = response.get("aggregations", {})
        return {
            "time_window_hours": hours_back,
            "external_only": external_only,
            "total_drops": response["hits"]["total"]["value"],
            "top_attacker_ips": aggregations.get("top_source_ips", {}).get("buckets", []),
            "top_targeted_ports": aggregations.get("top_targeted_ports", {}).get("buckets", []),
            "top_rules": aggregations.get("top_rules_triggered", {}).get("buckets", []),
            "top_countries": aggregations.get("top_countries", {}).get("buckets", []),
        }
    except Exception as e:
        return {"error": f"UniFi triage failed: {str(e)}"}


@mcp.tool(
    name="investigate_indicator",
    description="Search across both network (UniFi) and endpoint (Sysmon) logs for any occurrence of an IP address, domain, or file hash.",
)
async def investigate_indicator(
    indicator: Annotated[str, Field(description="The IP address, domain name, or file hash to investigate")],
    hours_back: Annotated[int, Field(description="Time window in hours to search")] = 48,
) -> Dict[str, Any]:
    """Cross-correlate an indicator across all log sources."""
    client = es_manager.get_client()
    query = {
        "bool": {
            "must": [
                {"multi_match": {"query": indicator, "type": "best_fields"}},
                {"range": {"@timestamp": {"gte": f"now-{hours_back}h", "lte": "now"}}},
            ]
        }
    }

    try:
        response = await client.search(
            index="logs-*,winlogbeat*",
            query=query,
            size=30,
            sort=[{"@timestamp": {"order": "desc"}}],
        )
        hits = response["hits"]["hits"]
        threat_assessment = await threat_intel.evaluate_indicator(indicator, hours_back=hours_back)
        return {
            "indicator": indicator,
            "time_window_hours": hours_back,
            "threat_assessment": threat_assessment,
            "total_occurrences": response["hits"]["total"]["value"],
            "timeline": [
                {
                    "timestamp": hit["_source"].get("@timestamp"),
                    "index": hit.get("_index"),
                    "source_ip": hit["_source"].get("source", {}).get("ip"),
                    "dest_ip": hit["_source"].get("destination", {}).get("ip"),
                    "dest_port": hit["_source"].get("destination", {}).get("port"),
                    "event_action": hit["_source"].get("event", {}).get("action"),
                    "process_name": hit["_source"].get("process", {}).get("name"),
                    "command_line": hit["_source"].get("process", {}).get("command_line"),
                    "user": hit["_source"].get("user", {}).get("name"),
                }
                for hit in hits
            ],
        }
    except Exception as e:
        return {"error": f"Indicator correlation failed: {str(e)}"}


@mcp.tool(
    name="lookup_threat_intel",
    description="Query external threat feeds (AbuseIPDB, VirusTotal) and local SIEM behavioral heuristics for an IP address, domain, or file hash.",
)
async def lookup_threat_intel(
    indicator: Annotated[str, Field(description="The IP address, domain name, or file hash to evaluate")],
    hours_back: Annotated[int, Field(description="Time window in hours for local behavioral telemetry analysis")] = 24,
) -> Dict[str, Any]:
    """Retrieve comprehensive threat intelligence, abuse reputation, and behavioral risk scores."""
    try:
        return await threat_intel.evaluate_indicator(indicator, hours_back=hours_back)
    except Exception as e:
        return {"error": f"Threat intelligence lookup failed: {str(e)}"}


@mcp.tool(
    name="triage_threat_actors",
    description="Automated SecOps workflow: scans top external perimeter attacker IPs from UniFi firewall drops, enriches each with threat intelligence, and optionally runs local Llama 3.2 to synthesize an executive triage report.",
)
async def triage_threat_actors(
    hours_back: Annotated[int, Field(description="Time window in hours to analyze for attack surges")] = 168,
    top_n: Annotated[int, Field(description="Number of top attacker IPs to evaluate (1 to 10)")] = 5,
    generate_ai_summary: Annotated[bool, Field(description="Whether to run local LLM (llama3.2:3b) to synthesize an executive SecOps triage report")] = True,
) -> Dict[str, Any]:
    """Autonomous perimeter triage and threat intelligence workflow."""
    unifi_summary = await triage_unifi_firewall(hours_back=hours_back, top_n=top_n, external_only=True)
    if "error" in unifi_summary:
        return unifi_summary

    raw_ips = [b["key"] for b in unifi_summary.get("top_attacker_ips", [])]
    attacker_ips = [ip for ip in raw_ips if not threat_intel.is_internal_lan_ip(ip)][:top_n]

    actor_evaluations: List[Dict[str, Any]] = list(
        await asyncio.gather(*(threat_intel.evaluate_indicator(ip, hours_back=hours_back) for ip in attacker_ips))
    )

    result: Dict[str, Any] = {
        "status": "success",
        "time_window_hours": hours_back,
        "external_only": True,
        "total_firewall_drops": unifi_summary.get("total_drops", 0),
        "actors_evaluated_count": len(actor_evaluations),
        "top_actors": actor_evaluations,
    }

    if generate_ai_summary and actor_evaluations:
        prompt_lines = [
            f"You are the Jarvis SecOps autonomous triage agent. Analyze these top {len(actor_evaluations)} external WAN perimeter attackers blocked by the firewall over the last {hours_back} hours (internal LAN hosts and workstations have been excluded):",
        ]
        for a in actor_evaluations:
            ind = a.get("indicator")
            verdict = a.get("verdict", {})
            local = a.get("local_heuristics", {})
            telemetry = local.get("telemetry", {})
            country = telemetry.get("country") or "Unknown"
            as_org = telemetry.get("as_org") or "Unknown ISP"
            prompt_lines.append(
                f"- IP: {ind} ({country} / {as_org}) | Score: {verdict.get('combined_score')}/100 | "
                f"Severity: {verdict.get('severity')} | Profile: {verdict.get('profile')} | "
                f"Drops: {telemetry.get('firewall_drops', 0)} | Ports: {telemetry.get('ports', [])}"
            )
        prompt_lines.append(
            "\nProvide a concise 3-part SecOps assessment:\n"
            "1. Attack Pattern & Geopolitical/ASN Campaign Analysis (Are these coordinated subnets, IoT botnets, or opportunistic scanners?)\n"
            "2. Highest-Priority External Threats (Which IPs/ASNs pose the highest risk and why?)\n"
            "3. Actionable WAN Perimeter Recommendations (Specific ASN/subnet blocks, GeoIP restrictions, or port hardening)."
        )
        ai_prompt = "\n".join(prompt_lines)

        ai_res = await ai_harness.execute_and_audit(
            prompt=ai_prompt,
            task_type="secops-triage",
            model="llama3.2:3b",
            agent_id="autonomous-triage-subagent",
            temperature=0.3,
            max_tokens=500,
        )
        result["ai_assessment"] = {
            "status": ai_res.get("status"),
            "model": ai_res.get("model"),
            "latency_ms": ai_res.get("latency_ms"),
            "tokens_per_second": ai_res.get("tokens_per_second"),
            "summary": ai_res.get("completion"),
            "audit_id": ai_res.get("audit_id"),
        }

    return result


@mcp.tool(
    name="get_proxmox_cluster_status",
    description="Check the operational health, CPU, memory, uptime, and node status of the Proxmox VE hypervisor.",
)
async def get_proxmox_cluster_status() -> Dict[str, Any]:
    """Retrieve Proxmox VE node and cluster status."""
    if not proxmox_manager.is_configured():
        return {
            "error": "Proxmox credentials not configured. Please set PROXMOX_HOST, PROXMOX_TOKEN_ID, and PROXMOX_TOKEN_SECRET in your environment or .env file."
        }
    try:
        nodes = await proxmox_manager.get_nodes()
        summary = []
        for n in nodes:
            node_name = n.get("node")
            try:
                detailed = await proxmox_manager.get_node_status(node_name)
            except Exception:
                detailed = {}

            mem_info = detailed.get("memory", {})
            mem_total = mem_info.get("total", n.get("maxmem", 0)) or 1
            mem_used = mem_info.get("used", n.get("mem", 0))

            disk_info = detailed.get("rootfs", {})
            disk_total = disk_info.get("total", n.get("maxdisk", 0)) or 1
            disk_used = disk_info.get("used", n.get("disk", 0))

            cpu_info = detailed.get("cpuinfo", {})
            uptime = detailed.get("uptime", n.get("uptime"))

            summary.append({
                "node": node_name,
                "status": n.get("status"),
                "pve_version": detailed.get("pveversion"),
                "kernel": detailed.get("kversion"),
                "cpu_model": cpu_info.get("model"),
                "cpu_cores": cpu_info.get("cores"),
                "cpu_threads": cpu_info.get("cpus"),
                "cpu_utilization_pct": round((detailed.get("cpu", n.get("cpu", 0)) or 0) * 100, 2),
                "load_average": detailed.get("loadavg", []),
                "memory_used_gb": round(mem_used / (1024**3), 2),
                "memory_total_gb": round(mem_total / (1024**3), 2),
                "memory_utilization_pct": round((mem_used / mem_total) * 100, 2),
                "rootfs_used_gb": round(disk_used / (1024**3), 2),
                "rootfs_total_gb": round(disk_total / (1024**3), 2),
                "uptime_seconds": uptime,
                "uptime_days": round((uptime or 0) / 86400, 1),
            })
        return {
            "host": proxmox_manager.host,
            "node_count": len(nodes),
            "nodes": summary,
        }
    except Exception as e:
        return {"error": f"Failed to retrieve Proxmox cluster status: {str(e)}"}



@mcp.tool(
    name="get_proxmox_vms",
    description="List all virtual machines (VMs) across Proxmox cluster nodes, including run status, allocated RAM, and CPU usage.",
)
async def get_proxmox_vms(
    node: Annotated[Optional[str], Field(description="Proxmox node name (e.g. 'pve'). If omitted, lists VMs across all cluster nodes.")] = None,
) -> Dict[str, Any]:
    """List virtual machines in Proxmox."""
    if not proxmox_manager.is_configured():
        return {
            "error": "Proxmox credentials not configured. Please set PROXMOX_HOST, PROXMOX_TOKEN_ID, and PROXMOX_TOKEN_SECRET."
        }
    try:
        if node:
            vms = await proxmox_manager.get_node_vms(node)
        else:
            vms = await proxmox_manager.get_cluster_resources(resource_type="vm")

        vm_list = []
        for vm in vms:
            maxmem = vm.get("maxmem", 0) or 1
            mem = vm.get("mem", 0)
            vm_list.append({
                "vmid": vm.get("vmid"),
                "name": vm.get("name"),
                "status": vm.get("status"),
                "node": vm.get("node", node),
                "cpu_utilization_pct": round((vm.get("cpu", 0) or 0) * 100, 2),
                "memory_used_mb": round(mem / (1024**2), 1),
                "memory_allocated_mb": round(maxmem / (1024**2), 1),
                "uptime_seconds": vm.get("uptime", 0),
            })
        return {
            "total_vms": len(vm_list),
            "vms": vm_list,
        }
    except Exception as e:
        return {"error": f"Failed to retrieve Proxmox VMs: {str(e)}"}


@mcp.tool(
    name="get_proxmox_vm_status",
    description="Get real-time operational status, CPU/RAM telemetry, disk I/O, and network metrics for a specific Proxmox VM.",
)
async def get_proxmox_vm_status(
    vmid: Annotated[int, Field(description="Proxmox VM ID (e.g. 100, 101)")],
    node: Annotated[Optional[str], Field(description="Proxmox node name. If omitted, will be auto-detected from the cluster.")] = None,
) -> Dict[str, Any]:
    """Get telemetry for a specific VM."""
    if not proxmox_manager.is_configured():
        return {
            "error": "Proxmox credentials not configured. Please set PROXMOX_HOST, PROXMOX_TOKEN_ID, and PROXMOX_TOKEN_SECRET."
        }
    try:
        target_node = node
        if not target_node:
            resources = await proxmox_manager.get_cluster_resources(resource_type="vm")
            for r in resources:
                if r.get("vmid") == vmid:
                    target_node = r.get("node")
                    break
        if not target_node:
            nodes = await proxmox_manager.get_nodes()
            if nodes:
                target_node = nodes[0].get("node")

        if not target_node:
            return {"error": f"Could not determine Proxmox node for VM {vmid}."}

        status = await proxmox_manager.get_vm_status(target_node, vmid)
        maxmem = status.get("maxmem", 0) or 1
        mem = status.get("mem", 0)
        return {
            "vmid": vmid,
            "node": target_node,
            "name": status.get("name"),
            "status": status.get("status"),
            "qmpstatus": status.get("qmpstatus"),
            "cpu_utilization_pct": round((status.get("cpu", 0) or 0) * 100, 2),
            "memory_used_mb": round(mem / (1024**2), 1),
            "memory_allocated_mb": round(maxmem / (1024**2), 1),
            "disk_read_bytes": status.get("diskread", 0),
            "disk_write_bytes": status.get("diskwrite", 0),
            "net_in_bytes": status.get("netin", 0),
            "net_out_bytes": status.get("netout", 0),
            "uptime_seconds": status.get("uptime", 0),
        }
    except Exception as e:
        return {"error": f"Failed to retrieve VM {vmid} status: {str(e)}"}


@mcp.tool(
    name="get_proxmox_storage_status",
    description="Check the capacity, used space, free space, and operational health of Proxmox storage pools (including ZFS pools).",
)
async def get_proxmox_storage_status(
    node: Annotated[Optional[str], Field(description="Proxmox node name (e.g. 'pve'). If omitted, will check the first active node.")] = None,
) -> Dict[str, Any]:
    """Retrieve storage pool status and capacity."""
    if not proxmox_manager.is_configured():
        return {
            "error": "Proxmox credentials not configured. Please set PROXMOX_HOST, PROXMOX_TOKEN_ID, and PROXMOX_TOKEN_SECRET."
        }
    try:
        storages = await proxmox_manager.get_cluster_resources(resource_type="storage")
        if node:
            storages = [s for s in storages if s.get("node") == node]

        if not storages and node:
            storages = await proxmox_manager.get_storage_status(node)

        storage_list = []
        for s in storages:
            total = s.get("maxdisk", s.get("total", 0)) or 1
            used = s.get("disk", s.get("used", 0))
            avail = s.get("avail", max(0, total - used))
            storage_list.append({
                "storage": s.get("storage"),
                "node": s.get("node"),
                "type": s.get("plugintype", s.get("type")),
                "status": s.get("status", "available"),
                "total_gb": round(total / (1024**3), 2),
                "used_gb": round(used / (1024**3), 2),
                "available_gb": round(avail / (1024**3), 2),
                "used_pct": round((used / total) * 100, 2),
                "content": s.get("content"),
            })
        return {
            "total_pools": len(storage_list),
            "storage_pools": storage_list,
        }
    except Exception as e:
        return {"error": f"Failed to retrieve storage status: {str(e)}"}


@mcp.tool(
    name="get_ollama_status",
    description="Check the operational status of the Ollama GPU daemon and list all downloaded local LLM models.",
)
async def get_ollama_status() -> Dict[str, Any]:
    """Retrieve Ollama daemon version and downloaded models."""
    try:
        version = await ollama_manager.get_version()
        models = await ollama_manager.get_installed_models()
        total_size_gb = round(sum(m["size_gb"] for m in models), 2)
        return {
            "status": "online",
            "host": ollama_manager.host,
            "port": ollama_manager.port,
            "version": version,
            "total_models": len(models),
            "total_storage_gb": total_size_gb,
            "models": models,
        }
    except Exception as e:
        return {"error": f"Failed to connect to Ollama daemon: {str(e)}"}


@mcp.tool(
    name="get_ollama_running_models",
    description="Inspect models currently loaded into GPU VRAM or system RAM, including VRAM allocation and expiration time.",
)
async def get_ollama_running_models() -> Dict[str, Any]:
    """Retrieve models currently active in VRAM."""
    try:
        models = await ollama_manager.get_running_models()
        total_vram_mb = round(sum(m.get("size_vram_mb", 0) for m in models), 1)
        return {
            "loaded_models_count": len(models),
            "total_vram_used_mb": total_vram_mb,
            "running_models": models,
        }
    except Exception as e:
        return {"error": f"Failed to retrieve running Ollama models: {str(e)}"}


@mcp.tool(
    name="pull_ollama_model",
    description="Pull and download an LLM model into the 24/7 Ollama GPU instance (e.g. 'qwen3.5:9b', 'qwen3.5:2b', 'nomic-embed-text').",
)
async def pull_ollama_model(
    model_name: Annotated[str, Field(description="Name of model to download (e.g. 'qwen3.5:9b')")],
) -> Dict[str, Any]:
    """Download a model into Ollama."""
    try:
        res = await ollama_manager.pull_model(model_name)
        return {
            "model": model_name,
            "result": res,
            "status": "success",
        }
    except Exception as e:
        return {"error": f"Failed to pull model '{model_name}': {str(e)}"}


@mcp.tool(
    name="unload_ollama_model",
    description="Unload an active model from GPU VRAM to reclaim memory resources without restarting Ollama.",
)
async def unload_ollama_model(
    model_name: Annotated[str, Field(description="Name of the model to unload from VRAM")],
) -> Dict[str, Any]:
    """Unload a model from memory."""
    try:
        res = await ollama_manager.unload_model(model_name)
        return res
    except Exception as e:
        return {"error": f"Failed to unload model '{model_name}': {str(e)}"}


@mcp.tool(
    name="execute_ai_task",
    description="Execute an AI prompt on the local GPU node via Ollama (e.g. 'qwen3.5:9b'), automatically capturing reasoning tokens, throughput, and streaming an ECS audit record to Elasticsearch.",
)
async def execute_ai_task(
    prompt: Annotated[str, Field(description="The prompt or instruction for the local AI model to execute")],
    task_type: Annotated[str, Field(description="Classification of task (e.g. 'secops-triage', 'threat-analysis', 'incident-response', 'code-review', 'general')")] = "general",
    model: Annotated[str, Field(description="Model name to use (default: 'llama3.2:3b' for sub-second SecOps triage; or 'qwen3.5:9b' / 'qwen3.5:2b' for reasoning)")] = "llama3.2:3b",
    system_prompt: Annotated[Optional[str], Field(description="Optional system instruction for guiding model behavior or reasoning")] = None,
    session_id: Annotated[Optional[str], Field(description="Optional session or multi-turn workflow correlation ID")] = None,
    agent_id: Annotated[Optional[str], Field(description="Identifier of calling agent or subagent")] = "jarvis-agent",
    temperature: Annotated[Optional[float], Field(description="Sampling temperature between 0.0 and 2.0")] = 0.7,
    max_tokens: Annotated[Optional[int], Field(description="Optional maximum completion tokens to generate")] = None,
) -> Dict[str, Any]:
    """Execute an AI task on Ollama with full observability and SIEM audit logging."""
    return await ai_harness.execute_and_audit(
        prompt=prompt,
        task_type=task_type,
        model=model,
        system_prompt=system_prompt,
        session_id=session_id,
        agent_id=agent_id,
        temperature=temperature,
        max_tokens=max_tokens,
    )


@mcp.tool(
    name="query_ai_task_audits",
    description="Search historical AI task execution audit traces in Elasticsearch (logs-ai.agent_tasks-*), with filters for session ID, agent ID, or task type.",
)
async def query_ai_task_audits(
    session_id: Annotated[Optional[str], Field(description="Filter by specific session ID")] = None,
    agent_id: Annotated[Optional[str], Field(description="Filter by calling agent ID")] = None,
    task_type: Annotated[Optional[str], Field(description="Filter by task classification type")] = None,
    hours_back: Annotated[int, Field(description="Number of hours back to search")] = 24,
    limit: Annotated[int, Field(description="Maximum audit traces to return (max 100)")] = 10,
) -> Dict[str, Any]:
    """Query historical AI task execution audit traces from Elasticsearch."""
    return await ai_harness.query_audits(
        session_id=session_id,
        agent_id=agent_id,
        task_type=task_type,
        hours_back=hours_back,
        limit=limit,
    )


@mcp.tool(
    name="get_ai_observability_summary",
    description="Retrieve aggregated AI telemetry and observability metrics from Elastic SIEM: token throughput, average latency, tokens/sec, and task distributions.",
)
async def get_ai_observability_summary(
    hours_back: Annotated[int, Field(description="Time window in hours for metric aggregation")] = 24,
) -> Dict[str, Any]:
    """Retrieve aggregated AI observability and performance metrics from Elasticsearch."""
    return await ai_harness.get_observability_summary(hours_back=hours_back)


@mcp.tool(
    name="record_system_health",
    description="Capture and stream an instant hardware, GPU VRAM, and hypervisor health telemetry snapshot into Elastic SIEM.",
)
async def record_system_health() -> Dict[str, Any]:
    """Record an infrastructure telemetry snapshot (GPU VRAM, active models, Proxmox health)."""
    return await ai_harness.record_infrastructure_snapshot()


@mcp.tool(
    name="scan_detection_rules",
    description="Stage 1 Detection Engineering: Scan local elastic/detection-rules repository against live Elasticsearch field capabilities and Event IDs, copying compatible rules into detection-rules/candidates/.",
)
async def scan_detection_rules(
    directories: Annotated[
        Optional[List[str]],
        Field(description="Rule directories to scan (default: ['windows', 'network', 'cross-platform', 'threat_intel'])"),
    ] = None,
    copy_tier_1_only: Annotated[
        bool,
        Field(description="If True, only copy Tier 1 (>=75% field coverage) rules; if False, also copy Tier 2 partial coverage rules"),
    ] = False,
) -> Dict[str, Any]:
    """Scan upstream Elastic detection rules for compatibility with homelab telemetry."""
    return await rule_curator.scan_upstream_rules(
        directories=directories,
        copy_tier_1_only=copy_tier_1_only,
    )


@mcp.tool(
    name="analyze_candidate_rules",
    description="Stage 2 Detection Engineering: Run live Elasticsearch EQL/KQL dry-runs on candidate rules, verify telemetry liveness (solving the 0-hit ambiguity), identify noisy processes, and score Fidelity, Noise, Severity, and Urgency.",
)
async def analyze_candidate_rules(
    tactic: Annotated[
        Optional[str],
        Field(description="Optional MITRE ATT&CK tactic filter (e.g., 'Persistence', 'Credential Access', 'Execution', 'Initial Access')"),
    ] = None,
    category: Annotated[
        Optional[str],
        Field(description="Optional source category filter ('windows', 'network', 'cross-platform', 'threat_intel')"),
    ] = None,
    severity: Annotated[
        Optional[str],
        Field(description="Optional upstream severity filter ('critical', 'high', 'medium', 'low')"),
    ] = None,
    limit: Annotated[
        int,
        Field(description="Maximum number of candidate rules to dry-run in this batch"),
    ] = 25,
    hours_back: Annotated[
        int,
        Field(description="Time window in hours for historical dry-run search"),
    ] = 168,
) -> Dict[str, Any]:
    """Execute live dry-run analysis and liveness verification on candidate detection rules."""
    return await rule_curator.analyze_candidates(
        tactic=tactic,
        category=category,
        severity=severity,
        limit=limit,
        hours_back=hours_back,
    )


@mcp.tool(
    name="stage_and_deploy_detection_rule",
    description="Stage 3 Detection Engineering: Customize a candidate rule with Jarvis index patterns and homelab exception filters into detection-rules/tuned/, and optionally deploy to Kibana's Detection Engine API.",
)
async def stage_and_deploy_detection_rule(
    file_name: Annotated[
        str,
        Field(description="Rule TOML file name (e.g. 'persistence_scheduled_task_creation.toml')"),
    ],
    custom_exceptions: Annotated[
        Optional[List[str]],
        Field(description="Optional list of EQL/KQL exception clauses (e.g. ['not process.executable : \"C:\\\\Program Files\\\\Git\\\\*\"'])"),
    ] = None,
    override_severity: Annotated[
        Optional[str],
        Field(description="Optional severity override ('low', 'medium', 'high', 'critical')"),
    ] = None,
    deploy_to_kibana: Annotated[
        bool,
        Field(description="If True, push the tuned rule directly to Kibana's /api/detection_engine/rules API"),
    ] = False,
) -> Dict[str, Any]:
    """Stage a tuned Jarvis detection rule and optionally deploy it to Kibana."""
    return await rule_curator.stage_and_deploy_rule(
        file_name=file_name,
        custom_exceptions=custom_exceptions,
        override_severity=override_severity,
        deploy_to_kibana=deploy_to_kibana,
    )


@mcp.tool(
    name="sync_asset_inventory",
    description="Discover and synchronize homelab & enterprise asset inventory (UniFi Dream Router, Proxmox VE, Windows 11 Sysmon endpoint, Elastic SIEM, Ollama GPU node) using telemetry auto-discovery, environment-profile.json, and active LAN port probing into Elasticsearch (logs-threat_intel.assets-default).",
)
async def sync_asset_inventory(
    run_active_scan: Annotated[
        bool,
        Field(description="Whether to run asynchronous TCP port and service banner probing across discovered hosts"),
    ] = True,
    extra_ips: Annotated[
        Optional[List[str]],
        Field(description="Optional list of additional LAN IP addresses to probe and add to inventory"),
    ] = None,
) -> Dict[str, Any]:
    """Synchronize hybrid asset inventory into Elastic SIEM."""
    return await asset_inventory.sync_asset_inventory(
        run_active_scan=run_active_scan,
        extra_ips=extra_ips,
    )


@mcp.tool(
    name="ingest_threat_intel_feeds",
    description="Ingest bulk IOC feeds (abuse.ch Feodo Tracker C2 IPs, URLhaus malware hosts, MalwareBazaar SHA256 hashes) and 40+ curated CTI RSS feeds, score against the local environment profile, run a 90-day retroactive SIEM hunt across UniFi and Sysmon logs, and index into logs-threat_intel.indicators-default.",
)
async def ingest_threat_intel_feeds(
    feed_set: Annotated[
        str,
        Field(description="RSS feed catalog size: 'starter' (6 core feeds for fast execution) or 'full' (40+ government, vendor, news, cloud/AI feeds)"),
    ] = "starter",
    include_abuse_ch: Annotated[
        bool,
        Field(description="Include zero-auth bulk IOC feeds from abuse.ch (Feodo Tracker, URLhaus, MalwareBazaar)"),
    ] = True,
    lookback_days: Annotated[
        int,
        Field(description="Number of historical days in Elastic SIEM (UniFi & Sysmon) to search for retroactive IOC matches"),
    ] = 90,
) -> Dict[str, Any]:
    """Ingest external CTI feeds, score relevance, and run retroactive SIEM matching."""
    return await threat_feeds.ingest_all_feeds(
        feed_set=feed_set,
        include_abuse_ch=include_abuse_ch,
        lookback_days=lookback_days,
    )


@mcp.tool(
    name="scan_asset_vulnerabilities",
    description="Correlate inventoried assets (Ubiquiti UniFi Dream Router, Proxmox VE, Windows 11 Workstation, Elasticsearch/Kibana/Logstash, Ollama) against CISA Known Exploited Vulnerabilities (KEV) and NIST NVD CVE API v2, compute operational priority scores, and synthesize local AI remediation advice.",
)
async def scan_asset_vulnerabilities(
    query_nvd: Annotated[
        bool,
        Field(description="Whether to query the live NIST NVD CVE API v2 in addition to CISA KEV"),
    ] = True,
    generate_ai_advisory: Annotated[
        bool,
        Field(description="Whether to run local Ollama GPU model (llama3.2:3b) to synthesize a remediation brief"),
    ] = True,
    max_per_asset: Annotated[
        int,
        Field(description="Maximum top vulnerabilities to index per asset"),
    ] = 8,
) -> Dict[str, Any]:
    """Scan inventoried assets for recent CVEs and actively exploited CISA KEV flaws."""
    return await vuln_scanner.scan_all_assets(
        query_nvd=query_nvd,
        generate_ai_advisory=generate_ai_advisory,
        max_per_asset=max_per_asset,
    )


@mcp.tool(
    name="check_identity_exposure",
    description="Scan free OSINT, infostealer (HudsonRock Cavalier), credential breach (XposedOrNot), GitHub public commit metadata, and Shodan InternetDB WAN footprint feeds for personal user/email exposure and index into logs-threat_intel.identity-default.",
)
async def check_identity_exposure(
    names: Annotated[
        Optional[List[str]],
        Field(description="Optional list of full names to check (defaults to IDENTITY_WATCH_NAMES in .env)"),
    ] = None,
    emails: Annotated[
        Optional[List[str]],
        Field(description="Optional list of email addresses to check (defaults to IDENTITY_WATCH_EMAILS in .env)"),
    ] = None,
    usernames: Annotated[
        Optional[List[str]],
        Field(description="Optional list of usernames/handles to check (defaults to IDENTITY_WATCH_USERNAMES in .env)"),
    ] = None,
    check_wan_footprint: Annotated[
        bool,
        Field(description="Whether to check the homelab's external WAN IP against Shodan InternetDB for exposed ports/CVEs"),
    ] = True,
) -> Dict[str, Any]:
    """Check user identities, emails, and external WAN footprint for public breaches or infostealer logs."""
    return await identity_monitor.scan_identity_exposures(
        names=names,
        emails=emails,
        usernames=usernames,
        check_wan_footprint=check_wan_footprint,
    )


@mcp.tool(
    name="update_intel_disposition",
    description="Update the analyst review disposition ('unreviewed', 'actioned', 'confirmed', 'false_positive', 'expired', 'revoked') on a threat intel indicator, CVE vulnerability, or identity exposure record in Elasticsearch.",
)
async def update_intel_disposition(
    item_id: Annotated[
        str,
        Field(description="Document ID in Elasticsearch (e.g. 'feodo-ip-1.2.3.4', 'vuln-udr-gateway-01-CVE-2024-1234', 'identity-xposedornot-...')"),
    ],
    disposition: Annotated[
        str,
        Field(description="New disposition: 'unreviewed', 'actioned', 'confirmed', 'false_positive', 'expired', or 'revoked'"),
    ],
    index_name: Annotated[
        str,
        Field(description="Target Elasticsearch index ('logs-threat_intel.indicators-default', 'logs-threat_intel.vulnerabilities-default', or 'logs-threat_intel.identity-default')"),
    ] = "logs-threat_intel.indicators-default",
    owner: Annotated[
        str,
        Field(description="Analyst or team owner recording the decision"),
    ] = "SecOps Analyst",
    note: Annotated[
        str,
        Field(description="Analyst review note or mitigation context"),
    ] = "",
    case_url: Annotated[
        str,
        Field(description="Optional incident or ticket URL"),
    ] = "",
) -> Dict[str, Any]:
    """Persist analyst review disposition and notes on a threat intelligence document."""
    return await threat_feeds.update_disposition(
        item_id=item_id,
        disposition=disposition,
        index_name=index_name,
        owner=owner,
        note=note,
        case_url=case_url,
    )


if __name__ == "__main__":
    mcp.run()


