# Jarvis FastMCP Server: SIEM, Proxmox VE & Ollama GPU Compute

An asynchronous FastMCP server that connects AI assistants and multi-agent orchestrators directly to your **Elastic SIEM**, **Proxmox VE Hypervisor**, and **Ollama GPU Compute Node**.

---

## 🛠️ Available MCP Tools (26 Tools)

### 🛡️ Elastic SIEM, Threat Intelligence & Network Telemetry
| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| `get_cluster_health` | None | Returns cluster health status, shard counts, and active index statistics. |
| `search_security_events` | `query`, `index_pattern`, `hours_back`, `limit` | Executes Lucene queries across security logs (e.g. `event.action: firewall-drop`). |
| `triage_unifi_firewall` | `hours_back`, `top_n` | Aggregates UniFi Dream Router logs to discover top blocked attacker IPs and ports. |
| `investigate_indicator` | `indicator`, `hours_back` | Cross-correlates an IP, domain, or hash across UniFi logs and Sysmon events with automated threat intelligence scoring. |
| `lookup_threat_intel` | `indicator`, `hours_back` | Evaluates an IP, domain, or hash against AbuseIPDB, VirusTotal, and local behavioral risk scoring heuristics. |
| `triage_threat_actors` | `hours_back`, `top_n`, `generate_ai_summary` | Autonomous SecOps workflow: scans perimeter drop surges, enriches top attackers, and synthesizes executive AI triage via Llama 3.2. |
| `sync_asset_inventory` | `run_active_scan`, `extra_ips` | Discovers and syncs homelab assets (UniFi Dream Router, Proxmox VE, Windows 11 Sysmon endpoint, Elastic SIEM, Ollama GPU) with active LAN port/banner probing into `logs-threat_intel.assets-default`. |
| `ingest_threat_intel_feeds` | `feed_set`, `include_abuse_ch`, `lookback_days` | Ingests bulk IOCs (abuse.ch Feodo Tracker, URLhaus, MalwareBazaar) + 40+ curated CTI RSS feeds, scores environment relevance, and runs a 90-day retroactive SIEM hunt across UniFi and Sysmon logs. |
| `scan_asset_vulnerabilities` | `query_nvd`, `generate_ai_advisory`, `max_per_asset` | Correlates inventoried assets against CISA Known Exploited Vulnerabilities (KEV) and NIST NVD CVE API v2, indexing prioritized CVEs and local GPU AI remediation guidance into `logs-threat_intel.vulnerabilities-default`. |
| `check_identity_exposure` | `names`, `emails`, `usernames`, `check_wan_footprint` | Scans free OSINT, infostealer logs (HudsonRock Cavalier), breach databases (XposedOrNot), GitHub public commits, and Shodan InternetDB WAN footprint into `logs-threat_intel.identity-default`. |
| `update_intel_disposition` | `item_id`, `disposition`, `index_name`, `owner`, `note`, `case_url` | Persists analyst review disposition (`unreviewed`, `actioned`, `confirmed`, `false_positive`, `expired`, `revoked`) on an indicator, CVE, or identity alert. |

### 🎯 Detection Engineering & Rule Curation (`elastic/detection-rules`)
| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| `scan_detection_rules` | `categories`, `min_match_ratio`, `copy_candidates` | Scans upstream `elastic/detection-rules` `.toml` files against live Elasticsearch `_field_caps` and stages compatible candidates into `detection-rules/candidates/`. |
| `analyze_candidate_rules` | `max_rules`, `hours_back`, `category_filter`, `only_hits`, `run_ai_review` | Executes 30-day live EQL/KQL retro-hunts with telemetry liveness verification and optional local LLM false-positive analysis. |
| `stage_and_deploy_detection_rule` | `rule_file`, `deploy_to_kibana`, `enable_rule`, `custom_exception_query` | Rewrites rule index patterns, injects homelab exceptions, saves tuned JSON to `detection-rules/tuned/`, and deploys to Kibana's Detection Engine. |

### 🖥️ Proxmox VE Hypervisor & Infrastructure
| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| `get_proxmox_cluster_status` | None | Checks node health, CPU % load, RAM usage, storage usage, and host uptime. |
| `get_proxmox_vms` | `node` (optional) | Lists all VMs/containers, status (`running`/`stopped`), CPU utilization, and allocated RAM. |
| `get_proxmox_vm_status` | `vmid`, `node` (optional) | Returns real-time CPU, RAM, disk I/O, and network transfer rates for a specific VM. |
| `get_proxmox_storage_status` | `node` (optional) | Checks capacity, used space, free space, and status of storage pools (including ZFS pools). |

### 🧠 Ollama GPU Compute & Model Management
| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| `get_ollama_status` | None | Checks Ollama daemon health, version, and lists all downloaded local models with sizes and parameter counts. |
| `get_ollama_running_models` | None | Inspects models currently loaded into GPU VRAM or system RAM, VRAM allocations, and expiration times. |
| `pull_ollama_model` | `model_name` | Pulls/downloads a model into the 24/7 Ollama GPU instance (e.g. `qwen3.5:9b`). |
| `unload_ollama_model` | `model_name` | Offloads a model from GPU VRAM to reclaim resources without restarting Ollama. |

### 🤖 AI Task Observability & Agent Auditing
| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| `execute_ai_task` | `prompt`, `task_type`, `model`, `system_prompt`, `session_id`, `agent_id`, `temperature`, `max_tokens` | Executes an AI prompt on local Ollama GPU node, extracts thinking/reasoning chains (`qwen3.5:9b`), measures token throughput, and streams full ECS audit record to Elasticsearch (`logs-ai.agent_tasks-*`). |
| `query_ai_task_audits` | `session_id`, `agent_id`, `task_type`, `hours_back`, `limit` | Searches historical AI task execution audit traces in Elasticsearch with correlation filters. |
| `get_ai_observability_summary` | `hours_back` | Calculates aggregated telemetry: total tasks, prompt/completion tokens, avg latency, avg tokens/sec, and task/model distribution. |
| `record_system_health` | None | Samples current GPU VRAM allocation, active Ollama models, and Proxmox node CPU/RAM, streaming snapshot into Elastic SIEM (`logs-ai.health-*`). |

---

## ⚙️ Environment Configuration

Set the following in `mcp-server/.env`:

```ini
# Elastic SIEM
ELASTIC_HOST=10.0.0.20
ELASTIC_PORT=9200
ELASTIC_USER=elastic
ELASTIC_PASSWORD=ChangemeSecurePass2026!
ELASTIC_USE_SSL=false

# Proxmox VE REST API
PROXMOX_HOST=10.0.0.10
PROXMOX_PORT=8006
PROXMOX_VERIFY_SSL=false
PROXMOX_TOKEN_ID=secops-agent@pve!jarvis-token
PROXMOX_TOKEN_SECRET=00000000-0000-0000-0000-000000000000
PROXMOX_USER=jarvis
PROXMOX_PASSWORD=...

# Ollama GPU Compute Node
OLLAMA_HOST=10.0.0.20
OLLAMA_PORT=11434
```

---

## 🚀 Running Locally & Antigravity IDE Integration

### 1. Install & Test
```bash
pip install -e .
python -m pytest
python -m src.server
```

### 2. Antigravity IDE MCP Config (`~/.gemini/config/mcp_config.json`)
```json
{
  "mcpServers": {
    "jarvis-siem": {
      "command": "/opt/jarvis/mcp-server/.venv/Scripts/python.exe",
      "args": ["-m", "src.server"],
      "cwd": "/opt/jarvis/mcp-server"
    }
  }
}
```
*(All environment variables are loaded directly from `mcp-server/.env`)*.
