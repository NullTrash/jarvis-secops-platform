# Jarvis SecOps Platform

[![Elastic SIEM](https://img.shields.io/badge/Elastic_SIEM-8.17.0-005571?style=for-the-badge&logo=elasticsearch&logoColor=white)](https://www.elastic.co/)
[![FastMCP](https://img.shields.io/badge/FastMCP-0.4.0+-4B32C3?style=for-the-badge&logo=python&logoColor=white)](https://github.com/jlowin/fastmcp)
[![Proxmox VE](https://img.shields.io/badge/Proxmox_VE-Virtualization-E57000?style=for-the-badge&logo=proxmox&logoColor=white)](https://www.proxmox.com/)
[![Ollama GPU](https://img.shields.io/badge/Ollama_GPU-Local_Inference-black?style=for-the-badge&logo=nvidia&logoColor=white)](https://ollama.ai/)
[![Python Tests](https://img.shields.io/badge/Pytest-32_Passed_(100%25)-success?style=for-the-badge&logo=pytest&logoColor=white)](mcp-server/tests)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

An enterprise-grade, hybrid Security Operations (SecOps) platform that unifies perimeter firewall intelligence, endpoint telemetry, virtualization observability, and agentic AI incident triage into an air-gapped, zero-cloud architecture.

Built on **Elasticsearch 8.17**, **Logstash**, **Kibana**, **Ubiquiti UniFi**, **Microsoft Sysmon**, **Proxmox VE**, and **FastMCP** with dedicated local GPU acceleration.

---

## 🌟 Executive Summary & Architectural Highlights

- **Perimeter Telemetry Streaming**: High-throughput syslog ingestion (UDP/TCP 514) from UniFi Dream Router (UDR) gateways, processing over **1.12 million firewall drops** with automated Grok parsing and MaxMind GeoIP / ASN enrichment.
- **Endpoint Detection & Visibility**: Real-time Windows endpoint monitoring via **Microsoft Sysmon** and Elastic Winlogbeat, capturing process lineage (EID 1), network connections (EID 3), file tampering (EID 11), registry persistence (EID 13), and DNS queries (EID 22).
- **Virtualization & Host Observability**: Bidirectional telemetry integration with **Proxmox VE** REST APIs, tracking node CPU/RAM allocations, virtual machine states, and ZFS storage pools.
- **Threat Intelligence & Behavioral Scoring**: Multi-feed reputation engine combining external intelligence (AbuseIPDB, VirusTotal) with local SIEM behavioral risk heuristics (0–100 score, horizontal port scan breadth, critical service targeting, Sysmon correlation).
- **Autonomous SecOps Incident Triage**: Hands-off perimeter triage workflow analyzing attack spikes, categorizing threat actor profiles, and generating actionable drop/ban recommendations via local `llama3.2:3b` at **111.5 tok/s**.
- **Dedicated Local GPU Acceleration**: Hardware PCIe passthrough to a dedicated Ollama VM powering sub-second local LLM inference (**111.5 tok/s**, 513ms warm latency) with zero external API dependencies or cloud data egress.
- **Agentic AI Flight Recorder & MCP Server**: A standards-compliant **FastMCP** server providing autonomous security agents direct tool access to the SIEM cluster while logging structured audit trails (`logs-ai.agent_tasks-default`) capturing reasoning tokens, throughput, and system health.

---

## 🏗️ Architecture Diagram

```mermaid
flowchart TD
    subgraph Perimeter["Perimeter & Endpoint Sources"]
        UDR["Ubiquiti UniFi Dream Router\n(Firewall Drops & IPS/IDS)"]
        SYS["Windows 11 Workstations\n(Sysmon + Winlogbeat)"]
        PVE_HOST["Proxmox VE Host\n(VMs, Containers, ZFS Pool)"]
    end

    subgraph Ingestion["Ingestion & Normalization Layer"]
        LS["Logstash 8.17 Pipeline\n- Grok Syslog Parser\n- MaxMind GeoIP Enrichment\n- MaxMind ASN Enrichment\n- ECS Normalization"]
        IP["Elasticsearch Ingest Pipeline\n(unifi-firewall-ecs-geoip)"]
    end

    subgraph CoreSIEM["Core SIEM Cluster (Proxmox VM 1)"]
        ES[("Elasticsearch 8.17 Cluster\n- logs-network.unifi-default\n- logs-endpoint.sysmon-default\n- logs-ai.agent_tasks-default\n- metrics-system.health-default")]
        KIB["Kibana 8.17 Analytics\n- UniFi Threat Map\n- Sysmon Process Tree\n- AI Flight Recorder"]
    end

    subgraph GPUCompute["Local GPU Compute Node (Proxmox VM 2)"]
        GPU["NVIDIA GPU Passthrough\n(GTX 1070 8GB VRAM)"]
        OLLAMA["Ollama 0.40+ Engine\n- Llama 3.2 3B (111 tok/s triage)\n- Qwen 2.5/3.5 (Deep Reasoning)"]
    end

    subgraph AgentLayer["Agentic AI & FastMCP Orchestration"]
        MCP["Jarvis FastMCP Server\n(18 Security & Ops Tools)"]
        AI_AGENT["Autonomous AI Agents\n(Claude, Gemini, Antigravity)"]
    end

    UDR -->|Syslog UDP/TCP 514| LS
    SYS -->|Beats TCP 5044| LS
    PVE_HOST -.->|REST API 8006| MCP
    LS --> IP --> ES
    ES <--> KIB
    MCP <-->|Async Elasticsearch API| ES
    MCP <-->|Local REST API 11434| OLLAMA
    GPU --- OLLAMA
    AI_AGENT <-->|Model Context Protocol| MCP
```

---

## 📊 Live Verified Benchmarks & Telemetry

| Metric / Dimension | Verified Benchmark | Context & Hardware |
| :--- | :--- | :--- |
| **Ingested Firewall Events** | **3,372,666+ documents** | Real-world WAN drop & flow telemetry from UniFi Dream Router |
| **Endpoint Events Streamed** | **117,143+ documents** | Windows Sysmon telemetry forwarded via Winlogbeat |
| **Local LLM Throughput** | **111.5 tokens / second** | `llama3.2:3b` on dedicated NVIDIA GTX 1070 GPU |
| **Warm Inference Latency** | **513 ms** | Sub-second threat triage without cloud API hops |
| **Reasoning Model Support** | Native thinking extraction | Captures chain-of-thought traces (`qwen3.5:9b`) without payload truncation |
| **SIEM Storage Efficiency** | **Elasticsearch Index Lifecycle** | Automated single-node data streams with rollover policies |
| **Test Suite Reliability** | **32 / 32 Passing (100%)** | Full unit test coverage across MCP tools, threat intelligence, and AI harness |

---

## 🖥️ Pre-Built Kibana Dashboards & Live Visuals

The repository includes turnkey, self-contained Kibana 8.17 dashboard exports in `docker/core-siem/dashboards/` alongside an autonomous FastMCP threat triage workflow:

### 1. Autonomous SecOps Threat Triage (`triage_threat_actors`)
![Autonomous AI SecOps Triage Workflow](docs/images/autonomous-ai-triage-demo.png)
- **RFC 1918 LAN False-Positive Exclusion**: Automatically filters internal workstation and gateway traffic before scoring external WAN threat actors.
- **Multi-Source Behavioral Risk Scoring (0–100)**: Combines AbuseIPDB v2, VirusTotal v3, and local SIEM heuristics (drop volume, horizontal port scan breadth across 142+ ports, critical service targeting on SSH/SMB/RDP/Telnet).
- **Cross-Index Endpoint Verification**: Correlates external attacker IPs against **117,000+ Windows Sysmon events** (`EID 1` Process Creation & `EID 3` Network Connect) to confirm zero internal host callbacks before synthesizing UniFi `WAN_IN` remediation rules via `llama3.2:3b` at **110+ tok/s**.

---

### 2. UniFi Firewall Traffic & Threat Map (`unifi-threat-map.ndjson`)
![UniFi Firewall Traffic & Threat Map Dashboard](docs/images/dashboard-unifi-threat-map.png)
- **Total Inbound Events & Filtered WAN Drops KPI**: Real-time visibility across **3.37M+ firewall events** and isolated external WAN drops.
- **Drop Velocity & Threat Surges**: 15-minute bucketed XY line chart identifying port scan spikes and volumetric attacks (e.g., `198.51.100.22` / `AS43942`).
- **Attacking Countries & Autonomous Systems (ASNs)**: Breakdown powered by MaxMind GeoIP and ASN databases across global hosting providers, VPN exit nodes, and scanner networks.
- **Targeted Destination Ports & Live Drop Stream**: Real-time tabular feed of blocked WAN probes targeting Telnet (`23`), SSH (`22`), SMB (`445`), and DNS (`53`).

---

### 3. Sysmon Endpoint Process Tree & Threat Activity (`sysmon-endpoint.ndjson`)
![Sysmon Endpoint Process Tree & Threat Activity Dashboard](docs/images/dashboard-sysmon-endpoint.png)
- **Endpoint Event ID Matrix**: Filterable visualizations for Sysmon Event IDs `1` (Process Create), `3` (Network Connect), `11` (FileCreate), `13` (Registry Value Set), and `22` (DNSEvent).
- **Process Lineage & Anomaly Feed**: Chronological process creation tracking execution paths, parent-child relationships, and command-line parameters on monitored Windows 11 endpoints.
- **Lateral Movement & Outbound Beacons**: Network connection auditing correlated with initiating process IDs and DNS queries.

---

### 4. AI Observability & Agent Flight Recorder (`ai-observability-flight-recorder.ndjson`)
![AI Observability & Agent Flight Recorder Dashboard](docs/images/dashboard-ai-flight-recorder.png)
- **Autonomous Audit Feed**: Structured stream (`logs-ai.agent_tasks-default`) tracking every agent interaction, prompt, completion, latency, and token count.
- **Inference Efficiency Metrics**: Live tracking of tokens-per-second (**111.5 tok/s** peak on `llama3.2:3b`), warm latency (**513 ms**), and model utilization across the GPU node.
- **Reasoning Traces**: Dedicated capture of internal chain-of-thought reasoning traces (`qwen3.5:9b`) separate from final structured tool outputs.

---

## 🛠️ FastMCP Server Tools Catalog

The **Jarvis FastMCP Server** (`mcp-server/`) exposes 18 enterprise tools to connected AI assistants:

| Category | Tool Name | Description |
| :--- | :--- | :--- |
| **SIEM & Threat Intel** | `get_cluster_health` | Checks Elastic cluster status, shard health, and top 15 indices. |
| | `search_security_events` | Flexible Lucene query search across any ECS data stream with time bounds. |
| | `triage_unifi_firewall` | Aggregates perimeter drop spikes, top attacker IPs, targeted ports, and rules. |
| | `investigate_indicator` | Automated cross-index correlation for an IP or hostname across perimeter and endpoint logs with threat intel. |
| | `lookup_threat_intel` | Evaluates an IP, domain, or hash against AbuseIPDB, VirusTotal, and local SIEM behavioral risk heuristics. |
| | `triage_threat_actors` | Automated SecOps workflow: scans perimeter drop surges, enriches top attackers, and synthesizes executive AI triage via Llama 3.2. |
| **Proxmox VE** | `get_proxmox_cluster_status` | Inspects virtualization host CPU, RAM, kernel version, and status. |
| | `get_proxmox_vms` | Lists all VMs and LXC containers with resource usage. |
| | `get_proxmox_vm_status` | Retrieves status and real-time CPU/memory metrics for a specific VM ID. |
| | `get_proxmox_storage_status` | Audits ZFS, LVM, and directory storage pool capacities. |
| **Ollama GPU Node** | `get_ollama_status` | Verifies local Ollama service availability, version, and model library. |
| | `get_ollama_running_models` | Queries active models loaded in GPU VRAM and their memory footprint. |
| | `pull_ollama_model` | Asynchronously pulls a model (e.g. `llama3.2:3b`, `qwen3.5:9b`) into local storage. |
| | `unload_ollama_model` | Immediately reclaims GPU VRAM without restarting the compute service. |
| **AI Observability** | `execute_ai_task` | Runs local AI inference, records telemetry, and streams audit records to Elasticsearch. |
| | `query_ai_task_audits` | Queries past AI agent decision traces and reasoning sessions. |
| | `get_ai_observability_summary` | Generates token usage, latency distributions, and model performance aggregates. |
| | `record_system_health` | Records host infrastructure, VRAM utilization, and cluster health snapshots to the SIEM. |

---

## 🚀 Quickstart & Deployment

### Prerequisites
- Docker Engine 24.0+ & Docker Compose v2.20+
- (Optional for GPU node) NVIDIA Container Toolkit with compatible driver
- Python 3.10+ (for local MCP server execution)

### 1. Launch Core SIEM (Elasticsearch, Logstash, Kibana)
```bash
cd docker/core-siem
cp .env.example .env
# Edit .env with your desired passwords and memory allocations
docker compose up -d
```
Once healthy:
- **Elasticsearch**: `http://localhost:9200`
- **Kibana**: `http://localhost:5601`
- **Logstash Syslog Port**: UDP/TCP `514`
- **Logstash Beats Port**: TCP `5044`

### 2. Launch Local GPU Inference Node (Ollama)
```bash
cd docker/gpu-compute
cp .env.example .env
docker compose up -d

# Pre-load recommended high-speed triage model
docker exec -it jarvis-ollama-gpu ollama pull llama3.2:3b
```

### 3. Import Pre-built Dashboards
In the Kibana Web UI:
1. Navigate to **Stack Management** $\rightarrow$ **Saved Objects**.
2. Click **Import** in the upper-right corner.
3. Upload `docker/core-siem/dashboards/unifi-threat-map.ndjson`, `sysmon-endpoint.ndjson`, or `ai-observability-flight-recorder.ndjson`.

### 4. Run the FastMCP Server
```bash
cd mcp-server
cp .env.example .env
# Configure ELASTIC_HOST, PROXMOX_HOST, and OLLAMA_HOST in .env

# Run directly using FastMCP CLI
fastmcp run src/server.py:mcp
```

Or connect via Claude Desktop / Antigravity by adding to your MCP configuration:
```json
{
  "mcpServers": {
    "jarvis-secops": {
      "command": "python",
      "args": ["-m", "src.server"],
      "cwd": "/opt/jarvis/mcp-server",
      "env": {
        "ELASTIC_HOST": "10.0.0.20",
        "ELASTIC_PORT": "9200",
        "ELASTIC_USER": "elastic",
        "ELASTIC_PASSWORD": "your_secure_password",
        "OLLAMA_HOST": "10.0.0.20",
        "OLLAMA_PORT": "11434"
      }
    }
  }
}
```

---

## 🧪 Automated Testing

The platform maintains a comprehensive unit test suite covering tool execution, error handling, mock SIEM responses, and the AI observability harness.

```bash
cd mcp-server
pytest
```

Output:
```text
============================= test session starts =============================
platform linux -- Python 3.11+, pytest-9.1.1
rootdir: /opt/jarvis/mcp-server
configfile: pyproject.toml
collected 32 items

tests/test_ai_harness.py .........                                       [ 28%]
tests/test_mcp_tools.py ...                                              [ 37%]
tests/test_ollama_tools.py ....                                          [ 50%]
tests/test_proxmox_tools.py .....                                        [ 65%]
tests/test_threat_intel.py ...........                                   [100%]

============================= 32 passed in 0.91s ==============================
```

---

## 📂 Repository Layout

```text
├── docker/
│   ├── core-siem/              # Elastic SIEM cluster definition
│   │   ├── config/             # Logstash runtime configuration
│   │   ├── dashboards/         # Exported Kibana NDJSON dashboards
│   │   ├── pipeline/           # Logstash grok, filter, and output pipelines
│   │   └── docker-compose.yml  # Elasticsearch, Kibana, Logstash stack
│   └── gpu-compute/            # Local AI compute node
│       ├── scripts/            # Model bootstrap scripts
│       └── docker-compose.yml  # Ollama with NVIDIA GPU passthrough
├── docs/                       # Technical deployment guides & dashboard previews
│   ├── images/                 # Live Kibana & AI triage dashboard screenshots
│   ├── proxmox-gpu-passthrough.md # IOMMU, VFIO, and Docker CUDA configuration
│   ├── sysmon-deployment.md       # Windows Sysmon & Winlogbeat deployment
│   └── unifi-syslog-setup.md      # UniFi Dream Router remote syslog guide
├── mcp-server/                 # Python FastMCP server
│   ├── src/                    # Tool implementations and AI observability harness
│   │   ├── ai_harness.py       # Metrics, token extraction, and SIEM audit logging
│   │   ├── client.py           # Async Elasticsearch client manager
│   │   ├── ollama.py           # Async Ollama client manager
│   │   ├── proxmox.py          # Async Proxmox VE REST client manager
│   │   ├── server.py           # 18 registered FastMCP tools
│   │   └── threat_intel.py     # Multi-feed threat intel & behavioral risk engine
│   ├── tests/                  # Pytest automated test suite (32 unit tests)
│   ├── Dockerfile              # Containerized MCP server
│   └── pyproject.toml          # Project dependencies and tool settings
├── scripts/                    # Live verification & SecOps triage runner
│   └── test_threat_intel_live.py  # End-to-end threat intel & AI triage demo script
├── LICENSE                     # MIT License
└── README.md                   # Platform documentation
```

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).

