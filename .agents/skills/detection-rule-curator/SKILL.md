---
name: detection-rule-curator
description: >-
  On-demand Detection Engineering & Rule Curation workflow for the Jarvis Elastic SIEM.
  Scans the local `elasticpublic/elastic-detection-rules` repository against live
  Elasticsearch field capabilities (`_field_caps`), stages compatible candidate rules,
  runs live EQL/KQL dry-runs to verify telemetry liveness and false-positive noise,
  and deploys tuned rules to `detection-rules/tuned/` and Kibana's Detection Engine.
---

# Jarvis Detection Rule Curator Skill

Use this skill whenever the user wants to scan, evaluate, dry-run, tune, or deploy detection rules from `elasticpublic/elastic-detection-rules` against the Jarvis Elastic SIEM.

## Model Quota Efficiency Guideline
When delegating bulk Stage 2 rule analysis or false-positive exception drafting to a subagent, **always use `Model="flash"`** (`invoke_subagent(..., Model="flash")`) or local Ollama GPU inference so that high-volume rule evaluations use the daily-resetting high-speed model rather than the weekly flagship quota.

---

## 3-Stage Detection Engineering Workflow

### Stage 1: Scan & Import Applicable Candidate Rules
Run Stage 1 to compare all 2,350+ rules in `elasticpublic/elastic-detection-rules/rules` against the live Elasticsearch `_field_caps` and active `event.code` / `winlog.channel` distributions:

```powershell
mcp-server\.venv\Scripts\python.exe scripts/curate_detection_rules.py scan
```
- **Output**:
  - Copies compatible `.toml` rules into `detection-rules/candidates/<category>/`
  - Writes `detection-rules/candidate_manifest.json` breaking down:
    - **Tier 1 Ready Candidates** ($\ge$75% field coverage in live Elasticsearch + active Event IDs)
    - **Tier 2 Partial Coverage Candidates** (50%–74% field coverage — identifies which Sysmon/Windows Audit fields would unlock more rules)

---

### Stage 2: Deep Live Dry-Run & Telemetry Liveness Analysis
Remember: **0 hits does NOT automatically mean a rule is ready.**
Stage 2 verifies two things for every candidate rule:
1. **Telemetry Liveness Proof**: Confirms that the prerequisite event category (`process`, `network`, `registry`, `file`, `dns`, `iam`) and `event.code` have **non-zero baseline volume** in Elasticsearch. Rules with 0 baseline volume are marked `BLIND_SPOT_NO_TELEMETRY`.
2. **Retro-Hunt Dry-Run & Noise Profiling**: Executes the rule's EQL (`/_eql/search`) or KQL/Lucene query against `winlogbeat-*,logs-endpoint.sysmon-*,logs-network.unifi-default` over the last 7 days (`hours_back=168`) and classifies each rule into:
   - `SILENT_CANDIDATE_VERIFIED_LOGS` (0 hits + verified live telemetry stream)
   - `LOW_NOISE_ACTIVE_HITS` (1–10 hits — high priority to inspect)
   - `NOISY_BASELINE_ACTIVITY` (>10 hits — captures top triggering `process.executable` paths like `git.exe`, `python.exe`, `powershell.exe` and auto-generates `recommended_exceptions`)

```powershell
# Analyze top candidate rules (optionally filter by --tactic, --category, or --severity)
mcp-server\.venv\Scripts\python.exe scripts/curate_detection_rules.py analyze --tactic "Persistence" --limit 25
```

---

### Stage 3: Tune for Jarvis & Deploy to Kibana Detection Engine
Once a rule is vetted in Stage 2, promote it to `detection-rules/tuned/` (rewriting index patterns to `["winlogbeat-*", "logs-endpoint.sysmon-*", "logs-network.unifi-default"]` and injecting any homelab exception filters), and optionally push it live to Kibana (`/api/detection_engine/rules`):

```powershell
mcp-server\.venv\Scripts\python.exe scripts/curate_detection_rules.py tune --file <rule_file.toml> --deploy
```

