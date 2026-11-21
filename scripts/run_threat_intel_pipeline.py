#!/usr/bin/env python3
"""Jarvis Threat Intelligence, Asset Vulnerability & Identity OSINT Pipeline Runner.

Supports:
  - `--once`             : Execute all 4 pipeline stages once and index to Elasticsearch.
  - `--check-pipeline`   : Verify Elasticsearch indices, environment profile, and feed reachability.
  - `--deploy-dashboard` : Import the pre-built Kibana Threat Intel dashboard via Saved Objects API.
  - `--daemon`           : Run continuously on a configurable interval (`--interval-hours`).
"""

import argparse
import asyncio
import os
import sys
from pathlib import Path
import httpx
from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent
MCP_DIR = REPO_ROOT / "mcp-server"
load_dotenv(MCP_DIR / ".env")
sys.path.insert(0, str(MCP_DIR))

from src.server import (
    sync_asset_inventory,
    ingest_threat_intel_feeds,
    scan_asset_vulnerabilities,
    check_identity_exposure,
    es_manager,
)


async def deploy_kibana_dashboard() -> bool:
    """Import threat-intel-vuln-identity.ndjson into Kibana Saved Objects API."""
    ndjson_path = REPO_ROOT / "docker" / "core-siem" / "dashboards" / "threat-intel-vuln-identity.ndjson"
    if not ndjson_path.exists():
        print(f"[!] Dashboard file not found: {ndjson_path}")
        return False

    es_host = os.getenv("ELASTIC_HOST", "10.0.0.20")
    kibana_port = os.getenv("KIBANA_PORT", "5601")
    es_user = os.getenv("ELASTIC_USER", "elastic")
    es_pass = os.getenv("ELASTIC_PASSWORD", "ChangemeSecurePass2026!")

    url = f"http://{es_host}:{kibana_port}/api/saved_objects/_import?overwrite=true"
    headers = {"kbn-xsrf": "true"}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            with open(ndjson_path, "rb") as fh:
                files = {"file": ("threat-intel-vuln-identity.ndjson", fh, "application/ndjson")}
                resp = await client.post(url, headers=headers, files=files, auth=(es_user, es_pass))
                if resp.status_code == 200 and resp.json().get("success"):
                    print(
                        f"[+] Deployed Kibana Dashboard 'jarvis-threat-intel-command-center' "
                        f"to http://{es_host}:{kibana_port}/app/dashboards#/view/jarvis-threat-intel-command-center"
                    )
                    return True
                else:
                    print(f"[!] Kibana import response ({resp.status_code}): {resp.text[:300]}")
                    return False
    except Exception as e:
        print(f"[!] Failed to deploy Kibana dashboard: {e}")
        return False


async def check_pipeline_health() -> int:
    """Verify environment profile, Elasticsearch connectivity, and threat intel index counts."""
    print("=" * 80)
    print(" JARVIS THREAT INTEL PIPELINE HEALTH CHECK (/check-pipeline)")
    print("=" * 80)
    failures = 0

    profile_path = MCP_DIR / "config" / "environment-profile.json"
    if profile_path.exists():
        print(f"[PASS] Environment profile loaded: {profile_path}")
    else:
        print(f"[FAIL] Missing environment profile: {profile_path}")
        failures += 1

    try:
        client = es_manager.get_client()
        health = await client.cluster.health()
        print(f"[PASS] Elasticsearch Cluster: {health.get('cluster_name')} (Status: {health.get('status')})")

        for idx in (
            "logs-threat_intel.assets-default",
            "logs-threat_intel.indicators-default",
            "logs-threat_intel.vulnerabilities-default",
            "logs-threat_intel.identity-default",
        ):
            try:
                cnt_res = await client.count(index=idx)
                print(f"[INFO] Index {idx}: {cnt_res.get('count', 0)} documents")
            except Exception:
                print(f"[WARN] Index {idx}: not yet initialized (run with --once)")
    except Exception as e:
        print(f"[FAIL] Elasticsearch connectivity error: {e}")
        failures += 1

    await es_manager.close()
    return 1 if failures > 0 else 0


async def run_pipeline_once(feed_set: str = "starter", deploy_dash: bool = True) -> None:
    """Execute all 4 threat intelligence pipeline stages end-to-end."""
    print("=" * 85)
    print(" JARVIS SECOPS: THREAT INTEL, ASSET VULNERABILITY & IDENTITY OSINT PIPELINE")
    print("=" * 85)

    # Stage 1: Hybrid Asset Inventory Sync
    print("\n[Stage 1/4] Synchronizing Hybrid Asset Inventory (Proxmox + SIEM + Active LAN Scan)...")
    inv_res = await sync_asset_inventory(run_active_scan=True)
    print(f"    -> Environment:  {inv_res.get('environment_name')}")
    print(f"    -> Total Assets: {inv_res.get('total_assets')} (Indexed: {inv_res.get('indexed_to_es')} to {inv_res.get('index_name')})")
    for a in inv_res.get("assets", []):
        print(
            f"       * {a.get('name')} ({a.get('ip')}) | Version: {a.get('version')} | "
            f"Open Ports: {a.get('open_ports')} | Sources: {a.get('discovery_sources')}"
        )

    # Stage 2: Multi-Feed IOC Ingestion & 90-Day Retroactive SIEM Hunt
    print(f"\n[Stage 2/4] Ingesting CTI Feeds (feed_set='{feed_set}' + abuse.ch) & Running 90-Day Retro SIEM Hunt...")
    feed_res = await ingest_threat_intel_feeds(feed_set=feed_set, include_abuse_ch=True, lookback_days=90)
    retro = feed_res.get("retroactive_siem_hunt", {})
    print(f"    -> Total CTI Items Ingested:    {feed_res.get('total_ingested')} (Indexed: {feed_res.get('indexed_to_es')})")
    print(f"    -> Environment-Matched Items:   {feed_res.get('environment_relevant_count')}")
    print(
        f"    -> 90-Day Retro SIEM Checked:   {retro.get('ips_checked')} IPs, "
        f"{retro.get('domains_checked')} Domains, {retro.get('hashes_checked')} Hashes"
    )
    print(f"    -> Retroactive SIEM Matches:    {retro.get('items_with_siem_hits')} indicators ({retro.get('total_siem_event_matches')} events)")
    for top_i in feed_res.get("top_priority_intel", [])[:5]:
        print(
            f"       * [{top_i['priority_score']}/100] {top_i['feed']}: {top_i['title'][:65]} "
            f"(EnvScore: {top_i['environment_score']}, Matches: {top_i['environment_matches']})"
        )

    # Stage 3: Asset-Specific Vulnerability & CISA KEV Correlation
    print("\n[Stage 3/4] Correlating Asset Inventory against CISA KEV & NIST NVD CVE API v2...")
    vuln_res = await scan_asset_vulnerabilities(query_nvd=True, generate_ai_advisory=True)
    print(f"    -> CISA KEV Catalog Loaded:     {vuln_res.get('cisa_kev_catalog_size')} actively exploited CVEs")
    print(f"    -> Asset Vulnerabilities Found: {vuln_res.get('total_vulnerabilities_matched')} (Indexed: {vuln_res.get('indexed_to_es')})")
    for ab in vuln_res.get("asset_breakdown", []):
        print(
            f"       * {ab['asset_name']} ({ab['ip']}): {ab['vulnerabilities_found']} CVEs "
            f"({ab['cisa_kev_count']} CISA KEV) -> {ab['top_cves']}"
        )
    if vuln_res.get("ai_advisory") and vuln_res["ai_advisory"].get("summary"):
        ai = vuln_res["ai_advisory"]
        print(f"\n    [Local GPU AI Vulnerability Brief ({ai.get('model')} @ {ai.get('tokens_per_second')} tok/s)]:")
        for line in (ai.get("summary") or "").splitlines()[:10]:
            if line.strip():
                print(f"      {line}")

    # Stage 4: Personal Identity & OSINT Exposure Monitoring
    print("\n[Stage 4/4] Running Personal Identity & OSINT Exposure Checks (HudsonRock, XposedOrNot, GitHub, Shodan)...")
    id_res = await check_identity_exposure(check_wan_footprint=True)
    print(f"    -> Monitored Names:     {id_res.get('monitored_names')}")
    print(f"    -> Monitored Emails:    {id_res.get('monitored_emails_masked')}")
    print(f"    -> Monitored Usernames: {id_res.get('monitored_usernames')}")
    print(f"    -> Total Checks Run:    {id_res.get('total_checks_run')} (Indexed: {id_res.get('indexed_to_es')})")
    for f in id_res.get("findings", []):
        print(
            f"       * [{f['severity']}] {f['source']} ({f['identifier_display']}): {f['details'][:95]}"
        )

    if deploy_dash:
        print("\n[Dashboard] Deploying Kibana Threat Intel, Vuln & Identity Command Center...")
        await deploy_kibana_dashboard()

    await es_manager.close()
    print("\n" + "=" * 85)
    print(" PIPELINE EXECUTION COMPLETED SUCCESSFULLY!")
    print("=" * 85)


async def main_async(args: argparse.Namespace) -> int:
    if args.check_pipeline:
        return await check_pipeline_health()

    if args.deploy_dashboard and not args.once and not args.daemon:
        ok = await deploy_kibana_dashboard()
        await es_manager.close()
        return 0 if ok else 1

    if args.daemon:
        interval_sec = max(300, int(args.interval_hours * 3600))
        print(f"[*] Starting Jarvis Threat Intel background daemon (interval: {args.interval_hours}h)...")
        while True:
            await run_pipeline_once(feed_set=args.feed_set, deploy_dash=args.deploy_dashboard)
            await asyncio.sleep(interval_sec)
    else:
        await run_pipeline_once(feed_set=args.feed_set, deploy_dash=args.deploy_dashboard)
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Jarvis Threat Intelligence, Asset Vuln & Identity OSINT Runner")
    parser.add_argument("--once", action="store_true", default=True, help="Run the full pipeline once (default)")
    parser.add_argument("--check-pipeline", action="store_true", help="Run health check on ES indices and environment profile")
    parser.add_argument("--deploy-dashboard", action="store_true", default=True, help="Deploy Kibana dashboard after run")
    parser.add_argument("--feed-set", choices=["starter", "full"], default="starter", help="RSS feed catalog size")
    parser.add_argument("--daemon", action="store_true", help="Run continuously on a schedule")
    parser.add_argument("--interval-hours", type=float, default=6.0, help="Hours between daemon runs (default: 6)")
    args = parser.parse_args()
    sys.exit(asyncio.run(main_async(args)))


if __name__ == "__main__":
    main()
