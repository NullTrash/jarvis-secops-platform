#!/usr/bin/env python3
"""CLI Runner for the Jarvis 3-Stage Detection Rule Curation Pipeline."""

import argparse
import asyncio
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "mcp-server"))

from src.detection_rules import DetectionRuleCurator


async def main():
    parser = argparse.ArgumentParser(description="Jarvis Detection Rule Curator (Stage 1 Scan -> Stage 2 Analyze -> Stage 3 Tune/Deploy)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Stage 1: scan
    scan_p = subparsers.add_parser("scan", help="Stage 1: Scan elasticpublic/elastic-detection-rules against live ES field capabilities")
    scan_p.add_argument("--tier1-only", action="store_true", help="Only copy Tier 1 (>=75%% field coverage) rules to candidates/")

    # Stage 2: analyze
    an_p = subparsers.add_parser("analyze", help="Stage 2: Run live EQL/KQL dry-runs and telemetry liveness checks on candidate rules")
    an_p.add_argument("--tactic", type=str, default=None, help="Filter by MITRE ATT&CK tactic (e.g. 'Persistence', 'Credential Access', 'Defense Evasion')")
    an_p.add_argument("--category", type=str, default=None, help="Filter by category ('windows', 'network', 'cross-platform', 'threat_intel')")
    an_p.add_argument("--severity", type=str, default=None, help="Filter by upstream severity ('critical', 'high', 'medium', 'low')")
    an_p.add_argument("--limit", type=int, default=30, help="Number of candidate rules to dry-run (default: 30)")
    an_p.add_argument("--hours", type=int, default=168, help="Lookback window in hours (default: 168 / 7 days)")

    # Stage 3: tune
    tune_p = subparsers.add_parser("tune", help="Stage 3: Stage a tuned Jarvis rule and optionally deploy to Kibana Detection Engine")
    tune_p.add_argument("--file", type=str, required=True, help="TOML rule filename (e.g. persistence_scheduled_task.toml)")
    tune_p.add_argument("--exception", action="append", default=[], help="EQL/KQL exception clause to append")
    tune_p.add_argument("--severity", type=str, default=None, help="Override severity")
    tune_p.add_argument("--deploy", action="store_true", help="Deploy directly to Kibana /api/detection_engine/rules")

    # Stage 3 Batch: deploy-pack
    pack_p = subparsers.add_parser("deploy-pack", help="Stage & deploy the Curated Homelab Top N Detection Rule Pack to Kibana")
    pack_p.add_argument("--count", type=int, default=25, help="Number of rules in the curated pack (default: 25)")

    args = parser.parse_args()
    curator = DetectionRuleCurator()

    try:
        if args.command == "scan":
            print("=" * 85)
            print(" STAGE 1: SCANNING UPSTREAM ELASTIC DETECTION RULES AGAINST LIVE SIEM TELEMETRY")
            print("=" * 85)
            res = await curator.scan_upstream_rules(copy_tier_1_only=args.tier1_only)
            print(f"[+] Total Rules Scanned:          {res['total_rules_scanned']}")
            print(f"[+] Tier 1 Ready Candidates:      {res['tier_1_ready_count']} (>=75% field match + active Event IDs)")
            print(f"[+] Tier 2 Partial Candidates:    {res['tier_2_partial_count']} (50-74% field match)")
            print(f"[+] Copied to candidates/:        {res['copied_to_candidates_count']}")
            print(f"[+] Manifest Saved:               {res['manifest_path']}")
            print("\n--- Candidates by MITRE ATT&CK Tactic ---")
            for tac, cnt in list(res["candidates_by_tactic"].items())[:12]:
                print(f"  * {tac:<28} : {cnt} rules")
            print("\n--- Rejection Reasons Summary ---")
            for reason, cnt in res["rejection_summary"].items():
                print(f"  * {reason:<45} : {cnt} rules")
            print("\n--- Top Missing Fields Across Candidates (Telemetry Upgrade Opportunities) ---")
            for mf, cnt in list(res["top_missing_fields"].items())[:10]:
                print(f"  * {mf:<40} : referenced in {cnt} rules")

        elif args.command == "analyze":
            print("=" * 85)
            print(" STAGE 2: DEEP LIVE DRY-RUN & TELEMETRY LIVENESS ANALYSIS")
            print("=" * 85)
            res = await curator.analyze_candidates(
                tactic=args.tactic,
                category=args.category,
                severity=args.severity,
                limit=args.limit,
                hours_back=args.hours,
            )
            print(f"[+] Analyzed {res['rules_analyzed_count']} candidate rules over last {args.hours}h:")
            for k, v in res["noise_and_liveness_breakdown"].items():
                print(f"  * {k:<35} : {v}")
            print("\n--- Top 20 Detailed Candidate Scorecards (Active Hits Prioritized) ---")
            for idx, r in enumerate(res["results"][:20], 1):
                a = r["assessment"]
                d = r["dry_run"]
                l = r["liveness"]
                print(
                    f"\n[{idx:02d}] {r['name']} ({r['file_name']})\n"
                    f"     Urgency: {a['homelab_urgency_label']} ({a['homelab_urgency_score']}/100) | "
                    f"Upstream Severity: {r['upstream_severity'].upper()} | Language: {r['language'].upper()}\n"
                    f"     Tactics: {', '.join(r['tactics'])}\n"
                    f"     Liveness: {l['status']} (Category '{l['required_category']}' baseline={l['baseline_category_docs']} docs)\n"
                    f"     Dry-Run Hits ({d['hours_back']}h): {d['hit_count']} hits | Profile: {a['noise_profile']} | Fidelity: {a['fidelity']}"
                )
                if d["noisy_culprits"]:
                    print(f"     Triggering Processes/Sources: {d['noisy_culprits']}")
                if a["recommended_exceptions"]:
                    print(f"     Recommended Homelab Exceptions: {a['recommended_exceptions'][:2]}")
                if d["query_error"]:
                    print(f"     Query Note: {d['query_error'][:120]}")

        elif args.command == "tune":
            res = await curator.stage_and_deploy_rule(
                file_name=args.file,
                custom_exceptions=args.exception or None,
                override_severity=args.severity,
                deploy_to_kibana=args.deploy,
            )
            print(json.dumps(res, indent=2))

        elif args.command == "deploy-pack":
            print("=" * 85)
            print(f" STAGE 3: STAGING & DEPLOYING CURATED HOMELAB TOP {args.count} RULE PACK TO KIBANA")
            print("=" * 85)
            res = await curator.deploy_curated_top_pack(pack_size=args.count, deploy_to_kibana=True)
            print(f"[+] Deployed Rules: {res['deployed_count']} / {res['requested_pack_size']}")
            print(f"[+] Catalog Saved:  {res['catalog_path']}\n")
            for idx, r in enumerate(res["rules"], 1):
                status = "DEPLOYED" if r["kibana_deployed"] else f"FAILED ({r['kibana_status']})"
                print(
                    f"  [{idx:02d}] {status:<10} | {r['severity'].upper():<8} | "
                    f"Hits(30d): {r['dry_run_hits_30d']:<2} | {r['name']} ({', '.join(r['tactics'][:2])})"
                )
    finally:
        await curator.es.close()


if __name__ == "__main__":
    asyncio.run(main())
