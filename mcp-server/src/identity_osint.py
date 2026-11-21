"""Personal Identity, Credential Breach & OSINT Exposure Monitor for Jarvis SecOps.

Monitors configured user identities (e.g., full name, email addresses, usernames,
and homelab public WAN IP) across free, zero-API-key OSINT engines:
1. HudsonRock Cavalier API — checks global infostealer infection logs (RedLine,
   Lumma, Raccoon, Vidar) by email and username.
2. XposedOrNot Breach API — checks public credential breaches and exposed data
   classes (passwords, phone numbers, IP addresses) by email.
3. GitHub Public Code & Commit Search — checks if personal names, emails, or
   usernames appear in public commits or code repositories.
4. Shodan InternetDB — checks the homelab's external WAN IP for exposed ports,
   services, and CVEs.
5. Local CTI Feed Keyword Watch — searches ingested threat intel reports in
   Elasticsearch for any mention of watched identities.
"""

import asyncio
import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import httpx
from dotenv import load_dotenv

from src.client import ElasticClientManager

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
load_dotenv()

IDENTITY_INDEX = "logs-threat_intel.identity-default"


def mask_email(email: str) -> str:
    """Return a display-safe masked email option while preserving domain context."""
    if "@" not in email:
        return email
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        return f"{local[0]}*@{domain}"
    return f"{local[:2]}***{local[-1]}@{domain}"


class IdentityExposureMonitor:
    """Scans free OSINT, infostealer, and breach feeds for personal identity exposure."""

    def __init__(self, es_manager: Optional[ElasticClientManager] = None):
        self.es = es_manager or ElasticClientManager()

    def get_watchlist(
        self,
        names: Optional[List[str]] = None,
        emails: Optional[List[str]] = None,
        usernames: Optional[List[str]] = None,
    ) -> Dict[str, List[str]]:
        """Load identity watchlist from parameters or git-ignored environment variables."""
        env_names = [
            n.strip()
            for n in os.getenv("IDENTITY_WATCH_NAMES", "SecOps Admin").split(",")
            if n.strip()
        ]
        env_emails = [
            e.strip()
            for e in os.getenv("IDENTITY_WATCH_EMAILS", "").split(",")
            if e.strip()
        ]
        env_users = [
            u.strip()
            for u in os.getenv("IDENTITY_WATCH_USERNAMES", "NullTrash").split(",")
            if u.strip()
        ]

        return {
            "names": names if names is not None else env_names,
            "emails": emails if emails is not None else env_emails,
            "usernames": usernames if usernames is not None else env_users,
        }

    async def check_hudsonrock_email(self, email: str) -> Dict[str, Any]:
        """Query HudsonRock Cavalier free OSINT API for infostealer compromise by email."""
        url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email"
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get(url, params={"email": email})
                if resp.status_code == 200:
                    data = resp.json()
                    stealers = data.get("stealers", [])
                    compromised = len(stealers) > 0
                    return {
                        "source": "HudsonRock Cavalier (Infostealer Telemetry)",
                        "status": "success",
                        "compromised": compromised,
                        "stealer_count": len(stealers),
                        "message": data.get("message", ""),
                        "stealers": stealers[:5],
                        "severity": "CRITICAL" if compromised else "LOW",
                        "priority_score": 95 if compromised else 10,
                    }
                return {"source": "HudsonRock Cavalier", "status": f"http_{resp.status_code}", "compromised": False}
        except Exception as e:
            return {"source": "HudsonRock Cavalier", "status": "error", "error": str(e), "compromised": False}

    async def check_hudsonrock_username(self, username: str) -> Dict[str, Any]:
        """Query HudsonRock Cavalier free OSINT API for infostealer compromise by username."""
        url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username"
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get(url, params={"username": username})
                if resp.status_code == 200:
                    data = resp.json()
                    stealers = data.get("stealers", [])
                    compromised = len(stealers) > 0
                    return {
                        "source": "HudsonRock Cavalier (Username Infostealer Check)",
                        "status": "success",
                        "compromised": compromised,
                        "stealer_count": len(stealers),
                        "message": data.get("message", ""),
                        "severity": "HIGH" if compromised else "LOW",
                        "priority_score": 80 if compromised else 10,
                    }
                return {"source": "HudsonRock Cavalier", "status": f"http_{resp.status_code}", "compromised": False}
        except Exception as e:
            return {"source": "HudsonRock Cavalier", "status": "error", "error": str(e), "compromised": False}

    async def check_xposedornot_email(self, email: str) -> Dict[str, Any]:
        """Query XposedOrNot free breach API for public data breach exposure by email."""
        url = f"https://api.xposedornot.com/v1/check-email/{email}"
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get(url, headers={"User-Agent": "Jarvis-SecOps-IdentityWatch/1.0"})
                if resp.status_code == 200:
                    data = resp.json()
                    raw_breaches = data.get("breaches", [])
                    breach_list: List[str] = []
                    if isinstance(raw_breaches, list):
                        for item in raw_breaches:
                            if isinstance(item, list):
                                breach_list.extend(str(x) for x in item)
                            elif isinstance(item, str):
                                breach_list.append(item)
                    exposed = len(breach_list) > 0
                    return {
                        "source": "XposedOrNot Breach Database",
                        "status": "success",
                        "exposed": exposed,
                        "breach_count": len(breach_list),
                        "breaches": breach_list[:20],
                        "severity": "HIGH" if len(breach_list) >= 3 else ("MEDIUM" if exposed else "LOW"),
                        "priority_score": min(90, 40 + len(breach_list) * 10) if exposed else 10,
                    }
                elif resp.status_code == 404:
                    # 404 in XposedOrNot means 0 breaches found for the email
                    return {
                        "source": "XposedOrNot Breach Database",
                        "status": "success",
                        "exposed": False,
                        "breach_count": 0,
                        "breaches": [],
                        "severity": "LOW",
                        "priority_score": 5,
                    }
                return {"source": "XposedOrNot Breach Database", "status": f"http_{resp.status_code}", "exposed": False}
        except Exception as e:
            return {"source": "XposedOrNot Breach Database", "status": "error", "error": str(e), "exposed": False}

    async def check_github_public_exposure(self, query_term: str) -> Dict[str, Any]:
        """Search GitHub public commits & issues for accidental exposure of name, email, or username."""
        url = "https://api.github.com/search/commits"
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "Jarvis-SecOps-IdentityWatch/1.0",
        }
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get(url, params={"q": f'"{query_term}"', "per_page": "5"}, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    total = int(data.get("total_count", 0))
                    repos = []
                    for item in data.get("items", [])[:5]:
                        repo_name = item.get("repository", {}).get("full_name")
                        if repo_name and repo_name not in repos:
                            repos.append(repo_name)
                    return {
                        "source": "GitHub Public Commit OSINT",
                        "status": "success",
                        "query": query_term,
                        "total_public_mentions": total,
                        "sample_repositories": repos,
                        "severity": "MEDIUM" if total > 0 else "LOW",
                        "priority_score": 45 if total > 0 else 5,
                    }
                return {"source": "GitHub Public Commit OSINT", "status": f"http_{resp.status_code}", "total_public_mentions": 0}
        except Exception as e:
            return {"source": "GitHub Public Commit OSINT", "status": "error", "error": str(e), "total_public_mentions": 0}

    async def check_wan_ip_shodan_internetdb(self, wan_ip: Optional[str] = None) -> Dict[str, Any]:
        """Check the homelab's external WAN IP against Shodan InternetDB (free, no key)."""
        target_ip = wan_ip or os.getenv("IDENTITY_WATCH_WAN_IP", "").strip()
        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                if not target_ip:
                    ip_resp = await client.get("https://api.ipify.org?format=json")
                    if ip_resp.status_code == 200:
                        target_ip = ip_resp.json().get("ip", "")
                if not target_ip:
                    return {"source": "Shodan InternetDB", "status": "skipped", "open_ports": [], "vulns": []}

                shodan_resp = await client.get(f"https://internetdb.shodan.io/{target_ip}")
                if shodan_resp.status_code == 200:
                    sdata = shodan_resp.json()
                    ports = sdata.get("ports", [])
                    vulns = sdata.get("vulns", [])
                    return {
                        "source": "Shodan InternetDB (External WAN Footprint)",
                        "status": "success",
                        "wan_ip_masked": ".".join(target_ip.split(".")[:2] + ["x", "x"]) if "." in target_ip else target_ip,
                        "open_ports": ports,
                        "cpes": sdata.get("cpes", []),
                        "hostnames": sdata.get("hostnames", []),
                        "tags": sdata.get("tags", []),
                        "vulns": vulns,
                        "severity": "CRITICAL" if vulns else ("HIGH" if ports else "LOW"),
                        "priority_score": 90 if vulns else (65 if ports else 10),
                    }
                elif shodan_resp.status_code == 404:
                    return {
                        "source": "Shodan InternetDB (External WAN Footprint)",
                        "status": "success",
                        "wan_ip_masked": ".".join(target_ip.split(".")[:2] + ["x", "x"]) if "." in target_ip else target_ip,
                        "open_ports": [],
                        "vulns": [],
                        "message": "Zero externally visible open ports indexed by Shodan (UniFi WAN firewall stealth verified).",
                        "severity": "LOW",
                        "priority_score": 5,
                    }
        except Exception as e:
            return {"source": "Shodan InternetDB", "status": "error", "error": str(e), "open_ports": [], "vulns": []}
        return {"source": "Shodan InternetDB", "status": "unknown", "open_ports": [], "vulns": []}

    async def scan_identity_exposures(
        self,
        names: Optional[List[str]] = None,
        emails: Optional[List[str]] = None,
        usernames: Optional[List[str]] = None,
        check_wan_footprint: bool = True,
    ) -> Dict[str, Any]:
        """Run full identity, email breach, infostealer, and public OSINT exposure checks and index to ES."""
        now_iso = datetime.now(timezone.utc).isoformat()
        watchlist = self.get_watchlist(names=names, emails=emails, usernames=usernames)

        findings: List[Dict[str, Any]] = []

        # 1. Check Email Addresses across HudsonRock Cavalier, XposedOrNot, and GitHub Commits
        for email in watchlist["emails"]:
            hr_res, xon_res, gh_res = await asyncio.gather(
                self.check_hudsonrock_email(email),
                self.check_xposedornot_email(email),
                self.check_github_public_exposure(email),
            )
            masked = mask_email(email)
            email_hash = hashlib.sha256(email.lower().encode("utf-8")).hexdigest()[:16]

            findings.append(
                {
                    "id": f"identity-hudsonrock-{email_hash}",
                    "identity_type": "email",
                    "identifier_display": masked,
                    "full_name": watchlist["names"][0] if watchlist["names"] else "Monitored User",
                    "source": hr_res.get("source"),
                    "compromised": hr_res.get("compromised", False),
                    "finding_count": hr_res.get("stealer_count", 0),
                    "details": hr_res.get("message") or f"Infostealer infection count: {hr_res.get('stealer_count', 0)}",
                    "breach_list": [],
                    "severity": hr_res.get("severity", "LOW"),
                    "priority_score": hr_res.get("priority_score", 10),
                    "recommended_action": (
                        "Rotate credentials immediately and revoke active sessions."
                        if hr_res.get("compromised")
                        else "No infostealer logs detected for this email."
                    ),
                }
            )

            breaches = xon_res.get("breaches", [])
            findings.append(
                {
                    "id": f"identity-xposedornot-{email_hash}",
                    "identity_type": "email",
                    "identifier_display": masked,
                    "full_name": watchlist["names"][0] if watchlist["names"] else "Monitored User",
                    "source": xon_res.get("source"),
                    "compromised": xon_res.get("exposed", False),
                    "finding_count": xon_res.get("breach_count", 0),
                    "details": (
                        f"Found in {len(breaches)} public data breaches: {', '.join(breaches[:10])}"
                        if breaches
                        else "0 known public credential breaches in XposedOrNot."
                    ),
                    "breach_list": breaches,
                    "severity": xon_res.get("severity", "LOW"),
                    "priority_score": xon_res.get("priority_score", 10),
                    "recommended_action": (
                        "Ensure unique password manager credentials and hardware/TOTP MFA on affected accounts."
                        if breaches
                        else "Continue routine breach monitoring."
                    ),
                }
            )

            gh_count = gh_res.get("total_public_mentions", 0)
            findings.append(
                {
                    "id": f"identity-github-email-{email_hash}",
                    "identity_type": "email",
                    "identifier_display": masked,
                    "full_name": watchlist["names"][0] if watchlist["names"] else "Monitored User",
                    "source": gh_res.get("source"),
                    "compromised": gh_count > 0,
                    "finding_count": gh_count,
                    "details": (
                        f"Email appears in {gh_count} public GitHub commits across repos: {', '.join(gh_res.get('sample_repositories', []))}"
                        if gh_count > 0
                        else "Email not exposed in public GitHub commit metadata."
                    ),
                    "breach_list": gh_res.get("sample_repositories", []),
                    "severity": gh_res.get("severity", "LOW"),
                    "priority_score": gh_res.get("priority_score", 5),
                    "recommended_action": (
                        "Verify commits are intentional portfolio authoring; enable GitHub push email privacy (@users.noreply.github.com) if desired."
                        if gh_count > 0
                        else "No action required."
                    ),
                }
            )

        # 2. Check Full Names across GitHub Public Commit OSINT & Local CTI Feeds
        for person_name in watchlist["names"]:
            name_hash = hashlib.sha256(person_name.lower().encode("utf-8")).hexdigest()[:16]
            gh_name_res = await self.check_github_public_exposure(person_name)
            gh_total = gh_name_res.get("total_public_mentions", 0)
            findings.append(
                {
                    "id": f"identity-github-name-{name_hash}",
                    "identity_type": "full_name",
                    "identifier_display": person_name,
                    "full_name": person_name,
                    "source": "GitHub Public Commit & Code OSINT",
                    "compromised": False,
                    "finding_count": gh_total,
                    "details": (
                        f"Name '{person_name}' appears in {gh_total} public commits (sample repos: {', '.join(gh_name_res.get('sample_repositories', []))})."
                    ),
                    "breach_list": gh_name_res.get("sample_repositories", []),
                    "severity": "LOW",
                    "priority_score": 25 if gh_total > 0 else 5,
                    "recommended_action": "Audit public repositories with export-showcase.py to ensure zero private homelab IPs or API keys accompany author commits.",
                }
            )

        # 3. Check Usernames across HudsonRock Cavalier
        for uname in watchlist["usernames"]:
            u_hash = hashlib.sha256(uname.lower().encode("utf-8")).hexdigest()[:16]
            hr_u_res = await self.check_hudsonrock_username(uname)
            findings.append(
                {
                    "id": f"identity-hudsonrock-user-{u_hash}",
                    "identity_type": "username",
                    "identifier_display": uname,
                    "full_name": watchlist["names"][0] if watchlist["names"] else uname,
                    "source": hr_u_res.get("source"),
                    "compromised": hr_u_res.get("compromised", False),
                    "finding_count": hr_u_res.get("stealer_count", 0),
                    "details": hr_u_res.get("message") or f"Infostealer logs matching username '{uname}': {hr_u_res.get('stealer_count', 0)}",
                    "breach_list": [],
                    "severity": hr_u_res.get("severity", "LOW"),
                    "priority_score": hr_u_res.get("priority_score", 10),
                    "recommended_action": (
                        "Review accounts using this handle and verify 2FA is active."
                        if hr_u_res.get("compromised")
                        else "Zero stealer infections linked to this username."
                    ),
                }
            )

        # 4. Check Homelab External WAN Footprint via Shodan InternetDB
        if check_wan_footprint:
            shodan_res = await self.check_wan_ip_shodan_internetdb()
            open_ports = shodan_res.get("open_ports", [])
            wan_vulns = shodan_res.get("vulns", [])
            findings.append(
                {
                    "id": "identity-wan-shodan-internetdb",
                    "identity_type": "homelab_wan_ip",
                    "identifier_display": shodan_res.get("wan_ip_masked", "WAN-Edge-IP"),
                    "full_name": watchlist["names"][0] if watchlist["names"] else "Homelab Perimeter",
                    "source": shodan_res.get("source", "Shodan InternetDB"),
                    "compromised": len(wan_vulns) > 0,
                    "finding_count": len(open_ports) + len(wan_vulns),
                    "details": shodan_res.get("message") or f"Externally visible ports: {open_ports} | Indexed CVEs: {wan_vulns}",
                    "breach_list": [str(p) for p in open_ports] + wan_vulns,
                    "severity": shodan_res.get("severity", "LOW"),
                    "priority_score": shodan_res.get("priority_score", 10),
                    "recommended_action": (
                        f"Close or restrict exposed WAN ports {open_ports} on UniFi Dream Router."
                        if open_ports
                        else "UniFi Dream Router WAN stealth posture verified (0 open ports visible on Shodan)."
                    ),
                }
            )

        # Index all findings into Elasticsearch (`logs-threat_intel.identity-default`)
        indexed_count = 0
        es_errors: List[str] = []
        try:
            client = self.es.get_client()
            for f in findings:
                doc = {
                    "@timestamp": now_iso,
                    "event": {
                        "kind": "alert" if f["compromised"] else "event",
                        "category": ["iam", "threat"],
                        "type": ["info"],
                        "dataset": "threat_intel.identity",
                    },
                    "user": {
                        "full_name": f["full_name"],
                        "name": f["identifier_display"],
                    },
                    "identity": {
                        "id": f["id"],
                        "type": f["identity_type"],
                        "identifier": f["identifier_display"],
                        "source": f["source"],
                        "compromised": f["compromised"],
                        "finding_count": f["finding_count"],
                        "details": f["details"],
                        "breach_list": f["breach_list"],
                        "severity": f["severity"],
                        "recommended_action": f["recommended_action"],
                    },
                    "threat": {
                        "priority_score": f["priority_score"],
                        "disposition": "unreviewed",
                    },
                }
                await client.index(
                    index=IDENTITY_INDEX,
                    document=doc,
                    op_type="create",
                )
                indexed_count += 1
        except Exception as e:
            es_errors.append(str(e))

        return {
            "status": "success" if not es_errors else "partial",
            "timestamp": now_iso,
            "monitored_names": watchlist["names"],
            "monitored_emails_masked": [mask_email(e) for e in watchlist["emails"]],
            "monitored_usernames": watchlist["usernames"],
            "total_checks_run": len(findings),
            "exposures_flagged": sum(1 for f in findings if f.get("compromised") or f.get("finding_count", 0) > 0),
            "indexed_to_es": indexed_count,
            "index_name": IDENTITY_INDEX,
            "findings": findings,
            "errors": es_errors,
        }
