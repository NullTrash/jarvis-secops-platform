"""Multi-Source Threat Intelligence Feed Ingestor & Retroactive SIEM Matcher.

Adapts matt-snyder-stuff/threat-intel architecture to Jarvis Elastic SIEM:
1. Curated 40+ CTI RSS/Atom Feeds (CISA, Unit 42, Mandiant, CrowdStrike, Talos,
   SentinelOne, The DFIR Report, BleepingComputer, Krebs, etc.) with IOC extraction,
   MITRE ATT&CK technique detection, Threat Actor extraction, and Admiralty reliability.
2. Bulk Zero-Auth IOC Feeds from abuse.ch (Feodo Tracker Botnet C2 IPs, URLhaus
   malware URLs/hosts, ThreatFox recent IOCs, MalwareBazaar SHA256 hashes).
3. Industry Reach + Environment Relevance Priority Scoring (0-100).
4. Retroactive SIEM IOC Matching (`late-ioc-matcher` pattern): hunts 90 days of
   UniFi firewall/DNS logs and Windows Sysmon endpoint logs for any historical
   matches against newly ingested IOCs.
5. Analyst Review State & Disposition Management (`unreviewed`, `actioned`,
   `confirmed`, `false_positive`, `expired`, `revoked`).
"""

import asyncio
import hashlib
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import httpx

from src.asset_inventory import AssetInventoryManager
from src.client import ElasticClientManager
from src.threat_intel import INTERNAL_PRIVATE_NETWORKS

INDICATORS_INDEX = "logs-threat_intel.indicators-default"
VALID_DISPOSITIONS = {"unreviewed", "actioned", "confirmed", "false_positive", "expired", "revoked"}

# ── Curated RSS Feed Catalog (from matt-snyder-stuff/threat-intel/sources/feeds.py) ──
GOVT_FEEDS = [
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "https://www.cisa.gov/news.xml",
    "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
]

VENDOR_FEEDS = [
    "https://unit42.paloaltonetworks.com/feed/",
    "https://www.mandiant.com/resources/blog/rss.xml",
    "https://www.crowdstrike.com/blog/feed/",
    "https://www.recordedfuture.com/feed",
    "https://securelist.com/feed/",
    "https://www.rapid7.com/blog/rss.xml",
    "https://www.tenable.com/blog/feed",
    "https://www.sentinelone.com/labs/feed/",
    "https://feeds.feedburner.com/feedburner/Talos",
    "https://blog.virustotal.com/feeds/posts/default",
    "https://socprime.com/blog/feed/",
    "https://feeds.trendmicro.com/Anti-MalwareBlog",
    "https://feeds.feedburner.com/TheDfirReport",
    "https://www.malware-traffic-analysis.net/blog-entries.rss",
]

NEWS_FEEDS = [
    "https://feeds.feedburner.com/TheHackersNews",
    "https://bleepingcomputer.com/feed/",
    "https://krebsonsecurity.com/feed/",
    "https://therecord.media/feed/",
    "https://www.darkreading.com/rss.xml",
    "https://feeds.feedburner.com/Securityweek",
    "https://cyberscoop.com/feed/",
    "https://www.helpnetsecurity.com/feed/",
]

CLOUD_AI_FEEDS = [
    "https://www.wiz.io/api/feed/cloud-threat-landscape/rss.xml",
    "https://aws.amazon.com/blogs/security/feed/",
    "https://cloud.google.com/feeds/security-bulletins.xml",
    "https://googleprojectzero.blogspot.com/feeds/posts/default",
    "https://msrc.microsoft.com/blog/feed",
    "https://blog.cloudflare.com/tag/security/rss/",
    "https://snyk.io/blog/feed/",
    "https://blog.trailofbits.com/feed/",
]

VULN_AND_ISAC_FEEDS = [
    "https://github.com/advisories.atom",
    "https://www.exploit-db.com/rss.xml",
    "https://isc.sans.edu/rssfeed_full.xml",
]

STARTER_FEEDS = [
    GOVT_FEEDS[0],        # CISA Advisories
    VENDOR_FEEDS[0],      # Palo Alto Unit 42
    NEWS_FEEDS[1],        # BleepingComputer
     NEWS_FEEDS[0],       # The Hacker News
    CLOUD_AI_FEEDS[4],    # Microsoft Security Response Center
    VULN_AND_ISAC_FEEDS[2], # SANS ISC
]

FULL_FEEDS = GOVT_FEEDS + VENDOR_FEEDS + NEWS_FEEDS + CLOUD_AI_FEEDS + VULN_AND_ISAC_FEEDS

# ── Threat Actors & Vendors (adapted from matt-snyder-stuff/threat-intel/sources/base.py) ──
KNOWN_ACTORS = [
    "APT1", "APT10", "APT28", "APT29", "APT30", "APT31", "APT32", "APT33",
    "APT34", "APT35", "APT38", "APT40", "APT41",
    "Volt Typhoon", "Salt Typhoon", "Silk Typhoon", "Flax Typhoon",
    "Sandworm", "Cozy Bear", "Fancy Bear", "Lazarus Group", "Lazarus",
    "Kimsuky", "Andariel", "BlueNoroff",
    "RansomHub", "Cl0p", "Clop", "LockBit", "ALPHV", "BlackCat",
    "Akira", "Play", "Black Basta", "Royal", "Hive", "8Base", "Medusa",
    "BianLian", "Hunters International", "Rhysida", "Qilin", "Fog",
    "FIN7", "FIN8", "Scattered Spider", "ShinyHunters", "LAPSUS$", "UNC3944",
    "Octo Tempest", "Midnight Blizzard", "Forest Blizzard", "TA505", "TA577",
]
_ACTORS_SORTED = sorted(KNOWN_ACTORS, key=len, reverse=True)
ACTOR_RE = re.compile(rf"\b({'|'.join(re.escape(a) for a in _ACTORS_SORTED)})\b", re.I)

TRACKED_VENDORS = [
    "Ubiquiti", "UniFi", "Proxmox", "Debian", "Elastic", "Elasticsearch", "Kibana",
    "Logstash", "Microsoft", "Windows", "Docker", "Kubernetes", "Ollama", "NVIDIA",
    "Cisco", "Fortinet", "Palo Alto", "Ivanti", "Citrix", "VMware", "AWS", "Azure",
    "GCP", "Google Cloud", "Okta", "GitHub", "Cloudflare", "CrowdStrike", "Splunk",
]
_VENDORS_SORTED = sorted(TRACKED_VENDORS, key=len, reverse=True)
VENDOR_RE = re.compile(rf"\b({'|'.join(re.escape(v) for v in _VENDORS_SORTED)})\b", re.I)

PUBLISHER_MAP = {
    "cisa.gov": ("CISA", 90, "A"),
    "ncsc.gov.uk": ("NCSC UK", 90, "A"),
    "unit42.paloaltonetworks.com": ("Palo Alto Unit 42", 85, "A"),
    "mandiant.com": ("Mandiant", 85, "A"),
    "crowdstrike.com": ("CrowdStrike", 85, "A"),
    "recordedfuture.com": ("Recorded Future", 85, "A"),
    "msrc.microsoft.com": ("Microsoft MSRC", 85, "A"),
    "aws.amazon.com": ("AWS Security Blog", 85, "A"),
    "cloud.google.com": ("Google Cloud Security", 85, "A"),
    "googleprojectzero.blogspot.com": ("Google Project Zero", 90, "A"),
    "wiz.io": ("Wiz", 85, "A"),
    "securelist.com": ("Kaspersky Securelist", 80, "B"),
    "rapid7.com": ("Rapid7", 80, "B"),
    "tenable.com": ("Tenable", 80, "B"),
    "sentinelone.com": ("SentinelOne", 80, "B"),
    "blog.virustotal.com": ("VirusTotal", 80, "B"),
    "blog.cloudflare.com": ("Cloudflare", 80, "B"),
    "snyk.io": ("Snyk", 80, "B"),
    "blog.trailofbits.com": ("Trail of Bits", 85, "A"),
    "isc.sans.edu": ("SANS ISC", 85, "A"),
    "github.com": ("GitHub Security Advisories", 85, "A"),
    "exploit-db.com": ("Exploit-DB", 80, "B"),
    "malware-traffic-analysis.net": ("Malware Traffic Analysis", 85, "A"),
    "bleepingcomputer.com": ("BleepingComputer", 75, "B"),
    "krebsonsecurity.com": ("Krebs on Security", 75, "B"),
    "therecord.media": ("The Record", 75, "B"),
    "darkreading.com": ("Dark Reading", 70, "C"),
    "cyberscoop.com": ("CyberScoop", 75, "B"),
    "helpnetsecurity.com": ("Help Net Security", 70, "C"),
}

_FEEDBURNER_MAP = {
    "talos": ("Cisco Talos", 85, "A"),
    "thedfirreport": ("The DFIR Report", 85, "A"),
    "thehackersnews": ("The Hacker News", 70, "C"),
    "securityweek": ("SecurityWeek", 75, "B"),
    "antimalwareblog": ("Trend Micro", 80, "B"),
}

# ── IOC & MITRE Regex Patterns ──
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_MD5_RE = re.compile(r"(?<![a-fA-F\d])[a-fA-F\d]{32}(?![a-fA-F\d])")
_SHA1_RE = re.compile(r"(?<![a-fA-F\d])[a-fA-F\d]{40}(?![a-fA-F\d])")
_SHA256_RE = re.compile(r"(?<![a-fA-F\d])[a-fA-F\d]{64}(?![a-fA-F\d])")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}(?:[\[\(\\]\.\]?|\.)[\]\)]?){3}\d{1,3}\b")
_TRAIL_RE = re.compile(r"[\.\?>\"'\)\]]+$")


def refang(value: str) -> str:
    """Normalize a defanged IOC string (hxxp, [.], (dot)) to plain form."""
    v = value or ""
    v = re.sub(r"^hxxps?", lambda m: m.group(0).replace("xx", "tt"), v, flags=re.I)
    for pat, rep in (("[dot]", "."), ("(dot)", "."), ("[.]", "."), ("(.)", "."), (r"\.", ".")):
        v = v.replace(pat, rep)
    v = re.sub(r"[\[\(]\.[\]\)]", ".", v)
    return _TRAIL_RE.sub("", v).strip()


def extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    """Extract CVEs, IPv4s, hashes, and MITRE ATT&CK technique IDs from text."""
    t = (text or "").replace("\x00", "")
    cves = sorted({m.group(0).upper() for m in _CVE_RE.finditer(t)})
    mitre_ids = sorted({m.group(0).upper() for m in _MITRE_RE.finditer(t)})
    sha256s = sorted({m.group(0).lower() for m in _SHA256_RE.finditer(t)})

    sha1s = []
    for m in _SHA1_RE.finditer(t):
        end = m.end()
        if end < len(t) and t[end] in "0123456789abcdefABCDEF":
            continue
        sha1s.append(m.group(0).lower())
    sha1s = sorted(set(sha1s))

    md5s = sorted({m.group(0).lower() for m in _MD5_RE.finditer(t)})

    ipv4s = []
    for m in _IPV4_RE.finditer(t):
        cand = refang(m.group(0))
        parts = cand.split(".")
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            ipv4s.append(cand)
    ipv4s = sorted(set(ipv4s))

    return {
        "cve": cves,
        "mitre_attack": mitre_ids,
        "ipv4": ipv4s,
        "sha256": sha256s,
        "sha1": sha1s,
        "md5": md5s,
    }


def extract_actors_and_vendors(text: str) -> Tuple[List[str], List[str], List[str]]:
    """Extract threat actors, vendors, and surface classification labels from text."""
    t = text or ""
    actors = []
    for m in ACTOR_RE.finditer(t):
        matched = m.group(0)
        canon = next((a for a in _ACTORS_SORTED if a.lower() == matched.lower()), matched)
        if canon not in actors:
            actors.append(canon)

    vendors = []
    for m in VENDOR_RE.finditer(t):
        matched = m.group(0)
        canon = next((v for v in _VENDORS_SORTED if v.lower() == matched.lower()), matched)
        if canon not in vendors:
            vendors.append(canon)

    tl = t.lower()
    labels: List[str] = []
    if any(k in tl for k in ("unifi", "ubiquiti", "router", "firewall", "gateway", "wan")):
        labels.append("network-perimeter")
    if "unifi" in tl or "ubiquiti" in tl:
        labels.append("unifi")
    if any(k in tl for k in ("proxmox", "kvm", "qemu", "hypervisor", "virtualization")):
        labels.append("proxmox")
        labels.append("hypervisor")
    if any(k in tl for k in ("windows", "sysmon", "active directory", "powershell", "ntlm")):
        labels.append("windows-endpoint")
    if any(k in tl for k in ("elasticsearch", "kibana", "logstash", "elastic")):
        labels.append("elastic-siem")
    if any(k in tl for k in ("llm", "ollama", "ai agent", "mcp")):
        labels.append("ai-llm")
    if any(k in tl for k in ("docker", "container", "kubernetes", "k8s")):
        labels.append("cloud-container")
    if "ransomware" in tl:
        labels.append("ransomware")
    if any(k in tl for k in ("zero-day", "0-day", "actively exploited", "in the wild")):
        labels.append("zero-day")

    return actors, vendors, sorted(set(labels))


def resolve_publisher(url: str) -> Tuple[str, int, str]:
    """Return (publisher_name, confidence_0_100, admiralty_reliability_A_F)."""
    if not url:
        return ("Unknown", 60, "C")
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        if host.startswith("www."):
            host = host[4:]
        if "feedburner.com" in host:
            slug = parsed.path.strip("/").split("/")[-1].lower().replace("-", "")
            for k, val in _FEEDBURNER_MAP.items():
                if k in slug:
                    return val
        for domain, val in PUBLISHER_MAP.items():
            if host == domain or host.endswith("." + domain):
                return val
        parts = host.split(".")
        name = parts[-2].replace("-", " ").title() if len(parts) >= 2 else host
        return (name, 65, "C")
    except Exception:
        return ("Unknown", 60, "C")


class ThreatFeedPipeline:
    """Ingests bulk IOC feeds & CTI RSS feeds, scores relevance, and runs retroactive SIEM matching."""

    def __init__(
        self,
        es_manager: Optional[ElasticClientManager] = None,
        inventory_manager: Optional[AssetInventoryManager] = None,
    ):
        self.es = es_manager or ElasticClientManager()
        self.inventory = inventory_manager or AssetInventoryManager(es_manager=self.es)

    async def fetch_feodo_tracker_ips(self, max_items: int = 50) -> List[Dict[str, Any]]:
        """Fetch active Botnet C2 IPs from abuse.ch Feodo Tracker (no API key required)."""
        url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
        items: List[Dict[str, Any]] = []
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, list):
                        for entry in data[:max_items]:
                            ip = entry.get("ip_address")
                            if not ip:
                                continue
                            malware = entry.get("malware", "Botnet C2")
                            port = entry.get("port")
                            as_name = entry.get("as_name", "")
                            country = entry.get("country", "")
                            first_seen = entry.get("first_seen", "")
                            items.append(
                                {
                                    "id": f"feodo-ip-{ip}",
                                    "indicator": ip,
                                    "indicator_type": "ipv4",
                                    "feed_name": "abuse.ch Feodo Tracker",
                                    "source_type": "abuse_ch_feodo",
                                    "source_reliability": "A",
                                    "confidence": 90,
                                    "tlp": "TLP:CLEAR",
                                    "title": f"Feodo Tracker Botnet C2: {malware} ({ip}:{port})",
                                    "description": (
                                        f"Active {malware} botnet command-and-control server at {ip}:{port} "
                                        f"(ASN: {as_name}, Country: {country}, First seen: {first_seen})."
                                    ),
                                    "malware_family": malware,
                                    "url": f"https://feodotracker.abuse.ch/browse/host/{ip}/",
                                    "labels": ["botnet-c2", "network-perimeter", malware.lower()],
                                    "threat_actors": [],
                                    "vendors": [],
                                    "cves": [],
                                    "mitre_attack": ["T1071"],
                                    "published_at": datetime.now(timezone.utc).isoformat(),
                                }
                            )
        except Exception:
            pass
        return items

    async def fetch_urlhaus_recent(self, max_items: int = 40) -> List[Dict[str, Any]]:
        """Fetch recent active malware distribution URLs/hosts from abuse.ch URLhaus."""
        url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
        items: List[Dict[str, Any]] = []
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    lines = [
                        line.strip()
                        for line in resp.text.splitlines()
                        if line.strip() and not line.startswith("#")
                    ]
                    for line in lines[:max_items]:
                        # CSV format: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
                        parts = [p.strip('"') for p in line.split('","')]
                        if len(parts) < 8:
                            continue
                        uh_id, date_added, mal_url, status, _, threat, tags_str, uh_link = parts[:8]
                        parsed_host = urlparse(mal_url).hostname or mal_url
                        tags = [t.strip() for t in tags_str.split(",") if t.strip()]
                        items.append(
                            {
                                "id": f"urlhaus-{uh_id}",
                                "indicator": parsed_host,
                                "indicator_type": "ipv4" if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", parsed_host) else "domain",
                                "feed_name": "abuse.ch URLhaus",
                                "source_type": "abuse_ch_urlhaus",
                                "source_reliability": "A",
                                "confidence": 85,
                                "tlp": "TLP:CLEAR",
                                "title": f"URLhaus Malware Host: {parsed_host} ({threat or 'malware_download'})",
                                "description": f"Malware distribution URL ({status}): {mal_url} | Tags: {', '.join(tags)}",
                                "malware_family": tags[0] if tags else threat,
                                "url": uh_link,
                                "labels": ["malware-distribution", "network-perimeter"] + [t.lower() for t in tags[:4]],
                                "threat_actors": [],
                                "vendors": [],
                                "cves": [],
                                "mitre_attack": ["T1105"],
                                "published_at": datetime.now(timezone.utc).isoformat(),
                            }
                        )
        except Exception:
            pass
        return items

    async def fetch_malwarebazaar_hashes(self, max_items: int = 40) -> List[Dict[str, Any]]:
        """Fetch recent SHA256 malware file hashes from abuse.ch MalwareBazaar."""
        url = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
        items: List[Dict[str, Any]] = []
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    hashes = [
                        line.strip().lower()
                        for line in resp.text.splitlines()
                        if line.strip() and not line.startswith("#") and len(line.strip()) == 64
                    ]
                    for h in hashes[:max_items]:
                        items.append(
                            {
                                "id": f"bazaar-sha256-{h[:20]}",
                                "indicator": h,
                                "indicator_type": "sha256",
                                "feed_name": "abuse.ch MalwareBazaar",
                                "source_type": "abuse_ch_bazaar",
                                "source_reliability": "A",
                                "confidence": 88,
                                "tlp": "TLP:CLEAR",
                                "title": f"MalwareBazaar Recent Payload SHA256: {h[:16]}...",
                                "description": f"Active malware sample SHA256 hash ingested from abuse.ch MalwareBazaar: {h}",
                                "malware_family": "MalwareBazaar Sample",
                                "url": f"https://bazaar.abuse.ch/sample/{h}/",
                                "labels": ["malware-hash", "windows-endpoint"],
                                "threat_actors": [],
                                "vendors": [],
                                "cves": [],
                                "mitre_attack": ["T1204"],
                                "published_at": datetime.now(timezone.utc).isoformat(),
                            }
                        )
        except Exception:
            pass
        return items

    def _parse_rss_xml(self, xml_text: str, feed_url: str, max_per_feed: int = 8) -> List[Dict[str, Any]]:
        """Parse RSS 2.0 or Atom XML into normalized CTI report items."""
        reports: List[Dict[str, Any]] = []
        try:
            root = ET.fromstring(xml_text)
        except Exception:
            return reports

        pub_name, pub_conf, pub_rel = resolve_publisher(feed_url)

        # Collect RSS <item> or Atom <entry>
        entries = root.findall(".//item")
        is_atom = False
        if not entries:
            entries = root.findall(".//{http://www.w3.org/2005/Atom}entry")
            is_atom = True

        for entry in entries[:max_per_feed]:
            if not is_atom:
                title = (entry.findtext("title") or "").strip()
                link = (entry.findtext("link") or "").strip()
                desc = (entry.findtext("description") or "").strip()
                pub_date_raw = (entry.findtext("pubDate") or "").strip()
            else:
                ns = "{http://www.w3.org/2005/Atom}"
                title = (entry.findtext(f"{ns}title") or "").strip()
                desc = (entry.findtext(f"{ns}summary") or entry.findtext(f"{ns}content") or "").strip()
                pub_date_raw = (entry.findtext(f"{ns}published") or entry.findtext(f"{ns}updated") or "").strip()
                link = ""
                link_el = entry.find(f"{ns}link")
                if link_el is not None:
                    link = link_el.attrib.get("href", "").strip()

            if not title:
                continue

            # Strip HTML tags from description
            clean_desc = re.sub(r"<[^>]+>", " ", desc)
            clean_desc = re.sub(r"\s+", " ", clean_desc).strip()[:1500]

            pub_iso = datetime.now(timezone.utc).isoformat()
            if pub_date_raw:
                try:
                    dt = parsedate_to_datetime(pub_date_raw)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    pub_iso = dt.astimezone(timezone.utc).isoformat()
                except Exception:
                    try:
                        dt = datetime.fromisoformat(pub_date_raw.replace("Z", "+00:00"))
                        pub_iso = dt.astimezone(timezone.utc).isoformat()
                    except Exception:
                        pass

            full_text = f"{title} {clean_desc}"
            extracted_iocs = extract_iocs_from_text(full_text)
            actors, vendors, labels = extract_actors_and_vendors(full_text)

            # Determine primary indicator (CVE > IPv4 > SHA256 > Report URL)
            if extracted_iocs["cve"]:
                primary_ind = extracted_iocs["cve"][0]
                ind_type = "cve"
            elif extracted_iocs["ipv4"]:
                primary_ind = extracted_iocs["ipv4"][0]
                ind_type = "ipv4"
            elif extracted_iocs["sha256"]:
                primary_ind = extracted_iocs["sha256"][0]
                ind_type = "sha256"
            else:
                primary_ind = link or title[:80]
                ind_type = "report"

            stable_hash = hashlib.sha1((link or title).encode("utf-8")).hexdigest()[:16]
            reports.append(
                {
                    "id": f"cti-rss-{stable_hash}",
                    "indicator": primary_ind,
                    "indicator_type": ind_type,
                    "feed_name": f"CTI RSS ({pub_name})",
                    "publisher": pub_name,
                    "source_type": "rss",
                    "source_reliability": pub_rel,
                    "confidence": pub_conf,
                    "tlp": "TLP:CLEAR",
                    "title": title,
                    "description": clean_desc,
                    "malware_family": actors[0] if actors else (vendors[0] if vendors else "CTI Report"),
                    "url": link or feed_url,
                    "labels": labels,
                    "threat_actors": actors,
                    "vendors": vendors,
                    "cves": extracted_iocs["cve"],
                    "extracted_ips": extracted_iocs["ipv4"],
                    "extracted_hashes": extracted_iocs["sha256"] + extracted_iocs["md5"],
                    "mitre_attack": extracted_iocs["mitre_attack"],
                    "published_at": pub_iso,
                }
            )

        return reports

    async def fetch_rss_feeds(
        self, feed_set: str = "starter", max_per_feed: int = 8
    ) -> List[Dict[str, Any]]:
        """Concurrently fetch and parse CTI RSS/Atom feeds (`starter` or `full`)."""
        urls = FULL_FEEDS if feed_set == "full" else STARTER_FEEDS

        async def _fetch_one(client: httpx.AsyncClient, url: str) -> List[Dict[str, Any]]:
            try:
                resp = await client.get(url, headers={"User-Agent": "Jarvis-SecOps-CTI/1.3"})
                if resp.status_code == 200 and resp.text:
                    return self._parse_rss_xml(resp.text, url, max_per_feed=max_per_feed)
            except Exception:
                pass
            return []

        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
            batches = await asyncio.gather(*(_fetch_one(client, u) for u in urls))

        all_reports: List[Dict[str, Any]] = []
        seen_ids: Set[str] = set()
        for batch in batches:
            for item in batch:
                if item["id"] not in seen_ids:
                    seen_ids.add(item["id"])
                    all_reports.append(item)
        return all_reports

    def score_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Compute Industry Reach Score, Environment Relevance Score, and Operational Priority Score.

        Follows matt-snyder-stuff/threat-intel's scoring model:
          - reach_score: publisher confidence weight + surface labels + named actors + CVEs
          - environment_score: weighted match against Jarvis environment-profile.json
          - priority_score: min(100, reach_score + int(0.5 * environment_score))
        """
        labels = item.get("labels", [])
        actors = item.get("threat_actors", [])
        vendors = item.get("vendors", [])
        cves = item.get("cves", [])
        base_conf = int(item.get("confidence", 70))

        reach_score = min(
            100,
            int(base_conf * 0.45)
            + (len(labels) * 7)
            + (len(actors) * 10)
            + (len(cves) * 12)
            + (15 if item.get("indicator_type") in {"ipv4", "sha256", "domain"} else 0),
        )

        env_score, env_matches = self.inventory.score_environment_relevance(
            title=item.get("title", ""),
            description=item.get("description", ""),
            labels=labels,
            vendors=vendors,
            threat_actors=actors,
        )

        priority_score = min(100, reach_score + int(env_score * 0.6))
        if env_score >= 40:
            priority_score = max(priority_score, 75)

        item["reach_score"] = reach_score
        item["environment_score"] = env_score
        item["environment_matches"] = env_matches
        item["priority_score"] = priority_score
        return item

    async def retroactive_siem_match(
        self, items: List[Dict[str, Any]], lookback_days: int = 90
    ) -> Dict[str, Any]:
        """Search 90 days of historical UniFi firewall/DNS and Sysmon endpoint logs for ingested IOCs.

        Implements the `late-ioc-matcher` pattern from matt-snyder-stuff/threat-intel.
        """
        ip_candidates: Set[str] = set()
        domain_candidates: Set[str] = set()
        hash_candidates: Set[str] = set()

        for it in items:
            ind = it.get("indicator", "")
            itype = it.get("indicator_type", "")
            if itype == "ipv4" and ind:
                ip_candidates.add(ind)
            elif itype == "domain" and ind:
                domain_candidates.add(ind)
            elif itype in {"sha256", "md5", "sha1"} and ind:
                hash_candidates.add(ind.lower())

            for extra_ip in it.get("extracted_ips", []):
                ip_candidates.add(extra_ip)
            for extra_h in it.get("extracted_hashes", []):
                hash_candidates.add(extra_h.lower())

        matched_ips: Dict[str, int] = {}
        matched_domains: Dict[str, int] = {}
        matched_hashes: Dict[str, int] = {}

        try:
            client = self.es.get_client()

            # 1. Batch check IPs across UniFi and Sysmon
            if ip_candidates:
                ip_list = list(ip_candidates)[:200]
                ip_res = await client.search(
                    index="logs-network.unifi-*,logs-endpoint.*,winlogbeat*",
                    size=0,
                    query={
                        "bool": {
                            "must": [
                                {"range": {"@timestamp": {"gte": f"now-{lookback_days}d", "lte": "now"}}},
                                {
                                    "bool": {
                                        "should": [
                                            {"terms": {"source.ip": ip_list}},
                                            {"terms": {"destination.ip": ip_list}},
                                        ],
                                        "minimum_should_match": 1,
                                    }
                                },
                            ]
                        }
                    },
                    aggs={
                        "src_hits": {"terms": {"field": "source.ip", "size": 100}},
                        "dst_hits": {"terms": {"field": "destination.ip", "size": 100}},
                    },
                )
                for b in ip_res.get("aggregations", {}).get("src_hits", {}).get("buckets", []):
                    if b["key"] in ip_candidates:
                        matched_ips[b["key"]] = matched_ips.get(b["key"], 0) + b["doc_count"]
                for b in ip_res.get("aggregations", {}).get("dst_hits", {}).get("buckets", []):
                    if b["key"] in ip_candidates:
                        matched_ips[b["key"]] = matched_ips.get(b["key"], 0) + b["doc_count"]

            # 2. Batch check Domains against Sysmon DNS (EID 22)
            if domain_candidates:
                dom_list = list(domain_candidates)[:150]
                dom_res = await client.search(
                    index="logs-endpoint.*,winlogbeat*",
                    size=0,
                    query={
                        "bool": {
                            "must": [
                                {"range": {"@timestamp": {"gte": f"now-{lookback_days}d", "lte": "now"}}},
                                {"terms": {"dns.question.name": dom_list}},
                            ]
                        }
                    },
                    aggs={"dom_hits": {"terms": {"field": "dns.question.name", "size": 50}}},
                )
                for b in dom_res.get("aggregations", {}).get("dom_hits", {}).get("buckets", []):
                    matched_domains[b["key"]] = b["doc_count"]

            # 3. Batch check File Hashes against Sysmon Process Creation (EID 1)
            if hash_candidates:
                h_list = list(hash_candidates)[:150]
                h_res = await client.search(
                    index="logs-endpoint.*,winlogbeat*",
                    size=0,
                    query={
                        "bool": {
                            "must": [
                                {"range": {"@timestamp": {"gte": f"now-{lookback_days}d", "lte": "now"}}},
                                {
                                    "bool": {
                                        "should": [
                                            {"terms": {"process.hash.sha256": h_list}},
                                            {"terms": {"process.hash.md5": h_list}},
                                            {"terms": {"file.hash.sha256": h_list}},
                                        ],
                                        "minimum_should_match": 1,
                                    }
                                },
                            ]
                        }
                    },
                    aggs={"sha256_hits": {"terms": {"field": "process.hash.sha256", "size": 50}}},
                )
                for b in h_res.get("aggregations", {}).get("sha256_hits", {}).get("buckets", []):
                    matched_hashes[b["key"].lower()] = b["doc_count"]
        except Exception:
            pass

        # Annotate items with retroactive SIEM hit counts
        total_retro_hits = 0
        items_with_hits = 0
        for it in items:
            ind = it.get("indicator", "")
            hits = (
                matched_ips.get(ind, 0)
                + matched_domains.get(ind, 0)
                + matched_hashes.get(ind.lower(), 0)
            )
            for eip in it.get("extracted_ips", []):
                hits += matched_ips.get(eip, 0)
            for eh in it.get("extracted_hashes", []):
                hits += matched_hashes.get(eh.lower(), 0)

            it["retro_siem_hits"] = hits
            if hits > 0:
                items_with_hits += 1
                total_retro_hits += hits
                it["priority_score"] = 100
                it["retro_classification"] = "high_confidence_siem_match"
            else:
                it["retro_classification"] = "no_historical_exposure"

        return {
            "lookback_days": lookback_days,
            "ips_checked": len(ip_candidates),
            "domains_checked": len(domain_candidates),
            "hashes_checked": len(hash_candidates),
            "items_with_siem_hits": items_with_hits,
            "total_siem_event_matches": total_retro_hits,
            "matched_ips": matched_ips,
            "matched_domains": matched_domains,
            "matched_hashes": matched_hashes,
        }

    async def ingest_all_feeds(
        self,
        feed_set: str = "starter",
        include_abuse_ch: bool = True,
        lookback_days: int = 90,
    ) -> Dict[str, Any]:
        """Ingest bulk IOC feeds + CTI RSS feeds, score against environment, run retro SIEM hunt, and index to ES."""
        now_iso = datetime.now(timezone.utc).isoformat()

        tasks = [self.fetch_rss_feeds(feed_set=feed_set)]
        if include_abuse_ch:
            tasks.extend(
                [
                    self.fetch_feodo_tracker_ips(max_items=40),
                    self.fetch_urlhaus_recent(max_items=35),
                    self.fetch_malwarebazaar_hashes(max_items=35),
                ]
            )

        results = await asyncio.gather(*tasks)
        all_items: List[Dict[str, Any]] = []
        for batch in results:
            all_items.extend(batch)

        # Score all items against the Jarvis Environment Profile
        for it in all_items:
            self.score_item(it)
            it.setdefault("analyst_disposition", "unreviewed")

        # Run 90-day retroactive SIEM matching
        retro_summary = await self.retroactive_siem_match(all_items, lookback_days=lookback_days)

        # Index into Elasticsearch (`logs-threat_intel.indicators-default`)
        indexed_count = 0
        es_errors: List[str] = []
        try:
            client = self.es.get_client()
            for it in all_items:
                doc = {
                    "@timestamp": it.get("published_at") or now_iso,
                    "ingested_at": now_iso,
                    "event": {
                        "kind": "enrichment",
                        "category": ["threat"],
                        "type": ["indicator"],
                        "dataset": "threat_intel.indicators",
                    },
                    "threat": {
                        "feed": {
                            "name": it.get("feed_name"),
                            "source_type": it.get("source_type"),
                            "reliability": it.get("source_reliability"),
                            "confidence": it.get("confidence"),
                            "tlp": it.get("tlp"),
                        },
                        "indicator": {
                            "value": it.get("indicator"),
                            "type": it.get("indicator_type"),
                            "ip": it.get("indicator") if it.get("indicator_type") == "ipv4" else None,
                            "domain": it.get("indicator") if it.get("indicator_type") == "domain" else None,
                            "sha256": it.get("indicator") if it.get("indicator_type") == "sha256" else None,
                            "url": it.get("url"),
                        },
                        "report": {
                            "id": it.get("id"),
                            "title": it.get("title"),
                            "description": it.get("description"),
                            "malware_family": it.get("malware_family"),
                            "labels": it.get("labels", []),
                            "actors": it.get("threat_actors", []),
                            "vendors": it.get("vendors", []),
                            "cves": it.get("cves", []),
                            "mitre_attack": it.get("mitre_attack", []),
                        },
                        "scoring": {
                            "reach_score": it.get("reach_score", 0),
                            "environment_score": it.get("environment_score", 0),
                            "environment_matches": it.get("environment_matches", []),
                            "priority_score": it.get("priority_score", 0),
                        },
                        "retro_hunt": {
                            "siem_hits": it.get("retro_siem_hits", 0),
                            "classification": it.get("retro_classification", "no_historical_exposure"),
                        },
                        "disposition": it.get("analyst_disposition", "unreviewed"),
                    },
                }
                await client.index(
                    index=INDICATORS_INDEX,
                    document=doc,
                    op_type="create",
                )
                indexed_count += 1
        except Exception as e:
            es_errors.append(str(e))

        # Sort by priority_score descending for summary return
        top_items = sorted(all_items, key=lambda x: x.get("priority_score", 0), reverse=True)[:15]
        env_matched = [i for i in all_items if i.get("environment_score", 0) > 0]

        return {
            "status": "success" if not es_errors else "partial",
            "timestamp": now_iso,
            "feed_set": feed_set,
            "total_ingested": len(all_items),
            "indexed_to_es": indexed_count,
            "index_name": INDICATORS_INDEX,
            "environment_relevant_count": len(env_matched),
            "retroactive_siem_hunt": retro_summary,
            "top_priority_intel": [
                {
                    "id": i["id"],
                    "title": i["title"],
                    "feed": i["feed_name"],
                    "indicator": i["indicator"],
                    "type": i["indicator_type"],
                    "priority_score": i["priority_score"],
                    "environment_score": i["environment_score"],
                    "environment_matches": i["environment_matches"],
                    "retro_siem_hits": i.get("retro_siem_hits", 0),
                    "cves": i.get("cves", []),
                }
                for i in top_items
            ],
            "errors": es_errors,
        }

    async def update_disposition(
        self,
        item_id: str,
        disposition: str,
        index_name: str = INDICATORS_INDEX,
        owner: str = "SecOps Admin",
        note: str = "",
        case_url: str = "",
    ) -> Dict[str, Any]:
        """Update analyst review disposition on an IOC, report, CVE, or identity finding in Elasticsearch."""
        if disposition not in VALID_DISPOSITIONS:
            return {
                "status": "error",
                "error": f"Invalid disposition '{disposition}'. Must be one of: {sorted(VALID_DISPOSITIONS)}",
            }

        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            client = self.es.get_client()
            target_index = index_name
            target_id = item_id
            # Resolve backing data stream index if item_id is a logical report/vuln/identity ID
            try:
                search_res = await client.search(
                    index=index_name,
                    size=1,
                    sort=[{"@timestamp": {"order": "desc"}}],
                    query={
                        "bool": {
                            "should": [
                                {"term": {"_id": item_id}},
                                {"term": {"threat.report.id.keyword": item_id}},
                                {"term": {"vulnerability.id.keyword": item_id}},
                                {"term": {"identity.id.keyword": item_id}},
                            ],
                            "minimum_should_match": 1,
                        }
                    },
                )
                hits = search_res.get("hits", {}).get("hits", [])
                if hits:
                    target_index = hits[0].get("_index", index_name)
                    target_id = hits[0].get("_id", item_id)
            except Exception:
                pass

            await client.update(
                index=target_index,
                id=target_id,
                doc={
                    "threat": {
                        "disposition": disposition,
                        "review": {
                            "owner": owner,
                            "note": note,
                            "case_url": case_url,
                            "reviewed_at": now_iso,
                        },
                    }
                },
            )
            return {
                "status": "success",
                "item_id": item_id,
                "index": index_name,
                "disposition": disposition,
                "owner": owner,
                "note": note,
                "reviewed_at": now_iso,
            }
        except Exception as e:
            return {"status": "error", "item_id": item_id, "error": str(e)}
