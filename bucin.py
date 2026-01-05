#!/usr/bin/env python3
"""
BUCIN - Browse • Uncover • Collect • Intel • Network
-------------------------------------------------
Version: 2.0.0

Advanced OSINT & External Threat Hunting toolkit.
This tool provides comprehensive external reconnaissance capabilities:
 - `subdomains`: crt.sh passive subdomain enumeration + liveness checks
 - `probe`: Liveness & path probing (e.g., /.env, /.git/config)
 - `crawl`: Lightweight crawling + secret scanning (regex-based)
 - `tls`: TLS certificate grabbing
 - `buckets`: S3/GCP/Azure public bucket checks
 - `dns`: DNS record enumeration (MX, TXT, NS, etc.)
 - `whois`: Whois domain registration lookup
 - `ports`: Common port scanning
 - `headers`: HTTP security headers analysis
 - `wayback`: Wayback Machine URL discovery
 - `tech`: Technology stack detection
 - `cors`: CORS misconfiguration detection
 - `takeover`: Subdomain takeover vulnerability check
 - `social`: Social media profile discovery
 - `all`: Combined quick footprint

License: MIT
Repository: https://github.com/Masriyan/Bucin
"""

from __future__ import annotations
import argparse
import concurrent.futures as cf
import csv
import json
import os
import re
import socket
import ssl
import sys
import traceback
from collections import deque
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Dict, Optional, Set, Tuple
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
import tldextract

# Optional imports with graceful fallback
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = BLUE = WHITE = ""
    class Style:
        RESET_ALL = BRIGHT = ""

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    def tqdm(iterable, *args, **kwargs):
        return iterable

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# -------------------------- Branding & UI copy ----------------------------
VERSION = "2.0.0"

BUCIN_BANNER = f'''{Fore.CYAN}{Style.BRIGHT}
╔══════════════════════════════════════════════════════════════════════════════╗
║  ██████╗ ██╗   ██╗ ██████╗██╗███╗   ██╗                                      ║
║  ██╔══██╗██║   ██║██╔════╝██║████╗  ██║                                      ║
║  ██████╔╝██║   ██║██║     ██║██╔██╗ ██║                                      ║
║  ██╔══██╗██║   ██║██║     ██║██║╚██╗██║                                      ║
║  ██████╔╝╚██████╔╝╚██████╗██║██║ ╚████║                                      ║
║  ╚═════╝  ╚═════╝  ╚═════╝╚═╝╚═╝  ╚═══╝                                      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  {Fore.WHITE}Browse • Uncover • Collect • Intel • Network{Fore.CYAN}              v{VERSION}       ║
║  {Fore.YELLOW}OSINT & External Threat Hunting Toolkit{Fore.CYAN}                               ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}'''

CLI_PROMPT = f"{Fore.CYAN}[BUCIN]{Style.RESET_ALL}"

def log_info(msg: str):
    print(f"{CLI_PROMPT} {Fore.WHITE}{msg}{Style.RESET_ALL}")

def log_success(msg: str):
    print(f"{CLI_PROMPT} {Fore.GREEN}✓ {msg}{Style.RESET_ALL}")

def log_warning(msg: str):
    print(f"{CLI_PROMPT} {Fore.YELLOW}⚠ {msg}{Style.RESET_ALL}")

def log_error(msg: str):
    print(f"{CLI_PROMPT} {Fore.RED}✗ {msg}{Style.RESET_ALL}")

def log_section(title: str):
    print(f"\n{Fore.MAGENTA}{'─'*60}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}  {title}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}{'─'*60}{Style.RESET_ALL}")

LOG_MESSAGES = {
    'start': "Initiating reconnaissance...",
    'collect': "Collecting public assets and signals of exposure...",
    'unreachable': "Target unreachable — documented for review.",
    'done': "Mission complete. Report generated.",
    'dns': "Querying DNS records...",
    'whois': "Fetching WHOIS registration data...",
    'ports': "Scanning for open ports...",
    'headers': "Analyzing HTTP security headers...",
    'wayback': "Querying Wayback Machine for historical URLs...",
    'tech': "Detecting technology stack...",
    'cors': "Testing CORS configuration...",
    'takeover': "Checking for subdomain takeover vulnerabilities...",
}

UA = {
    "User-Agent": os.getenv("BUCIN_USER_AGENT", "BUCIN/2.0 (+https://github.com/Masriyan/Bucin)")
}
requests.packages.urllib3.disable_warnings()

# --------------------------- Utilities ------------------------------------

def ts() -> str:
    return datetime.utcnow().strftime("%Y%m%d-%H%M%S")


def ensure_outdir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p


def write_json(path: Path, data: Iterable[dict]):
    with path.open("w", encoding="utf-8") as f:
        json.dump(list(data), f, ensure_ascii=False, indent=2)


def write_csv(path: Path, rows: Iterable[dict]):
    rows = list(rows)
    if not rows:
        path.write_text("")
        return
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=sorted(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def domain_root(host: str) -> str:
    ext = tldextract.extract(host)
    if not ext.registered_domain:
        return host
    return ext.registered_domain


def parse_targets(target_arg: str) -> List[str]:
    p = Path(target_arg)
    if p.exists() and p.is_file():
        out: List[str] = []
        for ln in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            out.append(ln)
        return out
    return [target_arg]

# ----------------------- Subdomain enumeration (crt.sh) -------------------

def fetch_crtsh(domain: str, timeout: int = 20) -> Set[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, headers=UA, timeout=timeout)
        if r.status_code != 200:
            return set()
        data = r.json()
        subs: Set[str] = set()
        for row in data:
            name = row.get("name_value", "")
            for line in str(name).split("\n"):
                line = line.strip().lower()
                if line.endswith(domain.lower()) and "*" not in line:
                    subs.add(line)
        return subs
    except Exception:
        return set()

# --------------------------- Networking helpers ---------------------------

def resolve_host(host: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(host, None)
        addrs = sorted({i[4][0] for i in infos})
        return addrs
    except Exception:
        return []


def http_head(url: str, timeout: int = 10) -> Tuple[int, Dict[str, str]]:
    try:
        r = requests.head(url, headers=UA, timeout=timeout, allow_redirects=True, verify=False)
        return r.status_code, dict(r.headers)
    except Exception:
        return 0, {}


def probe_alive(host: str) -> Dict[str, object]:
    result = {"host": host}
    for scheme in ("http", "https"):
        url = f"{scheme}://{host}"
        code, headers = http_head(url)
        result[f"{scheme}_status"] = code
        if headers.get("Server"):
            result[f"{scheme}_server"] = headers.get("Server")
    result["ips"] = resolve_host(host)
    return result

# --------------------------- Path probing ---------------------------------
COMMON_PATHS = [
    "/.env", "/env.js", "/.git/config", "/.git/HEAD", "/.svn/entries",
    "/config.json", "/config.yml", "/.DS_Store", "/backup.zip", "/db.sqlite3",
    "/swagger", "/swagger.json", "/openapi.json", "/.well-known/security.txt",
    "/admin", "/debug", "/phpinfo.php", "/robots.txt", "/sitemap.xml"
]


def probe_paths(base_url: str, paths: Iterable[str], timeout: int = 12) -> List[Dict[str, object]]:
    if not base_url.startswith("http"):
        base_url = "https://" + base_url
    results = []
    with cf.ThreadPoolExecutor(max_workers=12) as ex:
        futs = []
        for p in paths:
            url = base_url.rstrip("/") + p
            futs.append(ex.submit(requests.get, url, headers=UA, timeout=timeout, verify=False))
        for p, fut in zip(paths, futs):
            try:
                r = fut.result(timeout=timeout+5)
                results.append({"path": p, "status": r.status_code, "length": len(r.content), "url": r.url})
            except Exception:
                results.append({"path": p, "status": 0, "length": 0, "url": base_url.rstrip("/")+p})
    return results

# --------------------------- Crawler & secret scan ------------------------
SECRET_REGEXES = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?(secret|sk|access)?(.{0,5})?[:=\"]{1}([A-Za-z0-9/+=]{40})",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Slack Token": r"xox[baprs]-[A-Za-z0-9\-]{10,48}",
    "Heroku API": r"(?i)heroku(.{0,20})?key(.{0,5})?[:=\"]([0-9a-f]{32})",
    "Private Key": r"-----BEGIN (?:RSA|DSA|EC|PGP) PRIVATE KEY-----",
    "JWT": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}",
    "Email": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
}

@dataclass
class PageFinding:
    url: str
    status: int
    content_length: int
    secrets: List[Dict[str, str]]


def crawl(start_url: str, max_pages: int = 150, same_host_only: bool = True, scan_secrets: bool = True) -> List[PageFinding]:
    start_url = start_url if start_url.startswith("http") else ("https://" + start_url)
    seen: Set[str] = set()
    host = (tldextract.extract(start_url).registered_domain or tldextract.extract(start_url).fqdn)
    q = deque([start_url])
    out: List[PageFinding] = []
    session = requests.Session()
    session.headers.update(UA)
    while q and len(seen) < max_pages:
        url = q.popleft()
        if url in seen:
            continue
        seen.add(url)
        try:
            r = session.get(url, timeout=15, verify=False)
        except Exception:
            continue
        secs: List[Dict[str, str]] = []
        if scan_secrets and r.ok and r.text:
            for name, pattern in SECRET_REGEXES.items():
                for m in re.finditer(pattern, r.text):
                    val = m.group(0)
                    secs.append({"type": name, "match": (val[:120] + "…") if len(val) > 120 else val})
        out.append(PageFinding(url=url, status=r.status_code, content_length=len(r.content), secrets=secs))
        if len(seen) >= max_pages:
            break
        if r.ok and "text/html" in r.headers.get("Content-Type", ""):
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a.get("href")
                if not href or href.startswith("javascript:") or href.startswith("mailto:"):
                    continue
                full = requests.compat.urljoin(url, href)
                if same_host_only:
                    try:
                        if tldextract.extract(full).registered_domain == tldextract.extract(start_url).registered_domain:
                            if full not in seen and len(full) < 2048:
                                q.append(full)
                    except Exception:
                        pass
                else:
                    if full not in seen and len(full) < 2048:
                        q.append(full)
    return out

# --------------------------- TLS certificate grab ------------------------

def grab_cert(host: str, port: int = 443, timeout: int = 8) -> Dict[str, object]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return {
                    "host": host,
                    "issuer": dict(x[0] for x in cert.get('issuer', [])),
                    "subject": dict(x[0] for x in cert.get('subject', [])),
                    "notBefore": cert.get('notBefore'),
                    "notAfter": cert.get('notAfter'),
                    "subjectAltName": cert.get('subjectAltName'),
                    "version": cert.get('version'),
                }
    except Exception as e:
        return {"host": host, "error": str(e)}

# --------------------------- Bucket checks --------------------------------
AWS_SUFFIXES = ["s3.amazonaws.com", "s3-eu-west-1.amazonaws.com", "s3-us-west-2.amazonaws.com"]
GCP_SUFFIXES = ["storage.googleapis.com"]
AZ_SUFFIXES = ["blob.core.windows.net"]


def candidate_buckets(company_name: str, wordlist: Optional[Iterable[str]] = None) -> Set[str]:
    words = set()
    base = re.sub(r"[^a-z0-9]+", " ", company_name.lower()).split()
    words.update(base)
    if wordlist:
        for w in wordlist:
            w = w.strip().lower()
            if w and not w.startswith("#"):
                words.add(w)
    seeds = set()
    for w in words:
        seeds.update({w, f"{w}-dev", f"{w}-prod", f"{w}-staging", f"{w}assets", f"{w}cdn", f"{w}public"})
    return seeds


def check_bucket_public(name: str) -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []
    for suf in AWS_SUFFIXES:
        url = f"http://{name}.{suf}/"
        try:
            r = requests.get(url, headers=UA, timeout=10)
            results.append({"provider": "aws", "bucket": name, "endpoint": url, "status": str(r.status_code), "leak": "<ListBucketResult>" if b"ListBucketResult" in r.content else ""})
        except Exception:
            pass
    for suf in GCP_SUFFIXES:
        url = f"https://{suf}/{name}/"
        try:
            r = requests.get(url, headers=UA, timeout=10)
            results.append({"provider": "gcp", "bucket": name, "endpoint": url, "status": str(r.status_code), "leak": "<ListBucketResult>" if b"ListBucketResult" in r.content else ""})
        except Exception:
            pass
    for suf in AZ_SUFFIXES:
        url = f"https://{name}.{suf}/?restype=container&comp=list"
        try:
            r = requests.get(url, headers=UA, timeout=10)
            results.append({"provider": "azure", "bucket": name, "endpoint": url, "status": str(r.status_code), "leak": "<EnumerationResults>" if b"EnumerationResults" in r.content else ""})
        except Exception:
            pass
    return results

# --------------------------- [NEW] Whois Lookup ---------------------------
def fetch_whois_info(domain: str) -> Dict[str, object]:
    print(f"{CLI_PROMPT}  Fetching whois for {domain}...")
    try:
        import whois
        w = whois.query(domain)
        if w:
            # Convert datetime objects to ISO strings for JSON/CSV
            data = w.__dict__
            for k, v in data.items():
                if isinstance(v, datetime):
                    data[k] = v.isoformat()
                if isinstance(v, list) and v and isinstance(v[0], datetime):
                    data[k] = [item.isoformat() for item in v]
            return {"domain": domain, **data}
        return {"domain": domain, "error": "No whois data found."}
    except ImportError:
        print(f"{CLI_PROMPT}  ERROR: 'python-whois' library not found. Please run 'pip install python-whois'")
        return {"domain": domain, "error": "python-whois not installed"}
    except Exception as e:
        return {"domain": domain, "error": str(e)}

# ------------------------ [NEW] DNS Record Fetching -----------------------
RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']

def fetch_dns_records(domain: str) -> List[Dict[str, str]]:
    print(f"{CLI_PROMPT}  Fetching DNS records for {domain}...")
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        results = []
        for rtype in RECORD_TYPES:
            try:
                answers = resolver.resolve(domain, rtype)
                for rdata in answers:
                    results.append({"domain": domain, "type": rtype, "value": rdata.to_text()})
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoMetaqueries):
                pass
            except Exception:
                pass # Other DNS errors
        if not results:
             results.append({"domain": domain, "type": "INFO", "value": "No common records found or domain does not exist."})
        return results
    except ImportError:
        print(f"{CLI_PROMPT}  ERROR: 'dnspython' library not found. Please run 'pip install dnspython'")
        return [{"domain": domain, "type": "ERROR", "value": "dnspython not installed"}]
    except Exception as e:
        return [{"domain": domain, "type": "ERROR", "value": str(e)}]

# ------------------------- [NEW] Port Scanning ----------------------------
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 5900, 8080, 8443]

def scan_port(host: str, port: int, timeout: int = 2) -> Dict[str, object]:
    try:
        ip_list = resolve_host(host)
        ip = ip_list[0] if ip_list else None
        if not ip:
            return {"host": host, "port": port, "open": False, "error": "Cannot resolve host"}
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                return {"host": host, "ip": ip, "port": port, "open": True}
            else:
                return {"host": host, "ip": ip, "port": port, "open": False}
    except Exception as e:
        return {"host": host, "port": port, "open": False, "error": str(e)}

# ------------------------- HTTP Security Headers ---------------------------
SECURITY_HEADERS = {
    'Strict-Transport-Security': {'severity': 'HIGH', 'desc': 'HSTS header missing'},
    'X-Content-Type-Options': {'severity': 'MEDIUM', 'desc': 'MIME sniffing protection missing'},
    'X-Frame-Options': {'severity': 'MEDIUM', 'desc': 'Clickjacking protection missing'},
    'X-XSS-Protection': {'severity': 'LOW', 'desc': 'XSS protection header missing'},
    'Content-Security-Policy': {'severity': 'HIGH', 'desc': 'CSP header missing'},
    'Referrer-Policy': {'severity': 'LOW', 'desc': 'Referrer policy not set'},
    'Permissions-Policy': {'severity': 'LOW', 'desc': 'Permissions policy not set'},
}

def analyze_security_headers(url: str, timeout: int = 10) -> Dict[str, object]:
    if not url.startswith("http"):
        url = "https://" + url
    result = {"url": url, "headers": {}, "missing": [], "score": 0}
    try:
        r = requests.get(url, headers=UA, timeout=timeout, verify=False, allow_redirects=True)
        result["status_code"] = r.status_code
        present = 0
        for header, info in SECURITY_HEADERS.items():
            value = r.headers.get(header)
            if value:
                result["headers"][header] = value
                present += 1
            else:
                result["missing"].append({"header": header, "severity": info['severity'], "desc": info['desc']})
        result["score"] = round((present / len(SECURITY_HEADERS)) * 100, 1)
        result["server"] = r.headers.get("Server", "")
        result["powered_by"] = r.headers.get("X-Powered-By", "")
    except Exception as e:
        result["error"] = str(e)
    return result

# ------------------------- Wayback Machine URL Discovery -------------------
def fetch_wayback_urls(domain: str, limit: int = 500) -> List[Dict[str, str]]:
    log_info(f"Querying Wayback Machine for {domain}...")
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=timestamp,original,statuscode,mimetype&collapse=urlkey&limit={limit}"
    try:
        r = requests.get(url, headers=UA, timeout=60)
        if r.status_code != 200:
            return [{"domain": domain, "error": f"HTTP {r.status_code}"}]
        data = r.json()
        if len(data) <= 1:
            return [{"domain": domain, "info": "No archived URLs found"}]
        results = []
        for row in data[1:]:
            results.append({
                "domain": domain,
                "timestamp": row[0],
                "url": row[1],
                "status": row[2],
                "mimetype": row[3]
            })
        return results
    except Exception as e:
        return [{"domain": domain, "error": str(e)}]

# ------------------------- Technology Detection ----------------------------
TECH_SIGNATURES = {
    'WordPress': [r'wp-content', r'wp-includes', r'/wp-json/'],
    'Joomla': [r'/components/', r'/modules/', r'Joomla'],
    'Drupal': [r'Drupal', r'/sites/default/', r'/misc/drupal.js'],
    'Laravel': [r'laravel_session', r'X-Powered-By.*Laravel'],
    'Django': [r'csrfmiddlewaretoken', r'django'],
    'React': [r'react\.', r'react-dom', r'_reactRoot'],
    'Vue.js': [r'vue\.js', r'vue\.min\.js', r'v-cloak'],
    'Angular': [r'ng-version', r'angular\.js', r'ng-app'],
    'jQuery': [r'jquery', r'jQuery'],
    'Bootstrap': [r'bootstrap\.css', r'bootstrap\.js'],
    'Nginx': [r'nginx', r'Nginx'],
    'Apache': [r'Apache', r'apache'],
    'Cloudflare': [r'cloudflare', r'cf-ray', r'__cfduid'],
    'AWS': [r'amazonaws', r'x-amz-'],
    'Google Analytics': [r'google-analytics', r'gtag', r'ga\.js'],
}

def detect_technologies(url: str, timeout: int = 15) -> Dict[str, object]:
    if not url.startswith("http"):
        url = "https://" + url
    result = {"url": url, "detected": [], "headers": {}}
    try:
        r = requests.get(url, headers=UA, timeout=timeout, verify=False)
        result["status_code"] = r.status_code
        content = r.text
        headers_str = str(r.headers)
        
        for tech, patterns in TECH_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, content, re.I) or re.search(pattern, headers_str, re.I):
                    if tech not in result["detected"]:
                        result["detected"].append(tech)
                    break
        
        result["headers"]["Server"] = r.headers.get("Server", "")
        result["headers"]["X-Powered-By"] = r.headers.get("X-Powered-By", "")
    except Exception as e:
        result["error"] = str(e)
    return result

# ------------------------- CORS Misconfiguration Check ---------------------
def check_cors(url: str, timeout: int = 10) -> Dict[str, object]:
    if not url.startswith("http"):
        url = "https://" + url
    result = {"url": url, "vulnerable": False, "details": []}
    test_origins = ["https://evil.com", "null", urlparse(url).scheme + "://" + urlparse(url).netloc]
    
    try:
        for origin in test_origins:
            headers_with_origin = {**UA, "Origin": origin}
            r = requests.get(url, headers=headers_with_origin, timeout=timeout, verify=False)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            
            if acao == "*":
                result["vulnerable"] = True
                result["details"].append({"origin": origin, "acao": acao, "issue": "Wildcard origin"})
            elif acao == origin and origin == "https://evil.com":
                result["vulnerable"] = True
                result["details"].append({"origin": origin, "acao": acao, "acac": acac, "issue": "Reflects arbitrary origin"})
            elif acao == "null":
                result["vulnerable"] = True
                result["details"].append({"origin": origin, "acao": acao, "issue": "Null origin allowed"})
    except Exception as e:
        result["error"] = str(e)
    return result

# ------------------------- Subdomain Takeover Check ------------------------
TAKEOVER_SIGNATURES = {
    'AWS S3': {'cname': ['s3.amazonaws.com'], 'fingerprint': ['NoSuchBucket']},
    'GitHub Pages': {'cname': ['github.io'], 'fingerprint': ["There isn't a GitHub Pages site here"]},
    'Heroku': {'cname': ['herokuapp.com', 'herokussl.com'], 'fingerprint': ['No such app']},
    'Shopify': {'cname': ['myshopify.com'], 'fingerprint': ['Sorry, this shop is currently unavailable']},
    'Tumblr': {'cname': ['tumblr.com'], 'fingerprint': ["There's nothing here"]},
    'WordPress.com': {'cname': ['wordpress.com'], 'fingerprint': ['Do you want to register']},
    'Zendesk': {'cname': ['zendesk.com'], 'fingerprint': ['Help Center Closed']},
    'Azure': {'cname': ['azurewebsites.net', 'cloudapp.azure.com'], 'fingerprint': ['404 Web Site not found']},
    'Fastly': {'cname': ['fastly.net'], 'fingerprint': ['Fastly error: unknown domain']},
}

def check_subdomain_takeover(subdomain: str) -> Dict[str, object]:
    result = {"subdomain": subdomain, "vulnerable": False, "service": None, "cname": None}
    try:
        import dns.resolver
        try:
            answers = dns.resolver.resolve(subdomain, 'CNAME')
            for rdata in answers:
                cname = str(rdata.target).rstrip('.')
                result["cname"] = cname
                for service, data in TAKEOVER_SIGNATURES.items():
                    for cname_pattern in data['cname']:
                        if cname_pattern in cname:
                            try:
                                r = requests.get(f"http://{subdomain}", headers=UA, timeout=10, verify=False)
                                for fp in data['fingerprint']:
                                    if fp in r.text:
                                        result["vulnerable"] = True
                                        result["service"] = service
                                        result["fingerprint"] = fp
                                        return result
                            except:
                                pass
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            result["info"] = "No CNAME or domain does not exist"
    except ImportError:
        result["error"] = "dnspython not installed"
    except Exception as e:
        result["error"] = str(e)
    return result

# ------------------------- Social Media Discovery --------------------------
SOCIAL_PLATFORMS = {
    'Twitter': 'https://twitter.com/{}',
    'GitHub': 'https://github.com/{}',
    'LinkedIn': 'https://www.linkedin.com/company/{}',
    'Facebook': 'https://www.facebook.com/{}',
    'Instagram': 'https://www.instagram.com/{}',
    'YouTube': 'https://www.youtube.com/@{}',
}

def discover_social_profiles(name: str) -> List[Dict[str, str]]:
    results = []
    name_slug = re.sub(r'[^a-z0-9]+', '', name.lower())
    variations = [name_slug, name.replace(' ', ''), name.replace(' ', '-').lower()]
    
    for platform, url_template in SOCIAL_PLATFORMS.items():
        for variant in variations:
            url = url_template.format(variant)
            try:
                r = requests.head(url, headers=UA, timeout=8, allow_redirects=True)
                if r.status_code == 200:
                    results.append({"platform": platform, "url": url, "status": "Found", "variant": variant})
                    break
            except:
                pass
    return results if results else [{"platform": "INFO", "url": "", "status": "No profiles found"}]

# ------------------------- Additional Secret Patterns ----------------------
EXTRA_SECRET_REGEXES = {
    "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,}",
    "Discord Token": r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}",
    "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Publishable": r"pk_live_[0-9a-zA-Z]{24}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "SendGrid API Key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
    "Firebase URL": r"https://[a-z0-9-]+\.firebaseio\.com",
    "Square OAuth": r"sq0atp-[0-9A-Za-z\-_]{22}",
    "Paypal Braintree": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
}

# Merge with existing patterns
SECRET_REGEXES.update(EXTRA_SECRET_REGEXES)

# --------------------------- Reporting ------------------------------------

HTML_REPORT_TEMPLATE = '''
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <style>
    body {{ font-family: Arial, sans-serif; color: #222; margin: 40px; }}
    header {{ border-bottom: 1px solid #ddd; padding-bottom: 10px; margin-bottom: 20px; }}
    h1 {{ color: #0b3d91; }}
    .muted {{ color: #666; }}
    table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; table-layout: fixed; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 13px; word-wrap: break-word; }}
    th {{ background: #f6f8fb; }}
    footer {{ border-top: 1px solid #eee; padding-top: 10px; margin-top: 30px; color: #666; font-size: 12px; }}
    .cover {{ text-align: center; margin-top: 80px; margin-bottom: 60px; }}
    .cover h1 {{ font-size: 36px; margin: 0; }}
    .cover p {{ font-size: 14px; color: #444; margin-top: 10px; }}
  </style>
</head>
<body>
  <header>
    <div style="display:flex; align-items:center; gap:12px;">
      <div style="font-weight:700; color:#0b3d91;">BUCIN</div>
      <div class="muted">Browse • Uncover • Collect • Intel • Network</div>
    </div>
  </header>
  <section class="cover">
    <h1>{title}</h1>
    <p class="muted">Generated by BUCIN — corporate reconnaissance with tasteful melancholy.</p>
    <p class="muted">Report time: {report_time}</p>
  </section>
  {body}
  <footer>
    <div>Generated by BUCIN • We pursue assets with dedication. Even if the domain never notices us.</div>
  </footer>
</body>
</html>
'''


def render_html_report(title: str, sections: Dict[str, List[Dict[str, object]]]) -> str:
    body_parts = []
    for sec_name, rows in sections.items():
        body_parts.append(f"<h2>{sec_name} ({len(rows)})</h2>")
        if not rows:
            body_parts.append("<p class='muted'>— no results —</p>")
            continue
        keys = sorted({k for r in rows for k in r.keys()})
        tbl = ["<table>", "<tr>" + "".join(f"<th>{k}</th>" for k in keys) + "</tr>"]
        for r in rows:
            tbl.append("<tr>" + "".join(f"<td>{str(r.get(k,''))}</td>" for k in keys) + "</tr>")
        tbl.append("</table>")
        # --- FIX: Use '\n' to join for valid HTML structure ---
        body_parts.append('\n'.join(tbl))
    # --- FIX: Use '\n' to join for valid HTML structure ---
    body = '\n'.join(body_parts)
    return HTML_REPORT_TEMPLATE.format(title=title, body=body, report_time=datetime.utcnow().isoformat() + 'Z')


def try_html_to_pdf(html_path: Path, pdf_path: Path) -> bool:
    try:
        import pdfkit
        pdfkit.from_file(str(html_path), str(pdf_path))
        return True
    except Exception:
        pass
    try:
        from weasyprint import HTML
        HTML(filename=str(html_path)).write_pdf(str(pdf_path))
        return True
    except Exception:
        pass
    return False


def generate_reports(outdir: Path, basename: str, sections: Dict[str, List[Dict[str, object]]], formats: List[str]):
    ensure_outdir(outdir)
    csv_paths = []
    for name, rows in sections.items():
        if not rows:
            continue
        # Sanitize section name for filename
        sane_name = re.sub(r'[^a-z0-9_]+', '', name.lower().replace(' ', '_'))
        csv_file = outdir / f"{basename}_{sane_name}.csv"
        write_csv(csv_file, rows)
        csv_paths.append(csv_file)
    html_file = outdir / f"{basename}.html"
    html = render_html_report(basename, sections)
    html_file.write_text(html, encoding="utf-8")
    pdf_file = outdir / f"{basename}.pdf"
    pdf_ok = False
    if 'pdf' in formats:
        pdf_ok = try_html_to_pdf(html_file, pdf_file)
    return {
        'csv_files': [str(p) for p in csv_paths],
        'html_file': str(html_file),
        'pdf_file': str(pdf_file) if pdf_ok else None
    }

# --------------------------- CLI command handlers -------------------------

def cmd_subdomains(args):
    print(CLI_PROMPT, BUCIN_BANNER)
    print(CLI_PROMPT, LOG_MESSAGES['start'])
    domain = args.domain.lower()
    subs = fetch_crtsh(domain)
    rows = []
    with cf.ThreadPoolExecutor(max_workers=16) as ex:
        futs = {ex.submit(probe_alive, s): s for s in sorted(subs)}
        for fut in cf.as_completed(futs):
            rows.append(fut.result())
    outdir = ensure_outdir(Path(args.output or "out"))
    base = f"{ts()}_subdomains"
    write_json(outdir / f"{base}.json", rows)
    write_csv(outdir / f"{base}.csv", rows)
    if args.report:
        res = generate_reports(outdir, base, {'subdomains': rows}, args.report)
        print(CLI_PROMPT, "Reports:", res)
    print(CLI_PROMPT, f"Found {len(rows)} subdomains. Results saved to {outdir}.")


def cmd_probe(args):
    print(CLI_PROMPT, LOG_MESSAGES['collect'])
    targets = parse_targets(args.target)
    all_rows = []
    for t in targets:
        paths = COMMON_PATHS
        if args.paths != "common":
            try:
                paths = [p.strip() for p in Path(args.paths).read_text().splitlines() if p.strip() and not p.startswith("#")]
            except Exception as e:
                print(f"{CLI_PROMPT} ERROR: Could not read paths file '{args.paths}'. Error: {e}")
                continue
        rows = probe_paths(t, paths)
        all_rows.extend([dict(target=t, **r) for r in rows])
    outdir = ensure_outdir(Path(args.output or "out"))
    base = f"{ts()}_probe"
    write_json(outdir / f"{base}.json", all_rows)
    write_csv(outdir / f"{base}.csv", all_rows)
    if args.report:
        res = generate_reports(outdir, base, {'probe': all_rows}, args.report)
        print(CLI_PROMPT, "Reports:", res)
    print(CLI_PROMPT, f"Probe finished. Results: {len(all_rows)} entries. Saved to {outdir}.")


def cmd_crawl(args):
    print(CLI_PROMPT, LOG_MESSAGES['collect'])
    targets = parse_targets(args.target)
    all_findings = []
    for t in targets:
        findings = crawl(t, max_pages=args.max_pages, same_host_only=not args.cross_domain, scan_secrets=args.secrets)
        all_findings.extend([asdict(f) for f in findings])
    outdir = ensure_outdir(Path(args.output or "out"))
    base = f"{ts()}_crawl"
    write_json(outdir / f"{base}.json", all_findings)
    write_csv(outdir / f"{base}.csv", all_findings)
    if args.report:
        res = generate_reports(outdir, base, {'crawl_findings': all_findings}, args.report)
        print(CLI_PROMPT, "Reports:", res)
    leaks = sum(len(f.get('secrets', [])) for f in all_findings)
    print(CLI_PROMPT, f"Crawl done: {len(all_findings)} pages, secrets found: {leaks}. Results in {outdir}.")


def cmd_tls(args):
    targets = parse_targets(args.host)
    rows = []
    for t in targets:
        rows.append(grab_cert(t, port=args.port))
    outdir = ensure_outdir(Path(args.output or "out"))
    base = f"{ts()}_tls"
    write_json(outdir / f"{base}.json", rows)
    write_csv(outdir / f"{base}.csv", rows)
    if args.report:
        res = generate_reports(outdir, base, {'tls': rows}, args.report)
        print(CLI_PROMPT, "Reports:", res)
    print(CLI_PROMPT, f"TLS information saved to {outdir}.")


def cmd_buckets(args):
    wl = None
    if args.wordlist and Path(args.wordlist).exists():
        wl = Path(args.wordlist).read_text(encoding="utf-8", errors="ignore").splitlines()
    seeds = candidate_buckets(args.name, wl)
    rows: List[Dict[str, str]] = []
    with cf.ThreadPoolExecutor(max_workers=16) as ex:
        futs = {ex.submit(check_bucket_public, s): s for s in sorted(seeds)}
        for fut in cf.as_completed(futs):
            for r in fut.result():
                rows.append(r)
    outdir = ensure_outdir(Path(args.output or "out"))
    base = f"{ts()}_buckets"
    write_json(outdir / f"{base}.json", rows)
    write_csv(outdir / f"{base}.csv", rows)
    if args.report:
        res = generate_reports(outdir, base, {'buckets': rows}, args.report)
        print(CLI_PROMPT, "Reports:", res)
    open_count = sum(1 for r in rows if r.get("status") in ("200", "204") or r.get("leak"))
    print(CLI_PROMPT, f"Bucket candidates checked: {len(seeds)}, possible open: {open_count}. Results in {outdir}.")


def cmd_whois(args):
    print(CLI_PROMPT, LOG_MESSAGES['whois'])
    targets = parse_targets(args.domain)
    rows = [fetch_whois_info(domain_root(t)) for t in targets]
    outdir = ensure_outdir(Path(args.output or "out"))
    base = f"{ts()}_whois"
    write_json(outdir / f"{base}.json", rows)
    write_csv(outdir / f"{base}.csv", rows)
    if args.report:
        res = generate_reports(outdir, base, {'whois': rows}, args.report)
        print(CLI_PROMPT, "Reports:", res)
    print(CLI_PROMPT, f"Whois information saved to {outdir}.")


def cmd_dns(args):
    print(CLI_PROMPT, LOG_MESSAGES['dns'])
    targets = parse_targets(args.domain)
    all_rows = []
    for t in targets:
        all_rows.extend(fetch_dns_records(domain_root(t)))
    outdir = ensure_outdir(Path(args.output or "out"))
    base = f"{ts()}_dns"
    write_json(outdir / f"{base}.json", all_rows)
    write_csv(outdir / f"{base}.csv", all_rows)
    if args.report:
        res = generate_reports(outdir, base, {'dns_records': all_rows}, args.report)
        print(CLI_PROMPT, "Reports:", res)
    print(CLI_PROMPT, f"DNS records saved to {outdir}.")


def cmd_ports(args):
    print(CLI_PROMPT, LOG_MESSAGES['ports'])
    targets = parse_targets(args.host)
    ports_to_scan = COMMON_PORTS
    if args.ports:
        ports_to_scan = [int(p.strip()) for p in args.ports.split(',') if p.strip().isdigit()]
    
    all_rows = []
    with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = []
        for t in targets:
            for p in ports_to_scan:
                futs.append(ex.submit(scan_port, t, p, args.timeout))
        
        for fut in cf.as_completed(futs):
            res = fut.result()
            if not args.show_closed and not res.get('open'):
                continue
            all_rows.append(res)
    
    outdir = ensure_outdir(Path(args.output or "out"))
    base = f"{ts()}_ports"
    # Sort for readability
    all_rows.sort(key=lambda x: (x.get('host', ''), x.get('port', 0)))
    write_json(outdir / f"{base}.json", all_rows)
    write_csv(outdir / f"{base}.csv", all_rows)
    if args.report:
        res = generate_reports(outdir, base, {'port_scan': all_rows}, args.report)
        print(CLI_PROMPT, "Reports:", res)
    open_count = sum(1 for r in all_rows if r.get('open'))
    log_success(f"Port scan complete. Found {open_count} open ports. Results in {outdir}.")


def cmd_headers(args):
    log_section("HTTP Security Headers Analysis")
    log_info(LOG_MESSAGES['headers'])
    targets = parse_targets(args.host)
    all_rows = []
    for t in tqdm(targets, desc="Analyzing headers", disable=not HAS_TQDM):
        result = analyze_security_headers(t)
        all_rows.append(result)
    
    outdir = ensure_outdir(Path(args.output or "out"))
    base = f"{ts()}_headers"
    write_json(outdir / f"{base}.json", all_rows)
    write_csv(outdir / f"{base}.csv", all_rows)
    if args.report:
        res = generate_reports(outdir, base, {'security_headers': all_rows}, args.report)
        log_info(f"Reports: {res}")
    
    avg_score = sum(r.get('score', 0) for r in all_rows) / len(all_rows) if all_rows else 0
    log_success(f"Headers analysis complete. Average security score: {avg_score:.1f}%. Results in {outdir}.")


def cmd_wayback(args):
    log_section("Wayback Machine URL Discovery")
    log_info(LOG_MESSAGES['wayback'])
    targets = parse_targets(args.domain)
    all_rows = []
    for t in targets:
        rows = fetch_wayback_urls(domain_root(t), limit=args.limit)
        all_rows.extend(rows)
    
    outdir = ensure_outdir(Path(args.output or "out"))
    base = f"{ts()}_wayback"
    write_json(outdir / f"{base}.json", all_rows)
    write_csv(outdir / f"{base}.csv", all_rows)
    if args.report:
        res = generate_reports(outdir, base, {'wayback_urls': all_rows}, args.report)
        log_info(f"Reports: {res}")
    log_success(f"Found {len(all_rows)} archived URLs. Results in {outdir}.")


def cmd_tech(args):
    log_section("Technology Detection")
    log_info(LOG_MESSAGES['tech'])
    targets = parse_targets(args.target)
    all_rows = []
    for t in tqdm(targets, desc="Detecting technologies", disable=not HAS_TQDM):
        result = detect_technologies(t)
        all_rows.append(result)
    
    outdir = ensure_outdir(Path(args.output or "out"))
    base = f"{ts()}_tech"
    write_json(outdir / f"{base}.json", all_rows)
    write_csv(outdir / f"{base}.csv", all_rows)
    if args.report:
        res = generate_reports(outdir, base, {'technologies': all_rows}, args.report)
        log_info(f"Reports: {res}")
    
    all_techs = set()
    for r in all_rows:
        all_techs.update(r.get('detected', []))
    log_success(f"Detected {len(all_techs)} unique technologies. Results in {outdir}.")


def cmd_cors(args):
    log_section("CORS Misconfiguration Testing")
    log_info(LOG_MESSAGES['cors'])
    targets = parse_targets(args.target)
    all_rows = []
    for t in tqdm(targets, desc="Testing CORS", disable=not HAS_TQDM):
        result = check_cors(t)
        all_rows.append(result)
    
    outdir = ensure_outdir(Path(args.output or "out"))
    base = f"{ts()}_cors"
    write_json(outdir / f"{base}.json", all_rows)
    write_csv(outdir / f"{base}.csv", all_rows)
    if args.report:
        res = generate_reports(outdir, base, {'cors_results': all_rows}, args.report)
        log_info(f"Reports: {res}")
    
    vuln_count = sum(1 for r in all_rows if r.get('vulnerable'))
    if vuln_count > 0:
        log_warning(f"Found {vuln_count} potential CORS misconfigurations!")
    else:
        log_success("No CORS vulnerabilities detected.")
    log_info(f"Results saved to {outdir}.")


def cmd_takeover(args):
    log_section("Subdomain Takeover Check")
    log_info(LOG_MESSAGES['takeover'])
    domain = domain_root(args.domain)
    
    log_info("Fetching subdomains from crt.sh...")
    subs = fetch_crtsh(domain)
    log_info(f"Found {len(subs)} subdomains to check.")
    
    all_rows = []
    for sub in tqdm(sorted(subs), desc="Checking takeover", disable=not HAS_TQDM):
        result = check_subdomain_takeover(sub)
        all_rows.append(result)
    
    outdir = ensure_outdir(Path(args.output or "out"))
    base = f"{ts()}_takeover"
    write_json(outdir / f"{base}.json", all_rows)
    write_csv(outdir / f"{base}.csv", all_rows)
    if args.report:
        res = generate_reports(outdir, base, {'takeover_check': all_rows}, args.report)
        log_info(f"Reports: {res}")
    
    vuln_count = sum(1 for r in all_rows if r.get('vulnerable'))
    if vuln_count > 0:
        log_warning(f"Found {vuln_count} potentially vulnerable subdomains!")
    else:
        log_success("No subdomain takeover vulnerabilities detected.")
    log_info(f"Results saved to {outdir}.")


def cmd_social(args):
    log_section("Social Media Discovery")
    log_info(f"Searching for social profiles of '{args.name}'...")
    results = discover_social_profiles(args.name)
    
    outdir = ensure_outdir(Path(args.output or "out"))
    base = f"{ts()}_social_{args.name.replace(' ', '_')}"
    write_json(outdir / f"{base}.json", results)
    write_csv(outdir / f"{base}.csv", results)
    if args.report:
        res = generate_reports(outdir, base, {'social_profiles': results}, args.report)
        log_info(f"Reports: {res}")
    
    found = sum(1 for r in results if r.get('status') == 'Found')
    log_success(f"Found {found} social media profiles. Results in {outdir}.")



def cmd_all(args):
    print(BUCIN_BANNER)
    log_info(LOG_MESSAGES['start'])
    domain = domain_root(args.domain)
    base_url = args.target or ("https://" + domain)
    sections = {}

    log_section("Subdomain Enumeration")
    log_info("Fetching subdomains via crt.sh...")
    subs = fetch_crtsh(domain)
    alive = []
    with cf.ThreadPoolExecutor(max_workers=16) as ex:
        futs = {ex.submit(probe_alive, s): s for s in sorted(subs)}
        for fut in tqdm(cf.as_completed(futs), total=len(futs), desc="Checking liveness", disable=not HAS_TQDM):
            alive.append(fut.result())
    sections['subdomains'] = alive
    log_success(f"Found {len(alive)} live subdomains.")

    log_section("Path Probing")
    log_info("Probing common paths...")
    probe = probe_paths(base_url, COMMON_PATHS)
    sections['probe'] = probe
    log_success(f"Found {sum(1 for p in probe if p.get('status') == 200)} interesting paths.")

    log_section("Web Crawling")
    log_info("Lightweight crawl + secret scan...")
    findings = crawl(base_url, max_pages=min(args.max_pages, 200), same_host_only=True, scan_secrets=True)
    sections['crawl'] = [asdict(f) for f in findings]
    leaks = sum(len(f.get('secrets', [])) for f in sections['crawl'])
    log_success(f"Crawled {len(findings)} pages. Secrets found: {leaks}.")
    
    log_section("DNS & WHOIS")
    log_info("Fetching DNS records...")
    dns_records = fetch_dns_records(domain)
    sections['dns_records'] = dns_records

    log_info("Fetching WHOIS record...")
    whois_data = [fetch_whois_info(domain)]
    sections['whois'] = whois_data

    log_section("Security Analysis")
    log_info("Analyzing HTTP security headers...")
    headers_result = analyze_security_headers(base_url)
    sections['security_headers'] = [headers_result]
    log_success(f"Security headers score: {headers_result.get('score', 0)}%")

    log_info("Detecting technologies...")
    tech_result = detect_technologies(base_url)
    sections['technologies'] = [tech_result]
    log_success(f"Detected technologies: {', '.join(tech_result.get('detected', ['None']))}")

    outdir = ensure_outdir(Path(args.output or "out"))
    base = f"{ts()}_all_{domain}"
    
    for name, rows in sections.items():
        if rows:
            write_json(outdir / f"{base}_{name}.json", rows)
            write_csv(outdir / f"{base}_{name}.csv", rows)

    if args.report:
        res = generate_reports(outdir, base, sections, args.report)
        log_info(f"Reports: {res}")
    
    log_section("Summary")
    log_success(f"Full footprint complete! Results saved to {outdir}")


# --------------------------- CLI builder ----------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="BUCIN - External OSINT & Threat Hunting (corporate-absurd edition)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s1 = sub.add_parser("subdomains", help="Passive subdomain enumeration + liveness check")
    s1.add_argument("-d", "--domain", required=True, help="Root domain, e.g. example.com")
    s1.add_argument("-o", "--output", default="out")
    s1.add_argument("--report", help="Comma separated report formats (csv,html,pdf)", default="", type=str)
    s1.set_defaults(func=cmd_subdomains)

    s2 = sub.add_parser("probe", help="Probe common paths on host/URL or targets file")
    s2.add_argument("-t", "--target", required=True, help="Base URL/host or path to a file with targets (one per line)")
    s2.add_argument("-p", "--paths", default="common", help="'common' or path to a file listing paths")
    s2.add_argument("-o", "--output", default="out")
    s2.add_argument("--report", help="Comma separated report formats (csv,html,pdf)", default="", type=str)
    s2.set_defaults(func=cmd_probe)

    s3 = sub.add_parser("crawl", help="Lightweight crawler + secret scanner")
    s3.add_argument("-t", "--target", required=True, help="Start URL or path to file with URLs")
    s3.add_argument("--max-pages", type=int, default=150)
    s3.add_argument("--cross-domain", action="store_true", help="Follow cross-domain links")
    s3.add_argument("--secrets", action="store_true", help="Enable secret scanning")
    s3.add_argument("-o", "--output", default="out")
    s3.add_argument("--report", help="Comma separated report formats (csv,html,pdf)", default="", type=str)
    s3.set_defaults(func=cmd_crawl)

    s4 = sub.add_parser("tls", help="Retrieve TLS certificate details (host or file)")
    s4.add_argument("--host", required=True, help="Host or path to file with hosts")
    s4.add_argument("--port", type=int, default=443)
    s4.add_argument("-o", "--output", default="out")
    s4.add_argument("--report", help="Comma separated report formats (csv,html,pdf)", default="", type=str)
    s4.set_defaults(func=cmd_tls)

    s5 = sub.add_parser("buckets", help="Check public buckets (AWS/GCP/Azure)")
    s5.add_argument("-n", "--name", required=True, help="Company/brand name to generate candidate buckets")
    s5.add_argument("--wordlist", help="Optional wordlist")
    s5.add_argument("-o", "--output", default="out")
    s5.add_argument("--report", help="Comma separated report formats (csv,html,pdf)", default="", type=str)
    s5.set_defaults(func=cmd_buckets)

    # --- [NEW] WHOIS ---
    s_whois = sub.add_parser("whois", help="[NEW] Fetch domain whois registration info")
    s_whois.add_argument("-d", "--domain", required=True, help="Domain or file with domains")
    s_whois.add_argument("-o", "--output", default="out")
    s_whois.add_argument("--report", help="Comma separated report formats (csv,html,pdf)", default="", type=str)
    s_whois.set_defaults(func=cmd_whois)
    
    # --- [NEW] DNS ---
    s_dns = sub.add_parser("dns", help="[NEW] Enumerate common DNS records")
    s_dns.add_argument("-d", "--domain", required=True, help="Domain or file with domains")
    s_dns.add_argument("-o", "--output", default="out")
    s_dns.add_argument("--report", help="Comma separated report formats (csv,html,pdf)", default="", type=str)
    s_dns.set_defaults(func=cmd_dns)

    # --- [NEW] PORTS ---
    s_ports = sub.add_parser("ports", help="Scan common ports")
    s_ports.add_argument("--host", required=True, help="Host or file with hosts")
    s_ports.add_argument("-p", "--ports", help="Comma-separated list of ports (default: common list)")
    s_ports.add_argument("-t", "--threads", type=int, default=16, help="Threads for scanning")
    s_ports.add_argument("--timeout", type=int, default=2, help="Port connection timeout")
    s_ports.add_argument("--show-closed", action="store_true", help="Show closed ports in output (default: open only)")
    s_ports.add_argument("-o", "--output", default="out")
    s_ports.add_argument("--report", help="Comma separated report formats (csv,html,pdf)", default="", type=str)
    s_ports.set_defaults(func=cmd_ports)

    # --- HEADERS (Security Headers Analysis) ---
    s_headers = sub.add_parser("headers", help="Analyze HTTP security headers")
    s_headers.add_argument("--host", required=True, help="Host or file with hosts")
    s_headers.add_argument("-o", "--output", default="out")
    s_headers.add_argument("--report", help="Comma separated report formats (csv,html,pdf)", default="", type=str)
    s_headers.set_defaults(func=cmd_headers)

    # --- WAYBACK (Wayback Machine URL Discovery) ---
    s_wayback = sub.add_parser("wayback", help="Discover historical URLs via Wayback Machine")
    s_wayback.add_argument("-d", "--domain", required=True, help="Domain or file with domains")
    s_wayback.add_argument("--limit", type=int, default=500, help="Maximum URLs to retrieve")
    s_wayback.add_argument("-o", "--output", default="out")
    s_wayback.add_argument("--report", help="Comma separated report formats (csv,html,pdf)", default="", type=str)
    s_wayback.set_defaults(func=cmd_wayback)

    # --- TECH (Technology Detection) ---
    s_tech = sub.add_parser("tech", help="Detect technology stack of a website")
    s_tech.add_argument("-t", "--target", required=True, help="URL or file with URLs")
    s_tech.add_argument("-o", "--output", default="out")
    s_tech.add_argument("--report", help="Comma separated report formats (csv,html,pdf)", default="", type=str)
    s_tech.set_defaults(func=cmd_tech)

    # --- CORS (CORS Misconfiguration Check) ---
    s_cors = sub.add_parser("cors", help="Test for CORS misconfigurations")
    s_cors.add_argument("-t", "--target", required=True, help="URL or file with URLs")
    s_cors.add_argument("-o", "--output", default="out")
    s_cors.add_argument("--report", help="Comma separated report formats (csv,html,pdf)", default="", type=str)
    s_cors.set_defaults(func=cmd_cors)

    # --- TAKEOVER (Subdomain Takeover Check) ---
    s_takeover = sub.add_parser("takeover", help="Check for subdomain takeover vulnerabilities")
    s_takeover.add_argument("-d", "--domain", required=True, help="Domain to check subdomains")
    s_takeover.add_argument("-o", "--output", default="out")
    s_takeover.add_argument("--report", help="Comma separated report formats (csv,html,pdf)", default="", type=str)
    s_takeover.set_defaults(func=cmd_takeover)

    # --- SOCIAL (Social Media Discovery) ---
    s_social = sub.add_parser("social", help="Discover social media profiles")
    s_social.add_argument("-n", "--name", required=True, help="Company/brand name to search")
    s_social.add_argument("-o", "--output", default="out")
    s_social.add_argument("--report", help="Comma separated report formats (csv,html,pdf)", default="", type=str)
    s_social.set_defaults(func=cmd_social)

    # --- ALL (Full Footprint) ---
    s6 = sub.add_parser("all", help="Full footprint: subdomains + probe + crawl + dns + whois + headers + tech")
    s6.add_argument("-d", "--domain", required=True)
    s6.add_argument("-t", "--target", help="Optional base URL (default https://<domain>)")
    s6.add_argument("--max-pages", type=int, default=120)
    s6.add_argument("-o", "--output", default="out")
    s6.add_argument("--report", help="Comma separated report formats (csv,html,pdf)", default="", type=str)
    s6.set_defaults(func=cmd_all)

    return p


def main(argv: Optional[List[str]] = None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if hasattr(args, 'report') and args.report:
        args.report = [x.strip().lower() for x in args.report.split(',') if x.strip()]
    else:
        # Ensure args.report is always a list, even if empty
        if not hasattr(args, 'report'):
            # This is for commands that don't have a --report flag
            # To be safe, let's just add it to all.
            args.report = []
        elif not args.report:
            args.report = []
            
    try:
        args.func(args)
    except KeyboardInterrupt:
        print(CLI_PROMPT, "Operation cancelled by user. We accept it with grace.")
    except Exception as e:
        print(CLI_PROMPT, "Error:", e)
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()


# --------------------------- README (short) -------------------------------
# BUCIN - Corporate Bucin Intelligence Framework

README = r'''
BUCIN (Browse • Uncover • Collect • Intel • Network)
--------------------------------------------------

Corporate-but-absurd external reconnaissance toolkit for OSINT, exposure mapping,
and lightweight external threat hunting.

Key features:
 - Passive subdomain enumeration via crt.sh
 - Liveness checks (HTTP/HTTPS)
 - Common path probing (.env, .git, swagger, etc.)
 - Lightweight crawling with secret detection (regex-based)
 - Public bucket checks (AWS/GCP/Azure)
 - TLS certificate inspection
 - [NEW] DNS record enumeration (MX, TXT, NS, CNAME)
 - [NEW] Whois domain registration lookup
 - [NEW] Common port scanning
 - Reports in CSV, HTML, and optional PDF

Usage examples:
  python bucin.py subdomains -d example.com -o out --report csv,html
  python bucin.py probe -t targets.txt -o reports --report html,pdf
  python bucin.py crawl -t https://example.com --max-pages 200 --secrets --report csv,html
  python bucin.py dns -d example.com --report html
  python bucin.py whois -d example.com
  python bucin.py ports --host example.com -p 80,443,8080
  python bucin.py all -d example.com --report html,pdf

Dependencies:
  pip install requests beautifulsoup4 tldextract python-dotenv
  
Optional (for new features):
  pip install dnspython python-whois

Optional (PDF):
  pip install pdfkit weasyprint
  # pdfkit also needs wkhtmltopdf available in PATH

Branding & Tone:
BUCIN presents results in a formal professional voice with subtle, tasteful
melancholy — corporate copy that is slightly absurd. Messages remain suitable
for enterprise usage while keeping the playful identity.
'''

# --------------------------- Minimal SVG logo -----------------------------
# (No change to SVG)
SVG_LOGO = r'''
<svg xmlns="http://www.w3.org/2000/svg" width="240" height="60" viewBox="0 0 240 60">
  <rect width="240" height="60" rx="8" fill="#0b3d91" />
  <text x="20" y="38" font-family="Arial, Helvetica, sans-serif" font-size="20" fill="#fff">BUCIN</text>
  <text x="110" y="36" font-family="Arial, Helvetica, sans-serif" font-size="10" fill="#cfe0ff">Browse • Uncover • Collect • Intel • Network</text>
</svg>
'''

# End of file