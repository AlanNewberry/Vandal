# Vandal, Web Vulnerability Scanner

A command-line vulnerability scanner that tests URLs for common security issues. Detects reflected XSS, SQL injection, missing security headers, subdomains and historical URLs in one tool.

## Features

- **Reflected XSS detection** . Tests multiple payload variants against URL and POST parameters
- **SQL injection testing** . Error-based and time-based detection with safe payloads (no destructive queries)
- **Security headers audit** . Checks 7 standard headers: X-Frame-Options, CSP, X-XSS-Protection, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **Subdomain enumeration** . Discovers subdomains via certificate transparency logs (crt.sh)
- **Wayback URL collection** . Fetches historical URLs from Wayback Machine
- **Parameter fuzzing** . Tests all parameter combinations up to a configurable depth
- **WAF detection** . Detects 403/429 blocks and backs off automatically
- **Severity levels** . Each finding is tagged LOW, MEDIUM, HIGH, or CRITICAL
- **JSON output** . Export findings to a JSON report with timestamps
- **Two scan modes** . Fast (default) for quick checks, full for exhaustive testing

## Requirements

- Python 3.9 or later
- Internet access

## Install

```bash
git clone https://github.com/AlanNewberry/Vandal.git
cd Vandal
pip install -r requirements.txt
```

## Usage

```
python3 vandal.py URL [URL...] [options]
```

### Examples

Scan a single URL:

```bash
python3 vandal.py https://example.com
```

Multiple targets:

```bash
python3 vandal.py https://example.com https://target.org
```

Full scan mode (slower, more thorough):

```bash
python3 vandal.py https://example.com --full
```

Custom User-Agent and delay:

```bash
python3 vandal.py https://example.com --user-agent "Bot/1.0" --delay 0.5
```

Save results to JSON:

```bash
python3 vandal.py https://example.com -o results.json
```

Quiet mode (no banners or progress bars):

```bash
python3 vandal.py https://example.com -q
```

### All flags

| Flag | Description |
|---|---|
| `--full` | Full scan mode |
| `--user-agent UA` | Custom User-Agent header |
| `--delay SECS` | Delay between requests (default 0.01) |
| `-o FILE` / `--output FILE` | Write findings to JSON file |
| `-q` / `--quiet` | Suppress banners and progress |
| `-V` / `--version` | Show version |

## Running tests

```bash
pip install pytest
python3 -m pytest test_vandal.py -v
```

## Limitations

- Signature and heuristic based detection. False positives and false negatives are possible.
- Not a replacement for manual penetration testing or tools like Burp Suite.
- Single-threaded. Large target lists will take time.
- Subdomain enumeration depends on crt.sh availability.

## Legal

This tool is for authorized security testing only. Do not scan targets without explicit written permission from the owner. Unauthorized scanning may violate local, state, or federal law. The author assumes no responsibility for misuse.

## License

All rights reserved unless otherwise stated.

## Author

Originally developed by Alan Newberry under the alias `44ghost44`.
