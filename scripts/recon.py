#!/usr/bin/env python3
"""
recon.py - Interactive Reconnaissance Script

Parses a Burp Suite scope JSON and runs reconnaissance phases:
1. Load scope and display hosts
2. Proxy load targets through Burp Suite
3. Fingerprint web technologies (whatweb, wafw00f, nmap)
4. Subdomain enumeration (subfinder)
5. Directory scanning (ffuf)
6. File scanning (ffuf)
7. Live host probing (httpx)
8. Screenshots (gowitness)
9. JavaScript crawling (katana)
10. Parameter discovery (paramspider)
11. Nuclei vulnerability scanning

Runs on Windows 10. Kali tools executed via WSL.
Results output to terminal and markdown report.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

import requests
from requests.exceptions import ConnectionError, Timeout, RequestException

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
WSL_DISTRO = "kali"
DEFAULT_PROXY = "127.0.0.1:8080"
DEFAULT_TIMEOUT = 10
DEFAULT_DELAY = 1.0
DIR_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
FILE_EXTENSIONS = "php,txt,bak,conf,log,xml,json,env,old,zip,asp,aspx,ashx,asmx,svc,config,cs,csproj,sln"

# Speed profiles: (label, nmap_timing, ffuf_rate, ffuf_threads, subfinder_rate_limit)
SPEED_PROFILES = {
    "1": ("Stealth   (~10 req/s)",   "-T2", 10,  5,  5),
    "2": ("Moderate  (~50 req/s)",   "-T3", 50,  20, 20),
    "3": ("Aggressive (~150 req/s)", "-T4", 150, 50, 50),
    "4": ("Insane    (no limit)",    "-T5", 0,   50, 0),
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def banner():
    print("\n" + "=" * 60)
    print("  RECON-KIT  |  Interactive Reconnaissance")
    print("=" * 60 + "\n")


def section(title, number=None):
    prefix = f"[{number}] " if number else ""
    print(f"\n{'─' * 60}")
    print(f"  {prefix}{title}")
    print(f"{'─' * 60}\n")


def prompt_yn(question):
    while True:
        ans = input(f"  {question} (y/n): ").strip().lower()
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False


def prompt_speed():
    """Prompt user to select a scan speed profile. Returns profile tuple."""
    print("  Select scan speed:\n")
    for key, (label, *_) in SPEED_PROFILES.items():
        print(f"    [{key}] {label}")
    print()
    while True:
        choice = input("  Speed [1-4]: ").strip()
        if choice in SPEED_PROFILES:
            label = SPEED_PROFILES[choice][0]
            print(f"  Selected: {label}\n")
            return SPEED_PROFILES[choice]
        print("  Invalid choice. Enter 1-4.")


def wsl_run(cmd, timeout=120):
    """Run a command in Kali WSL and return stdout."""
    full_cmd = ["wsl", "-d", WSL_DISTRO, "--", "bash", "-c", cmd]
    try:
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", "Timeout", -1
    except FileNotFoundError:
        return "", "WSL not found. Is Kali WSL installed?", -1


# ---------------------------------------------------------------------------
# Phase 0: Scope Parsing
# ---------------------------------------------------------------------------

def parse_burp_scope(path):
    """Parse Burp scope JSON and return a dict of host info.

    Returns:
        dict: {hostname: {"allow_dir_scan": bool, "allow_subdomain_scan": bool, "results": {}}}
    """
    with open(path, "r") as f:
        data = json.load(f)

    entries = data.get("target", {}).get("scope", {}).get("include", [])
    hosts = {}

    for entry in entries:
        if not entry.get("enabled", False):
            continue

        host_pattern = entry.get("host", "")
        file_pattern = entry.get("file", "")

        # Extract hostname from regex
        hostname = host_pattern.strip("^$").replace("\\.", ".")

        if not hostname:
            continue

        # Determine if this is a wildcard/subdomain pattern
        # e.g., "^\.com$" → ".com" (wildcard), "^target\.com$" → exact match
        is_wildcard = hostname.startswith(".")

        if hostname not in hosts:
            hosts[hostname] = {
                "hostname": hostname,
                "allow_dir_scan": False,
                "allow_subdomain_scan": is_wildcard,
                "results": {},
            }

        # If any entry for this host allows full path scanning
        if file_pattern == "^/.*$":
            hosts[hostname]["allow_dir_scan"] = True

        # If wildcard, mark subdomain scanning
        if is_wildcard:
            hosts[hostname]["allow_subdomain_scan"] = True

    return hosts


def display_hosts(hosts):
    """Display parsed hosts with their permissions."""
    # Filter out wildcard-only entries for display
    display = {h: v for h, v in hosts.items() if not h.startswith(".")}
    max_len = max((len(h) for h in display), default=20)

    for hostname, info in sorted(display.items()):
        dirs = "\033[92m✓\033[0m" if info["allow_dir_scan"] else "\033[91m✗\033[0m"
        subs = "\033[92m✓\033[0m" if info["allow_subdomain_scan"] else "\033[91m✗\033[0m"
        print(f"    {hostname:<{max_len + 2}} [dirs: {dirs}] [subs: {subs}]")

    dir_count = sum(1 for v in display.values() if v["allow_dir_scan"])
    sub_count = sum(1 for v in display.values() if v["allow_subdomain_scan"])
    print(f"\n  {len(display)} unique hosts. "
          f"{sub_count} allow subdomain scanning, "
          f"{dir_count} allow directory scanning.")


# ---------------------------------------------------------------------------
# Phase 1: Burp Proxy Loading
# ---------------------------------------------------------------------------

def hit_target(host, proxy, timeout):
    """Send HTTP and HTTPS requests through the Burp proxy."""
    proxies = {
        "http": f"http://{proxy}",
        "https": f"http://{proxy}",
    }

    results = {}
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            resp = requests.get(
                url,
                proxies=proxies,
                verify=False,
                timeout=timeout,
                allow_redirects=True,
            )
            results[scheme] = {
                "status": resp.status_code,
                "final_url": resp.url if resp.url != url else None,
                "error": None,
            }
        except Timeout:
            results[scheme] = {"status": None, "final_url": None, "error": "Timeout"}
        except ConnectionError:
            results[scheme] = {"status": None, "final_url": None, "error": "Connection failed"}
        except RequestException as e:
            results[scheme] = {"status": None, "final_url": None, "error": str(e)}

    return results


def format_status(result):
    """Format a single protocol result for terminal display."""
    if result["error"]:
        return f"\033[91m{result['error']}\033[0m"
    code = result["status"]
    if 200 <= code < 300:
        s = f"\033[92m{code}\033[0m"
    elif 300 <= code < 400:
        s = f"\033[93m{code}\033[0m"
    else:
        s = f"\033[91m{code}\033[0m"
    if result.get("final_url"):
        s += f" → {result['final_url']}"
    return s


def proxy_load(hosts, proxy, timeout, delay):
    """Load all hosts through the Burp proxy."""
    section("Burp Proxy Loader", 2)

    if not prompt_yn("Is Burp Suite running and proxy active on " + proxy + "?"):
        print("  Skipping proxy loading.")
        return
    if not prompt_yn("Are you connected to the target VPN?"):
        print("  Skipping proxy loading.")
        return

    print()
    scannable = {h: v for h, v in hosts.items() if not h.startswith(".")}
    total = len(scannable)

    for i, (hostname, info) in enumerate(sorted(scannable.items())):
        result = hit_target(hostname, proxy, timeout)
        info["results"]["proxy"] = result

        https_str = format_status(result["https"])
        http_str = format_status(result["http"])
        print(f"  [{i + 1}/{total}] {hostname:<40s} HTTPS [{https_str}]  HTTP [{http_str}]")

        if i < total - 1:
            time.sleep(delay)

    # Disable dir/subdomain scanning for hosts that returned 403
    blocked = []
    for hostname, info in scannable.items():
        proxy_result = info["results"].get("proxy", {})
        https_status = proxy_result.get("https", {}).get("status")
        http_status = proxy_result.get("http", {}).get("status")
        if https_status == 403 or (https_status is None and http_status == 403):
            info["allow_dir_scan"] = False
            info["allow_subdomain_scan"] = False
            blocked.append(hostname)

    if blocked:
        print(f"\n  \033[93m{len(blocked)} host(s) returned 403 — excluded from dir/subdomain scanning:\033[0m")
        for h in sorted(blocked):
            print(f"    - {h}")

    print(f"\n  Done. {total} hosts loaded into Burp.")


# ---------------------------------------------------------------------------
# Phase 2: Fingerprinting
# ---------------------------------------------------------------------------

def run_whatweb(host, timeout):
    url = f"https://{host}"
    stdout, stderr, rc = wsl_run(f"whatweb -a 3 --color=never {url} 2>/dev/null", timeout)
    return stdout if rc == 0 else stderr


def run_wafw00f(host, timeout):
    url = f"https://{host}"
    stdout, stderr, rc = wsl_run(f"wafw00f {url} 2>/dev/null", timeout)
    return stdout if rc == 0 else stderr


def run_nmap(host, timeout, nmap_timing="-T3"):
    stdout, stderr, rc = wsl_run(f"nmap -sV -p 80,443 --open {nmap_timing} {host} 2>/dev/null", timeout)
    return stdout if rc == 0 else stderr


def fingerprint(hosts, timeout, speed):
    """Run fingerprinting tools on all hosts."""
    section("Fingerprinting", 3)

    if not prompt_yn("Run fingerprinting on all hosts?"):
        print("  Skipping fingerprinting.")
        return

    _, nmap_timing, *_ = speed
    scannable = {h: v for h, v in hosts.items() if not h.startswith(".")}
    total = len(scannable)

    for i, (hostname, info) in enumerate(sorted(scannable.items())):
        print(f"\n  [{i + 1}/{total}] {hostname}")

        print(f"    Running whatweb...")
        whatweb_out = run_whatweb(hostname, timeout)
        print(f"    {whatweb_out[:200]}" if whatweb_out else "    No output")

        print(f"    Running wafw00f...")
        wafw00f_out = run_wafw00f(hostname, timeout)
        # Extract WAF line
        for line in wafw00f_out.splitlines():
            if "is behind" in line.lower() or "no waf" in line.lower():
                print(f"    {line.strip()}")
                break
        else:
            print(f"    {wafw00f_out[:200]}" if wafw00f_out else "    No output")

        print(f"    Running nmap...")
        nmap_out = run_nmap(hostname, timeout, nmap_timing)
        # Show port lines
        for line in nmap_out.splitlines():
            if re.match(r"\d+/tcp", line.strip()):
                print(f"    {line.strip()}")

        info["results"]["fingerprint"] = {
            "whatweb": whatweb_out,
            "wafw00f": wafw00f_out,
            "nmap": nmap_out,
        }

    print(f"\n  Fingerprinting complete.")


# ---------------------------------------------------------------------------
# Phase 3: Subdomain Enumeration
# ---------------------------------------------------------------------------

def run_subfinder(domain, timeout, rate_limit=0):
    rate_flag = f"-rate-limit {rate_limit}" if rate_limit > 0 else ""
    stdout, stderr, rc = wsl_run(f"subfinder -d {domain} -silent {rate_flag} 2>/dev/null", timeout)
    if rc == 0 and stdout:
        return [s.strip() for s in stdout.splitlines() if s.strip()]
    return []


def enum_subdomains(hosts, timeout, speed):
    """Run subdomain enumeration on eligible hosts."""
    section("Subdomain Enumeration", 4)

    # Find hosts that allow subdomain scanning
    eligible = {h: v for h, v in hosts.items() if v["allow_subdomain_scan"] and not h.startswith(".")}

    # Also check wildcard entries for base domains
    wildcards = {h.lstrip("."): v for h, v in hosts.items() if h.startswith(".")}

    # Combine: eligible explicit hosts + wildcard base domains
    targets = {}
    targets.update(eligible)
    for domain, info in wildcards.items():
        if domain not in targets:
            targets[domain] = info

    if not targets:
        print("  No hosts allow subdomain scanning. Skipping.")
        return

    print(f"  {len(targets)} domain(s) allow subdomain scanning:")
    for domain in sorted(targets):
        print(f"    - {domain}")

    if not prompt_yn("Proceed with subdomain enumeration?"):
        print("  Skipping subdomain enumeration.")
        return

    _, _, _, _, subfinder_rate = speed

    for domain in sorted(targets):
        print(f"\n  Running subfinder on {domain}...")
        subdomains = run_subfinder(domain, timeout, subfinder_rate)

        if subdomains:
            print(f"    Found {len(subdomains)} subdomains:")
            for sub in sorted(subdomains):
                print(f"      {sub}")
        else:
            print(f"    No subdomains found.")

        # Store results on the base domain entry or the wildcard entry
        if domain in hosts:
            hosts[domain]["results"]["subdomains"] = subdomains
        else:
            # Store on the wildcard entry
            wildcard_key = f".{domain}"
            if wildcard_key in hosts:
                hosts[wildcard_key]["results"]["subdomains"] = subdomains

    print(f"\n  Subdomain enumeration complete.")


# ---------------------------------------------------------------------------
# Phase 4: Directory Scanning
# ---------------------------------------------------------------------------

def parse_ffuf_output(stdout):
    """Parse ffuf output lines into list of (path, status_code) tuples."""
    results = []
    for line in stdout.splitlines():
        if "[Status:" not in line:
            continue
        # Format: path  [Status: 200, Size: 1234, Words: 56, Lines: 12, Duration: 123ms]
        # Root path has no prefix, just whitespace before [Status:
        match = re.match(r"^(\S*)\s*\[Status:\s*(\d+)", line.strip())
        if match:
            path = match.group(1) if match.group(1) else "/"
            results.append((path, int(match.group(2))))
    return results


def run_ffuf_dir(host, wordlist, timeout, ffuf_rate=0, ffuf_threads=20, status_codes="200,204,301,302,307,401,403"):
    url = f"https://{host}/FUZZ"
    rate_flag = f"-rate {ffuf_rate}" if ffuf_rate > 0 else ""
    cmd = f"ffuf -u {url} -w {wordlist} -mc {status_codes} -t {ffuf_threads} {rate_flag} 2>/dev/null"
    stdout, stderr, rc = wsl_run(cmd, timeout)
    return parse_ffuf_output(stdout)


def prompt_status_codes(default="200,204,301,302,307,401,403"):
    """Prompt user to select which HTTP status codes to match."""
    print(f"  Which HTTP status codes should be included in results?\n")
    print(f"    [1] 200 only              (just successful responses)")
    print(f"    [2] 200,204,301,302,307   (success + redirects)")
    print(f"    [3] 200,204,301,302,307,401,403  (default - includes auth/forbidden)")
    print(f"    [4] Custom")
    print()
    while True:
        choice = input("  Status codes [1-4]: ").strip()
        if choice == "1":
            codes = "200"
        elif choice == "2":
            codes = "200,204,301,302,307"
        elif choice == "3":
            codes = default
        elif choice == "4":
            codes = input("  Enter comma-separated status codes: ").strip()
        else:
            print("  Invalid choice. Enter 1-4.")
            continue
        print(f"  Matching: {codes}\n")
        return codes


def scan_directories(hosts, timeout, speed):
    """Run directory scanning on eligible hosts."""
    section("Directory Scanning", 5)

    eligible = {h: v for h, v in hosts.items() if v["allow_dir_scan"] and not h.startswith(".")}

    if not eligible:
        print("  No hosts allow directory scanning. Skipping.")
        return

    print(f"  {len(eligible)} host(s) allow directory scanning.")
    if not prompt_yn("Proceed with directory scanning?"):
        print("  Skipping directory scanning.")
        return

    status_codes = prompt_status_codes()
    _, _, ffuf_rate, ffuf_threads, _ = speed

    for hostname in sorted(eligible):
        print(f"\n  Scanning {hostname}...")
        results = run_ffuf_dir(hostname, DIR_WORDLIST, timeout, ffuf_rate, ffuf_threads, status_codes)

        if results:
            print(f"    Found {len(results)} entries:")
            for path, code in results[:50]:  # Limit terminal output
                print(f"      {path} ({code})")
            if len(results) > 50:
                print(f"      ... and {len(results) - 50} more (see report)")
        else:
            print(f"    No directories found.")

        eligible[hostname]["results"]["directories"] = results

    print(f"\n  Directory scanning complete.")


# ---------------------------------------------------------------------------
# Phase 5: File Scanning
# ---------------------------------------------------------------------------

def run_ffuf_files(host, wordlist, extensions, timeout, ffuf_rate=0, ffuf_threads=20, status_codes="200,204,301,302,307,401,403"):
    url = f"https://{host}/FUZZ"
    ext_list = ",".join(f".{e}" for e in extensions.split(","))
    rate_flag = f"-rate {ffuf_rate}" if ffuf_rate > 0 else ""
    cmd = f"ffuf -u {url} -w {wordlist} -e {ext_list} -mc {status_codes} -t {ffuf_threads} {rate_flag} 2>/dev/null"
    stdout, stderr, rc = wsl_run(cmd, timeout)
    return parse_ffuf_output(stdout)


def scan_files(hosts, timeout, speed):
    """Run file scanning on eligible hosts."""
    section("File Scanning", 6)

    eligible = {h: v for h, v in hosts.items() if v["allow_dir_scan"] and not h.startswith(".")}

    if not eligible:
        print("  No hosts allow file scanning. Skipping.")
        return

    print(f"  {len(eligible)} host(s) eligible for file scanning.")
    if not prompt_yn("Run file scanning?"):
        print("  Skipping file scanning.")
        return

    status_codes = prompt_status_codes()
    _, _, ffuf_rate, ffuf_threads, _ = speed

    for hostname in sorted(eligible):
        print(f"\n  Scanning {hostname} for files ({FILE_EXTENSIONS})...")
        results = run_ffuf_files(hostname, DIR_WORDLIST, FILE_EXTENSIONS, timeout, ffuf_rate, ffuf_threads, status_codes)

        if results:
            print(f"    Found {len(results)} files:")
            for path, code in results[:50]:
                print(f"      {path} ({code})")
            if len(results) > 50:
                print(f"      ... and {len(results) - 50} more (see report)")
        else:
            print(f"    No files found.")

        eligible[hostname]["results"]["files"] = results

    print(f"\n  File scanning complete.")


# ---------------------------------------------------------------------------
# Phase 6: Live Host Probing (httpx)
# ---------------------------------------------------------------------------

def run_httpx(hosts_list, timeout):
    """Run httpx on a list of hosts and return parsed results."""
    # Write hosts to a temp file for httpx input
    hosts_str = "\\n".join(hosts_list)
    cmd = f"echo -e '{hosts_str}' | httpx -silent -status-code -title -tech-detect -follow-redirects 2>/dev/null"
    stdout, stderr, rc = wsl_run(cmd, timeout)
    if stdout:
        return [line.strip() for line in stdout.splitlines() if line.strip()]
    return []


def probe_live_hosts(hosts, timeout):
    """Probe hosts and discovered subdomains with httpx."""
    section("Live Host Probing (httpx)", 7)

    if not prompt_yn("Run live host probing with httpx?"):
        print("  Skipping live host probing.")
        return

    # Collect all hosts + discovered subdomains
    all_targets = []
    scannable = {h: v for h, v in hosts.items() if not h.startswith(".")}
    for hostname in sorted(scannable):
        all_targets.append(hostname)

    # Add discovered subdomains
    for info in hosts.values():
        subs = info["results"].get("subdomains", [])
        for sub in subs:
            if sub not in all_targets:
                all_targets.append(sub)

    print(f"  Probing {len(all_targets)} targets...")
    results = run_httpx(all_targets, timeout)

    if results:
        print(f"    {len(results)} live hosts found:\n")
        for line in results:
            print(f"      {line}")
    else:
        print(f"    No live hosts detected.")

    # Store results globally
    hosts["__httpx_results"] = {"results": {"httpx": results}, "hostname": "__httpx", "allow_dir_scan": False, "allow_subdomain_scan": False}

    print(f"\n  Live host probing complete.")


# ---------------------------------------------------------------------------
# Phase 7: Screenshots (gowitness)
# ---------------------------------------------------------------------------

def screenshot_hosts(hosts, timeout):
    """Capture screenshots of live hosts with gowitness."""
    section("Screenshots (gowitness)", 8)

    print("  \033[93mNote: Screenshots will be saved in the Kali filesystem.\033[0m")
    if not prompt_yn("Capture screenshots with gowitness?"):
        print("  Skipping screenshots.")
        return

    output_dir = input("  Screenshot output directory (default: /tmp/gowitness): ").strip()
    if not output_dir:
        output_dir = "/tmp/gowitness"

    # Collect all targets
    all_targets = []
    scannable = {h: v for h, v in hosts.items() if not h.startswith(".") and h != "__httpx_results"}
    for hostname in sorted(scannable):
        all_targets.append(f"https://{hostname}")

    for info in hosts.values():
        subs = info["results"].get("subdomains", [])
        for sub in subs:
            all_targets.append(f"https://{sub}")

    targets_str = "\\n".join(all_targets)
    print(f"\n  Screenshotting {len(all_targets)} targets...")

    cmd = f"mkdir -p {output_dir} && echo -e '{targets_str}' | gowitness scan file -f - --screenshot-path {output_dir} 2>/dev/null"
    stdout, stderr, rc = wsl_run(cmd, timeout)

    if rc == 0:
        # Count screenshots
        count_stdout, _, _ = wsl_run(f"ls {output_dir}/*.png 2>/dev/null | wc -l", 10)
        count = count_stdout.strip() if count_stdout else "0"
        print(f"    {count} screenshots saved to {output_dir}")
    else:
        print(f"    \033[91mgowitness error: {stderr[:200]}\033[0m")

    hosts["__screenshot_results"] = {"results": {"screenshots": {"output_dir": output_dir, "count": all_targets}}, "hostname": "__screenshots", "allow_dir_scan": False, "allow_subdomain_scan": False}

    print(f"\n  Screenshots complete.")


# ---------------------------------------------------------------------------
# Phase 8: JavaScript Crawling (katana)
# ---------------------------------------------------------------------------

def run_katana(host, timeout):
    url = f"https://{host}"
    cmd = f"katana -u {url} -jc -silent -d 2 -ef css,png,jpg,jpeg,gif,svg,woff,woff2,ttf,ico 2>/dev/null"
    stdout, stderr, rc = wsl_run(cmd, timeout)
    if stdout:
        return [line.strip() for line in stdout.splitlines() if line.strip()]
    return []


def crawl_js(hosts, timeout):
    """Crawl targets for JavaScript files and endpoints with katana."""
    section("JavaScript Crawling (katana)", 9)

    if not prompt_yn("Crawl targets for JS files and endpoints with katana?"):
        print("  Skipping JS crawling.")
        return

    scannable = {h: v for h, v in hosts.items() if v.get("allow_dir_scan") and not h.startswith(".")}

    if not scannable:
        print("  No hosts eligible for crawling.")
        return

    print(f"  Crawling {len(scannable)} host(s)...\n")

    for hostname in sorted(scannable):
        print(f"  [{hostname}]")
        results = run_katana(hostname, timeout)

        # Filter for interesting findings
        js_files = [r for r in results if r.endswith(".js")]
        api_endpoints = [r for r in results if "/api/" in r or "/v1/" in r or "/v2/" in r or "/graphql" in r]
        other = [r for r in results if r not in js_files and r not in api_endpoints]

        if js_files:
            print(f"    JS files ({len(js_files)}):")
            for f in js_files[:20]:
                print(f"      {f}")
            if len(js_files) > 20:
                print(f"      ... and {len(js_files) - 20} more (see report)")

        if api_endpoints:
            print(f"    API endpoints ({len(api_endpoints)}):")
            for ep in api_endpoints[:20]:
                print(f"      {ep}")

        if not js_files and not api_endpoints:
            print(f"    No JS files or API endpoints found. ({len(other)} other URLs crawled)")

        scannable[hostname]["results"]["katana"] = {
            "js_files": js_files,
            "api_endpoints": api_endpoints,
            "all_urls": results,
        }

    print(f"\n  JS crawling complete.")


# ---------------------------------------------------------------------------
# Phase 9: Parameter Discovery (paramspider)
# ---------------------------------------------------------------------------

def run_paramspider(host, timeout):
    cmd = f"paramspider -d {host} --quiet 2>/dev/null"
    stdout, stderr, rc = wsl_run(cmd, timeout)
    if stdout:
        return [line.strip() for line in stdout.splitlines() if line.strip() and line.startswith("http")]
    return []


def discover_params(hosts, timeout):
    """Discover URL parameters with paramspider."""
    section("Parameter Discovery (paramspider)", 10)

    if not prompt_yn("Run parameter discovery with paramspider?"):
        print("  Skipping parameter discovery.")
        return

    scannable = {h: v for h, v in hosts.items() if v.get("allow_dir_scan") and not h.startswith(".")}

    if not scannable:
        print("  No hosts eligible for parameter discovery.")
        return

    print(f"  Scanning {len(scannable)} host(s)...\n")

    for hostname in sorted(scannable):
        print(f"  [{hostname}]")
        results = run_paramspider(hostname, timeout)

        if results:
            print(f"    Found {len(results)} parameterized URLs:")
            for url in results[:30]:
                print(f"      {url}")
            if len(results) > 30:
                print(f"      ... and {len(results) - 30} more (see report)")
        else:
            print(f"    No parameterized URLs found.")

        scannable[hostname]["results"]["params"] = results

    print(f"\n  Parameter discovery complete.")


# ---------------------------------------------------------------------------
# Phase 10: Nuclei Vulnerability Scanning
# ---------------------------------------------------------------------------

def run_nuclei(host, timeout, templates):
    url = f"https://{host}"
    template_flag = f"-t {templates}" if templates else ""
    cmd = f"nuclei -u {url} -silent {template_flag} 2>/dev/null"
    stdout, stderr, rc = wsl_run(cmd, timeout)
    if stdout:
        return [line.strip() for line in stdout.splitlines() if line.strip()]
    return []


def nuclei_scan(hosts, timeout):
    """Run nuclei vulnerability scanning."""
    section("Nuclei Vulnerability Scanning", 11)

    print("  \033[93mNote: Nuclei sends active probes. Ensure this is in scope.\033[0m\n")
    if not prompt_yn("Run nuclei vulnerability scanning?"):
        print("  Skipping nuclei scanning.")
        return

    print("\n  Select template categories:\n")
    print("    [1] Safe only          (misconfigs, exposures, info)")
    print("    [2] Medium risk        (safe + CVEs, default-logins)")
    print("    [3] All templates      (includes fuzzing - noisy)")
    print("    [4] Custom path")
    print()

    while True:
        choice = input("  Templates [1-4]: ").strip()
        if choice == "1":
            templates = "misconfiguration,exposure,miscellaneous"
            break
        elif choice == "2":
            templates = "misconfiguration,exposure,cves,default-logins,miscellaneous"
            break
        elif choice == "3":
            templates = ""
            break
        elif choice == "4":
            templates = input("  Enter template path or tags: ").strip()
            break
        else:
            print("  Invalid choice. Enter 1-4.")

    template_flag = f"-tags {templates}" if templates else ""

    scannable = {h: v for h, v in hosts.items() if not h.startswith(".") and h != "__httpx_results" and h != "__screenshot_results"}

    print(f"\n  Scanning {len(scannable)} host(s)...\n")

    for hostname in sorted(scannable):
        print(f"  [{hostname}]")
        url = f"https://{hostname}"
        cmd = f"nuclei -u {url} -silent {template_flag} 2>/dev/null"
        stdout, stderr, rc = wsl_run(cmd, timeout)

        results = [line.strip() for line in stdout.splitlines() if line.strip()] if stdout else []

        if results:
            print(f"    \033[91mFound {len(results)} issue(s):\033[0m")
            for finding in results:
                print(f"      {finding}")
        else:
            print(f"    No issues found.")

        scannable[hostname]["results"]["nuclei"] = results

    print(f"\n  Nuclei scanning complete.")

def write_report(hosts, scope_file, output_path):
    """Write a markdown report with all results."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    scannable = {h: v for h, v in hosts.items() if not h.startswith(".")}

    lines = [
        "# Recon Report",
        "",
        f"**Date:** {timestamp}",
        f"**Scope file:** {scope_file}",
        f"**Hosts scanned:** {len(scannable)}",
        "",
    ]

    # Proxy results
    proxy_hosts = {h: v for h, v in scannable.items() if "proxy" in v["results"]}
    if proxy_hosts:
        lines.extend([
            "## Proxy Loading Results",
            "",
            "| Host | HTTPS | HTTP | Redirect |",
            "|------|-------|------|----------|",
        ])
        for hostname in sorted(proxy_hosts):
            proxy = proxy_hosts[hostname]["results"]["proxy"]
            https_r = proxy.get("https", {})
            http_r = proxy.get("http", {})
            https_s = str(https_r.get("status", "")) if not https_r.get("error") else https_r["error"]
            http_s = str(http_r.get("status", "")) if not http_r.get("error") else http_r["error"]
            redirect = ""
            for scheme in ("https", "http"):
                r = proxy.get(scheme, {})
                if r.get("final_url"):
                    redirect = r["final_url"]
                    break
            lines.append(f"| {hostname} | {https_s} | {http_s} | {redirect} |")
        lines.append("")

    # Fingerprinting results
    fp_hosts = {h: v for h, v in scannable.items() if "fingerprint" in v["results"]}
    if fp_hosts:
        lines.extend(["## Fingerprinting", ""])
        for hostname in sorted(fp_hosts):
            fp = fp_hosts[hostname]["results"]["fingerprint"]
            lines.append(f"### {hostname}")
            lines.append("")
            if fp.get("whatweb"):
                lines.append("**WhatWeb:**")
                lines.append("```")
                lines.append(fp["whatweb"])
                lines.append("```")
                lines.append("")
            if fp.get("wafw00f"):
                lines.append("**WAF Detection:**")
                lines.append("```")
                lines.append(fp["wafw00f"])
                lines.append("```")
                lines.append("")
            if fp.get("nmap"):
                lines.append("**Nmap Service Scan:**")
                lines.append("```")
                lines.append(fp["nmap"])
                lines.append("```")
                lines.append("")

    # Subdomain results
    sub_hosts = {h: v for h, v in hosts.items() if "subdomains" in v["results"]}
    if sub_hosts:
        lines.extend(["## Subdomain Enumeration", ""])
        for hostname in sorted(sub_hosts):
            subs = sub_hosts[hostname]["results"]["subdomains"]
            display_name = hostname.lstrip(".")
            lines.append(f"### {display_name}")
            lines.append("")
            if subs:
                for sub in sorted(subs):
                    lines.append(f"- {sub}")
            else:
                lines.append("No subdomains found.")
            lines.append("")

    # Directory results
    dir_hosts = {h: v for h, v in scannable.items() if "directories" in v["results"]}
    if dir_hosts:
        lines.extend(["## Directory Scanning", ""])
        for hostname in sorted(dir_hosts):
            dirs = dir_hosts[hostname]["results"]["directories"]
            lines.append(f"### {hostname}")
            lines.append("")
            if dirs:
                for path, code in dirs:
                    lines.append(f"- `{path}` ({code})")
            else:
                lines.append("No directories found.")
            lines.append("")

    # File results
    file_hosts = {h: v for h, v in scannable.items() if "files" in v["results"]}
    if file_hosts:
        lines.extend(["## File Scanning", ""])
        for hostname in sorted(file_hosts):
            files = file_hosts[hostname]["results"]["files"]
            lines.append(f"### {hostname}")
            lines.append("")
            if files:
                for path, code in files:
                    lines.append(f"- `{path}` ({code})")
            else:
                lines.append("No files found.")
            lines.append("")

    # httpx results
    httpx_data = hosts.get("__httpx_results", {}).get("results", {}).get("httpx", [])
    if httpx_data:
        lines.extend(["## Live Host Probing (httpx)", ""])
        for line in httpx_data:
            lines.append(f"- `{line}`")
        lines.append("")

    # Screenshot results
    ss_data = hosts.get("__screenshot_results", {}).get("results", {}).get("screenshots", {})
    if ss_data:
        lines.extend([
            "## Screenshots (gowitness)",
            "",
            f"Screenshots saved to: `{ss_data.get('output_dir', 'N/A')}`",
            f"Targets screenshotted: {len(ss_data.get('count', []))}",
            "",
        ])

    # Katana JS crawl results
    katana_hosts = {h: v for h, v in scannable.items() if "katana" in v.get("results", {})}
    if katana_hosts:
        lines.extend(["## JavaScript Crawling (katana)", ""])
        for hostname in sorted(katana_hosts):
            katana = katana_hosts[hostname]["results"]["katana"]
            lines.append(f"### {hostname}")
            lines.append("")
            if katana.get("js_files"):
                lines.append("**JS Files:**")
                for f in katana["js_files"]:
                    lines.append(f"- `{f}`")
                lines.append("")
            if katana.get("api_endpoints"):
                lines.append("**API Endpoints:**")
                for ep in katana["api_endpoints"]:
                    lines.append(f"- `{ep}`")
                lines.append("")
            if not katana.get("js_files") and not katana.get("api_endpoints"):
                lines.append(f"No JS files or API endpoints found. ({len(katana.get('all_urls', []))} URLs crawled)")
                lines.append("")

    # Parameter discovery results
    param_hosts = {h: v for h, v in scannable.items() if "params" in v.get("results", {})}
    if param_hosts:
        lines.extend(["## Parameter Discovery (paramspider)", ""])
        for hostname in sorted(param_hosts):
            params = param_hosts[hostname]["results"]["params"]
            lines.append(f"### {hostname}")
            lines.append("")
            if params:
                for url in params:
                    lines.append(f"- `{url}`")
            else:
                lines.append("No parameterized URLs found.")
            lines.append("")

    # Nuclei results
    nuclei_hosts = {h: v for h, v in scannable.items() if "nuclei" in v.get("results", {})}
    if nuclei_hosts:
        lines.extend(["## Nuclei Vulnerability Scanning", ""])
        for hostname in sorted(nuclei_hosts):
            findings = nuclei_hosts[hostname]["results"]["nuclei"]
            lines.append(f"### {hostname}")
            lines.append("")
            if findings:
                for finding in findings:
                    lines.append(f"- `{finding}`")
            else:
                lines.append("No issues found.")
            lines.append("")

    # Write file
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        f.write("\n".join(lines))

    print(f"\n  Report saved to: {output_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="RECON-KIT: Interactive Reconnaissance Script")
    parser.add_argument("scope_file", nargs="?", help="Path to Burp scope JSON file")
    parser.add_argument("-p", "--proxy", default=DEFAULT_PROXY, help="Burp proxy address (default: 127.0.0.1:8080)")
    parser.add_argument("-o", "--output", default="./recon-report.md", help="Markdown report output path")
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout in seconds")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="Delay between hosts in seconds")
    parser.add_argument("--scan-timeout", type=int, default=600, help="Timeout for Kali tool commands in seconds")
    args = parser.parse_args()

    banner()

    # Phase 0: Load scope
    section("Load Scope", 1)

    scope_file = args.scope_file
    if not scope_file:
        scope_file = input("  Enter path to Burp scope JSON: ").strip()

    try:
        hosts = parse_burp_scope(scope_file)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"\n  \033[91mError reading scope file: {e}\033[0m")
        sys.exit(1)

    if not hosts:
        print("  \033[93mNo enabled hosts found in scope file.\033[0m")
        sys.exit(0)

    print(f"\n  Parsed hosts:\n")
    display_hosts(hosts)

    # Select scan speed
    section("Scan Speed", "")
    speed = prompt_speed()

    # Phase 1: Proxy loading
    proxy_load(hosts, args.proxy, args.timeout, args.delay)

    # Phase 2: Fingerprinting
    fingerprint(hosts, args.scan_timeout, speed)

    # Phase 3: Subdomain enumeration
    enum_subdomains(hosts, args.scan_timeout, speed)

    # Phase 4: Directory scanning
    scan_directories(hosts, args.scan_timeout, speed)

    # Phase 5: File scanning
    scan_files(hosts, args.scan_timeout, speed)

    # Phase 6: Live host probing
    probe_live_hosts(hosts, args.scan_timeout)

    # Phase 7: Screenshots
    screenshot_hosts(hosts, args.scan_timeout)

    # Phase 8: JS crawling
    crawl_js(hosts, args.scan_timeout)

    # Phase 9: Parameter discovery
    discover_params(hosts, args.scan_timeout)

    # Phase 10: Nuclei scanning
    nuclei_scan(hosts, args.scan_timeout)

    # Write report
    section("Report", 12)
    write_report(hosts, scope_file, args.output)

    print("\n  Recon complete.\n")


if __name__ == "__main__":
    main()
