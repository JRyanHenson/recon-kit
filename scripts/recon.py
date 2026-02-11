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
import glob
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
DEBUG = False  # Set via --debug flag
WSL_DISTRO = "kali"
DEFAULT_PROXY = "127.0.0.1:8080"
DEFAULT_TIMEOUT = 10
DEFAULT_DELAY = 1.0
DIR_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
FILE_EXTENSIONS = "php,txt,bak,conf,log,xml,json,env,old,zip,asp,aspx,ashx,asmx,svc,config,cs,csproj,sln"

# Base directory for hunt projects (Windows path)
HUNTS_BASE_DIR = r"C:\Users\p7snkx7mvj\Desktop\Hunts"
# WSL-translated path for tools that run in Kali
HUNTS_BASE_DIR_WSL = "/mnt/c/Users/p7snkx7mvj/Desktop/Hunts"
# Downloads folder to check for scope files
DOWNLOADS_DIR = r"C:\Users\p7snkx7mvj\Downloads"

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
    if DEBUG:
        print(f"    \033[90m[DEBUG] wsl_run timeout: {timeout}s\033[0m")
    try:
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        if DEBUG:
            print(f"    \033[91m[DEBUG] subprocess.TimeoutExpired after {timeout}s\033[0m")
        return "", "Timeout", -1
    except FileNotFoundError:
        return "", "WSL not found. Is Kali WSL installed?", -1


# ---------------------------------------------------------------------------
# Phase 0: Scope Parsing
# ---------------------------------------------------------------------------

def parse_burp_scope(path):
    """Parse Burp scope JSON and return a dict of host info.

    Returns:
        dict: {hostname: {"allow_dir_scan": bool, "allow_subdomain_scan": bool, "base_path": str, "results": {}}}
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
        # Handle wildcard subdomain patterns: ^.+\\.target\\.gov$ or ^.*\\.target\\.gov$ → *.target.gov
        is_wildcard = False
        if host_pattern.startswith("^.+\\.") or host_pattern.startswith("^.*\\."):
            # Wildcard subdomain pattern - extract base domain
            # ^.+\\.target\\.gov$ → .target.gov (wildcard marker)
            # Skip 5 chars: ^ . + \ .
            hostname = "." + host_pattern[5:].rstrip("$").replace("\\.", ".")
            is_wildcard = True
        else:
            hostname = host_pattern.strip("^$").replace("\\.", ".")
            # Also check for patterns like ^\.target\.gov$ (starts with \.)
            is_wildcard = hostname.startswith(".")

        if not hostname:
            continue

        if hostname not in hosts:
            hosts[hostname] = {
                "hostname": hostname,
                "allow_dir_scan": False,
                "allow_subdomain_scan": is_wildcard,
                "base_path": "/",
                "results": {},
            }

        # Check if file pattern allows directory scanning
        # Patterns ending with .*$ allow scanning (e.g., ^/.*$, ^/srp2/.*$)
        if file_pattern.endswith(".*$"):
            hosts[hostname]["allow_dir_scan"] = True
            # Extract base path: ^/srp2/.*$ → /srp2/
            base_path = file_pattern[1:-3]  # Remove ^ prefix and .*$ suffix
            if base_path and not base_path.endswith("/"):
                base_path += "/"
            if base_path:
                hosts[hostname]["base_path"] = base_path

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
        base_path = info.get("base_path", "/")
        base_info = f" (base: {base_path})" if base_path != "/" else ""
        print(f"    {hostname:<{max_len + 2}} [dirs: {dirs}] [subs: {subs}]{base_info}")

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

    # Block hosts that returned 403/404 from all subsequent phases
    blocked = []
    for hostname, info in scannable.items():
        proxy_result = info["results"].get("proxy", {})
        https_status = proxy_result.get("https", {}).get("status")
        http_status = proxy_result.get("http", {}).get("status")
        if https_status in (403, 404) or (https_status is None and http_status in (403, 404)):
            info["blocked"] = True
            blocked.append(hostname)

    if blocked:
        print(f"\n  \033[93m{len(blocked)} host(s) returned 403/404 — excluded from all scanning phases:\033[0m")
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
    scannable = {h: v for h, v in hosts.items() if not h.startswith(".") and not v.get("blocked")}
    total = len(scannable)

    if not total:
        print("  No eligible hosts. Skipping.")
        return

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
    eligible = {h: v for h, v in hosts.items() if v["allow_subdomain_scan"] and not h.startswith(".") and not v.get("blocked")}

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

def strip_ansi(text):
    """Remove ANSI escape sequences from text."""
    return re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)


def parse_ffuf_output(stdout, base_path="/"):
    """Parse ffuf output lines into list of (path, status_code) tuples."""
    results = []
    base = base_path.rstrip("/")
    for line in stdout.splitlines():
        # Strip ANSI escape codes first
        line = strip_ansi(line)
        if "[Status:" not in line:
            continue
        # Format: path  [Status: 200, Size: 1234, Words: 56, Lines: 12, Duration: 123ms]
        # Root path has no prefix, just whitespace before [Status:
        match = re.match(r"^(\S*)\s*\[Status:\s*(\d+)", line.strip())
        if match:
            found_path = match.group(1) if match.group(1) else ""
            # Prepend base path to results (e.g., /srp2 + /admin → /srp2/admin)
            full_path = f"{base}/{found_path.lstrip('/')}" if found_path else base or "/"
            results.append((full_path, int(match.group(2))))
    return results


def run_ffuf_dir(host, wordlist, timeout, ffuf_rate=0, ffuf_threads=20, status_codes="200,204,301,302,307,401,403", base_path="/"):
    # Build URL with base path (e.g., /srp2/FUZZ instead of /FUZZ)
    base = base_path.rstrip("/")
    url = f"https://{host}{base}/FUZZ"
    rate_flag = f"-rate {ffuf_rate}" if ffuf_rate > 0 else ""
    # Use ffuf's -maxtime instead of subprocess timeout (more reliable on Windows/WSL)
    cmd = f"ffuf -u {url} -w {wordlist} -mc {status_codes} -t {ffuf_threads} {rate_flag} -maxtime {timeout} -noninteractive"
    stdout, stderr, rc = wsl_run(cmd, timeout + 60)
    return parse_ffuf_output(stdout, base_path), stdout, stderr


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

    eligible = {h: v for h, v in hosts.items() if v["allow_dir_scan"] and not h.startswith(".") and not v.get("blocked")}

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
        base_path = eligible[hostname].get("base_path", "/")
        print(f"\n  Scanning {hostname} (base: {base_path})...")
        results, raw_stdout, raw_stderr = run_ffuf_dir(hostname, DIR_WORDLIST, timeout, ffuf_rate, ffuf_threads, status_codes, base_path)

        if results:
            print(f"    Found {len(results)} entries:")
            for path, code in results[:50]:  # Limit terminal output
                print(f"      {path} ({code})")
            if len(results) > 50:
                print(f"      ... and {len(results) - 50} more (see report)")
        else:
            print(f"    No directories found.")
            if DEBUG:
                if raw_stdout:
                    print(f"    \033[90m[DEBUG] ffuf raw output (first 500 chars):\033[0m")
                    print(f"    {raw_stdout[:500]}")
                if raw_stderr:
                    print(f"    \033[90m[DEBUG] ffuf stderr (first 200 chars):\033[0m {raw_stderr[:200]}")

        eligible[hostname]["results"]["directories"] = results

    print(f"\n  Directory scanning complete.")


# ---------------------------------------------------------------------------
# Phase 5: File Scanning
# ---------------------------------------------------------------------------

def run_ffuf_files(host, wordlist, extensions, timeout, ffuf_rate=0, ffuf_threads=20, status_codes="200,204,301,302,307,401,403", base_path="/"):
    # Build URL with base path (e.g., /srp2/FUZZ instead of /FUZZ)
    base = base_path.rstrip("/")
    url = f"https://{host}{base}/FUZZ"
    ext_list = ",".join(f".{e}" for e in extensions.split(","))
    rate_flag = f"-rate {ffuf_rate}" if ffuf_rate > 0 else ""
    # Use ffuf's -maxtime instead of subprocess timeout (more reliable on Windows/WSL)
    cmd = f"ffuf -u {url} -w {wordlist} -e {ext_list} -mc {status_codes} -t {ffuf_threads} {rate_flag} -maxtime {timeout} -noninteractive"
    if DEBUG:
        print(f"    \033[90m[DEBUG] cmd: {cmd}\033[0m")
    # Use very long subprocess timeout since ffuf handles its own timing
    stdout, stderr, rc = wsl_run(cmd, timeout + 60)
    if DEBUG:
        print(f"    \033[90m[DEBUG] rc: {rc}, stdout len: {len(stdout)}, stderr len: {len(stderr)}\033[0m")
        if stderr and len(stderr) < 1000:
            print(f"    \033[90m[DEBUG] stderr: {stderr[:500]}\033[0m")
    return parse_ffuf_output(stdout, base_path), stdout, stderr


def scan_files(hosts, timeout, speed):
    """Run file scanning on eligible hosts."""
    section("File Scanning", 6)

    eligible = {h: v for h, v in hosts.items() if v["allow_dir_scan"] and not h.startswith(".") and not v.get("blocked")}

    if not eligible:
        print("  No hosts allow file scanning. Skipping.")
        return

    print(f"  {len(eligible)} host(s) eligible for file scanning.")
    print(f"  \033[93mNote: More extensions = much longer scan time.\033[0m\n")

    print("  Select extension set:\n")
    print("    [1] Common (5)        - txt,bak,conf,log,xml")
    print("    [2] Web (8)           - php,txt,bak,conf,log,xml,json,env")
    print("    [3] IIS/ASP (7)       - asp,aspx,ashx,asmx,svc,config,txt")
    print("    [4] All (19)          - full extension list")
    print("    [5] Custom            - enter your own")
    print()

    while True:
        ext_choice = input("  Extensions [1-5]: ").strip()
        if ext_choice == "1":
            extensions = "txt,bak,conf,log,xml"
            break
        elif ext_choice == "2":
            extensions = "php,txt,bak,conf,log,xml,json,env"
            break
        elif ext_choice == "3":
            extensions = "asp,aspx,ashx,asmx,svc,config,txt"
            break
        elif ext_choice == "4":
            extensions = FILE_EXTENSIONS
            break
        elif ext_choice == "5":
            extensions = input("  Enter comma-separated extensions (no dots): ").strip()
            break
        else:
            print("  Invalid choice. Enter 1-5.")

    num_extensions = len(extensions.split(","))
    print(f"  Using {num_extensions} extensions: {extensions}\n")

    if not prompt_yn("Proceed with file scanning?"):
        print("  Skipping file scanning.")
        return

    status_codes = prompt_status_codes()
    _, _, ffuf_rate, ffuf_threads, _ = speed

    # Estimate timeout based on requests and speed
    # Wordlist has ~4600 entries, each tested with N extensions
    estimated_requests = 4600 * num_extensions
    effective_rate = ffuf_rate if ffuf_rate > 0 else 100  # assume ~100 req/s if no limit
    estimated_seconds = (estimated_requests / effective_rate) * 1.5  # 1.5x buffer
    file_timeout = max(timeout, int(estimated_seconds))
    print(f"  \033[90m(Timeout: {file_timeout // 60} min for ~{estimated_requests} requests)\033[0m\n")

    for hostname in sorted(eligible):
        base_path = eligible[hostname].get("base_path", "/")
        print(f"\n  Scanning {hostname} for files (base: {base_path})...")
        results, raw_stdout, raw_stderr = run_ffuf_files(hostname, DIR_WORDLIST, extensions, file_timeout, ffuf_rate, ffuf_threads, status_codes, base_path)

        if results:
            print(f"    Found {len(results)} files:")
            for path, code in results[:50]:
                print(f"      {path} ({code})")
            if len(results) > 50:
                print(f"      ... and {len(results) - 50} more (see report)")
        else:
            print(f"    No files found.")
            if DEBUG:
                if raw_stdout:
                    print(f"    \033[90m[DEBUG] ffuf raw output (first 500 chars):\033[0m")
                    print(f"    {raw_stdout[:500]}")
                if raw_stderr:
                    print(f"    \033[90m[DEBUG] ffuf stderr (first 200 chars):\033[0m {raw_stderr[:200]}")

        eligible[hostname]["results"]["files"] = results

    print(f"\n  File scanning complete.")


# ---------------------------------------------------------------------------
# Phase 6: Live Host Probing (httpx)
# ---------------------------------------------------------------------------

def run_httpx(hosts_list, timeout):
    """Run httpx on a list of hosts and return parsed results."""
    # Write hosts to a temp file for httpx input
    hosts_str = "\\n".join(hosts_list)
    cmd = f"echo -e '{hosts_str}' | httpx -silent -status-code -title -tech-detect -follow-redirects"
    if DEBUG:
        print(f"    \033[90m[DEBUG] httpx targets: {hosts_list}\033[0m")
        print(f"    \033[90m[DEBUG] cmd: {cmd}\033[0m")
    stdout, stderr, rc = wsl_run(cmd, timeout)
    if DEBUG:
        print(f"    \033[90m[DEBUG] rc: {rc}, stdout len: {len(stdout)}, stderr len: {len(stderr)}\033[0m")
        if stderr and len(stderr) < 500:
            print(f"    \033[90m[DEBUG] stderr: {stderr}\033[0m")
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
    scannable = {h: v for h, v in hosts.items() if not h.startswith(".") and not v.get("blocked")}
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

    print("  \033[90m(Use Linux path like /tmp/gowitness or /mnt/c/Users/... for Windows folders)\033[0m")
    output_dir = input("  Screenshot output directory (default: /tmp/gowitness): ").strip()
    if not output_dir:
        output_dir = "/tmp/gowitness"
    # Convert Windows paths to WSL paths
    if output_dir.startswith("C:") or output_dir.startswith("c:"):
        output_dir = "/mnt/c" + output_dir[2:].replace("\\", "/")
    elif output_dir.startswith("D:") or output_dir.startswith("d:"):
        output_dir = "/mnt/d" + output_dir[2:].replace("\\", "/")

    # Collect all targets
    all_targets = []
    scannable = {h: v for h, v in hosts.items() if not h.startswith(".") and h != "__httpx_results" and not v.get("blocked")}
    for hostname in sorted(scannable):
        all_targets.append(f"https://{hostname}")

    for info in hosts.values():
        subs = info["results"].get("subdomains", [])
        for sub in subs:
            all_targets.append(f"https://{sub}")

    print(f"\n  Screenshotting {len(all_targets)} targets...")

    # Write URLs to temp file (more reliable than echo -e piping)
    urls_file = f"{output_dir}/urls.txt"
    urls_content = "\n".join(all_targets)
    write_cmd = f"mkdir -p {output_dir} && cat > {urls_file} << 'URLS_EOF'\n{urls_content}\nURLS_EOF"
    wsl_run(write_cmd, 30)

    cmd = f"gowitness scan file -f {urls_file} -s {output_dir} --screenshot-fullpage --write-none"
    if DEBUG:
        print(f"    \033[90m[DEBUG] cmd: {cmd}\033[0m")
    stdout, stderr, rc = wsl_run(cmd, timeout)
    if DEBUG:
        print(f"    \033[90m[DEBUG] rc: {rc}, stdout len: {len(stdout)}, stderr len: {len(stderr)}\033[0m")
        if stderr:
            print(f"    \033[90m[DEBUG] stderr: {stderr[:500]}\033[0m")

    # Count screenshots (gowitness defaults to jpeg format)
    count_stdout, _, _ = wsl_run(f"ls {output_dir}/*.jpeg {output_dir}/*.jpg {output_dir}/*.png 2>/dev/null | wc -l", 10)
    count = count_stdout.strip() if count_stdout else "0"
    print(f"    {count} screenshots saved to {output_dir}")

    if rc != 0 and stderr:
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

    scannable = {h: v for h, v in hosts.items() if v.get("allow_dir_scan") and not h.startswith(".") and not v.get("blocked")}

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
    # Use -s for stream mode (outputs URLs directly)
    cmd = f"paramspider -d {host} -s"
    if DEBUG:
        print(f"    \033[90m[DEBUG] cmd: {cmd}\033[0m")
    stdout, stderr, rc = wsl_run(cmd, timeout)
    if DEBUG:
        print(f"    \033[90m[DEBUG] rc: {rc}, stdout: {len(stdout)}, stderr: {len(stderr)}\033[0m")
        if stderr and len(stderr) < 300:
            print(f"    \033[90m[DEBUG] stderr: {stderr}\033[0m")
        if rc != 0:
            print(f"    \033[90m[DEBUG] paramspider may have failed\033[0m")
    if stdout:
        return [line.strip() for line in stdout.splitlines() if line.strip() and line.startswith("http")]
    return []


def discover_params(hosts, timeout):
    """Discover URL parameters with paramspider."""
    section("Parameter Discovery (paramspider)", 10)

    if not prompt_yn("Run parameter discovery with paramspider?"):
        print("  Skipping parameter discovery.")
        return

    scannable = {h: v for h, v in hosts.items() if v.get("allow_dir_scan") and not h.startswith(".") and not v.get("blocked")}

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

def run_nuclei(host, timeout, templates, use_automatic=False):
    url = f"https://{host}"
    if use_automatic:
        template_flag = "-as"
    elif templates:
        template_flag = f"-tags {templates}"
    else:
        template_flag = "-as"  # Default to automatic scan
    cmd = f"nuclei -u {url} -silent {template_flag}"
    if DEBUG:
        print(f"    \033[90m[DEBUG] cmd: {cmd}\033[0m")
    stdout, stderr, rc = wsl_run(cmd, timeout)
    if DEBUG:
        print(f"    \033[90m[DEBUG] rc: {rc}, stdout: {len(stdout)}, stderr: {len(stderr)}\033[0m")
        if stderr and len(stderr) < 500:
            print(f"    \033[90m[DEBUG] stderr: {stderr[:500]}\033[0m")
        if rc != 0:
            print(f"    \033[90m[DEBUG] nuclei may have failed\033[0m")
    if stdout:
        return [strip_ansi(line.strip()) for line in stdout.splitlines() if line.strip()]
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

    # Use -tags for specific templates, or -as (automatic scan) for all templates
    template_flag = f"-tags {templates}" if templates else "-as"

    scannable = {h: v for h, v in hosts.items() if not h.startswith(".") and h != "__httpx_results" and h != "__screenshot_results" and not v.get("blocked")}

    print(f"\n  Scanning {len(scannable)} host(s)...\n")

    for hostname in sorted(scannable):
        print(f"  [{hostname}]")
        url = f"https://{hostname}"
        cmd = f"nuclei -u {url} -silent {template_flag}"
        stdout, stderr, rc = wsl_run(cmd, timeout)

        results = [strip_ansi(line.strip()) for line in stdout.splitlines() if line.strip()] if stdout else []

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
                    full_url = f"https://{hostname}/{path.lstrip('/')}" if path else f"https://{hostname}/"
                    lines.append(f"- {full_url} ({code})")
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
                    full_url = f"https://{hostname}/{path.lstrip('/')}" if path else f"https://{hostname}/"
                    lines.append(f"- {full_url} ({code})")
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
                lines.append("```")
                for finding in findings:
                    lines.append(finding)
                lines.append("```")
            else:
                lines.append("No issues found.")
            lines.append("")

    # Write file
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"\n  Report saved to: {output_path}")


# ---------------------------------------------------------------------------
# Per-Host Report Writer
# ---------------------------------------------------------------------------

def write_host_report(hostname, info, output_dir):
    """Write a markdown report for a single host."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    safe_hostname = hostname.replace(".", "_").replace(":", "_")
    output_path = os.path.join(output_dir, f"{safe_hostname}.md")

    lines = [
        f"# Recon Report: {hostname}",
        "",
        f"**Date:** {timestamp}",
        "",
    ]

    results = info.get("results", {})

    # Proxy results
    if "proxy" in results:
        proxy = results["proxy"]
        lines.extend(["## Connectivity", ""])
        for scheme in ("https", "http"):
            r = proxy.get(scheme, {})
            if r.get("error"):
                lines.append(f"- **{scheme.upper()}:** {r['error']}")
            elif r.get("status"):
                line = f"- **{scheme.upper()}:** {r['status']}"
                if r.get("final_url"):
                    line += f" → {r['final_url']}"
                lines.append(line)
        lines.append("")

    # Fingerprinting
    if "fingerprint" in results:
        fp = results["fingerprint"]
        lines.extend(["## Fingerprinting", ""])
        if fp.get("whatweb"):
            lines.extend(["### WhatWeb", "```", fp["whatweb"], "```", ""])
        if fp.get("wafw00f"):
            lines.extend(["### WAF Detection", "```", fp["wafw00f"], "```", ""])
        if fp.get("nmap"):
            lines.extend(["### Nmap", "```", fp["nmap"], "```", ""])

    # Subdomains
    if "subdomains" in results and results["subdomains"]:
        lines.extend(["## Subdomains", ""])
        for sub in sorted(results["subdomains"]):
            lines.append(f"- {sub}")
        lines.append("")

    # Directories
    if "directories" in results and results["directories"]:
        lines.extend(["## Directories", ""])
        for path, code in results["directories"]:
            full_url = f"https://{hostname}/{path.lstrip('/')}" if path else f"https://{hostname}/"
            lines.append(f"- {full_url} ({code})")
        lines.append("")

    # Files
    if "files" in results and results["files"]:
        lines.extend(["## Files", ""])
        for path, code in results["files"]:
            full_url = f"https://{hostname}/{path.lstrip('/')}" if path else f"https://{hostname}/"
            lines.append(f"- {full_url} ({code})")
        lines.append("")

    # httpx
    if "httpx" in results and results["httpx"]:
        lines.extend(["## Live Host Probe", ""])
        for line in results["httpx"]:
            lines.append(f"- `{line}`")
        lines.append("")

    # Katana
    if "katana" in results:
        katana = results["katana"]
        lines.extend(["## JavaScript Crawling", ""])
        if katana.get("js_files"):
            lines.append("### JS Files")
            for f in katana["js_files"]:
                lines.append(f"- `{f}`")
            lines.append("")
        if katana.get("api_endpoints"):
            lines.append("### API Endpoints")
            for ep in katana["api_endpoints"]:
                lines.append(f"- `{ep}`")
            lines.append("")

    # Parameters
    if "params" in results and results["params"]:
        lines.extend(["## Parameters", ""])
        for url in results["params"]:
            lines.append(f"- `{url}`")
        lines.append("")

    # Nuclei
    if "nuclei" in results and results["nuclei"]:
        lines.extend(["## Vulnerabilities", ""])
        lines.append("```")
        for finding in results["nuclei"]:
            lines.append(finding)
        lines.append("```")
        lines.append("")

    # Write file
    os.makedirs(output_dir, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return output_path


# ---------------------------------------------------------------------------
# Phase Settings Collection
# ---------------------------------------------------------------------------

def collect_phase_settings(hosts, speed):
    """Collect all phase settings upfront before processing hosts."""
    settings = {}

    section("Phase Selection", 2)
    print("  Select which phases to run for each target:\n")

    settings["proxy"] = prompt_yn("Load targets through Burp proxy?")
    settings["fingerprint"] = prompt_yn("Run fingerprinting (whatweb, wafw00f, nmap)?")
    settings["subdomains"] = prompt_yn("Run subdomain enumeration?")
    settings["directories"] = prompt_yn("Run directory scanning?")
    settings["files"] = prompt_yn("Run file scanning?")
    settings["httpx"] = prompt_yn("Run live host probing (httpx)?")
    settings["screenshots"] = prompt_yn("Capture screenshots (gowitness)?")
    settings["katana"] = prompt_yn("Run JS crawling (katana)?")
    settings["paramspider"] = prompt_yn("Run parameter discovery?")
    settings["nuclei"] = prompt_yn("Run nuclei scanning?")

    # Collect additional settings for enabled phases
    if settings["directories"]:
        print()
        settings["dir_status_codes"] = prompt_status_codes()

    if settings["files"]:
        print("\n  Select extension set for file scanning:\n")
        print("    [1] Common (5)        - txt,bak,conf,log,xml")
        print("    [2] Web (8)           - php,txt,bak,conf,log,xml,json,env")
        print("    [3] IIS/ASP (7)       - asp,aspx,ashx,asmx,svc,config,txt")
        print("    [4] All (19)          - full extension list")
        print("    [5] Custom            - enter your own")
        print()
        while True:
            ext_choice = input("  Extensions [1-5]: ").strip()
            if ext_choice == "1":
                settings["file_extensions"] = "txt,bak,conf,log,xml"
                break
            elif ext_choice == "2":
                settings["file_extensions"] = "php,txt,bak,conf,log,xml,json,env"
                break
            elif ext_choice == "3":
                settings["file_extensions"] = "asp,aspx,ashx,asmx,svc,config,txt"
                break
            elif ext_choice == "4":
                settings["file_extensions"] = FILE_EXTENSIONS
                break
            elif ext_choice == "5":
                settings["file_extensions"] = input("  Enter comma-separated extensions: ").strip()
                break
            else:
                print("  Invalid choice. Enter 1-5.")
        settings["file_status_codes"] = prompt_status_codes()

    if settings["nuclei"]:
        print("\n  Select nuclei template category:\n")
        print("    [1] Safe only          (misconfigs, exposures, info)")
        print("    [2] Medium risk        (safe + CVEs, default-logins)")
        print("    [3] All templates      (includes fuzzing - noisy)")
        print("    [4] Custom path")
        print()
        while True:
            choice = input("  Templates [1-4]: ").strip()
            if choice == "1":
                settings["nuclei_templates"] = "misconfiguration,exposure,miscellaneous"
                break
            elif choice == "2":
                settings["nuclei_templates"] = "misconfiguration,exposure,cves,default-logins,miscellaneous"
                break
            elif choice == "3":
                settings["nuclei_templates"] = ""
                break
            elif choice == "4":
                settings["nuclei_templates"] = input("  Enter template path or tags: ").strip()
                break
            else:
                print("  Invalid choice. Enter 1-4.")

    return settings


# ---------------------------------------------------------------------------
# Single Host Processor
# ---------------------------------------------------------------------------

def process_host(hostname, info, settings, speed, proxy_addr, timeout, scan_timeout, report_dir):
    """Process a single host through all enabled phases."""
    print(f"\n{'=' * 60}")
    print(f"  Processing: {hostname}")
    print(f"{'=' * 60}")

    _, nmap_timing, ffuf_rate, ffuf_threads, subfinder_rate = speed

    # Check if blocked
    if info.get("blocked"):
        print(f"  \033[93mHost blocked (403/404 on initial probe). Skipping.\033[0m")
        return

    # Proxy loading
    if settings.get("proxy") and "proxy" not in info["results"]:
        print(f"\n  [Proxy Load]")
        result = hit_target(hostname, proxy_addr, timeout)
        info["results"]["proxy"] = result
        https_str = format_status(result["https"])
        http_str = format_status(result["http"])
        print(f"    HTTPS [{https_str}]  HTTP [{http_str}]")

        # Check for 403/404 blocking
        https_status = result.get("https", {}).get("status")
        http_status = result.get("http", {}).get("status")
        if https_status in (403, 404) or (https_status is None and http_status in (403, 404)):
            info["blocked"] = True
            print(f"    \033[93mBlocked (403/404). Skipping remaining phases.\033[0m")
            return

    # Fingerprinting
    if settings.get("fingerprint") and not info.get("blocked"):
        print(f"\n  [Fingerprinting]")
        print(f"    whatweb...")
        whatweb_out = run_whatweb(hostname, scan_timeout)
        print(f"    wafw00f...")
        wafw00f_out = run_wafw00f(hostname, scan_timeout)
        print(f"    nmap...")
        nmap_out = run_nmap(hostname, scan_timeout, nmap_timing)
        info["results"]["fingerprint"] = {
            "whatweb": whatweb_out,
            "wafw00f": wafw00f_out,
            "nmap": nmap_out,
        }
        # Show summary
        for line in wafw00f_out.splitlines():
            if "is behind" in line.lower() or "no waf" in line.lower():
                print(f"    {line.strip()}")
                break

    # Subdomain enumeration
    if settings.get("subdomains") and info.get("allow_subdomain_scan") and not info.get("blocked"):
        print(f"\n  [Subdomains]")
        subdomains = run_subfinder(hostname, scan_timeout, subfinder_rate)
        info["results"]["subdomains"] = subdomains
        print(f"    Found {len(subdomains)} subdomains")
        for sub in subdomains[:10]:
            print(f"      {sub}")
        if len(subdomains) > 10:
            print(f"      ... and {len(subdomains) - 10} more")

    # Directory scanning
    if settings.get("directories") and info.get("allow_dir_scan") and not info.get("blocked"):
        base_path = info.get("base_path", "/")
        print(f"\n  [Directory Scan] (base: {base_path})")
        status_codes = settings.get("dir_status_codes", "200,204,301,302,307,401,403")
        results, _, _ = run_ffuf_dir(hostname, DIR_WORDLIST, scan_timeout, ffuf_rate, ffuf_threads, status_codes, base_path)
        info["results"]["directories"] = results
        print(f"    Found {len(results)} directories")
        for path, code in results[:10]:
            full_url = f"https://{hostname}/{path.lstrip('/')}" if path else f"https://{hostname}/"
            print(f"      {full_url} ({code})")
        if len(results) > 10:
            print(f"      ... and {len(results) - 10} more")

    # File scanning
    if settings.get("files") and info.get("allow_dir_scan") and not info.get("blocked"):
        base_path = info.get("base_path", "/")
        print(f"\n  [File Scan] (base: {base_path})")
        extensions = settings.get("file_extensions", FILE_EXTENSIONS)
        status_codes = settings.get("file_status_codes", "200,204,301,302,307,401,403")
        num_ext = len(extensions.split(","))
        estimated_requests = 4600 * num_ext
        effective_rate = ffuf_rate if ffuf_rate > 0 else 100
        file_timeout = max(scan_timeout, int((estimated_requests / effective_rate) * 1.5))
        results, _, _ = run_ffuf_files(hostname, DIR_WORDLIST, extensions, file_timeout, ffuf_rate, ffuf_threads, status_codes, base_path)
        info["results"]["files"] = results
        print(f"    Found {len(results)} files")
        for path, code in results[:10]:
            full_url = f"https://{hostname}/{path.lstrip('/')}" if path else f"https://{hostname}/"
            print(f"      {full_url} ({code})")
        if len(results) > 10:
            print(f"      ... and {len(results) - 10} more")

    # httpx
    if settings.get("httpx") and not info.get("blocked"):
        print(f"\n  [httpx Probe]")
        results = run_httpx([hostname], scan_timeout)
        info["results"]["httpx"] = results
        for line in results:
            print(f"    {line}")

    # Screenshots
    if settings.get("screenshots") and not info.get("blocked"):
        print(f"\n  [Screenshot]")
        output_dir = settings.get("screenshot_dir", "/tmp/gowitness")

        # Build list of URLs to screenshot: homepage + discovered directories + files
        urls = [f"https://{hostname}"]

        dirs = info["results"].get("directories", [])
        files = info["results"].get("files", [])

        if DEBUG:
            print(f"    \033[90m[DEBUG] Found {len(dirs)} directories and {len(files)} files in results\033[0m")

        # Add discovered directories
        for path, code in dirs:
            if path and path != "/":
                urls.append(f"https://{hostname}/{path.lstrip('/')}")

        # Add discovered files
        for path, code in files:
            if path and path != "/":
                urls.append(f"https://{hostname}/{path.lstrip('/')}")

        # Deduplicate
        urls = list(dict.fromkeys(urls))

        print(f"    Screenshotting {len(urls)} URLs...")

        # Write URLs to temp file (more reliable than echo -e piping)
        urls_file = f"{output_dir}/urls.txt"
        urls_content = "\n".join(urls)
        write_cmd = f"mkdir -p {output_dir} && cat > {urls_file} << 'URLS_EOF'\n{urls_content}\nURLS_EOF"
        wsl_run(write_cmd, 30)

        cmd = f"gowitness scan file -f {urls_file} -s {output_dir} --screenshot-fullpage --write-none"
        if DEBUG:
            print(f"    \033[90m[DEBUG] URLs: {urls[:5]}{'...' if len(urls) > 5 else ''}\033[0m")
            print(f"    \033[90m[DEBUG] cmd: {cmd}\033[0m")
        stdout, stderr, rc = wsl_run(cmd, scan_timeout)
        if DEBUG:
            print(f"    \033[90m[DEBUG] rc: {rc}, stdout: {len(stdout)}, stderr: {len(stderr)}\033[0m")
            if stderr and len(stderr) < 500:
                print(f"    \033[90m[DEBUG] stderr: {stderr[:500]}\033[0m")

        # Check what was actually saved
        count_stdout, _, _ = wsl_run(f"find {output_dir} -name '*.png' -o -name '*.jpeg' -o -name '*.jpg' 2>/dev/null | wc -l", 10)
        count = count_stdout.strip() if count_stdout else "0"
        print(f"    {count} screenshot(s) saved to {output_dir}")
        if rc != 0:
            print(f"    \033[91mError: {stderr[:200]}\033[0m")

    # Katana
    if settings.get("katana") and info.get("allow_dir_scan") and not info.get("blocked"):
        print(f"\n  [Katana JS Crawl]")
        results = run_katana(hostname, scan_timeout)
        js_files = [r for r in results if r.endswith(".js")]
        api_endpoints = [r for r in results if "/api/" in r or "/v1/" in r or "/v2/" in r or "/graphql" in r]
        info["results"]["katana"] = {"js_files": js_files, "api_endpoints": api_endpoints, "all_urls": results}
        print(f"    Found {len(js_files)} JS files, {len(api_endpoints)} API endpoints")

    # Paramspider
    if settings.get("paramspider") and info.get("allow_dir_scan") and not info.get("blocked"):
        print(f"\n  [Paramspider]")
        results = run_paramspider(hostname, scan_timeout)
        info["results"]["params"] = results
        print(f"    Found {len(results)} parameterized URLs")

    # Nuclei
    if settings.get("nuclei") and not info.get("blocked"):
        print(f"\n  [Nuclei Scan]")
        templates = settings.get("nuclei_templates", "")
        results = run_nuclei(hostname, scan_timeout, templates)
        info["results"]["nuclei"] = results
        if results:
            print(f"    \033[91mFound {len(results)} issues!\033[0m")
            for finding in results:
                print(f"      {finding}")
        else:
            print(f"    No issues found")

    # Write per-host report
    report_path = write_host_report(hostname, info, report_dir)
    print(f"\n  \033[92m→ Report saved: {report_path}\033[0m")


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
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    # Set global debug flag
    global DEBUG
    DEBUG = args.debug
    if DEBUG:
        print("  \033[93m[DEBUG MODE ENABLED]\033[0m\n")

    banner()

    # Phase 0: Load scope
    section("Load Scope", 1)

    scope_file = args.scope_file
    if not scope_file:
        # Check Downloads folder for JSON files
        json_files = glob.glob(os.path.join(DOWNLOADS_DIR, "*.json"))
        if json_files:
            # Sort by modification time, newest first
            json_files.sort(key=os.path.getmtime, reverse=True)
            print(f"  Found JSON file(s) in Downloads:\n")
            for i, f in enumerate(json_files[:5], 1):  # Show up to 5 most recent
                fname = os.path.basename(f)
                mtime = datetime.fromtimestamp(os.path.getmtime(f)).strftime("%Y-%m-%d %H:%M")
                print(f"    [{i}] {fname}  ({mtime})")
            print(f"    [0] Enter path manually")
            print()
            while True:
                choice = input("  Select file [0-5]: ").strip()
                if choice == "0":
                    scope_file = input("  Enter path to Burp scope JSON: ").strip()
                    break
                elif choice.isdigit() and 1 <= int(choice) <= len(json_files[:5]):
                    scope_file = json_files[int(choice) - 1]
                    print(f"  Using: {scope_file}")
                    break
                else:
                    print("  Invalid choice.")
        else:
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

    # Ask for project name and create project directory
    section("Project Setup", "")
    project_name = input("  Enter project name: ").strip()
    if not project_name:
        project_name = "untitled"
    # Sanitize project name for filesystem
    project_name = "".join(c if c.isalnum() or c in ('-', '_') else '_' for c in project_name)

    # Create project directory structure
    project_dir = os.path.join(HUNTS_BASE_DIR, project_name)
    project_dir_wsl = f"{HUNTS_BASE_DIR_WSL}/{project_name}"
    screenshots_dir_wsl = f"{project_dir_wsl}/screenshots"

    os.makedirs(project_dir, exist_ok=True)
    os.makedirs(os.path.join(project_dir, "screenshots"), exist_ok=True)

    print(f"  Project directory: {project_dir}")
    print(f"  Screenshots: {project_dir}\\screenshots")
    print(f"  Reports: {project_dir}\\<hostname>.md")

    # Select scan speed
    section("Scan Speed", "")
    speed = prompt_speed()

    # Collect all phase settings upfront
    settings = collect_phase_settings(hosts, speed)

    # Set screenshot directory to project screenshots folder
    settings["screenshot_dir"] = screenshots_dir_wsl

    # Set report directory to project folder
    report_dir = project_dir

    # Process each host one at a time
    scannable = {h: v for h, v in hosts.items() if not h.startswith(".")}
    total = len(scannable)

    section("Processing Targets", 3)
    print(f"  {total} target(s) to process. Each will get its own report.\n")

    for i, (hostname, info) in enumerate(sorted(scannable.items())):
        print(f"\n  [{i + 1}/{total}] Starting {hostname}...")
        process_host(
            hostname, info, settings, speed,
            args.proxy, args.timeout, args.scan_timeout, report_dir
        )

    # Write combined report
    section("Final Report", 4)
    combined_report_path = os.path.join(project_dir, "combined_report.md")
    write_report(hosts, scope_file, combined_report_path)

    print("\n  Recon complete.\n")
    print(f"  Project folder: {project_dir}")
    print(f"  Individual reports: {project_dir}\\<hostname>.md")
    print(f"  Combined report: {combined_report_path}")
    print(f"  Screenshots: {project_dir}\\screenshots\n")


if __name__ == "__main__":
    main()
