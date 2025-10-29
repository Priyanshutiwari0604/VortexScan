#!/usr/bin/env python3
"""
VORTEXSCAN - dirsearch-like directory & file discovery tool
Author: Tester (example)
Save as: vortexscan.py

Goals:
 - Behave very similarly to dirsearch / gobuster for common usage patterns.
 - CLI flags: -u/--url, -w/--wordlist, -e/--extensions, -t/--threads, -T/--timeout,
   -v/--verbose, -o/--output, --random-agent, --status, --no-redirects, --delay,
   --proxy, --auth, --recursive, --max-depth, --resume, --format (text/csv/json)
 - Default hides 404s (like dirsearch).
 - Scheme probing: if user passes host without scheme, tool probes https then http.
 - Resume support writes/reads output file.
 - ThreadPoolExecutor for concurrency; requests.Session pooling.
 - Friendly banner and legal reminder.
 - Color output if colorama installed (optional).
"""

from __future__ import annotations
import argparse
import concurrent.futures
import requests
import sys
import os
import random
import time
import json
from urllib.parse import urljoin, urlparse
from threading import Lock
from queue import Queue, Empty
from typing import Optional, Set, List, Tuple, Dict

# ----- Config & Banner -----
TOOL_NAME = "VORTEXSCAN"
BANNER = r"""
 __     ___  ____  _____  ________  ______   ___   _   __
 \ \   / / |/ /\ \/ / _ \|  ____\ \/ /  _ \ / _ \ | | / /
  \ \_/ /| ' /  \  / | | | |__   \  /| |_) | | | || |/ / 
   \   / |  <   /  \ | | |  __|  /  \|  _ <| | | ||    \ 
    | |  | . \ / /\ \ |_| | |____/ /\ \ |_) | |_| || |\  \
    |_|  |_|\_\/  \_\___/|______/_/  \_\____/ \___/ |_| \_\
                                                         
                      V O R T E X  S C A N
"""
DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "curl/7.85.0",
    "Wget/1.21.3 (linux-gnu)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
]
PRINT_LOCK = Lock()

# Optional colors (if user has colorama)
try:
    import colorama
    colorama.init(autoreset=True)
    RED = colorama.Fore.RED
    GREEN = colorama.Fore.GREEN
    YELLOW = colorama.Fore.YELLOW
    CYAN = colorama.Fore.CYAN
    RESET = colorama.Style.RESET_ALL
except Exception:
    RED = GREEN = YELLOW = CYAN = RESET = ""

# ----- Utilities -----
def safe_print(msg: str):
    with PRINT_LOCK:
        print(msg)

def print_banner():
    print(BANNER)
    print(f"[+] {TOOL_NAME} - dirsearch-like directory & file discovery")
    print("[!] Only scan targets you own or have explicit permission to test.\n")

def normalize_target(raw: str) -> str:
    """Return raw target; if missing scheme return as-is for probing later."""
    return raw.rstrip("/")

def probe_scheme(host: str, timeout: float, headers: Dict[str,str], proxy: Optional[str]) -> str:
    """If user didn't supply scheme, try https then http; return working base URL."""
    if host.startswith("http://") or host.startswith("https://"):
        return host.rstrip("/")
    # Try https
    for scheme in ("https://", "http://"):
        try:
            url = scheme + host
            s = requests.Session()
            if proxy:
                s.proxies.update({"http": proxy, "https": proxy})
            r = s.head(url, timeout=timeout, allow_redirects=True, headers=headers)
            # If we get any response code, we'll accept scheme (even 4xx/5xx).
            return url.rstrip("/")
        except requests.RequestException:
            continue
    # fallback to https if both failed
    return "https://" + host

def load_wordlist(path: str) -> List[str]:
    with open(path, "r", errors="ignore") as fh:
        lines = [ln.strip() for ln in fh if ln.strip() and not ln.strip().startswith("#")]
    return lines

def expand_targets(entries: List[str], exts: List[str]) -> List[str]:
    """
    Build target list (path portion). For each wordlist entry produce:
     - entry
     - entry.ext for each ext (not double-dot)
    Keep order and dedupe.
    """
    seen = set()
    out = []
    for e in entries:
        candidate = e.lstrip("/")
        if candidate not in seen:
            seen.add(candidate)
            out.append(candidate)
        for ext in exts:
            ext = ext.lstrip(".")
            if candidate.endswith("/"):
                # for directory-like entries, try index.ext
                idx = candidate.rstrip("/") + f"/index.{ext}"
                if idx not in seen:
                    seen.add(idx)
                    out.append(idx)
            else:
                cand2 = f"{candidate}.{ext}"
                if cand2 not in seen:
                    seen.add(cand2)
                    out.append(cand2)
    return out

def is_url_already_recorded(url: str, recorded_set: Set[str]) -> bool:
    return url in recorded_set

def default_headers(random_agent: bool) -> Dict[str,str]:
    if random_agent:
        return {"User-Agent": random.choice(DEFAULT_USER_AGENTS)}
    return {"User-Agent": DEFAULT_USER_AGENTS[0]}

# ----- Scanner class -----
class VortexScanner:
    def __init__(
        self,
        base: str,
        targets: List[str],
        threads: int = 40,
        timeout: float = 10.0,
        random_agent: bool = False,
        status_filter: Optional[Set[int]] = None,
        follow_redirects: bool = True,
        delay: float = 0.0,
        proxy: Optional[str] = None,
        auth: Optional[Tuple[str,str]] = None,
        verbose: bool = False,
        out_fp = None,
        recursive: bool = False,
        max_depth: int = 2,
        resume: bool = False,
        output_format: str = "text"
    ):
        self.base = base.rstrip("/")
        self.targets_queue = Queue()
        for t in targets:
            self.targets_queue.put((t, 0))
        self.threads = max(1, threads)
        self.timeout = timeout
        self.random_agent = random_agent
        self.status_filter = status_filter
        self.follow_redirects = follow_redirects
        self.delay = delay
        self.proxy = proxy
        self.auth = auth
        self.verbose = verbose
        self.out_fp = out_fp
        self.recursive = recursive
        self.max_depth = max_depth
        self.running = True
        self.output_format = output_format.lower()
        # discovered items: (status, url, size, elapsed)
        self.discovered: List[Tuple[int,str,int,float]] = []
        self.recorded_set: Set[str] = set()
        # If resuming from file, read existing entries into recorded_set
        if resume and out_fp:
            try:
                # ensure file cursor at start
                out_fp.flush()
                out_fp.seek(0)
                for ln in out_fp:
                    ln = ln.strip()
                    if not ln:
                        continue
                    # "200 https://example.com/foo (123 bytes, 0.12s)"
                    parts = ln.split()
                    if len(parts) >= 2:
                        url = parts[1]
                        self.recorded_set.add(url)
            except Exception:
                pass

    def _make_session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update(default_headers(self.random_agent))
        if self.proxy:
            s.proxies.update({"http": self.proxy, "https": self.proxy})
        if self.auth:
            s.auth = self.auth
        adapter = requests.adapters.HTTPAdapter(max_retries=1)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        return s

    def _interesting(self, code: int) -> bool:
        if self.status_filter is not None:
            return code in self.status_filter
        return code != 404

    def _enqueue_recursive_children(self, parent_url: str, depth: int, original_entries: List[str]):
        # For recursion: add original entries under the discovered path
        # Build relative path from base
        parsed = urlparse(parent_url)
        parent_path = parsed.path.rstrip("/")
        if parent_path == "":
            parent_path = "/"
        for e in original_entries:
            # skip absolute URLs in wordlist
            if e.startswith("http://") or e.startswith("https://"):
                continue
            new_path = (parent_path + "/" + e.lstrip("/")).lstrip("/")
            self.targets_queue.put((new_path, depth + 1))

    def worker(self, original_entries: List[str]):
        session = self._make_session()
        while self.running:
            try:
                path, depth = self.targets_queue.get(timeout=1)
            except Empty:
                return
            # join base + path
            url = urljoin(self.base + "/", path.lstrip("/"))
            # skip if recorded
            if is_url_already_recorded(url, self.recorded_set):
                self.targets_queue.task_done()
                continue
            # polite delay per worker
            if self.delay:
                time.sleep(self.delay)
            headers = default_headers(self.random_agent)
            start = time.time()
            try:
                resp = session.get(url, headers=headers, timeout=self.timeout, allow_redirects=self.follow_redirects)
                elapsed = time.time() - start
                code = resp.status_code
                size = len(resp.content) if resp.content is not None else 0
                final_url = resp.url
            except requests.RequestException as e:
                if self.verbose:
                    safe_print(f"{YELLOW}[!] request error for {url}: {e}{RESET}")
                self.targets_queue.task_done()
                continue

            # record using final_url (so redirects map cleanly)
            if final_url in self.recorded_set:
                self.targets_queue.task_done()
                continue
            # decide interesting
            if self._interesting(code):
                line = f"{code} {final_url} ({size} bytes, {elapsed:.2f}s)"
                # colorize by code type
                if 200 <= code < 300:
                    safe_print(f"{GREEN}{line}{RESET}")
                elif 300 <= code < 400:
                    safe_print(f"{CYAN}{line}{RESET}")
                elif 400 <= code < 500:
                    safe_print(f"{YELLOW}{line}{RESET}")
                else:
                    safe_print(f"{RED}{line}{RESET}")

                # append to discovered + write to output if requested
                self.discovered.append((code, final_url, size, elapsed))
                try:
                    if self.out_fp:
                        self.out_fp.write(line + "\n")
                        self.out_fp.flush()
                except Exception:
                    pass

                # recursion heuristic
                if self.recursive and depth < self.max_depth:
                    ctype = resp.headers.get("Content-Type", "")
                    lastseg = urlparse(final_url).path.rstrip("/").split("/")[-1]
                    # heuristics: html 200 and last segment has no extension -> possible directory; or url endswith '/'
                    if (code == 200 and "text/html" in ctype.lower() and "." not in lastseg) or final_url.endswith("/"):
                        self._enqueue_recursive_children(final_url, depth, original_entries)
            else:
                if self.verbose:
                    safe_print(f"- {code} {url} [{elapsed:.2f}s]")

            # mark visited
            self.recorded_set.add(final_url)
            self.targets_queue.task_done()

    def run(self, original_entries: List[str]):
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = [ex.submit(self.worker, original_entries) for _ in range(self.threads)]
            try:
                self.targets_queue.join()
            except KeyboardInterrupt:
                safe_print("\n[!] Interrupted by user - stopping")
                self.running = False
            # cancel futures
            for f in futures:
                try:
                    f.cancel()
                except Exception:
                    pass

# ----- CLI parsing & main -----
def parse_args():
    p = argparse.ArgumentParser(prog=TOOL_NAME, description="VORTEXSCAN - dirsearch-like directory & file discovery (use only on permitted targets)")
    p.add_argument("-u", "--url", required=True, help="Target URL or host (example.com or https://example.com)")
    p.add_argument("-w", "--wordlist", required=True, help="Wordlist file (one entry per line)")
    p.add_argument("-e", "--extensions", default="", help="Comma-separated extensions to append (e.g. php,html,txt)")
    p.add_argument("-t", "--threads", type=int, default=40, help="Threads (default 40)")
    p.add_argument("-T", "--timeout", type=float, default=10.0, help="Request timeout seconds (default 10)")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    p.add_argument("--random-agent", action="store_true", help="Rotate random user-agent per request")
    p.add_argument("-o", "--output", help="Output file to write findings")
    p.add_argument("--format", choices=["text","json","csv"], default="text", help="Output format when using --output (default text)")
    p.add_argument("--status", default="", help="Comma-separated status codes to show (e.g. 200,301,403). Default shows non-404.")
    p.add_argument("--no-redirects", action="store_true", help="Do not follow redirects")
    p.add_argument("--delay", type=float, default=0.0, help="Delay seconds between requests (per thread)")
    p.add_argument("--proxy", help="Proxy URL (e.g. http://127.0.0.1:8080)")
    p.add_argument("--auth", help="Basic auth user:pass")
    p.add_argument("--recursive", action="store_true", help="Enable recursive scanning within discovered directories")
    p.add_argument("--max-depth", type=int, default=2, help="Max recursion depth when using --recursive")
    p.add_argument("--resume", action="store_true", help="Resume from output file (append and skip recorded URLs if file exists)")
    return p.parse_args()

def main():
    args = parse_args()
    print_banner()

    base_raw = normalize_target(args.url)
    # prepare headers for probe
    probe_headers = default_headers(args.random_agent)
    base = probe_scheme(base_raw, args.timeout, probe_headers, args.proxy)
    if args.verbose:
        safe_print(f"[+] Using base: {base}")

    # load wordlist
    try:
        entries = load_wordlist(args.wordlist)
    except Exception as e:
        safe_print(f"{RED}[!] Failed to open wordlist: {e}{RESET}")
        sys.exit(1)
    exts = [x.strip().lstrip(".") for x in args.extensions.split(",") if x.strip()] if args.extensions else []
    targets = expand_targets(entries, exts)
    if args.verbose:
        safe_print(f"[+] Wordlist entries: {len(entries)} -> build targets: {len(targets)}")

    # parse status filter
    status_filter = None
    if args.status:
        try:
            status_filter = set(int(s) for s in args.status.split(",") if s.strip())
        except ValueError:
            safe_print(f"{RED}[!] Invalid --status list (must be integers){RESET}")
            sys.exit(1)

    out_fp = None
    if args.output:
        mode = "a+" if args.resume else "w"
        try:
            out_fp = open(args.output, mode, buffering=1)  # line buffered
            if args.resume:
                try:
                    out_fp.seek(0)
                except Exception:
                    pass
        except Exception as e:
            safe_print(f"{RED}[!] Unable to open output file: {e}{RESET}")
            sys.exit(1)

    auth = None
    if args.auth:
        if ":" not in args.auth:
            safe_print(f"{RED}[!] --auth requires user:pass format{RESET}")
            sys.exit(1)
        user, pwd = args.auth.split(":", 1)
        auth = (user, pwd)

    # Pre-populate scanner
    scanner = VortexScanner(
        base=base,
        targets=targets,
        threads=args.threads,
        timeout=args.timeout,
        random_agent=args.random_agent,
        status_filter=status_filter,
        follow_redirects=not args.no_redirects,
        delay=args.delay,
        proxy=args.proxy,
        auth=auth,
        verbose=args.verbose,
        out_fp=out_fp,
        recursive=args.recursive,
        max_depth=args.max_depth,
        resume=args.resume,
        output_format=args.format
    )

    # Feed original entries to scanner.run for recursion use
    scanner.run(original_entries=entries)

    # After run, optionally output structured formats if requested and file provided
    if args.output and args.format in ("json", "csv"):
        try:
            # read the text lines and convert - easier than storing structured earlier
            out_fp.flush()
            out_fp.seek(0)
            lines = [ln.strip() for ln in out_fp if ln.strip()]
            # parse lines like: 200 https://example.com/foo (123 bytes, 0.12s)
            parsed = []
            for ln in lines:
                parts = ln.split()
                if len(parts) >= 2:
                    try:
                        code = int(parts[0])
                    except Exception:
                        continue
                    url = parts[1]
                    # try to find size in parentheses
                    size = None
                    elapsed = None
                    if "(" in ln and "bytes" in ln:
                        try:
                            inside = ln.split("(",1)[1].split(")")[0]
                            # "123 bytes, 0.12s"
                            if "bytes" in inside:
                                s = inside.split("bytes")[0].strip().strip(",")
                                size = int(s)
                            if "s" in inside:
                                elapsed = float(inside.split(",")[-1].strip().rstrip("s"))
                        except Exception:
                            pass
                    parsed.append({"status": code, "url": url, "size": size, "time": elapsed})
            if args.format == "json":
                # overwrite output file with json
                out_fp.seek(0)
                out_fp.truncate(0)
                out_fp.write(json.dumps(parsed, indent=2))
                out_fp.flush()
            elif args.format == "csv":
                import csv
                out_fp.seek(0)
                out_fp.truncate(0)
                writer = csv.DictWriter(out_fp, fieldnames=["status","url","size","time"])
                writer.writeheader()
                for row in parsed:
                    writer.writerow(row)
                out_fp.flush()
        except Exception:
            # ignore formatting errors
            pass

    # Show summary on console
    safe_print("\n[+] Scan finished.")
    if scanner.discovered:
        safe_print(f"[+] Found {len(scanner.discovered)} results.")
    else:
        safe_print("[+] No interesting results (based on filters).")

    if out_fp:
        out_fp.close()

if __name__ == "__main__":
    main()
