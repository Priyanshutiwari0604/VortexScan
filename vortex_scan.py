#!/usr/bin/env python3
"""
VORTEXSCAN - dirsearch-like directory & file discovery tool
Author: Tester (example)
Save as: vortexscan.py

Hybrid Output Mode:
 - Clean Professional Mode (default): Lightweight, dependency-free, color-coded
 - Advanced UI Mode: Auto-enabled if 'rich' is installed - tables, progress bars, live display
 - Machine-friendly export: CSV/JSON formats for automation

Goals:
 - Behave very similarly to dirsearch / gobuster for common usage patterns.
 - CLI flags: -u/--url, -w/--wordlist, -e/--extensions, -t/--threads, -T/--timeout,
   -v/--verbose, -o/--output, --random-agent, --status, --no-redirects, --delay,
   --proxy, --auth, --recursive, --max-depth, --resume, --format (text/csv/json)
 - Default hides 404s (like dirsearch).
 - Scheme probing: if user passes host without scheme, tool probes https then http.
 - Resume support writes/reads output file.
 - ThreadPoolExecutor for concurrency; requests.Session pooling.
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
from datetime import datetime

# ----- Detect rich library for advanced UI -----
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.live import Live
    from rich.panel import Panel
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# ----- Config & Banner -----
TOOL_NAME = "VORTEXSCAN"
VERSION = "2.0"
BANNER = r"""
╦  ╦╔═╗╦═╗╔╦╗╔═╗═╗ ╦  ╔═╗╔═╗╔═╗╔╗╔
╚╗╔╝║ ║╠╦╝ ║ ║╣ ╔╩╦╝  ╚═╗║  ╠═╣║║║
 ╚╝ ╚═╝╩╚═ ╩ ╚═╝╩ ╚═  ╚═╝╚═╝╩ ╩╝╚╝
    Directory & File Discovery Tool
"""
DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "curl/7.85.0",
    "Wget/1.21.3 (linux-gnu)",
]
PRINT_LOCK = Lock()

# Optional colors (if user has colorama or fallback to ANSI)
try:
    import colorama
    colorama.init(autoreset=True)
    RED = colorama.Fore.RED
    GREEN = colorama.Fore.GREEN
    YELLOW = colorama.Fore.YELLOW
    CYAN = colorama.Fore.CYAN
    BLUE = colorama.Fore.BLUE
    MAGENTA = colorama.Fore.MAGENTA
    RESET = colorama.Style.RESET_ALL
    BRIGHT = colorama.Style.BRIGHT
    DIM = colorama.Style.DIM
except Exception:
    # Fallback to ANSI codes
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    BRIGHT = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

# ----- Utilities -----
def safe_print(msg: str):
    with PRINT_LOCK:
        print(msg)

def print_banner(use_rich: bool = False):
    if use_rich and RICH_AVAILABLE:
        console = Console()
        console.print(BANNER, style="bold cyan")
        console.print(f"[bold]{TOOL_NAME}[/bold] v{VERSION} - Directory & File Discovery Tool", style="cyan")
        console.print("[yellow]⚠️  Only scan targets you own or have explicit permission to test.[/yellow]\n")
    else:
        print(f"{CYAN}{BRIGHT}{BANNER}{RESET}")
        print(f"{BRIGHT}[+] {TOOL_NAME} v{VERSION} - Directory & File Discovery Tool{RESET}")
        print(f"{YELLOW}[!] Only scan targets you own or have explicit permission to test.{RESET}\n")

def normalize_target(raw: str) -> str:
    """Return raw target; if missing scheme return as-is for probing later."""
    return raw.rstrip("/")

def probe_scheme(host: str, timeout: float, headers: Dict[str,str], proxy: Optional[str]) -> str:
    """If user didn't supply scheme, try https then http; return working base URL."""
    if host.startswith("http://") or host.startswith("https://"):
        return host.rstrip("/")
    for scheme in ("https://", "http://"):
        try:
            url = scheme + host
            s = requests.Session()
            if proxy:
                s.proxies.update({"http": proxy, "https": proxy})
            r = s.head(url, timeout=timeout, allow_redirects=True, headers=headers)
            return url.rstrip("/")
        except requests.RequestException:
            continue
    return "https://" + host

def load_wordlist(path: str) -> List[str]:
    with open(path, "r", errors="ignore") as fh:
        lines = [ln.strip() for ln in fh if ln.strip() and not ln.strip().startswith("#")]
    return lines

def expand_targets(entries: List[str], exts: List[str]) -> List[str]:
    """Build target list with extensions"""
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

def format_size(size: int) -> str:
    """Format bytes to human readable"""
    if size < 1024:
        return f"{size}B"
    elif size < 1024 * 1024:
        return f"{size/1024:.1f}KB"
    else:
        return f"{size/(1024*1024):.1f}MB"

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
        output_format: str = "text",
        use_rich: bool = False
    ):
        self.base = base.rstrip("/")
        self.targets_queue = Queue()
        for t in targets:
            self.targets_queue.put((t, 0))
        self.total_targets = len(targets)
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
        self.use_rich = use_rich and RICH_AVAILABLE
        self.discovered: List[Tuple[int,str,int,float]] = []
        self.recorded_set: Set[str] = set()
        self.stats_by_code: Dict[int, int] = {}
        self.processed_count = 0
        self.start_time = time.time()
        
        if resume and out_fp:
            try:
                out_fp.flush()
                out_fp.seek(0)
                for ln in out_fp:
                    ln = ln.strip()
                    if not ln:
                        continue
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
        parsed = urlparse(parent_url)
        parent_path = parsed.path.rstrip("/")
        if parent_path == "":
            parent_path = "/"
        for e in original_entries:
            if e.startswith("http://") or e.startswith("https://"):
                continue
            new_path = (parent_path + "/" + e.lstrip("/")).lstrip("/")
            self.targets_queue.put((new_path, depth + 1))

    def _format_clean_output(self, code: int, url: str, size: int, elapsed: float) -> str:
        """Clean professional output format"""
        status_str = f"[{code}]"
        size_str = format_size(size)
        time_str = f"{elapsed:.2f}s"
        
        # Truncate URL if too long
        max_url_len = 70
        display_url = url if len(url) <= max_url_len else url[:max_url_len-3] + "..."
        
        return f"{status_str:7} {display_url:72} {size_str:>10} {time_str:>8}"

    def _get_status_color(self, code: int) -> str:
        """Get color for status code"""
        if 200 <= code < 300:
            return f"{GREEN}{BRIGHT}"
        elif 300 <= code < 400:
            return CYAN
        elif code == 403:
            return f"{YELLOW}{BRIGHT}"
        elif 400 <= code < 500:
            return YELLOW
        else:
            return RED

    def worker(self, original_entries: List[str], progress_callback=None):
        session = self._make_session()
        while self.running:
            try:
                path, depth = self.targets_queue.get(timeout=1)
            except Empty:
                return
            
            url = urljoin(self.base + "/", path.lstrip("/"))
            
            if is_url_already_recorded(url, self.recorded_set):
                self.targets_queue.task_done()
                self.processed_count += 1
                if progress_callback:
                    progress_callback()
                continue
            
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
                    safe_print(f"{YELLOW}[!] {url}: {e}{RESET}")
                self.targets_queue.task_done()
                self.processed_count += 1
                if progress_callback:
                    progress_callback()
                continue

            if final_url in self.recorded_set:
                self.targets_queue.task_done()
                self.processed_count += 1
                if progress_callback:
                    progress_callback()
                continue
            
            self.stats_by_code[code] = self.stats_by_code.get(code, 0) + 1
            
            if self._interesting(code):
                self.discovered.append((code, final_url, size, elapsed))
                
                if not self.use_rich:
                    # Clean professional output
                    line = self._format_clean_output(code, final_url, size, elapsed)
                    color = self._get_status_color(code)
                    safe_print(f"{color}{line}{RESET}")
                
                try:
                    if self.out_fp:
                        self.out_fp.write(f"{code} {final_url} ({size} bytes, {elapsed:.2f}s)\n")
                        self.out_fp.flush()
                except Exception:
                    pass

                if self.recursive and depth < self.max_depth:
                    ctype = resp.headers.get("Content-Type", "")
                    lastseg = urlparse(final_url).path.rstrip("/").split("/")[-1]
                    if (code == 200 and "text/html" in ctype.lower() and "." not in lastseg) or final_url.endswith("/"):
                        self._enqueue_recursive_children(final_url, depth, original_entries)
            else:
                if self.verbose and not self.use_rich:
                    safe_print(f"{DIM}[{code}] {url} [{elapsed:.2f}s]{RESET}")

            self.recorded_set.add(final_url)
            self.targets_queue.task_done()
            self.processed_count += 1
            if progress_callback:
                progress_callback()

    def run_clean_mode(self, original_entries: List[str]):
        """Clean professional mode output"""
        # Header
        safe_print(f"\n{BLUE}{'═'*100}{RESET}")
        safe_print(f"{BRIGHT}{'SCAN CONFIGURATION':^100}{RESET}")
        safe_print(f"{BLUE}{'═'*100}{RESET}")
        safe_print(f"  {BRIGHT}Target:{RESET}      {self.base}")
        safe_print(f"  {BRIGHT}Wordlist:{RESET}    {len(original_entries)} entries → {self.total_targets} targets (with extensions)")
        safe_print(f"  {BRIGHT}Threads:{RESET}     {self.threads}")
        safe_print(f"  {BRIGHT}Timeout:{RESET}     {self.timeout}s")
        if self.status_filter:
            safe_print(f"  {BRIGHT}Filter:{RESET}      Status codes: {','.join(map(str, sorted(self.status_filter)))}")
        else:
            safe_print(f"  {BRIGHT}Filter:{RESET}      All except 404")
        safe_print(f"  {BRIGHT}Started:{RESET}     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        safe_print(f"{BLUE}{'═'*100}{RESET}\n")
        
        # Column headers
        safe_print(f"{DIM}{'STATUS':7} {'URL':72} {'SIZE':>10} {'TIME':>8}{RESET}")
        safe_print(f"{DIM}{'-'*100}{RESET}")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = [ex.submit(self.worker, original_entries) for _ in range(self.threads)]
            try:
                self.targets_queue.join()
            except KeyboardInterrupt:
                safe_print(f"\n{YELLOW}[!] Interrupted by user - stopping...{RESET}")
                self.running = False
            
            for f in futures:
                try:
                    f.cancel()
                except Exception:
                    pass

    def run_rich_mode(self, original_entries: List[str]):
        """Advanced UI mode with rich library"""
        console = Console()
        
        # Configuration panel
        config_text = f"""[bold cyan]Target:[/bold cyan] {self.base}
[bold cyan]Wordlist:[/bold cyan] {len(original_entries)} entries → {self.total_targets} targets
[bold cyan]Threads:[/bold cyan] {self.threads}  [bold cyan]Timeout:[/bold cyan] {self.timeout}s
[bold cyan]Filter:[/bold cyan] {"Status: " + ",".join(map(str, sorted(self.status_filter))) if self.status_filter else "All except 404"}"""
        
        console.print(Panel(config_text, title="[bold]Scan Configuration[/bold]", border_style="blue"))
        
        # Live results table
        results_table = Table(show_header=True, header_style="bold cyan", box=box.ROUNDED)
        results_table.add_column("Status", style="bold", width=8)
        results_table.add_column("URL", style="", width=60)
        results_table.add_column("Size", justify="right", width=10)
        results_table.add_column("Time", justify="right", width=8)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            TimeElapsedColumn(),
            console=console,
            transient=False
        ) as progress:
            
            scan_task = progress.add_task("[cyan]Scanning...", total=self.total_targets)
            
            def update_progress():
                progress.update(scan_task, completed=self.processed_count)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
                futures = [ex.submit(self.worker, original_entries, update_progress) for _ in range(self.threads)]
                try:
                    self.targets_queue.join()
                except KeyboardInterrupt:
                    console.print("\n[yellow]⚠️  Interrupted by user - stopping...[/yellow]")
                    self.running = False
                
                for f in futures:
                    try:
                        f.cancel()
                    except Exception:
                        pass
        
        # Show results in table
        if self.discovered:
            console.print("\n")
            for code, url, size, elapsed in self.discovered:
                style = "green bold" if 200 <= code < 300 else "cyan" if 300 <= code < 400 else "yellow bold" if code == 403 else "yellow" if 400 <= code < 500 else "red"
                results_table.add_row(
                    f"[{style}]{code}[/{style}]",
                    url[:60] + "..." if len(url) > 60 else url,
                    format_size(size),
                    f"{elapsed:.2f}s"
                )
            
            console.print(results_table)

    def run(self, original_entries: List[str]):
        if self.use_rich:
            self.run_rich_mode(original_entries)
        else:
            self.run_clean_mode(original_entries)

    def print_summary(self):
        """Print detailed summary"""
        elapsed_total = time.time() - self.start_time
        
        if self.use_rich and RICH_AVAILABLE:
            console = Console()
            
            # Summary panel
            summary_text = f"[bold]Total Findings:[/bold] {len(self.discovered)}\n"
            summary_text += f"[bold]Scan Duration:[/bold] {elapsed_total:.2f}s\n"
            summary_text += f"[bold]Requests/sec:[/bold] {self.processed_count/elapsed_total:.2f}\n\n"
            
            if self.stats_by_code:
                summary_text += "[bold]Status Distribution:[/bold]\n"
                for code in sorted(self.stats_by_code.keys()):
                    style = "green" if 200 <= code < 300 else "cyan" if 300 <= code < 400 else "yellow" if 400 <= code < 500 else "red"
                    summary_text += f"  [{style}][{code}][/{style}] - {self.stats_by_code[code]} responses\n"
            
            console.print(Panel(summary_text, title="[bold]Scan Summary[/bold]", border_style="green"))
            
            # Highlight 200 responses
            success_responses = [(c, u, s, e) for c, u, s, e in self.discovered if c == 200]
            if success_responses:
                console.print("\n[bold green]  SUCCESS RESPONSES (200 OK):[/bold green]")
                for code, url, size, elapsed in success_responses:
                    console.print(f"  [green]✓[/green] {url} [{format_size(size)}] [{elapsed:.2f}s]")
        else:
            # Clean mode summary
            safe_print(f"\n{BLUE}{'═'*100}{RESET}")
            safe_print(f"{BRIGHT}{'SCAN SUMMARY':^100}{RESET}")
            safe_print(f"{BLUE}{'═'*100}{RESET}")
            safe_print(f"  {BRIGHT}Total Findings:{RESET}   {len(self.discovered)}")
            safe_print(f"  {BRIGHT}Scan Duration:{RESET}    {elapsed_total:.2f}s")
            safe_print(f"  {BRIGHT}Requests/sec:{RESET}     {self.processed_count/elapsed_total:.2f}")
            
            if self.stats_by_code:
                safe_print(f"\n  {BRIGHT}Status Distribution:{RESET}")
                for code in sorted(self.stats_by_code.keys()):
                    color = self._get_status_color(code)
                    safe_print(f"    {color}[{code}]{RESET} - {self.stats_by_code[code]} responses")
            
            # Highlight 200 responses
            success_responses = [(c, u, s, e) for c, u, s, e in self.discovered if c == 200]
            if success_responses:
                safe_print(f"\n{GREEN}{BRIGHT}{'═'*100}{RESET}")
                safe_print(f"{GREEN}{BRIGHT}  🎯 SUCCESS RESPONSES (200 OK): {len(success_responses)} found{RESET}")
                safe_print(f"{GREEN}{BRIGHT}{'═'*100}{RESET}")
                for code, url, size, elapsed in success_responses:
                    safe_print(f"{GREEN}  ✓ {url:75} [{format_size(size):>8}] [{elapsed:.2f}s]{RESET}")
            
            # Other interesting responses
            other_responses = [(c, u, s, e) for c, u, s, e in self.discovered if c != 200]
            if other_responses:
                safe_print(f"\n{BRIGHT}  OTHER FINDINGS:{RESET}")
                for code, url, size, elapsed in other_responses:
                    color = self._get_status_color(code)
                    symbol = "↪" if 300 <= code < 400 else "⊗" if code == 403 else "!" if 400 <= code < 500 else "✗"
                    safe_print(f"{color}  {symbol} [{code}] {url:70} [{format_size(size):>8}] [{elapsed:.2f}s]{RESET}")
            
            safe_print(f"{BLUE}{'═'*100}{RESET}\n")

# ----- CLI parsing & main -----
def parse_args():
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=f"{TOOL_NAME} v{VERSION} - Directory & File Discovery (use only on permitted targets)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Output Modes:
  Clean Professional Mode (default) - Lightweight, color-coded, aligned output
  Advanced UI Mode (auto-enabled)   - Rich tables & progress bars (requires 'rich' library)
  
Examples:
  %(prog)s -u https://example.com -w wordlist.txt
  %(prog)s -u example.com -w dirs.txt -e php,html,txt -t 50
  %(prog)s -u https://example.com -w wordlist.txt -o results.txt --format json
        """
    )
    p.add_argument("-u", "--url", required=True, help="Target URL or host")
    p.add_argument("-w", "--wordlist", required=True, help="Wordlist file")
    p.add_argument("-e", "--extensions", default="", help="Extensions (e.g. php,html,txt)")
    p.add_argument("-t", "--threads", type=int, default=40, help="Threads (default: 40)")
    p.add_argument("-T", "--timeout", type=float, default=10.0, help="Timeout in seconds (default: 10)")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    p.add_argument("--random-agent", action="store_true", help="Rotate user agents")
    p.add_argument("-o", "--output", help="Output file")
    p.add_argument("--format", choices=["text","json","csv"], default="text", help="Output format (default: text)")
    p.add_argument("--status", default="", help="Status codes filter (e.g. 200,301,403)")
    p.add_argument("--no-redirects", action="store_true", help="Don't follow redirects")
    p.add_argument("--delay", type=float, default=0.0, help="Delay between requests")
    p.add_argument("--proxy", help="Proxy URL")
    p.add_argument("--auth", help="Basic auth (user:pass)")
    p.add_argument("--recursive", action="store_true", help="Recursive scanning")
    p.add_argument("--max-depth", type=int, default=2, help="Max recursion depth (default: 2)")
    p.add_argument("--resume", action="store_true", help="Resume from output file")
    p.add_argument("--no-rich", action="store_true", help="Disable rich UI (use clean mode)")
    return p.parse_args()

def main():
    args = parse_args()
    
    # Determine UI mode
    use_rich = RICH_AVAILABLE and not args.no_rich
    
    if use_rich:
        safe_print(f"{GREEN}[✓] Advanced UI Mode enabled (rich library detected){RESET}")
    else:
        if not RICH_AVAILABLE and not args.no_rich:
            safe_print(f"{YELLOW}[i] Clean Professional Mode (install 'rich' for advanced UI: pip install rich){RESET}")
    
    print_banner(use_rich)

    base_raw = normalize_target(args.url)
    probe_headers = default_headers(args.random_agent)
    base = probe_scheme(base_raw, args.timeout, probe_headers, args.proxy)
    
    try:
        entries = load_wordlist(args.wordlist)
    except Exception as e:
        safe_print(f"{RED}[!] Failed to load wordlist: {e}{RESET}")
        sys.exit(1)
    
    exts = [x.strip().lstrip(".") for x in args.extensions.split(",") if x.strip()] if args.extensions else []
    targets = expand_targets(entries, exts)

    status_filter = None
    if args.status:
        try:
            status_filter = set(int(s) for s in args.status.split(",") if s.strip())
        except ValueError:
            safe_print(f"{RED}[!] Invalid --status format{RESET}")
            sys.exit(1)

    out_fp = None
    if args.output:
        mode = "a+" if args.resume else "w"
        try:
            out_fp = open(args.output, mode, buffering=1)
            if args.resume:
                try:
                    out_fp.seek(0)
                except Exception:
                    pass
        except Exception as e:
            safe_print(f"{RED}[!] Cannot open output file: {e}{RESET}")
            sys.exit(1)

    auth = None
    if args.auth:
        if ":" not in args.auth:
            safe_print(f"{RED}[!] --auth requires user:pass format{RESET}")
            sys.exit(1)
        user, pwd = args.auth.split(":", 1)
        auth = (user, pwd)

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
        output_format=args.format,
        use_rich=use_rich
    )

    scanner.run(original_entries=entries)

    # Print summary
    scanner.print_summary()

    # Export to structured formats if requested
    if args.output and args.format in ("json", "csv"):
        try:
            out_fp.flush()
            out_fp.seek(0)
            lines = [ln.strip() for ln in out_fp if ln.strip()]
            parsed = []
            for ln in lines:
                parts = ln.split()
                if len(parts) >= 2:
                    try:
                        code = int(parts[0])
                    except Exception:
                        continue
                    url = parts[1]
                    size = None
                    elapsed = None
                    if "(" in ln and "bytes" in ln:
                        try:
                            inside = ln.split("(",1)[1].split(")")[0]
                            if "bytes" in inside:
                                s = inside.split("bytes")[0].strip().strip(",")
                                size = int(s)
                            if "s" in inside:
                                elapsed = float(inside.split(",")[-1].strip().rstrip("s"))
                        except Exception:
                            pass
                    parsed.append({"status": code, "url": url, "size": size, "time": elapsed})
            
            if args.format == "json":
                out_fp.seek(0)
                out_fp.truncate(0)
                out_fp.write(json.dumps(parsed, indent=2))
                out_fp.flush()
                safe_print(f"{GREEN}[✓] Results exported to {args.output} (JSON format){RESET}")
            elif args.format == "csv":
                import csv
                out_fp.seek(0)
                out_fp.truncate(0)
                writer = csv.DictWriter(out_fp, fieldnames=["status","url","size","time"])
                writer.writeheader()
                for row in parsed:
                    writer.writerow(row)
                out_fp.flush()
                safe_print(f"{GREEN}[✓] Results exported to {args.output} (CSV format){RESET}")
        except Exception as e:
            safe_print(f"{YELLOW}[!] Export warning: {e}{RESET}")

    if out_fp:
        out_fp.close()

if __name__ == "__main__":
    main()
