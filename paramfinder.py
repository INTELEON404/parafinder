#!/usr/bin/env python3

import argparse
import asyncio
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Set, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import aiohttp
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich import box

# ==================== CONFIG & GLOBALS ====================
console = Console()
VERSION = "3.0"
FUZZ = "FUZZ"

SKIP_EXT = {
    ".jpg", ".jpeg", ".png", ".gif", ".css", ".js", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".pdf", ".zip", ".mp4", ".mp3", ".avi", ".exe", ".iso", ".apk"
}

HIGH_RISK = {
    "auth", "token", "password", "pass", "session", "secret", "cmd", "exec", "eval",
    "admin", "key", "api", "jwt", "bearer", "oauth", "client_id", "client_secret"
}
MED_RISK = {
    "id", "user", "uid", "redirect", "next", "page", "q", "query", "search", "ref",
    "return", "callback", "url", "path", "file", "dir", "debug", "test"
}

API_ROUTES = [
    "api", "v1", "v2", "rest", "graphql", "admin", "login", "auth", "oauth",
    "users", "profile", "settings", "config", "health", "status", "ping",
    "metrics", "debug", "test", "upload", "download", "search", "query"
]

GF_PATTERNS = {
    "ssrf": r"(?i)(url|redirect|next|dest|callback|to|ref|return|domain|host|path|uri|port|site)",
    "xss": r"(?i)(input|query|search|q|msg|error|title|name|value|text|html|body|script|src|href|on\w+)",
    "lfi": r"(?i)(file|document|folder|root|path|pg|style|pdf|template|php_path|doc|page|cat|dir|action|board)",
    "rce": r"(?i)(cmd|exec|command|daemon|upload|dir|download|log|ip|cli|ping|code|reg|do|func|run|print)",
    "sqli": r"(?i)(id|select|union|from|where|order|limit|insert|update|delete|drop|database|table|user)",
    "idor": r"(?i)(id|user|uid|account|profile|customer|client|record|entry|item|object|doc|file)",
    "ssti": r"(?i)(template|tpl|render|view|layout|theme|block|section|partial|include|extends)",
}

# YOUR CUSTOM ASCII ART + CLEAN BANNER
BANNER = f"""
[bold white]░█▀█░█▀█░█▀▄░█▀█░█▀▀░▀█▀░█▀█░█▀▄░█▀▀░█▀▄[/]
[bold white]░█▀▀░█▀█░█▀▄░█▀█░█▀▀░░█░░█░█░█░█░█▀▀░█▀▄[/]
[bold white]░▀░░░▀░▀░▀░▀░▀░▀░▀░░░▀▀▀░▀░▀░▀▀░░▀▀▀░▀░▀[/]

[bold yellow]  Parafinder - v{VERSION} - by INTELEON404 [/]
"""

# ==================== DATACLASS ====================
@dataclass
class Config:
    domain: str
    threads: int
    include: Optional[re.Pattern]
    exclude: Optional[re.Pattern]
    rate_limit: float
    retries: int
    sources: Set[str]
    outdir: str
    timeout: int
    gf: Optional[str]
    subs: bool
    proxy: Optional[str]
    tor: bool
    download_archives: bool
    quiet: bool
    api: bool

# ==================== HELPERS ====================
def print_banner():
    if console.is_terminal:
        console.print(BANNER)

def normalize_url(u: str) -> str:
    return u.strip().split("#")[0].rstrip("/")

def has_skip_ext(u: str) -> bool:
    return any(u.lower().endswith(ext) for ext in SKIP_EXT)

def dedupe(urls: List[str]) -> List[str]:
    seen = set()
    return [u for u in urls if (nu := normalize_url(u)) and nu not in seen and not seen.add(nu)]

def extract_params(urls: List[str]) -> Dict[str, int]:
    params = {}
    for u in urls:
        qs = urlparse(u).query
        for k in parse_qs(qs, keep_blank_values=True):
            k = k.lower()
            params[k] = params.get(k, 0) + 1
    return params

def score_params(params: Dict[str, int], gf_pat: Optional[re.Pattern]) -> tuple[Dict[str, str], List[str]]:
    scores = {}
    high = []
    for p in params:
        l = p.lower()
        score = "low"
        if any(r in l for r in HIGH_RISK):
            score = "high"
        elif any(r in l for r in MED_RISK):
            score = "medium"
        if gf_pat and gf_pat.search(p):
            score = f"{score}-gf"
        scores[p] = score
        if "high" in score:
            high.append(p)
    return scores, high

# === FUZZ INJECTION ===
def inject_fuzz(url: str) -> str:
    """Replace all parameter values with FUZZ, keep param names."""
    parsed = urlparse(url)
    if not parsed.query:
        return url

    params = parse_qs(parsed.query, keep_blank_values=True)
    fuzz_params = {k: [FUZZ] for k in params.keys()}
    new_query = urlencode(fuzz_params, doseq=True)
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_query, parsed.fragment
    ))

# ==================== SOURCES ====================
async def fetch_wayback(domain: str, cfg: Config, session: aiohttp.ClientSession) -> List[str]:
    search = f"*.{domain}/*" if cfg.subs else f"{domain}/*"
    params = {"url": search, "output": "text", "fl": "original", "collapse": "urlkey", "limit": "10000"}
    try:
        async with session.get("https://web.archive.org/cdx/search/cdx", params=params, timeout=30) as r:
            if r.status >= 500: return []
            text = await r.text()
        urls = [normalize_url(line) for line in text.splitlines() if "?" in line and not has_skip_ext(line)]
        if cfg.download_archives:
            await download_archives(urls, cfg)
        return urls
    except Exception as e:
        if not cfg.quiet:
            console.print(f"[red][!] wayback: {e}[/]")
        return []

async def download_archives(urls: List[str], cfg: Config):
    os.makedirs(f"{cfg.outdir}/archives", exist_ok=True)
    async with aiohttp.ClientSession() as sess:
        for u in urls[:50]:
            try:
                async with sess.get(u, timeout=10) as r:
                    if r.status == 200:
                        fname = f"{cfg.outdir}/archives/{hash(u)}.html"
                        with open(fname, "wb") as f:
                            f.write(await r.read())
            except: pass

async def fetch_otx(domain: str, cfg: Config, session: aiohttp.ClientSession) -> List[str]:
    try:
        async with session.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list") as r:
            if r.status >= 500: return []
            data = await r.json()
        return [u["url"] for u in data.get("url_list", []) if "?" in u["url"]]
    except Exception as e:
        if not cfg.quiet:
            console.print(f"[red][!] otx: {e}[/]")
        return []

async def fetch_urlscan(domain: str, cfg: Config, session: aiohttp.ClientSession) -> List[str]:
    try:
        async with session.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}") as r:
            if r.status >= 500: return []
            data = await r.json()
        return [t["page"]["url"] for t in data.get("results", []) if "?" in t["page"]["url"]]
    except Exception as e:
        if not cfg.quiet:
            console.print(f"[red][!] urlscan: {e}[/]")
        return []

async def discover_apis(domain: str, cfg: Config, session: aiohttp.ClientSession) -> List[str]:
    base = f"https://{domain}"
    apis = []
    for route in API_ROUTES:
        for method in ["GET", "POST"]:
            url = f"{base}/{route}"
            try:
                async with session.request(method, url, timeout=5) as r:
                    if r.status < 500:
                        apis.append(url)
            except: pass
    return apis

# ==================== COLLECTOR ====================
async def collect_urls(cfg: Config) -> List[str]:
    sources = {"wayback": fetch_wayback, "otx": fetch_otx, "urlscan": fetch_urlscan}
    active = cfg.sources or sources.keys()

    connector = aiohttp.TCPConnector(limit=cfg.threads, ssl=False)
    timeout = aiohttp.ClientTimeout(total=cfg.timeout)
    proxy = f"http://{cfg.proxy}" if cfg.proxy else None
    if cfg.tor:
        proxy = "socks5://127.0.0.1:9050"

    headers = {"User-Agent": f"Parafinder/{VERSION}"}
    async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
        if proxy:
            session.proxy = proxy

        all_urls = []
        with Progress(
            SpinnerColumn(), TextColumn("[bold blue]{task.description}"),
            BarColumn(), "[progress.percentage]{task.percentage:>3.0f}%",
            TimeRemainingColumn(), console=console, transient=cfg.quiet
        ) as progress:
            task = progress.add_task(f"Collecting from {len(active)} sources", total=len(active))
            semaphore = asyncio.Semaphore(cfg.threads)

            async def run_source(name, func):
                async with semaphore:
                    data = await func(cfg.domain, cfg, session)
                    all_urls.extend(data)
                    progress.advance(task)
                    if not cfg.quiet and data:
                        console.print(f"[green][+] {name}: {len(data)} URLs[/]")

            await asyncio.gather(*(run_source(n, f) for n, f in sources.items() if n in active))

        urls = dedupe(all_urls)
        if cfg.include:
            urls = [u for u in urls if cfg.include.search(u)]
        if cfg.exclude:
            urls = [u for u in urls if not cfg.exclude.search(u)]
        if cfg.gf:
            pat = re.compile(GF_PATTERNS[cfg.gf], re.IGNORECASE)
            urls = [u for u in urls if pat.search(u)]
        if cfg.api:
            apis = await discover_apis(cfg.domain, cfg, session)
            urls.extend(apis)
        return dedupe(urls)

# ==================== OUTPUT (TXT ONLY - FUZZ INJECTED) ====================
def save_txt_only(domain: str, urls: List[str], params: Dict[str, int], scores: Dict[str, str], high: List[str], duration: float, outdir: str):
    os.makedirs(outdir, exist_ok=True)
    filename = f"{domain}.txt"
    path = os.path.join(outdir, filename)

    # Inject FUZZ into all URLs
    fuzz_urls = [inject_fuzz(u) for u in urls]

    with open(path, "w") as f:
        f.write(f"# Parafinder Results for: {domain}\n")
        f.write(f"# Scanned on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Duration: {duration:.2f}s\n")
        f.write(f"# Total URLs: {len(fuzz_urls)}\n")
        f.write(f"# Unique Parameters: {len(params)}\n")
        f.write(f"# High-Risk Parameters: {len(high)}\n")
        f.write(f"# Generated by Parafinder v{VERSION} - FUZZ Ready\n\n")

        f.write("#" + "="*78 + "\n")
        f.write("# TOP 20 PARAMETERS\n")
        f.write("#" + "="*78 + "\n")
        for p, c in sorted(params.items(), key=lambda x: x[1], reverse=True)[:20]:
            f.write(f"# {p:<25} {c:>6}  [{scores.get(p, 'low')}]\n")
        f.write("\n")

        f.write("#" + "="*78 + "\n")
        f.write("# FUZZ-READY URLs (ParamSpider Style)\n")
        f.write("#" + "="*78 + "\n")
        for u in fuzz_urls:
            f.write(u + "\n")

    return path

# ==================== MAIN ====================
async def _main() -> None:
    parser = argparse.ArgumentParser(description=f"Parafinder v{VERSION} - Parameter Discovery Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. tesla.com)")
    parser.add_argument("-t", "--threads", type=int, default=50)
    parser.add_argument("--include", help="Include regex")
    parser.add_argument("--exclude", help="Exclude regex")
    parser.add_argument("--sources", help="wayback,otx,urlscan")
    parser.add_argument("--outdir", default="results")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--gf", choices=list(GF_PATTERNS.keys()))
    parser.add_argument("--subs", action="store_true", help="Include subdomains")
    parser.add_argument("--proxy")
    parser.add_argument("--tor", action="store_true")
    parser.add_argument("--download-archives", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--api", action="store_true", help="Discover API endpoints")

    args = parser.parse_args()

    cfg = Config(
        domain=args.domain.lower().strip(),
        threads=min(args.threads, 100),
        include=re.compile(args.include) if args.include else None,
        exclude=re.compile(args.exclude) if args.exclude else None,
        rate_limit=0,
        retries=2,
        sources={s.strip().lower() for s in (args.sources or "").split(",") if s.strip()},
        outdir=args.outdir,
        timeout=args.timeout,
        gf=args.gf,
        subs=args.subs,
        proxy=args.proxy,
        tor=args.tor,
        download_archives=args.download_archives,
        quiet=args.quiet,
        api=args.api,
    )

    print_banner()
    start = time.time()

    urls = await collect_urls(cfg)
    if not urls:
        console.print("[red][!] No URLs with parameters found.[/]")
        return

    params = extract_params(urls)
    gf_pat = re.compile(GF_PATTERNS[cfg.gf], re.IGNORECASE) if cfg.gf else None
    scores, high = score_params(params, gf_pat)

    duration = time.time() - start
    output_file = save_txt_only(cfg.domain, urls, params, scores, high, duration, cfg.outdir)

    table = Table(title="SCAN SUMMARY", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Target", cfg.domain)
    table.add_row("URLs", str(len(urls)))
    table.add_row("Params", str(len(params)))
    table.add_row("High-Risk", str(len(high)))
    table.add_row("Time", f"{duration:.2f}s")
    table.add_row("Output", output_file)
    console.print(table)

    console.print(f"\n[bold green]Results saved to:[/] [cyan]{output_file}[/]")
    console.print(f"[bold yellow]Use with ffuf, ParamSpider, or Burp Intruder: FUZZ = injection point[/]")

# ==================== ENTRY POINT ====================
def main():
    asyncio.run(_main())

if __name__ == "__main__":
    main()
