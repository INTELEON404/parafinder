#!/usr/bin/env python3
"""
ParaFinder
"""

import argparse
import asyncio
import csv
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Set, Optional

from urllib.parse import urlparse, parse_qs

import aiohttp
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich import box

# ==================== CONFIG & GLOBALS ====================
console = Console()
VERSION = "3.0"

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

BANNER = f"""
[bold cyan]╔═╗┌─┐┬─┐┌─┐┬─┐┌─┐┬─┐┌─┐┬─┐  ╔═╗╔═╗╦╔╗╔╔╦╗╔═╗╦═╗[/]
[bold cyan]╚═╗├┤ ├┬┘├┤ ├┬┘├─┤├┬┘├─┤├┬┘  ╠═╝║╣ ║║║║ ║ ║╣ ╠╦╝[/]
[bold cyan]╚═╝└─┘┴└─└─┘┴└─┴ ┴┴└─┴ ┴┴└─  ╩  ╚═╝╩╝╚╝ ╩ ╚═╝╩╚═[/]
[bold magenta]     ParaFinder  v{VERSION} - By INTELEON404 [/]
"""

# ==================== DATACLASS ====================
@dataclass
class Config:
    domain: str
    threads: int
    include: Optional[re.Pattern]
    exclude: Optional[re.Pattern]
    follow: bool
    rate_limit: float
    retries: int
    sources: Set[str]
    github_token: str
    samples: int
    outdir: str
    timeout: int
    fuzz: bool
    level: str
    api: bool
    gf: Optional[str]
    wordlist: Optional[str]
    depth: int
    subs: bool
    proxy: Optional[str]
    tor: bool
    download_archives: bool
    quiet: bool
    output_formats: List[str]
    jsonl: bool
    nuclei: bool

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

# ==================== SOURCES ====================
async def fetch_wayback(domain: str, cfg: Config, session: aiohttp.ClientSession) -> List[str]:
    params = {
        "url": f"*.{domain}/*" if cfg.subs else f"{domain}/*",
        "output": "text", "fl": "original", "collapse": "urlkey", "limit": "10000"
    }
    if cfg.level == "high":
        params["filter"] = "statuscode:200"
    async with session.get("https://web.archive.org/cdx/search/cdx", params=params) as r:
        text = await r.text() if r.status < 500 else ""
    urls = [normalize_url(line) for line in text.splitlines() if "?" in line and not has_skip_ext(line)]
    if cfg.download_archives:
        await download_archives(urls, cfg)
    return urls

async def download_archives(urls: List[str], cfg: Config):
    os.makedirs(f"{cfg.outdir}/archives", exist_ok=True)
    async with aiohttp.ClientSession() as sess:
        for u in urls[:100]:
            try:
                async with sess.get(u, timeout=10) as r:
                    if r.status == 200:
                        fname = f"{cfg.outdir}/archives/{hash(u)}.html"
                        with open(fname, "wb") as f:
                            f.write(await r.read())
            except:
                pass

async def fetch_otx(domain: str, cfg: Config, session: aiohttp.ClientSession) -> List[str]:
    async with session.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list") as r:
        data = await r.json() if r.status < 500 else {}
    return [u["url"] for u in data.get("url_list", []) if "?" in u["url"]]

async def fetch_urlscan(domain: str, cfg: Config, session: aiohttp.ClientSession) -> List[str]:
    async with session.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}") as r:
        data = await r.json() if r.status < 500 else {}
    return [t["page"]["url"] for t in data.get("results", []) if "?" in t["page"]["url"]]

# ==================== API DISCOVERY ====================
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
            except:
                pass
    return apis

# ==================== COLLECTOR ====================
async def collect_urls(cfg: Config) -> List[str]:
    sources = {
        "wayback": fetch_wayback,
        "otx": fetch_otx,
        "urlscan": fetch_urlscan,
    }
    active = cfg.sources or {"wayback", "otx", "urlscan"}

    connector = aiohttp.TCPConnector(limit=cfg.threads, ssl=False)
    timeout = aiohttp.ClientTimeout(total=cfg.timeout)
    proxy = f"http://{cfg.proxy}" if cfg.proxy else None
    if cfg.tor:
        proxy = "socks5://127.0.0.1:9050"

    headers = {"User-Agent": f"ParaFinder/{VERSION}"}
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
                    try:
                        data = await func(cfg.domain, cfg, session)
                        all_urls.extend(data)
                        progress.advance(task)
                        if not cfg.quiet:
                            console.print(f"[green][+] {name}: {len(data)} URLs[/]")
                    except Exception as e:
                        if not cfg.quiet:
                            console.print(f"[red][!] {name} failed: {e}[/]")

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

# ==================== OUTPUT ====================
def save_jsonl(urls: List[str], path: str):
    with open(path, "w") as f:
        for u in urls:
            f.write(json.dumps({"url": u}) + "\n")

def save_nuclei(result: dict, path: str):
    with open(path, "w") as f:
        for p in result["high_value"]:
            f.write(f"""
- id: parafinder-{p}
  info:
    name: High-risk parameter: {p}
    severity: high
  http:
    - method: GET
      path:
        - "{{{{BaseURL}}}}?{p}=FUZZ"
""")

# ==================== MAIN ====================
async def _main() -> None:
    parser = argparse.ArgumentParser(description=f"ParaFinder Ultra v{VERSION} - Professional Recon")
    parser.add_argument("-d", "--domain", required=True)
    parser.add_argument("-t", "--threads", type=int, default=50)
    parser.add_argument("--include", help="Include regex")
    parser.add_argument("--exclude", help="Exclude regex")
    parser.add_argument("--follow", action="store_true")
    parser.add_argument("--rate", type=int, default=0)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--sources", help="wayback,otx,urlscan")
    parser.add_argument("--github-token")
    parser.add_argument("--samples", type=int, default=8)
    parser.add_argument("--outdir", default="results")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--fuzz", action="store_true")
    parser.add_argument("--level", choices=["low", "high"], default="low")
    parser.add_argument("--api", action="store_true")
    parser.add_argument("--gf", choices=list(GF_PATTERNS.keys()))
    parser.add_argument("--wordlist")
    parser.add_argument("--depth", type=int, default=1)
    parser.add_argument("--subs", action="store_true")
    parser.add_argument("--proxy")
    parser.add_argument("--tor", action="store_true")
    parser.add_argument("--download-archives", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("-o", "--output", default="txt,json,csv,jsonl")
    parser.add_argument("--jsonl", action="store_true")
    parser.add_argument("--nuclei", action="store_true")

    args = parser.parse_args()

    cfg = Config(
        domain=args.domain,
        threads=min(args.threads, 100),
        include=re.compile(args.include) if args.include else None,
        exclude=re.compile(args.exclude) if args.exclude else None,
        follow=args.follow,
        rate_limit=args.rate,
        retries=args.retries,
        sources={s.strip().lower() for s in (args.sources or "").split(",") if s.strip()},
        github_token=args.github_token or "",
        samples=args.samples,
        outdir=args.outdir,
        timeout=args.timeout,
        fuzz=args.fuzz,
        level=args.level,
        api=args.api,
        gf=args.gf,
        wordlist=args.wordlist,
        depth=args.depth,
        subs=args.subs,
        proxy=args.proxy,
        tor=args.tor,
        download_archives=args.download_archives,
        quiet=args.quiet,
        output_formats=[f.strip().lower() for f in args.output.split(",")],
        jsonl=args.jsonl,
        nuclei=args.nuclei,
    )

    print_banner()
    start = time.time()
    base = f"parafinder_{args.domain.replace('.', '_')}_{int(time.time())}"

    urls = await collect_urls(cfg)
    if not urls:
        console.print("[red][!] No URLs found.[/]")
        return

    params = extract_params(urls)
    gf_pat = re.compile(GF_PATTERNS[cfg.gf], re.IGNORECASE) if cfg.gf else None
    scores, high = score_params(params, gf_pat)

    result = {
        "domain": cfg.domain,
        "urls": urls,
        "parameters": params,
        "high_value": high,
        "param_scores": scores,
        "scan_duration": f"{time.time() - start:.2f}s",
        "timestamp": datetime.now().isoformat(),
    }

    table = Table(title="RECON SUMMARY", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Target", cfg.domain)
    table.add_row("URLs Found", str(len(urls)))
    table.add_row("Unique Params", str(len(params)))
    table.add_row("High-Risk Params", str(len(high)))
    table.add_row("Duration", result["scan_duration"])
    console.print(table)

    os.makedirs(cfg.outdir, exist_ok=True)
    saved = []

    if "txt" in cfg.output_formats:
        path = f"{cfg.outdir}/{base}.txt"
        with open(path, "w") as f:
            f.write(f"ParaFinder Ultra v{VERSION}\nTarget: {cfg.domain}\n\n")
            f.write(f"Total URLs: {len(urls)}\nParams: {len(params)}\nHigh: {len(high)}\n\n")
            for p, c in sorted(params.items(), key=lambda x: x[1], reverse=True)[:20]:
                f.write(f"{p}: {c} [{scores[p]}]\n")
        saved.append(path)

    if "json" in cfg.output_formats:
        path = f"{cfg.outdir}/{base}.json"
        with open(path, "w") as f:
            json.dump(result, f, indent=2)
        saved.append(path)

    if "csv" in cfg.output_formats:
        path = f"{cfg.outdir}/{base}_params.csv"
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["param", "count", "score"])
            for p, c in sorted(params.items(), key=lambda x: x[1], reverse=True):
                w.writerow([p, c, scores[p]])
        saved.append(path)

    if cfg.jsonl:
        save_jsonl(urls, f"{cfg.outdir}/{base}.jsonl")

    if cfg.nuclei:
        save_nuclei(result, f"{cfg.outdir}/{base}_nuclei.yaml")

    console.print(f"\n[bold green]Scan complete! {len(saved)} files saved:[/]")
    for p in saved:
        console.print(f"  [green]→ {p}[/]")

# ==================== ENTRY POINT ====================
def main():
    """Entry point for pipx"""
    asyncio.run(_main())

if __name__ == "__main__":
    main()
