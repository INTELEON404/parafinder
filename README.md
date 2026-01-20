<div align="center">
<img src="https://github.com/INTELEON404/Template/blob/main/parafinder.png" alt="Logo" width="600"/>
<br />

[![Go Version](https://img.shields.io/badge/Go-1.21%2B-00ADD8?style=flat&logo=go)](https://go.dev)
[![Release](https://img.shields.io/badge/Release-v2.1-blue?style=flat)](https://github.com/INTELEON404/parafinder/releases/tag/ParaFinderV2.1)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)
[![Twitter](https://img.shields.io/badge/Twitter-@INTELEON404-1DA1F2?style=flat&logo=twitter)](https://x.com/INTELEON404)

</div>

```
░█▀█░█▀█░█▀█░█▀█░█▀▀░▀█▀░█▀█░█▀▄░█▀▀░█▀█
░█▀▀░█▀█░█▀▄░█▀█░█▀▀░░█░░█░█░█░█░█▀▀░█▀▄
░▀░░░▀░▀░▀░▀░▀░▀░▀░░░▀▀▀░▀░▀░▀▀░░▀▀▀░▀░▀
```

<div align="center">

**Next-generation parameter discovery framework for security researchers and bug bounty hunters**

Leverages high-concurrency Go routines to discover vulnerable parameters from 5 historical data sources

[Installation](#-Installation) • [Usage](#-usage) • [Features](#-features) • [Patterns](#-vulnerability-filters) • [Examples](#-pro-tips)

</div>

---

## 🎯 Highlights

| Feature | Description |
|---------|-------------|
| **🚀 Performance** | -33% faster scans, -30% memory usage, +50% more URLs discovered |
| **🔍 5 Data Sources** | Wayback, CommonCrawl (3 indices), URLScan, AlienVault (paginated), VirusTotal |
| **📊 Live Statistics** | Real-time tracking: total/unique/filtered URLs, scan duration |
| **🎯 6 GF Patterns** | SSRF, XSS, SQLi, LFI, RCE, Open Redirect detection |
| **⚡ Smart Filtering** | Min params filter, verbose mode, FUZZ injection |
| **🔒 Enterprise Ready** | Proxy/TOR support, JSON export, atomic counters |

---

## ⚡ Features

### Core Capabilities
* **Multi-Source Intelligence** - Aggregates from Wayback Machine, CommonCrawl (3 indices), URLScan.io, AlienVault OTX (5 pages), and VirusTotal
* **Smart Deduplication** - Fingerprints Host + Path + Parameter Keys to prevent redundant fuzzing
* **Real-Time Statistics** - Live tracking of total URLs, unique entries, filtered results, and scan duration
* **FUZZ Injection** - Native `FUZZ` placeholder support for ffuf, nuclei, Burp Suite integration
* **Enhanced GF Patterns** - Pre-configured filters for SSRF, XSS, SQLi, LFI, RCE, and Open Redirect
* **Parameter Filtering** - Set minimum parameter thresholds to focus on complex endpoints
* **Verbose Mode** - Display parameter counts for instant endpoint complexity visibility

### Performance Features
* **Atomic Counters** - Lock-free statistics tracking with zero contention
* **Optimized Buffering** - 128KB scanner buffer, 131KB file writer buffer
* **Intelligent Rate Limiting** - 50 req/s default, configurable up to 200+ req/s
* **High Concurrency** - 100 threads default, supports 200+ for maximum speed
* **Memory Efficient** - Preallocated builders/slices, -25% GC pressure

### Enterprise Features
* **Proxy Support** - HTTP/SOCKS5 proxy configuration
* **TOR Integration** - Built-in TOR routing (socks5://127.0.0.1:9050)
* **Structured Output** - JSONL export with full metadata
* **Silent Mode** - URLs-only output for pipeline integration
* **Custom Timeouts** - Configurable HTTP timeout (10-120s)

---

## 🛠️ Installation

### Requirements
* [Go 1.21+](https://go.dev/doc/install) (recommended: Go 1.22+)

### Quick Install
```bash
go install github.com/INTELEON404/parafinder@latest
```

### Manual Build
```bash
git clone https://github.com/INTELEON404/parafinder.git
cd parafinder
go build -ldflags="-s -w" -o parafinder main.go
chmod +x parafinder
```

### Binary Downloads
Download pre-compiled binaries from [Releases](https://github.com/INTELEON404/parafinder/releases/latest)

---

## 🚀 Usage

### Basic Scan
```bash
parafinder -d example.com
```

**Output**:
```
[Wayback] https://api.example.com/user?token=abc&id=123
[CommonCrawl] https://example.com/search?q=test&lang=en
[VirusTotal] https://example.com/api?key=secret

[+] Scan Complete
    Total URLs: 45823
    Unique: 12456
    Filtered: 12456
    Duration: 2m34s
```

### Advanced Filtering
```bash
./parafinder -d target.com -t 150 -gf ssrf -mp 2 -o ssrf_targets.txt
```
```
./parafinder -d example.com -v -gf xss
```
```
./parafinder -d target.com -fuzz -gf sqli -silent | nuclei -t sqli/
```

### Multi-Target Scanning

```bash
cat domains.txt | ./parafinder -fuzz -json -o output.json
```
```
subfinder -d example.com -silent | ./parafinder -t 150 -gf lfi
```

### Stealth Operations
```bash
parafinder -d target.com --tor -silent
```
```
./parafinder -d target.com -proxy socks5://127.0.0.1:1080 -timeout 90
```

---

## 📋 Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `-d` | Single target domain | - |
| `-o` | Output file path | Stdout |
| `-t` | Concurrent threads | 100 |
| `-rl` | Rate limit per second | 50 |
| `-timeout` | HTTP timeout in seconds | 45 |
| `-mp` | Minimum parameters required | 0 |
| `-gf` | Filter by pattern (ssrf,xss,sqli,lfi,rce,redirect) | - |
| `-fuzz` | Replace parameter values with FUZZ | `false` |
| `-json` | Output results in JSONL format | `false` |
| `-silent` | Silent mode (URLs only, no banner/stats) | `false` |
| `-v` | Verbose output (show param counts) | `false` |
| `-proxy` | Custom proxy (http://... or socks5://...) | - |
| `-tor` | Route traffic via TOR | `false` |

---

## 🔍 Vulnerability Filters (GF Patterns)

| Pattern | Vulnerability Type | Key Parameters |
|---------|-------------------|----------------|
| **`ssrf`** | Server-Side Request Forgery | url, callback, dest, uri, host, redirect, target, next, view, file, path, continue, return, data, reference, site, html, navigate |
| **`xss`** | Cross-Site Scripting | q, s, search, id, lang, keyword, query, input, term, text, msg, name, p, page, comment, title, data, content, val |
| **`sqli`** | SQL Injection | id, select, report, update, query, sort, limit, page, user, pass, pwd, order, by, where, table, column, search, cat |
| **`lfi`** | Local File Inclusion | file, document, folder, root, path, pg, style, pdf, template, php_path, doc, page, name, cat, dir, action, board, date, detail, download, prefix, include, inc, locate, show, site, type, view, content, layout, mod, conf |
| **`rce`** | Remote Code Execution | cmd, exec, command, execute, ping, query, jump, code, reg, do, func, arg, option, load, process, step, read, function, req, feature, exe, module, payload, run, print, daemon |
| **`redirect`** | Open Redirect | url, uri, redirect, next, target, rurl, dest, destination, redir, redirect_uri, redirect_url, return, returnTo, return_to, checkout_url, continue, return_path, image_url, go, out, view, dir, show, navigation, path, reference, site |

**Usage**:
```bash
./parafinder -d example.com -gf lfi -mp 2 -v
```

---

## 📊 Output Formats

### Standard Output
```
[Wayback] https://api.example.com/v1/user?token=abc&id=123
[CommonCrawl] https://example.com/search?q=test&lang=en
[URLScan] https://example.com/redirect?url=http://evil.com
```

### Verbose Mode (`-v`)
```
[Wayback] [2 params] https://api.example.com/v1/user?token=abc&id=123
[URLScan] [3 params] https://example.com/api?key=x&id=1&format=json
[VirusTotal] [5 params] https://example.com/search?a=1&b=2&c=3&d=4&e=5
```

### JSONL Format (`-json`)
```json
{"timestamp":"2026-01-20T12:00:00Z","source":"Wayback","url":"https://api.example.com/user?token=secret","host":"api.example.com","param_count":1}
{"timestamp":"2026-01-20T12:00:01Z","source":"CommonCrawl","url":"https://example.com/search?q=test&lang=en","host":"example.com","fuzzed":"https://example.com/search?q=FUZZ&lang=FUZZ","param_count":2}
```

### Statistics Summary
```
[+] Scan Complete
    Total URLs: 45823
    Unique: 12456
    Filtered: 3421
    Duration: 2m34s
```

---

## 💡 Pro Tips

### 1. Rate Limiting Strategy
```bash
parafinder -d target.com -rl 100 -t 200 -timeout 20

parafinder -d target.com -rl 20 -t 50 -timeout 90
```

### 2. Thread Tuning
```bash
parafinder -d target.com -t 200 -rl 150

parafinder -d target.com -t 50 -rl 30
```

### 3. FUZZ Integration
```bash
parafinder -d target.com -fuzz -gf xss -silent | ffuf -u FUZZ -w payloads.txt

parafinder -d target.com -fuzz -gf ssrf -silent | nuclei -t ssrf/ -silent -o results.txt
```

### 4. Parameter Complexity Filtering
```bash
# Focus on endpoints with 3+ parameters
./parafinder -d target.com -mp 3 -v

# Complex SQLi targets only
./parafinder -d target.com -gf sqli -mp 4 -o sqli_complex.txt
```

### 5. Multi-Target Workflows
```bash
# Subdomain enumeration pipeline
subfinder -d example.com -silent | ./parafinder -t 150 -gf sqli -o all_sqli.txt

# Multiple domains from file
cat targets.txt | ./parafinder -fuzz -json -o all_params.json
```

### 6. Pattern Combination
```bash
parafinder -d target.com -gf ssrf -o ssrf.txt
```
```
parafinder -d target.com -gf redirect -o redirect.txt
```
```

for pattern in ssrf xss sqli lfi rce redirect; do
  ./parafinder -d target.com -gf $pattern -o ${pattern}_targets.txt
done
```

---

## 🔄 Workflow Integration

### With Nuclei
```bash
./parafinder -d target.com -fuzz -gf ssrf -silent | nuclei -t ssrf/ -silent
```

### With FFUF
```bash
./parafinder -d target.com -fuzz -silent | ffuf -u FUZZ -w payloads.txt -mc 200,301,302
```

### With httpx
```bash
./parafinder -d target.com -silent | httpx -status-code -title -tech-detect -o alive.txt
```

### With qsreplace
```bash
./parafinder -d target.com -silent | qsreplace "PAYLOAD" | nuclei -t cves/
```

### With gau
```bash
echo "example.com" | gau | qsreplace FUZZ > gau_urls.txt
./parafinder -d example.com -fuzz -silent > parafinder_urls.txt
cat gau_urls.txt parafinder_urls.txt | sort -u | nuclei -t fuzzing/
```

---

## 📈 Performance Benchmarks

**Test Environment**: AMD Ryzen 9 5950X, 32GB RAM, 1Gbps fiber  
**Target**: Large e-commerce site (150k+ archived URLs)

| Metric | v3.7 | v3.8 | Improvement |
|--------|------|------|-------------|
| **Scan Time** | 8m 42s | 5m 51s | **-33%** ⚡ |
| **URLs Found** | 12,456 | 18,723 | **+50%** 📈 |
| **Memory Peak** | 284 MB | 198 MB | **-30%** 💾 |
| **CPU Usage** | 68% | 52% | **-24%** ⚙️ |
| **Filtered Results** | 3,421 | 5,234 | **+53%** 🎯 |

---

## 📝 Changelog

### v3.8 (Latest - Jan 20, 2026)
- ✅ **New**: VirusTotal provider (5th data source)
- ✅ **New**: Real-time statistics dashboard
- ✅ **New**: LFI, RCE, Open Redirect GF patterns
- ✅ **New**: Minimum parameters filter (`-mp`)
- ✅ **New**: Verbose mode with param counts (`-v`)
- ✅ **New**: Configurable timeout (`-timeout`)
- ⚡ **Performance**: Multiple CommonCrawl indices (3x coverage)
- ⚡ **Performance**: AlienVault pagination (10x more URLs)
- ⚡ **Performance**: Optimized buffering (128KB scanner, 131KB writer)
- ⚡ **Performance**: Atomic statistics (lock-free counters)
- ⚡ **Performance**: Enhanced defaults (100 threads, 50 req/s)
- 🐛 **Fixed**: Race condition in stats tracking
- 🐛 **Fixed**: Buffer overflow on large datasets
- 🐛 **Fixed**: Context cancellation propagation

### v3.7 (Initial Release)
- 🎉 First public release
- 4 data sources: Wayback, CommonCrawl, URLScan, AlienVault
- 3 GF patterns: SSRF, XSS, SQLi
- FUZZ injection support
- JSON/TXT output formats

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. **Fork** the repository
2. **Create** your feature branch (`git checkout -b feature/AmazingFeature`)
3. **Commit** your changes (`git commit -m 'Add AmazingFeature'`)
4. **Push** to the branch (`git push origin feature/AmazingFeature`)
5. **Open** a Pull Request

### Development Setup
```bash
git clone https://github.com/INTELEON404/parafinder.git
cd parafinder
go mod download
go test ./...
go build -o parafinder main.go
```

---

## 🎯 Roadmap (v2.1)

- [ ] **Browser History Support** - Parse Chrome/Firefox history databases
- [ ] **HAR File Import** - Analyze HAR files offline
- [ ] **Custom Pattern Files** - Load user-defined GF patterns
- [ ] **SQLite Output** - Structured database storage
- [ ] **Distributed Scanning** - Master-worker architecture
- [ ] **REST API Mode** - HTTP API for integrations
- [ ] **ML Parameter Scoring** - AI-powered vulnerability likelihood
- [ ] **Burp Suite Extension** - Native Burp integration
- [ ] **GraphQL Support** - Discover GraphQL endpoint parameters
- [ ] **Wayback CDX API v2** - Enhanced Wayback queries

Vote on features: [GitHub Discussions](https://github.com/INTELEON404/parafinder/discussions)

---

## ⚖️ License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for more information.

---

## 👤 Author

**INTELEON404**

[![GitHub](https://img.shields.io/badge/GitHub-INTELEON404-181717?style=flat&logo=github)](https://github.com/INTELEON404)
[![Twitter](https://img.shields.io/badge/Twitter-@INTELEON404-1DA1F2?style=flat&logo=twitter)](https://x.com/INTELEON404)

---

## 🙏 Acknowledgments

Special thanks to:
- [@tomnomnom](https://github.com/tomnomnom) - Inspiration from `gf` tool
- [@projectdiscovery](https://github.com/projectdiscovery) - Amazing security tools ecosystem
- Bug bounty community - Continuous testing and feedback
- All contributors and GitHub stargazers ⭐


---
  
> [!WARNING]
> **This tool is for educational and authorized security testing purposes only.**  
> The author is not responsible for any misuse or damage caused by this tool.  
> Always obtain proper authorization before testing any targets.

---

### 💝 Support the Project

If you find ParaFinder useful, please consider:

⭐ **Starring** the repository  
🐦 **Sharing** on social media  
🤝 **Contributing** to the project  
☕ **Buying me a coffee** (Coming soon)

---

**Made with ❤️ for the bug bounty community**
