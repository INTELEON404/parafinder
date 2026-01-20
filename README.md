<div align="center">
<img src="https://github.com/INTELEON404/Template/blob/main/parafinder.png" alt="Logo" width="600"/>
<br />
</div>

```
░█▀█░█▀█░█▀█░█▀█░█▀▀░▀█▀░█▀█░█▀▄░█▀▀░█▀█
░█▀▀░█▀█░█▀▄░█▀█░█▀▀░░█░░█░█░█░█░█▀▀░█▀▄
░▀░░░▀░▀░▀░▀░▀░▀░▀░░░▀▀▀░▀░▀░▀▀░░▀▀▀░▀░▀
```

**ParaFinder** is a next-generation parameter discovery framework built for security researchers and bug bounty hunters. It leverages high-concurrency Go routines to scrape historical URL data and identify high-risk parameters before you even start your active scans.

---

## ⚡ Key Features

* **Multi-Source Intelligence**: Aggregates data from **Wayback Machine**, **CommonCrawl**, **URLScan.io**, **AlienVault OTX**, and **VirusTotal**.
* **Smart Deduplication**: Normalizes URLs by fingerprinting Host + Path + Parameter Keys to prevent redundant fuzzing.
* **Real-Time Statistics**: Live tracking of total URLs, unique entries, and filtered results with scan duration.
* **FUZZ Injection**: Native support for `FUZZ` placeholders, making it 100% compatible with `ffuf`, `nuclei`, and `Burp Suite`.
* **Enhanced GF Patterns**: Filter specifically for `ssrf`, `sqli`, `xss`, `lfi`, `rce`, and `redirect` entry points.
* **Parameter Filtering**: Set minimum parameter thresholds to focus on complex endpoints.
* **Enterprise Features**: Native support for **Proxy/TOR** routing, structured **JSON** exports, and verbose mode.
* **Optimized Performance**: Atomic counters, buffered I/O (128KB), and intelligent rate limiting.

---

## 🛠️ Installation

### Pre-requisites

* [Go 1.21+](https://go.dev/doc/install)

### Install via Go

```bash
go install github.com/INTELEON404/parafinder@latest
```

### Manual Build

```bash
git clone https://github.com/INTELEON404/parafinder.git
cd parafinder
go build -o parafinder main.go
chmod +x parafinder
```

---

## 🚀 Usage

### Basic Parameter Discovery

```bash
./parafinder -d example.com
```

### Advanced Recon (Deep Scan)

Use 150 threads, filter for SSRF-vulnerable parameters, and require at least 2 parameters:

```bash
./parafinder -d example.com -t 150 -gf ssrf -mp 2 -o results.txt
```

### Multiple Targets with FUZZ Injection

```bash
cat domains.txt | ./parafinder -fuzz -json -o output.json
```

### Stealth Mode (TOR Routing)

```bash
./parafinder -d target.com --tor -silent
```

### Verbose Mode with Statistics

```bash
./parafinder -d example.com -v -gf xss
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
| `-gf` | Filter by vulnerability type | - |
| `-fuzz` | Replace parameter values with FUZZ | `false` |
| `-json` | Output results in JSONL format | `false` |
| `-silent` | Silent mode (URLs only, no banner) | `false` |
| `-v` | Verbose output (show param counts) | `false` |
| `-proxy` | Custom proxy (http/socks5) | - |
| `-tor` | Route traffic via TOR (socks5://127.0.0.1:9050) | `false` |

---

## 🔍 Vulnerability Filters (GF Patterns)

ParaFinder comes pre-configured with enhanced patterns to help you find the needle in the haystack:

| Pattern | Target Vulnerability | Key Parameters |
|---------|---------------------|----------------|
| **`ssrf`** | Server-Side Request Forgery | `url`, `callback`, `dest`, `uri`, `host`, `redirect`, `target`, `next`, `view`, `file`, `path`, `continue`, `return`, `data`, `reference`, `site` |
| **`xss`** | Cross-Site Scripting | `q`, `s`, `search`, `id`, `lang`, `keyword`, `query`, `input`, `term`, `text`, `msg`, `name`, `p`, `page`, `comment`, `title`, `data`, `content`, `val` |
| **`sqli`** | SQL Injection | `id`, `select`, `report`, `update`, `query`, `sort`, `limit`, `page`, `user`, `pass`, `pwd`, `order`, `by`, `where`, `table`, `column`, `search`, `cat` |
| **`lfi`** | Local File Inclusion | `file`, `document`, `folder`, `root`, `path`, `pg`, `style`, `pdf`, `template`, `php_path`, `doc`, `page`, `name`, `cat`, `dir`, `action`, `board` |
| **`rce`** | Remote Code Execution | `cmd`, `exec`, `command`, `execute`, `ping`, `query`, `jump`, `code`, `reg`, `do`, `func`, `arg`, `option`, `load`, `process`, `step`, `read` |
| **`redirect`** | Open Redirect | `url`, `uri`, `redirect`, `next`, `target`, `rurl`, `dest`, `destination`, `redir`, `redirect_uri`, `redirect_url`, `return`, `returnTo`, `checkout_url` |

---

## 📊 Output Examples

### Standard Output
```
[Wayback] https://api.example.com/v1/user?token=abc&id=123
[CommonCrawl] https://example.com/search?q=test&lang=en
[URLScan] https://example.com/redirect?url=http://evil.com
```

### Verbose Output (`-v`)
```
[Wayback] [2 params] https://api.example.com/v1/user?token=abc&id=123
[URLScan] [3 params] https://example.com/api?key=x&id=1&format=json
```

### JSONL Output (`-json`)
```json
[
  {
    "timestamp": "2026-01-20T12:00:00Z",
    "source": "Wayback",
    "url": "https://api.example.com/user?token=secret",
    "host": "api.example.com",
    "param_count": 1
  },
  {
    "timestamp": "2026-01-20T12:00:01Z",
    "source": "CommonCrawl",
    "url": "https://example.com/search?q=test&lang=en",
    "host": "example.com",
    "fuzzed": "https://example.com/search?q=FUZZ&lang=FUZZ",
    "param_count": 2
  }
]

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

1. **Rate Limiting**: Increase `-rl` for faster scans on stable connections (e.g., `-rl 100`)
2. **Thread Tuning**: Use `-t 200` for maximum speed, `-t 50` for stability
3. **FUZZ Integration**: Pipe output directly to fuzzing tools:
   ```bash
   ./parafinder -d target.com -fuzz -gf xss -silent | ffuf -u FUZZ -w -
   ```
4. **Parameter Filtering**: Use `-mp 3` to focus on complex endpoints with multiple parameters
5. **Multi-Target Scanning**: Combine with subdomain enumeration:
   ```bash
   subfinder -d example.com -silent | ./parafinder -t 150 -gf sqli -o sqli_targets.txt
   ```

---

## 🔄 Workflow Integration

### With Nuclei
```bash
./parafinder -d target.com -fuzz -gf ssrf -silent | nuclei -t ssrf/ -silent
```

### With FFUF
```bash
./parafinder -d target.com -fuzz -silent | ffuf -u FUZZ -w payloads.txt -mc 200
```

### With httpx
```bash
./parafinder -d target.com -silent | httpx -status-code -title -tech-detect
```

---

## 🤝 Contributing

We welcome contributions! Please feel free to submit a Pull Request.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 Changelog

### v3.8 (Latest)
- ✅ Added VirusTotal provider
- ✅ Implemented atomic statistics tracking
- ✅ Enhanced GF patterns (lfi, rce, redirect)
- ✅ Added minimum parameters filter (`-mp`)
- ✅ Verbose mode with parameter counts (`-v`)
- ✅ Multiple CommonCrawl indices support
- ✅ Improved buffering (128KB scanner, 131KB file)
- ✅ AlienVault pagination (up to 5 pages)
- ✅ Enhanced timeout control
- ✅ Real-time statistics summary

### v3.7
- Initial public release

---

## ⚖️ License

Distributed under the **MIT License**. See `LICENSE` for more information.

---

## 👤 Author

**INTELEON404**  
[GitHub](https://github.com/INTELEON404) • [Twitter/X](https://x.com/INTELEON404)

---

## 🙏 Acknowledgments

- [@tomnomnom](https://github.com/tomnomnom) for inspiration from `gf`
- [@projectdiscovery](https://github.com/projectdiscovery) for the amazing security tools ecosystem
- The bug bounty community for continuous feedback

---

> [!WARNING]  
> This tool is for educational and authorized security testing purposes only. The author is not responsible for any misuse or damage caused by this tool.

> [!TIP]  
> Star ⭐ this repository if you found it useful!
