<div align="center">
<img src="https://github.com/INTELEON404/Template/blob/main/parafinder.png" alt="Logo" width="600"/>
<br />
</div>

```
░█▀█░█▀█░█▀▄░█▀█░█▀▀░▀█▀░█▀█░█▀▄░█▀▀░█▀▄
░█▀▀░█▀█░█▀▄░█▀█░█▀▀░░█░░█░█░█░█░█▀▀░█▀▄
░▀░░░▀░▀░▀░▀░▀░▀░▀░░░▀▀▀░▀░▀░▀▀░░▀▀▀░▀░▀

```

**ParaFinder** is a next-generation parameter discovery framework built for security researchers and bug bounty hunters. It leverages high-concurrency Go routines to scrape historical URL data and identify high-risk parameters before you even start your active scans.

---

## ⚡ Key Features

* **Multi-Source Intelligence**: Aggregates data from **Wayback Machine**, **AlienVault OTX**, **URLScan.io**, and **CommonCrawl**.
* **Smart Deduplication**: Normalizes URLs by fingerprinting Host + Path + Parameter Keys to prevent redundant fuzzing.
* **Heuristic Priority Scoring**: Automatically identifies and flags high-risk parameters like `redirect`, `token`, `admin`, and `config`.
* **FUZZ Injection**: Native support for `FUZZ` placeholders, making it 100% compatible with `ffuf`, `nuclei`, and `Burp Suite`.
* **Built-in GF Patterns**: Filter specifically for `ssrf`, `sqli`, `xss`, `lfi`, and `rce` entry points.
* **Enterprise Features**: Native support for **Proxy/TOR** routing and structured **JSON/CSV** exports.

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

Gather subdomains, use 100 threads, and filter for SSRF-vulnerable parameters:

```bash
./parafinder -d example.com -subs -t 100 -gf ssrf -o results.json

```

### Stealth Mode (TOR Routing)

```bash
./parafinder -d target.com --tor

```

---

## 📋 Command Line Options

| Flag | Description | Default |
| --- | --- | --- |
| `-d` | Single target domain | - |
| `-l` | Path to file containing list of domains | - |
| `-t` | Max concurrent threads | 50 |
| `-subs` | Include subdomains in archive searches | `true` |
| `-gf` | Filter by vulnerability type (`ssrf`, `sqli`, `xss`, `lfi`) | - |
| `-proxy` | HTTP proxy (e.g. `http://127.0.0.1:8080`) | - |
| `-tor` | Route all traffic via TOR (SOCKS5) | `false` |
| `-json` | Output results in structured JSON format | `false` |
| `-o` | Output file path | Stdout |

---

## 🔍 Vulnerability Filters (GF Patterns)

ParaFinder comes pre-configured with patterns to help you find the needle in the haystack:

| Pattern | Target Vulnerability | Key Parameters |
| --- | --- | --- |
| **`ssrf`** | Server-Side Request Forgery | `url`, `callback`, `dest`, `uri`, `host` |
| **`xss`** | Cross-Site Scripting | `q`, `s`, `search`, `id`, `lang`, `keyword` |
| **`sqli`** | SQL Injection | `id`, `order`, `sort`, `filter`, `select` |
| **`lfi`** | Local File Inclusion | `file`, `path`, `doc`, `root`, `include` |
| **`idor`** | Insecure Direct Object Reference | `user_id`, `account`, `profile`, `order_id` |

---

## 📄 Output Example (`results.json`)

```json
{
  "url": "https://api.tesla.com/v1/user?token=secret_val&id=123",
  "fuzzed": "https://api.tesla.com/v1/user?token=FUZZ&id=FUZZ",
  "source": "Wayback",
  "priority": 10,
  "params": ["token", "id"],
  "added_at": "2026-01-20T12:00:00Z"
}

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

## ⚖️ License

Distributed under the **MIT License**. See `LICENSE` for more information.

---

## 👤 Author

**INTELEON404** [GitHub](https://github.com/INTELEON404) • [Twitter/X](https://x.com/INTELEON404)

> [!WARNING]
> This tool is for educational and authorized security testing purposes only. The author is not responsible for any misuse or damage caused by this tool.
