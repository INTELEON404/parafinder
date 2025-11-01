# ParaFinder  

## Overview  
ParaFinder Ultra (version 3.0.0) is a next‑generation reconnaissance toolkit designed for bug bounty hunters, penetration testers and security researchers. It automatically scans for parameter discovery, hidden API endpoints, and reconnaissance surfaces across HTTP services — built for modern workflows, async speed and rich output.

## Features  
- Fast asynchronous scanning powered by `aiohttp`  
- Rich interactive output in the terminal via `rich`  
- Parameter fuzzing and discovery for APIs and web applications  
- Support for automated subdomain, path and parameter enumeration  
- CLI command (`parafinder`) for quick & direct use  
- Dev tools built‑in: test suite setup (`pytest`), code‐style support (`black`, `ruff`)  
- Designed for recon workflows: bug‑bounty, pentest, and API‑security engagements

## Requirements  
- Python 3.9 or newer  
- Recommended: UNIX‑like environment (Linux, BSD, macOS)  
- Install via pipx or pip/Git for latest version

## Installation  

### From PyPI (coming soon)  
```bash
pipx install parafinder
````

### From GitHub (now)

```bash
pipx install git+https://github.com/inteleon404/parafinder.git
```

Or to install in development/editable mode:

```bash
git clone https://github.com/inteleon404/parafinder.git
cd parafinder
pip install -e .
```

## Usage

```bash
parafinder --help
```

Typical usage example:

```bash
parafinder -u https://example.com/api/v1 -p id,name,action --output findings.json
```

See CLI help for all available flags and options.

## Example Output

```
[2025‑11‑02 12:34:56] Target: https://example.com/api/v1  
🔍 Found parameter: “action=delete” → HTTP 200  
✨ Found hidden endpoint: /api/v1/admin/deleteUser  
Results saved to: findings.json
```

## Development & Contributing

Contributions are welcome! Here’s how to get started:

1. Fork the repository
2. Create a new branch: `git checkout -b feature/your‑feature`
3. Make your changes and add tests
4. Run tests:

   ```bash
   pytest
   ```
5. Commit, push and open a Pull Request

Please respect the code of conduct and include clear descriptions in your PRs.
See [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

## Optional Dependencies

```toml
[project.optional‑dependencies]  
dev = [  
  "pytest>=7.0",  
  "pytest‑asyncio",  
  "black",  
  "ruff"  
]
```

## License

This project is licensed under the MIT License — see `LICENSE` file for details.

## Links

* Homepage / Repository: [https://github.com/inteleon404/parafinder](https://github.com/inteleon404/parafinder)
* Issues: [https://github.com/inteleon404/parafinder/issues](https://github.com/inteleon404/parafinder/issues)
* Documentation: [https://github.com/inteleon404/parafinder#readme](https://github.com/inteleon404/parafinder#readme)

---

*Happy hunting! 🕵️*


