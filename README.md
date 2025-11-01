# ParaFinder   

## Overview  
ParaFinder Ultra (v3.0.0) is a next-generation reconnaissance toolkit designed for bug bounty hunters, penetration testers, and security researchers. It automates parameter discovery, hidden API endpoint enumeration, and reconnaissance across HTTP services, delivering high-speed asynchronous scanning with rich terminal output.

## Features  
- Asynchronous HTTP scanning using `aiohttp` for speed and efficiency  
- Rich, interactive terminal output powered by `rich`  
- Parameter fuzzing and discovery for APIs and web applications  
- Automated identification of hidden endpoints and query parameters  
- CLI-based tool for seamless integration into recon workflows  
- Structured JSON output for easy parsing and reporting  

## Requirements  
- Python 3.9 or newer  
- UNIX-like environment recommended (Linux, macOS, BSD)  

## Installation  

Clone the repository and install dependencies:

```bash
git clone https://github.com/inteleon404/parafinder.git
cd parafinder
pip install -r requirements.txt
````

> Ensure you are using a virtual environment for safe installation.

## Usage

Run the CLI tool:

```bash
python -m parafinder.cli --help
```

Typical usage example:

```bash
python -m parafinder.cli -u https://example.com/api/v1 -p id,name,action --output results.json
```

* `-u` : Target URL
* `-p` : List of parameters to scan
* `--output` : File to save findings

## Example Output

```
[2025-11-02 12:34:56] Target: https://example.com/api/v1
🔍 Found parameter: “action=delete” → HTTP 200
✨ Found hidden endpoint: /api/v1/admin/deleteUser
Results saved to: results.json
```

## Development & Contributing

We welcome contributions!

1. Fork the repository
2. Create a branch: `git checkout -b feature/your-feature`
3. Implement changes and add tests
4. Run tests:

   ```bash
   pytest
   ```
5. Commit, push, and open a Pull Request

Please follow the code of conduct and provide clear descriptions in PRs.

## License

MIT License – see `LICENSE` for details.

## Links

* Repository: [https://github.com/inteleon404/parafinder](https://github.com/inteleon404/parafinder)
* Issues: [https://github.com/inteleon404/parafinder/issues](https://github.com/inteleon404/parafinder/issues)

---

*Empowering ethical hackers with precise parameter discovery.*


