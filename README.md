#  `README.md`

````markdown
# VORTEXSCAN  
**Advanced Directory & File Discovery Tool**  
Author: Priyanshu Tiwari  

---

## Overview
**VORTEXSCAN** is a modern, high-performance web content discovery tool inspired by **dirsearch** and **gobuster**.  
It is designed for ethical hackers, penetration testers, and bug bounty hunters to identify hidden directories and files on web servers.

VORTEXSCAN supports both **clean terminal output** and an **advanced rich UI mode** (if the `rich` library is installed). It can also export machine-readable reports in **JSON** and **CSV** formats.

---

## Key Features

- **Hybrid Output Modes**
  - Clean Professional Mode (default)
  - Advanced UI Mode (auto-enabled if `rich` is installed)
  - Machine-friendly output: `text`, `json`, `csv`

- **Smart Scheme Probing**
  - Automatically detects and uses `https` or `http` if not provided

- **Concurrency & Performance**
  - Multi-threaded scanning using `ThreadPoolExecutor`
  - Connection reuse via `requests.Session`

- **Advanced Options**
  - Recursive scanning with depth control
  - Proxy and Basic Auth support
  - Resume support for long scans
  - Custom status filters and extensions
  - Randomized User-Agents for stealth
  - Delay and timeout control

- **Professional Output**
  - Color-coded status display
  - Status distribution summary
  - Requests per second metrics
  - Optional progress bars and tables (in rich mode)

---

## Installation

### Requirements
- **Python 3.7+**
- **Dependencies:**
  - `requests`
  - `colorama` *(optional, for colored output)*
  - `rich` *(optional, for advanced UI mode)*

### Install Dependencies
```bash
pip install requests colorama rich
````

### Clone Repository

```bash
git clone https://github.com/Priyanshutiwari0604/vortexscan.git
cd vortexscan
```

---

## Usage

### Basic Scan

```bash
python3 vortexscan.py -u https://example.com -w wordlist.txt
```

### Scan Without Scheme (auto probes https/http)

```bash
python3 vortexscan.py -u example.com -w common.txt
```

### Add Extensions

```bash
python3 vortexscan.py -u https://example.com -w dirs.txt -e php,html,txt
```

### Specify Output File

```bash
python3 vortexscan.py -u https://example.com -w wordlist.txt -o results.txt
```

### Export in JSON or CSV

```bash
python3 vortexscan.py -u https://example.com -w wordlist.txt -o results.json --format json
python3 vortexscan.py -u https://example.com -w wordlist.txt -o results.csv --format csv
```

### Filter by Status Codes

```bash
python3 vortexscan.py -u https://example.com -w wordlist.txt --status 200,301,403
```

### Recursive Scanning

```bash
python3 vortexscan.py -u https://example.com -w dirs.txt --recursive --max-depth 3
```

### Resume From Previous Scan

```bash
python3 vortexscan.py -u https://example.com -w dirs.txt -o results.txt --resume
```

---

## Command-Line Options

| Flag                 | Description                                                                |
| -------------------- | -------------------------------------------------------------------------- |
| `-u`, `--url`        | Target URL or host (required)                                              |
| `-w`, `--wordlist`   | Wordlist file (required)                                                   |
| `-e`, `--extensions` | Comma-separated extensions (e.g. php,html,txt)                             |
| `-t`, `--threads`    | Number of threads (default: 40)                                            |
| `-T`, `--timeout`    | Request timeout in seconds (default: 10)                                   |
| `-v`, `--verbose`    | Enable verbose output                                                      |
| `--random-agent`     | Use random User-Agent for each request                                     |
| `-o`, `--output`     | Output file path                                                           |
| `--format`           | Output format: text, json, csv                                             |
| `--status`           | Filter by HTTP status codes                                                |
| `--no-redirects`     | Do not follow redirects                                                    |
| `--delay`            | Delay between requests (seconds)                                           |
| `--proxy`            | Use HTTP/HTTPS proxy (e.g. [http://127.0.0.1:8080](http://127.0.0.1:8080)) |
| `--auth`             | Basic authentication (user:pass)                                           |
| `--recursive`        | Enable recursive scanning                                                  |
| `--max-depth`        | Maximum recursion depth (default: 2)                                       |
| `--resume`           | Resume from a previous output file                                         |
| `--no-rich`          | Disable advanced rich UI (use clean mode)                                  |

---

## Output Example (Clean Professional Mode)

```
══════════════════════════════════════════════════════════════════════════════
                               SCAN CONFIGURATION
═════════════════════════════════════════════════════════════════════════════
  Target:      https://example.com
  Wordlist:    500 entries → 800 targets (with extensions)
  Threads:     40
  Timeout:     10s
  Filter:      All except 404
  Started:     2025-11-03 10:30:00
═════════════════════════════════════════════════════════════════════════════

STATUS   URL                                                                     SIZE       TIME
----------------------------------------------------------------------------------------------------
[200]    https://example.com/index.php                                           2.3KB     0.25s
[301]    https://example.com/admin -> /login                                     0.8KB     0.19s
[403]    https://example.com/secret                                              1.0KB     0.33s
```

---

## Advanced UI Mode Example

When the `rich` library is installed, VORTEXSCAN automatically enables **Advanced UI Mode**, featuring:

* Live progress bars
* Real-time statistics
* Dynamic tables for results
* Colored panels for configuration and summary

---

## Example Output (JSON)

```json
[
  {
    "status": 200,
    "url": "https://example.com/admin",
    "size": 1024,
    "time": 0.42
  },
  {
    "status": 403,
    "url": "https://example.com/secret",
    "size": 512,
    "time": 0.35
  }
]
```

---

## Legal Disclaimer

This tool is intended **only for authorized security testing** and **educational purposes**.
Do **not** use it against systems without explicit permission from their owners.
Unauthorized use of this software may violate applicable laws.

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## Author

**Priyanshu Tiwari**
GitHub: [https://github.com/Priyanshutiwari0604](https://github.com/Priyanshutiwari0604)


