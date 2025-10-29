#  `README.md`

````markdown
# VORTEXSCAN

VORTEXSCAN is a dirsearch/gobuster-like directory & file discovery tool written in Python.  
It is intended for security testing on systems you own or have explicit permission to test.

> **Important**: Use this tool only on systems you have permission to scan. Unauthorized scanning is illegal.

---

## Features
- Multithreaded directory/file brute forcing (ThreadPoolExecutor)
- Extension appending (e.g. `.php`, `.html`)
- Status code filtering (default hides `404`)
- Follow or disable redirects
- Scheme probing (tries `https://` then `http://` if scheme not provided)
- Resume support for output files
- Optional recursion into discovered directories
- Proxy and Basic Auth support
- Random User-Agent rotation
- Verbose mode with optional colorized output (if `colorama` installed)
- Output formats: plaintext, `json`, `csv` (when `--output` used)

---

## Requirements
- Python 3.8+
- `requests` library
- (Optional) `colorama` for colored terminal output

Install dependencies:
```bash
pip install -r requirements.txt
````

`requirements.txt`:

```
requests
colorama
```

`colorama` is optional. The tool works without it.

---

## Usage

Save the tool as `vortexscan.py` and run:

```
python3 vortexscan.py -u <target> -w <wordlist> [options]
```

### Common examples

* Basic scan:

  ```
  python3 vortexscan.py -u example.com -w wordlist.txt
  ```

* With extensions and threads:

  ```
  python3 vortexscan.py -u example.com -w wordlist.txt -e php,html -t 80 -v
  ```

* Only show `200` and `301` responses, save to file:

  ```
  python3 vortexscan.py -u example.com -w wordlist.txt --status 200,301 -o found.txt
  ```

* Use proxy and basic auth:

  ```
  python3 vortexscan.py -u example.com -w wordlist.txt --proxy http://127.0.0.1:8080 --auth user:pass
  ```

* Recursive scan (2 levels):

  ```
  python3 vortexscan.py -u example.com -w wordlist.txt --recursive --max-depth 2 -o results.txt
  ```

* Resume a previous output file:

  ```
  python3 vortexscan.py -u example.com -w wordlist.txt -o results.txt --resume
  ```

* Output JSON instead of plain text:

  ```
  python3 vortexscan.py -u example.com -w wordlist.txt -o results.json --format json
  ```

---

## CLI Options (summary)

* `-u`, `--url` : Target (example.com or [https://example.com](https://example.com)) **(required)**
* `-w`, `--wordlist` : Wordlist file **(required)**
* `-e`, `--extensions` : Comma-separated extensions to append (e.g. `php,html`)
* `-t`, `--threads` : Number of threads (default `40`)
* `-T`, `--timeout` : Request timeout seconds (default `10`)
* `-v`, `--verbose` : Verbose output
* `--random-agent` : Rotate user-agent header
* `-o`, `--output` : Output file to write results
* `--format` : Output format when `--output` used (`text`, `json`, `csv`) — default `text`
* `--status` : Comma-separated status codes to show (e.g. `200,301,403`); default: show non-`404`
* `--no-redirects` : Do not follow redirects
* `--delay` : Delay seconds between requests (per thread)
* `--proxy` : Proxy URL (e.g. `http://127.0.0.1:8080`)
* `--auth` : Basic auth `user:pass`
* `--recursive` : Enable recursion into discovered directories
* `--max-depth` : Max recursion depth (default `2`)
* `--resume` : Resume from output file (append and skip recorded URLs if file exists)

---

## Notes & Limitations

* This tool aims to match dirsearch/gobuster behavior for common usage patterns but is not a drop-in replacement for every edge-case or plugin dirsearch supports.
* Heuristics for recursion are conservative: only when the response appears HTML or the path ends with `/`, and only up to `--max-depth`.
* The scanner preserves observed final URL when following redirects; resume and output dedupe use final URLs.
* For very large scans use a robust environment (Linux, high ulimit, stable network).

---




