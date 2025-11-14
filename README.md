# HTTP Header Analyzer

A Python-based tool to identify missing or weak HTTP security headers such as CSP, HSTS, X-Frame-Options, and more.

## Basic Usage

```bash```
python3 src/header_analyzer.py https://example.com
Example Output
pgsql
Copy code
[+] Content-Security-Policy: Present
[-] Strict-Transport-Security: Missing
[-] X-Frame-Options: Missing
