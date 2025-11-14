import requests
import argparse
import json
import time
from datetime import datetime
from urllib.parse import urlparse
import os

# ---------------------------------------------
# SECURITY HEADER DEFINITIONS + OWASP GUIDANCE
# ---------------------------------------------
HEADER_RULES = {
    "Content-Security-Policy": {
        "description": "Restricts resources the browser can load.",
        "severity": "HIGH",
        "remediation": "Define a strict CSP: default-src 'self'; object-src 'none'; base-uri 'none'",
    },
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS and prevents downgrade attacks.",
        "severity": "HIGH",
        "remediation": "Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks.",
        "severity": "MEDIUM",
        "remediation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing.",
        "severity": "MEDIUM",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "description": "Controls what referrer info is shared.",
        "severity": "LOW",
        "remediation": "Add: Referrer-Policy: no-referrer or strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "description": "Controls browser features (camera, geolocation, etc.).",
        "severity": "LOW",
        "remediation": "Add: Permissions-Policy: geolocation=(), microphone=() ...",
    }
}

# ---------------------------------------------
# UTILITY FUNCTIONS
# ---------------------------------------------

def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


def fetch(url):
    try:
        return requests.get(url, timeout=5)
    except requests.RequestException:
        return None


def analyze_single_target(url):
    url = normalize_url(url)
    response = fetch(url)

    if response is None:
        return {
            "url": url,
            "status": "unreachable",
            "missing_headers": [],
            "present_headers": [],
            "raw_headers": {}
        }

    headers = response.headers
    findings = {
        "url": url,
        "status": response.status_code,
        "missing_headers": [],
        "present_headers": [],
        "raw_headers": dict(headers)
    }

    for header, rule in HEADER_RULES.items():
        if header in headers:
            findings["present_headers"].append({
                "header": header,
                "severity": rule["severity"],
                "description": rule["description"]
            })
        else:
            findings["missing_headers"].append({
                "header": header,
                "severity": rule["severity"],
                "description": rule["description"],
                "remediation": rule["remediation"]
            })

    return findings


# ---------------------------------------------
# REPORT GENERATION
# ---------------------------------------------
def save_reports(results):
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    os.makedirs("reports", exist_ok=True)

    # JSON Report
    json_path = f"reports/header-report-{timestamp}.json"
    with open(json_path, "w") as f:
        json.dump(results, f, indent=4)

    # HTML Report
    html_path = f"reports/header-report-{timestamp}.html"
    with open(html_path, "w") as f:
        f.write(generate_html(results))

    print(f"\nSaved reports:\n- {json_path}\n- {html_path}")


def generate_html(results):
    html = """
    <html>
    <head>
        <title>HTTP Header Analyzer Report</title>
        <style>
            body { font-family: Arial; padding: 20px; }
            h2 { color: #333; }
            table { border-collapse: collapse; width: 100%; margin-bottom: 30px; }
            th, td { border: 1px solid #ccc; padding: 8px; }
            th { background: #333; color: white; }
            .high { color: red; font-weight: bold; }
            .medium { color: orange; font-weight: bold; }
            .low { color: green; font-weight: bold; }
        </style>
    </head>
    <body>
        <h1>HTTP Security Header Report</h1>
    """

    for r in results:
        html += f"<h2>{r['url']} (Status: {r['status']})</h2>"

        html += "<h3>Missing Headers</h3>"
        html += "<table><tr><th>Header</th><th>Severity</th><th>Description</th><th>Remediation</th></tr>"
        for h in r["missing_headers"]:
            html += f"<tr><td>{h['header']}</td><td class='{h['severity'].lower()}'>{h['severity']}</td><td>{h['description']}</td><td>{h['remediation']}</td></tr>"
        html += "</table>"

        html += "<h3>Present Headers</h3>"
        html += "<table><tr><th>Header</th><th>Severity</th><th>Description</th></tr>"
        for h in r["present_headers"]:
            html += f"<tr><td>{h['header']}</td><td class='{h['severity'].lower()}'>{h['severity']}</td><td>{h['description']}</td></tr>"
        html += "</table>"

    html += "</body></html>"
    return html


# ---------------------------------------------
# MAIN EXECUTION
# ---------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced HTTP Security Header Analyzer")
    parser.add_argument("target", nargs="+", help="URL(s) or file containing URLs")

    args = parser.parse_args()

    targets = []

    # Support list of URLs or file input
    for target in args.target:
        if target.endswith(".txt"):
            with open(target, "r") as f:
                targets.extend([line.strip() for line in f.readlines()])
        else:
            targets.append(target)

    results = []

    print("\nStarting HTTP Header Analysis...\n")
    time.sleep(0.5)

    for t in targets:
        finding = analyze_single_target(t)
        results.append(finding)

        print(f"\n=== {t} ===")
        print("Status:", finding["status"])

        # Present headers
        for h in finding["present_headers"]:
            print(f"\033[92m[+] {h['header']} (OK)\033[0m")

        # Missing headers
        for h in finding["missing_headers"]:
            sev = h["severity"]
            color = "91" if sev == "HIGH" else "93" if sev == "MEDIUM" else "96"
            print(f"\033[{color}m[-] {h['header']} MISSING | Severity: {sev}\033[0m")

    save_reports(results)
    print("\nAnalysis complete.\n")
