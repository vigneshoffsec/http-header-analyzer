import requests
import argparse

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]


def analyze_headers(url):
    if not url.startswith("http"):
        url = "https://" + url

    try:
        response = requests.get(url, timeout=5)
    except requests.RequestException as e:
        print(f"[!] Error fetching {url}: {e}")
        return

    print(f"\n=== Security Header Analysis for {url} ===\n")

    headers = response.headers

    for header in SECURITY_HEADERS:
        if header in headers:
            print(f"[+] {header}: Present")
        else:
            print(f"[-] {header}: Missing")

    print("\nStatus Code:", response.status_code)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Basic HTTP Security Header Analyzer")
    parser.add_argument("url", help="Target URL")

    args = parser.parse_args()
    analyze_headers(args.url)
