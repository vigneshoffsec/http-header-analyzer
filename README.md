# 🛡️ HTTP Header Analyzer (Advanced AppSec Tool)

A Python-based **HTTP security header auditing tool** that identifies weak or missing security headers across one or more web applications.
It generates **OWASP-aligned remediation guidance**, severity ratings, and exports **JSON + HTML reports** suitable for AppSec teams, vulnerability assessments, and developer handoff.

This tool automates the security header review process and accelerates security assessments.

---

<p align="center">
  <img src="assets/Port Scanner.png" width="600">
</p>
<br>
<p align="center">
  <img src="https://img.shields.io/badge/status-active-brightgreen">
  <img src="https://img.shields.io/badge/language-python-blue">
  <img src="https://img.shields.io/badge/type-offensive%20security-red">
  <img src="https://img.shields.io/badge/license-MIT-yellow">
</p>

# 📂 Project Structure

```
http-header-analyzer/
│── src/
│   └── header_analyzer.py
│── reports/
│   └── .gitkeep
│── wordlists/
│   └── .gitkeep
│── README.md
│── LICENSE
```

---

# 🚀 Features

### ✔ Full Security Header Evaluation

Checks for the industry-standard security headers:

* **Content-Security-Policy (CSP)**
* **Strict-Transport-Security (HSTS)**
* **X-Frame-Options**
* **X-Content-Type-Options**
* **Referrer-Policy**
* **Permissions-Policy**

### ✔ OWASP-Aligned Remediation

Each missing header includes:

* Severity (HIGH / MEDIUM / LOW)
* Description
* Recommended fix aligned with OWASP best practices

### ✔ Multi-Target Scanning

Scan:

* A single URL
* Multiple URLs
* A `.txt` file containing URLs

### ✔ JSON + HTML Reporting

Automatically generates:

* JSON report (`header-report-*.json`)
* HTML report (`header-report-*.html`)

Ideal for client deliverables.

### ✔ Colorized CLI Output

Clear and readable terminal output with severity-based highlighting.

### ✔ Domain Normalization

URLs automatically corrected to `https://` when needed.

---

# 🧪 Usage

### **Scan a Single Target**

```bash
python3 src/header_analyzer.py https://example.com
```

### **Scan Multiple Targets**

```bash
python3 src/header_analyzer.py https://site1.com https://site2.org https://site3.net
```

### **Scan from URL List File**

`targets.txt`:

```
https://example.com
https://app.test.com
https://login.internal
```

Run:

```bash
python3 src/header_analyzer.py targets.txt
```

---

# 📤 Example Console Output

```
=== https://example.com ===
Status: 200

[+] Content-Security-Policy (OK)
[-] Strict-Transport-Security MISSING | Severity: HIGH
[-] X-Frame-Options MISSING | Severity: MEDIUM
```

---

# 🧾 Example Report Files

Inside `/reports/`:

```
header-report-20251114-153210.json
header-report-20251114-153210.html
```

---

# 🛠 How It Works (Internals)

### 1. Normalize URL

Ensures `http://` or `https://` prefix is applied automatically.

### 2. Fetch HTTP Response

Uses a modern User-Agent and timeout protection.

### 3. Header Evaluation

For each of the 6 key security headers:

* Check presence
* Identify severity
* Provide OWASP remediation text

### 4. Structured Results

Stores:

* Present headers
* Missing headers
* Raw header dump
* Status code

### 5. Report Generation

Creates:

* JSON structured report
* HTML formatted table with severity coloring

---

# 📈 Severity Ratings

| Severity   | Meaning                                                       |
| ---------- | ------------------------------------------------------------- |
| **HIGH**   | Critical header missing; high exploitability (CSP, HSTS)      |
| **MEDIUM** | Important but not critical (XFO, X-Content-Type-Options)      |
| **LOW**    | Best-practice hardening (Referrer-Policy, Permissions-Policy) |

---

# 🧩 OWASP Remediation Mapping

The tool follows OWASP best practices for headers:

* **CSP:** Prevents XSS & injection
* **HSTS:** Prevents downgrade attacks
* **XFO:** Stops clickjacking
* **XCTO:** Prevents MIME sniffing
* **Referrer-Policy:** Reduces data leakage
* **Permissions-Policy:** Restricts browser features

---

# 📌 Example HTML Report Preview

(Automatically generated)

```
+--------------------------------------------------------------+
|               HTTP Security Header Report                    |
+--------------------------------------------------------------+
| URL: https://example.com                                     |
| Status: 200                                                  |
|--------------------------------------------------------------|
| Missing Headers:                                             |
|    HSTS – HIGH severity – remediation text...                |
|    X-Frame-Options – MEDIUM severity – remediation text...   |
| Present Headers:                                             |
|    Content-Security-Policy – HIGH severity (OK)             |
+--------------------------------------------------------------+
```

---

# 📌 Roadmap / Future Enhancements

* Scan recursion for pages discovered via sitemap
* CSP quality scoring
* Response header entropy checks
* Policy misconfiguration detection
* Passive fingerprinting detection

---

# 🧑‍⚖️ Ethical Disclaimer

This tool is intended for **authorized security testing and educational use only**.
Analyzing systems without permission is **illegal** and unethical.

---

# 👨‍💻 Author

**Vignesh Mani**
Offensive Security Researcher
GitHub: [https://github.com/vigneshoffsec](https://github.com/vigneshoffsec)
LinkedIn: [https://linkedin.com/in/vignesh-m17](https://linkedin.com/in/vignesh-m17)
