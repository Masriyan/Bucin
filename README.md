<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:667eea,100:764ba2&height=200&section=header&text=BUCIN&fontSize=80&fontColor=fff&animation=fadeIn&fontAlignY=35&desc=Browse%20•%20Uncover%20•%20Collect%20•%20Intel%20•%20Network&descAlignY=55&descSize=20" width="100%"/>
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/Version-2.0.0-blue?style=for-the-badge&logo=git&logoColor=white" alt="Version"></a>
  <a href="#"><img src="https://img.shields.io/badge/Python-3.8+-3776ab?style=for-the-badge&logo=python&logoColor=white" alt="Python"></a>
  <a href="#"><img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge&logo=opensourceinitiative&logoColor=white" alt="License"></a>
  <a href="#"><img src="https://img.shields.io/badge/Platform-Linux%20|%20macOS%20|%20Windows-orange?style=for-the-badge&logo=linux&logoColor=white" alt="Platform"></a>
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/PRs-Welcome-brightgreen?style=flat-square" alt="PRs Welcome"></a>
  <a href="#"><img src="https://img.shields.io/badge/Maintained-Yes-success?style=flat-square" alt="Maintained"></a>
  <a href="https://github.com/Masriyan/Bucin/stargazers"><img src="https://img.shields.io/github/stars/Masriyan/Bucin?style=flat-square&logo=github" alt="Stars"></a>
  <a href="https://github.com/Masriyan/Bucin/network/members"><img src="https://img.shields.io/github/forks/Masriyan/Bucin?style=flat-square&logo=github" alt="Forks"></a>
</p>

<br>

<p align="center">
  <b>🔍 A powerful OSINT & External Threat Hunting toolkit for security professionals</b>
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-commands">Commands</a> •
  <a href="#-reports">Reports</a> •
  <a href="#-contributing">Contributing</a>
</p>

---

<br>

## 🎯 What is BUCIN?

**BUCIN** is an all-in-one external reconnaissance toolkit designed for:
- 🔴 **Red Teams** - Attack surface discovery and vulnerability assessment
- � **Blue Teams** - External threat monitoring and exposure mapping
- � **Bug Bounty Hunters** - Target enumeration and secret scanning
- ⚪ **Security Researchers** - OSINT and passive reconnaissance

<br>

## ✨ Features

<table>
<tr>
<td width="50%">

### 🌐 Domain Intelligence
| Feature | Description |
|---------|-------------|
| 🔍 **Subdomains** | Passive enumeration via crt.sh |
| 📧 **DNS Records** | MX, TXT, NS, CNAME, A, AAAA |
| 📋 **WHOIS** | Domain registration data |
| ⏳ **Wayback** | Historical URL discovery |

</td>
<td width="50%">

### 🛡️ Security Analysis
| Feature | Description |
|---------|-------------|
| � **Headers** | Security headers scoring |
| 🌐 **CORS** | Misconfiguration testing |
| ⚠️ **Takeover** | Subdomain takeover check |
| 🔧 **Tech Stack** | Technology detection |

</td>
</tr>
<tr>
<td width="50%">

### 🕵️ Reconnaissance
| Feature | Description |
|---------|-------------|
| 🔎 **Probe** | Sensitive file discovery |
| 🕷️ **Crawl** | Web crawling + secrets |
| 🚪 **Ports** | Fast port scanning |
| 🔐 **TLS** | Certificate inspection |

</td>
<td width="50%">

### 📦 Asset Discovery
| Feature | Description |
|---------|-------------|
| 🪣 **Buckets** | AWS/GCP/Azure checks |
| 🔗 **Social** | Social media profiles |
| � **Secrets** | 18+ pattern detection |
| 📊 **Reports** | HTML, CSV, PDF, MD |

</td>
</tr>
</table>

<br>

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/Masriyan/Bucin.git
cd Bucin

# Install dependencies
pip install -r requirements.txt

# Or install via pip (editable mode)
pip install -e .
```

<details>
<summary>📦 <b>Dependencies</b></summary>

| Package | Purpose |
|---------|---------|
| `requests` | HTTP library |
| `beautifulsoup4` | HTML parsing |
| `tldextract` | Domain parsing |
| `colorama` | Colored output |
| `tqdm` | Progress bars |
| `dnspython` | DNS queries |
| `python-whois` | WHOIS lookups |

**Optional:**
- `pdfkit` / `weasyprint` - PDF reports
- `shodan` - Shodan integration

</details>

<br>

## 📖 Usage

### Quick Start

```bash
# Full reconnaissance on a target
bucin all -d example.com --report html,csv

# Just subdomains
bucin subdomains -d example.com

# Security headers check
bucin headers --host example.com

# Technology detection
bucin tech -t https://example.com
```

### Using Target Files

```bash
# Create a targets file
echo "example.com" > targets.txt
echo "test.example.com" >> targets.txt

# Run against multiple targets
bucin probe -t targets.txt
bucin ports --host targets.txt
```

<br>

## 🎮 Commands

<details>
<summary><b>🌐 subdomains</b> - Passive Subdomain Enumeration</summary>

```bash
bucin subdomains -d example.com [-o output] [--report csv,html]
```
Discovers subdomains via crt.sh certificate transparency logs and checks liveness.
</details>

<details>
<summary><b>🔎 probe</b> - Sensitive Path Discovery</summary>

```bash
bucin probe -t example.com [-p paths.txt] [-o output]
```
Probes for sensitive files: `.env`, `.git/config`, `swagger.json`, etc.
</details>

<details>
<summary><b>🕷️ crawl</b> - Web Crawler + Secret Scanner</summary>

```bash
bucin crawl -t https://example.com [--max-pages 150] [--secrets]
```
Crawls website and scans for exposed secrets (API keys, tokens, etc.)
</details>

<details>
<summary><b>🔐 tls</b> - TLS Certificate Inspection</summary>

```bash
bucin tls --host example.com [--port 443]
```
Retrieves and analyzes TLS certificate information.
</details>

<details>
<summary><b>🪣 buckets</b> - Cloud Bucket Enumeration</summary>

```bash
bucin buckets -n "company-name" [--wordlist words.txt]
```
Checks for public AWS S3, GCP Storage, and Azure Blob buckets.
</details>

<details>
<summary><b>📧 dns</b> - DNS Record Enumeration</summary>

```bash
bucin dns -d example.com
```
Fetches A, AAAA, MX, TXT, NS, and CNAME records.
</details>

<details>
<summary><b>📋 whois</b> - WHOIS Lookup</summary>

```bash
bucin whois -d example.com
```
Retrieves domain registration and ownership information.
</details>

<details>
<summary><b>🚪 ports</b> - Port Scanning</summary>

```bash
bucin ports --host example.com [-p 80,443,8080] [-t 16]
```
Fast concurrent port scanning with customizable port list.
</details>

<details>
<summary><b>🛡️ headers</b> - Security Headers Analysis</summary>

```bash
bucin headers --host example.com
```
Analyzes HTTP security headers and provides a security score.
</details>

<details>
<summary><b>⏳ wayback</b> - Wayback Machine URLs</summary>

```bash
bucin wayback -d example.com [--limit 500]
```
Discovers historical URLs from the Wayback Machine CDX API.
</details>

<details>
<summary><b>🔧 tech</b> - Technology Detection</summary>

```bash
bucin tech -t https://example.com
```
Detects web technologies: CMS, frameworks, libraries, CDNs, etc.
</details>

<details>
<summary><b>🌐 cors</b> - CORS Misconfiguration Testing</summary>

```bash
bucin cors -t https://example.com
```
Tests for CORS vulnerabilities (wildcard, null origin, reflection).
</details>

<details>
<summary><b>⚠️ takeover</b> - Subdomain Takeover Check</summary>

```bash
bucin takeover -d example.com
```
Checks subdomains for takeover vulnerabilities (dangling CNAMEs).
</details>

<details>
<summary><b>🔗 social</b> - Social Media Discovery</summary>

```bash
bucin social -n "Company Name"
```
Searches for social media profiles across platforms.
</details>

<details>
<summary><b>🎯 all</b> - Full Reconnaissance</summary>

```bash
bucin all -d example.com --report html,csv,pdf
```
Runs complete reconnaissance: subdomains, probe, crawl, DNS, WHOIS, headers, tech.
</details>

<br>

## 📊 Reports

BUCIN generates professional reports in multiple formats:

| Format | Command | Description |
|--------|---------|-------------|
| 📄 **CSV** | `--report csv` | Machine-readable spreadsheet |
| 🌐 **HTML** | `--report html` | Beautiful web report |
| 📑 **PDF** | `--report pdf` | Print-ready document |
| 📝 **Markdown** | `--report md` | GitHub-friendly format |

```bash
# Generate multiple formats at once
bucin all -d example.com --report csv,html,pdf
```

<br>

## 🔐 Secret Detection

BUCIN automatically detects **18+ types** of exposed secrets:

<table>
<tr>
<td>

- 🔑 AWS Access Keys
- 🔑 AWS Secret Keys
- 🔑 Google API Keys
- 🔑 Slack Tokens
- 🔑 GitHub Tokens
- 🔑 Discord Tokens

</td>
<td>

- 🔑 Stripe API Keys
- 🔑 Heroku API Keys
- 🔑 Mailgun Keys
- 🔑 Twilio Keys
- 🔑 SendGrid Keys
- 🔑 Firebase URLs

</td>
<td>

- 🔑 Private Keys (RSA/DSA/EC)
- 🔑 JWT Tokens
- � Square OAuth
- 🔑 PayPal Braintree
- �📧 Email Addresses
- 🔗 And more...

</td>
</tr>
</table>

<br>

## ⚙️ Configuration

### Environment Variables

```bash
# Custom user agent
export BUCIN_USER_AGENT="CustomAgent/1.0"

# Shodan API key (optional)
export SHODAN_API_KEY="your-api-key"
```

<br>

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Fork the repo, then:
git clone https://github.com/YOUR_USERNAME/Bucin.git
cd Bucin
git checkout -b feature/your-feature
# Make changes, then:
git commit -m "feat: add your feature"
git push origin feature/your-feature
# Open a Pull Request
```

<br>

## ⚠️ Disclaimer

> **This tool is intended for authorized security testing and educational purposes only.**
> 
> Always obtain proper authorization before scanning any systems. The authors are not responsible for misuse or damage caused by this tool.

<br>

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

<br>

---

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:667eea,100:764ba2&height=100&section=footer" width="100%"/>
</p>

<p align="center">
  <b>Made with ❤️ by <a href="https://github.com/Masriyan">Masriyan</a></b>
</p>

<p align="center">
  <a href="https://github.com/Masriyan/Bucin/stargazers">⭐ Star this repo if you find it useful!</a>
</p>
