URLTOTAL

Passive URL & Domain Intelligence Tool
(VirusTotal v2/v3 + urlscan.io)

urltotal is an ORWA-style passive reconnaissance tool that aggregates historical URLs, domains, IPs, paths, and parameters from VirusTotal and urlscan.io.

It is designed for manual bug hunting workflows, not automated exploitation.

🔍 What URLTOTAL Does

URLTOTAL collects historical attack surface that has been previously observed in the wild:

Full URLs (including parameters & extensions)

Domains & subdomains

IP addresses

Paths

Parameter names

It does not scan, does not fuzz, and does not exploit.



URLTOTAL follows the same philosophy used by many high-impact bug hunters:

Preserve raw URLs exactly as returned by data sources

Do not normalize, sanitize, or “fix” URLs

Do not infer vulnerabilities automatically

Let the hunter manually analyze & test

This makes it ideal for discovering:

Backup files (.zip, .7z, .tar.gz)

Exposed configuration files

OAuth / redirect endpoints

Debug & actuator endpoints

Legacy or internal URLs

Forgotten parameters

🚀 Data Sources
VirusTotal

Domain reports (v2)

IP address reports (v2)

Subdomains (v3)

urlscan.io

Historical page URLs

Observed requests

IPs seen during scans

All data is passive and historical.

📦 Installation
Requirements

Go ≥ 1.17

VirusTotal API keys

urlscan.io API keys

Clone
git clone https://github.com/YOURNAME/urltotal.git
cd urltotal

Build (single-file tool)
GO111MODULE=off go build -o urltotal urltotal.go

Install globally (optional)
sudo mv urltotal /usr/local/bin/urltotal
sudo chmod +x /usr/local/bin/urltotal

🔑 API Keys Setup

URLTOTAL reads keys from environment variables (recommended).

VirusTotal
export VT_V2_KEYS="key1,key2,key3,key4"
export VT_V3_KEYS="key5"

urlscan.io
export URLSCAN_KEYS="keyA,keyB"


Keys are rotated automatically to reduce rate-limit issues.

⚠️ Do NOT run urltotal with sudo, or environment variables will not be available.

🛠 Usage
Single Target
urltotal -i example.com

File Input
urltotal -f targets.txt

Output Directory
urltotal -f targets.txt -o output

Concurrency
urltotal -i example.com -w 12

📂 Output Files
File	Description
urls.txt	Full historical URLs (raw, unmodified)
domains.txt	Domains & subdomains
ips.txt	IP addresses
paths.txt	Unique URL paths
params.txt	Parameter names

All files are deduplicated and plain text.

🧪 Recommended Manual Workflow

After running URLTOTAL:

grep -Ei "\.zip|\.7z|\.env|backup|reset|token|actuator" urls.txt

grep -Ei "oauth|login|signin|callback|redirect" urls.txt

grep "=" urls.txt | head


These patterns frequently lead to:

Information disclosure

OAuth misconfigurations

Account takeover chains

Unauthorized access

❗ Important Notes

Empty output does not mean the tool is broken

Some targets simply have no historical exposure

Hardened domains (e.g. google.com) often return little or no data

Subdomains usually produce better results than apex domains

🔒 Ethics & Scope

URLTOTAL is intended for:

Bug bounty programs

Authorized security testing

Educational research

You are responsible for:

Following program rules

Respecting legal boundaries

Using data responsibly

🧠 Why Full URLs Matter

Full URLs help when:

Looking for exposed files

Debug endpoints

Static leaks

OAuth redirect issues

Full URLs do not automatically reveal:

Logic flaws

Auth bypasses

Privilege escalation

Those require manual testing and reasoning.

📌 Roadmap (Optional Ideas)

VT SHA256 → filename pivot

VT IP → URL pivot

Keyword tagging (non-filtering)

Output profiles (auth / files / backups)

📜 License

MIT License

🤝 Acknowledgements

Inspired by:

ORWA methodology

Passive reconnaissance techniques

Real-world bug bounty workflows
