# BugReconX - Subdomain + Recon CLI Tool

BugReconX is a powerful CLI tool for automated subdomain enumeration, HTTP response categorization, and Wayback URL extraction. Built for bug bounty hunters and recon automation.

# Usage

# Scan a single domain
python bugreconx.py -d example.com

# Scan multiple domains from a file
python bugreconx.py -i domains.txt

## Features

- Subdomain enumeration using:
  - subfinder
  - crt.sh
  - amass (passive)
- HTTP status code scanning via `httpx`
- Wayback archive URL, JS files, parameters, and endpoint extraction

## Requirements

- Python 3.6+
- Tools:
  - `subfinder`
  - `amass`
  - `httpx`
  - `waybackurls`

## Install

```bash
git clone https://github.com/asur2103/BugReconX.git
cd /BugReconX
pip install -r requirements.txt
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/OWASP/Amass/v3/...@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/waybackurls@latest




