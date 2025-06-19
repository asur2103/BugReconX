#!/usr/bin/env python3
# bugreconx.py - Full CLI-based Bug Hunting Recon Tool

BANNER = r"""
██████╗ ██╗   ██╗ ██████╗ ██████╗ ██████╗ ███████╗ ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██║   ██║██╔════╝██╔════╝██╔═══██╗██╔════╝██╔═══██╗████╗  ██║██║ ██╔╝
██████╔╝██║   ██║██║     ██║     ██║   ██║███████╗██║   ██║██╔██╗ ██║█████╔╝ 
██╔═══╝ ██║   ██║██║     ██║     ██║   ██║╚════██║██║   ██║██║╚██╗██║██╔═██╗ 
██║     ╚██████╔╝╚██████╗╚██████╗╚██████╔╝███████║╚██████╔╝██║ ╚████║██║  ██╗
╚═╝      ╚═════╝  ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
                   BugReconX - Subdomain + Recon CLI Tool
"""

import argparse
import os
import subprocess
from pathlib import Path
import requests
import time

def run_command(command, output_file=None):
    print(f"[+] Running: {command}")
    try:
        output = subprocess.check_output(command, shell=True, text=True)
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
        return output
    except subprocess.CalledProcessError as e:
        print(f"[-] Error: {e}")
        return ""

def enum_subdomains(domain_list, out_file):
    joined_domains = "\n".join(domain_list)
    tmp_input = "input_domains.txt"
    with open(tmp_input, 'w') as f:
        f.write(joined_domains)

    all_subs = set()

    print("[*] Running subfinder...")
    output = run_command(f"subfinder -silent -dL {tmp_input}")
    all_subs.update(output.splitlines())

    print("[*] Collecting subdomains from crt.sh...")
    for domain in domain_list:
        try:
            r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
            if r.status_code == 200:
                json_data = r.json()
                for entry in json_data:
                    name = entry.get('name_value')
                    if name:
                        all_subs.update(name.split('\n'))
            time.sleep(1)
        except Exception as e:
            print(f"[-] crt.sh error for {domain}: {e}")

    print("[*] Running amass...")
    output = run_command(f"amass enum -passive -dL {tmp_input} -silent")
    all_subs.update(output.splitlines())

    all_subs = sorted(set(s.strip().lower() for s in all_subs if s and '*' not in s))
    with open(out_file, 'w') as f:
        f.write("\n".join(all_subs))

    os.remove(tmp_input)

def filter_httpx(input_file):
    with open(input_file, 'r') as f:
        domains = f.read().splitlines()

    tmp_file = "tmp_httpx.txt"
    with open(tmp_file, 'w') as f:
        f.write("\n".join(domains))

    output = run_command(f"httpx -silent -status-code -no-color -l {tmp_file}")
    os.remove(tmp_file)

    categories = {'200': [], '403_404': [], '5xx': []}
    for line in output.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            url, code = parts[0], parts[1]
            if code == '[200]':
                categories['200'].append(url)
            elif code in ('[403]', '[404]'):
                categories['403_404'].append(url)
            elif code.startswith('[5'):
                categories['5xx'].append(url)

    for cat, items in categories.items():
        with open(f"output/{cat}.txt", 'w') as f:
            f.write("\n".join(items))

def wayback_extract(subdomain_file):
    with open(subdomain_file, 'r') as f:
        subdomains = f.read().splitlines()

    all_urls = set()
    js_urls = set()
    params = set()
    endpoints = set()

    try:
        for sub in subdomains:
            print(f"[+] Fetching Wayback URLs for: {sub}")
            output = run_command(f"waybackurls {sub}")
            urls = output.splitlines()
            all_urls.update(urls)

            for url in urls:
                if ".js" in url:
                    js_urls.add(url)
                if '?' in url:
                    params.add(url)
                if url.endswith(('.php', '.aspx', '.jsp', '.cgi')):
                    endpoints.add(url)

            with open("output/wayback_data.txt", 'w') as f:
                f.write("\n".join(sorted(all_urls)))
            with open("output/js_files.txt", 'w') as f:
                f.write("\n".join(sorted(js_urls)))
            with open("output/params.txt", 'w') as f:
                f.write("\n".join(sorted(params)))
            with open("output/endpoints.txt", 'w') as f:
                f.write("\n".join(sorted(endpoints)))

    except KeyboardInterrupt:
        print("\n[!] Wayback extraction interrupted by user (Ctrl+C).")
        print("[*] Partial wayback data saved in 'output/' folder.")

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="BugReconX - CLI Bug Recon Tool")
    parser.add_argument('-d', '--domain', help="Single domain to scan")
    parser.add_argument('-i', '--input', help="File with list of domains")
    args = parser.parse_args()

    Path("output").mkdir(exist_ok=True)

    domains = []
    if args.domain:
        domains = [args.domain.strip()]
    elif args.input:
        with open(args.input, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]

    if not domains:
        print("[-] No domain input provided. Use -d or -i.")
        return

    try:
        print("[+] Step 1: Enumerating subdomains...")
        enum_subdomains(domains, "output/all_subdomains.txt")

        print("[+] Step 2: Running httpx and categorizing status codes...")
        filter_httpx("output/all_subdomains.txt")

        print("[+] Step 3: Wayback URL extraction and filtering...")
        wayback_extract("output/all_subdomains.txt")

        print("[+] Recon completed! Check the 'output/' folder.")

    except KeyboardInterrupt:
        print("\n[!] Recon interrupted by user (Ctrl+C).")
        print("[*] Any progress up to this point has been saved in the 'output/' folder.")

if __name__ == '__main__':
    main()
