import argparse
import socket
import whois
import requests
import json
import dns.resolver
from datetime import datetime
import sys

# ---------- Logging ----------
def log(msg, verbose):
    if verbose:
        print(msg)

# ---------- WHOIS ----------
def whois_lookup(domain, verbose):
    log(f"[+] Running WHOIS for {domain}", verbose)
    try:
        result = whois.whois(domain)
        return str(result)
    except Exception as e:
        return f"WHOIS lookup failed: {e}"

# ---------- DNS ENUM ----------
def dns_enum(domain, verbose):
    log(f"[+] Performing DNS enumeration for {domain}", verbose)
    records = {}
    for record_type in ['A', 'MX', 'TXT', 'NS']:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [str(r) for r in answers]
        except:
            records[record_type] = []
    return json.dumps(records, indent=2)

# ---------- SUBDOMAIN ENUM ----------
def subdomain_enum(domain, verbose):
    log(f"[+] Enumerating subdomains for {domain}", verbose)
    subdomains = set()
    try:
        res = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
        for entry in res.json():
            name = entry['name_value']
            for sub in name.split("\n"):
                if domain in sub:
                    subdomains.add(sub.strip())
    except Exception as e:
        return f"Subdomain enum failed: {e}"
    return "\n".join(sorted(subdomains))

# ---------- PORT SCAN ----------
def port_scan(ip, ports, verbose):
    log(f"[+] Scanning ports on {ip}", verbose)
    open_ports = {}
    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(0.5)
            s.connect((ip, port))
            open_ports[port] = "Open"
            log(f"    [Open] {port}", verbose)
            s.close()
        except:
            pass
    return json.dumps(open_ports, indent=2)

# ---------- BANNER GRAB ----------
def banner_grab(ip, ports, verbose):
    log(f"[+] Grabbing banners on {ip}", verbose)
    banners = {}
    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((ip, port))
            s.send(b"HEAD / HTTP/1.1\r\nHost: {}\r\n\r\n".format(ip.encode()))
            banner = s.recv(1024).decode(errors='ignore')
            banners[port] = banner.strip()
            s.close()
        except:
            pass
    return json.dumps(banners, indent=2)

# ---------- TECHNOLOGY DETECTION ----------
def tech_detect(domain, verbose):
    log(f"[+] Detecting technologies on {domain}", verbose)
    try:
        res = requests.get(f"https://api.wappalyzer.com/lookup/v2/?url=http://{domain}")
        return json.dumps(res.json(), indent=2)
    except:
        return "Technology detection requires Wappalyzer API (Not implemented fully here)."

# ---------- REPORTING ----------
def generate_report(results, fmt="txt"):
    for target, modules in results.items():
        sanitized_target = target.replace("http://", "").replace("https://", "").replace("/", "_").replace(":", "_")
        filename = f"{sanitized_target}_report.{fmt}"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"=== Recon Report for {target} ===\n")
            for mod, output in modules.items():
                f.write(f"\n--- {mod.upper()} ---\n{output}\n")
        print(f"[+] Report saved to {filename}")

# ---------- MAIN ----------
def main():
    parser = argparse.ArgumentParser(description="Custom Reconnaissance Tool (Python)")
    parser.add_argument("--target", required=True, help="Target IP(s) or domain(s), comma-separated")
    parser.add_argument("--ports", default="80,443", help="'all' or comma-separated (e.g. 21,22,80)")
    parser.add_argument("--whois", action="store_true", help="Perform WHOIS lookup")
    parser.add_argument("--dns", action="store_true", help="Perform DNS enumeration")
    parser.add_argument("--subdomains", action="store_true", help="Enumerate subdomains")
    parser.add_argument("--scan", action="store_true", help="Port scan")
    parser.add_argument("--banner", action="store_true", help="Banner grabbing")
    parser.add_argument("--tech", action="store_true", help="Detect technologies")
    parser.add_argument("--report", choices=["txt", "html"], default="txt", help="Report format")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    targets = [t.strip() for t in args.target.split(",")]
    ports = list(range(1, 1025)) if args.ports == "all" else [int(p.strip()) for p in args.ports.split(",")]
    all_results = {}

    for target in targets:
        print(f"\n[***] Recon on {target} started.")
        results = {}
        if args.whois:
            results["whois"] = whois_lookup(target, args.verbose)
        if args.dns:
            results["dns"] = dns_enum(target, args.verbose)
        if args.subdomains:
            results["subdomains"] = subdomain_enum(target, args.verbose)
        if args.scan:
            results["scan"] = port_scan(target, ports, args.verbose)
        if args.banner:
            results["banner"] = banner_grab(target, ports, args.verbose)
        if args.tech:
            results["tech"] = tech_detect(target, args.verbose)
        all_results[target] = results

    generate_report(all_results, args.report)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit()
