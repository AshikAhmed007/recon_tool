# 🛡️ Reconnaissance Tool (Python)

A modular Python-based reconnaissance tool designed for web and network penetration testers. This tool supports various active and passive recon modules like WHOIS lookup, DNS enumeration, subdomain discovery, port scanning, banner grabbing, and basic technology detection.

---

## 📌 Features

- 🔍 **WHOIS Lookup**  
  Retrieve WHOIS information of domains to gather registrar, contact, and creation/expiry details.

- 🌐 **DNS Enumeration**  
  Extract DNS records (A, MX, TXT, NS) to uncover critical infrastructure components.

- 🧭 **Subdomain Enumeration**  
  Uses [crt.sh](https://crt.sh) to discover subdomains using public certificate transparency logs.

- 🚪 **Port Scanning**  
  Scan custom or all ports (1–1024) to find open ports on a target IP.

- 📡 **Banner Grabbing**  
  Grab service banners from open ports to identify technologies and versions.

- 🧪 **Technology Detection (Wappalyzer API)**  
  Identify technologies used on websites (requires a valid Wappalyzer API endpoint).

- 🧾 **Report Generation**  
  Saves results in `.txt` or `.html` report format (default is `.txt`).

- 📣 **Verbose Output**  
  Optional verbose logging for detailed runtime information.

---

## 🚀 Usage

```bash
python recon_tool.py --target example.com --whois --dns --subdomains --scan --banner --tech --report txt -v
```

### 🔧 Arguments

| Argument          | Description |
|-------------------|-------------|
| `--target`        | Target domain(s) or IP(s), comma-separated. **(Required)** |
| `--ports`         | Ports to scan (`80,443`, or `all` for 1–1024). Default: `80,443`. |
| `--whois`         | Perform WHOIS lookup. |
| `--dns`           | Perform DNS enumeration. |
| `--subdomains`    | Enumerate subdomains. |
| `--scan`          | Perform port scan. |
| `--banner`        | Grab banners from open ports. |
| `--tech`          | Detect website technologies (basic Wappalyzer API call). |
| `--report`        | Report format: `txt` or `html`. Default: `txt`. |
| `-v`, `--verbose` | Enable verbose output. |

---

## 📁 Output

- Each target's results are saved to a file named:  
  ```
  [target]_report.txt
  ```
  or  
  ```
  [target]_report.html
  ```

---

## 📝 Example

```bash
python recon_tool.py --target scanme.nmap.org,example.com --ports 21,22,80 --whois --scan --banner --report txt -v
```

---

## ⚠️ Disclaimer

This tool is intended **for educational and authorized security testing only**. Unauthorized use against systems you do not own or have permission to test is illegal and unethical.

---

## 📌 Requirements

Install dependencies using:

```bash
pip install -r requirements.txt
```

**`requirements.txt` sample:**

```txt
argparse
python-whois
requests
dnspython
```

---

## 📧 Contact

**Author:** Ashik Ahmed  
Feel free to reach out for collaboration or reporting issues.
