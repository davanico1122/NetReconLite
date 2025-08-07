# NetReconLite - Educational Network Reconnaissance Toolkit

![Banner](banner.png)

NetReconLite is a Python-based CLI toolkit designed for educational purposes to demonstrate basic network reconnaissance techniques in a legal and ethical manner.

**Disclaimer**: This tool is for educational purposes only. Always obtain proper authorization before scanning any network. Unauthorized scanning is illegal.

## Features

1. **TCP Port Scanner**: 
   - Scans specified ports on a target IP/domain
   - Uses multi-threading for efficient scanning
   
2. **WHOIS Lookup**:
   - Retrieves domain registration information
   - Requires `python-whois` module (`pip install python-whois`)
   
3. **Subdomain Enumeration**:
   - Discovers active subdomains using DNS resolution
   - Uses a wordlist file for brute-force scanning
   
4. **GeoIP Lookup**:
   - Simulates geographic location lookup
   - Uses local JSON database (dummy data)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/davanico1122/NetReconLite.git
   cd NetReconLite

2.Install dependencies:
  pip install python-whois

Usage
``` python recon.py [command] [options]

Commands:
 1.Port Scanning:
   python recon.py portscan TARGET -p PORT_RANGE

   Example:
   python recon.py portscan example.com -p 80-100
   
2.WHOIS Lookup:
  python recon.py whois DOMAIN

  Example:
  python recon.py whois example.com

3.GeoIP Lookup:
  python recon.py geoip IP_ADDRESS

  Example:
  python recon.py geoip 8.8.8.8

Ethical Considerations
Only scan networks you own or have explicit permission to scan

*Do not use this tool for malicious purposes

*Respect all applicable laws and regulations

*The GeoIP data is simulated and not real

License
This project is licensed under the MIT License - see the LICENSE file for details.


## How to Use:

1. Save all files in a directory named `NetReconLite`
2. Install required dependency: `pip install python-whois`
3. Run the tool: `python recon.py [command] [options]`

## Example Commands:

```bash
# Port scan
python recon.py portscan scanme.nmap.org -p 20-100

# WHOIS lookup
python recon.py whois google.com

# Subdomain enumeration
python recon.py subdomain google.com

# GeoIP lookup
python recon.py geoip 8.8.8.8
