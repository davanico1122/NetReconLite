import argparse
import socket
import threading
import json
import time
from datetime import datetime

# ASCII Banner
BANNER = r"""
 _   _      _   _____                 _        ___  _ _       
| \ | | ___| |_| ____|_ __ ___  _ __ | | ___  / _ \| | |_ __  
|  \| |/ _ \ __|  _| | '__/ _ \| '_ \| |/ _ \| | | | | | '_ \ 
| |\  |  __/ |_| |___| | | (_) | |_) | | (_) | |_| | | | |_) |
|_| \_|\___|\__|_____|_|  \___/| .__/|_|\___/ \___/|_|_| .__/ 
                               |_|                     |_|    
NetReconLite v1.0 - Educational Network Reconnaissance Toolkit
"""

def port_scan(target, ports, max_threads=100):
    open_ports = []
    lock = threading.Lock()
    
    def scan_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                result = s.connect_ex((target, port))
                if result == 0:
                    with lock:
                        open_ports.append(port)
        except:
            pass
    
    print(f"[*] Scanning {target}...")
    threads = []
    for port in ports:
        while threading.active_count() > max_threads:
            time.sleep(0.01)
        t = threading.Thread(target=scan_port, args=(port,))
        t.daemon = True
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()
    
    open_ports.sort()
    return open_ports

def whois_lookup(domain):
    try:
        import whois
        print(f"[*] Querying WHOIS for {domain}...")
        w = whois.whois(domain)
        return str(w)
    except ImportError:
        return "Error: python-whois module not installed. Run 'pip install python-whois'"
    except Exception as e:
        return f"WHOIS lookup failed: {str(e)}"

def subdomain_scan(domain, wordlist_path):
    valid_subdomains = []
    try:
        with open(wordlist_path, 'r') as f:
            subdomains = [line.strip() for line in f]
    except FileNotFoundError:
        return f"Error: Wordlist file not found at {wordlist_path}"
    
    print(f"[*] Scanning {domain} for subdomains...")
    for sub in subdomains:
        full_domain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(full_domain)
            valid_subdomains.append(full_domain)
            print(f"  [+] Found: {full_domain}")
        except socket.gaierror:
            continue
        except socket.error:
            break
    
    return valid_subdomains

def geoip_lookup(ip_address):
    try:
        with open('geoip_data.json', 'r') as f:
            geo_data = json.load(f)
        
        location = geo_data.get(ip_address)
        if location:
            return location
        return {"country": "Unknown", "city": "Unknown"}
    except FileNotFoundError:
        return {"country": "Error", "city": "geoip_data.json not found"}

def parse_ports(port_range):
    ports = []
    parts = port_range.split('-')
    if len(parts) == 1:
        ports.append(int(parts[0]))
    elif len(parts) == 2:
        start = int(parts[0])
        end = int(parts[1])
        ports.extend(range(start, end + 1))
    return ports

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(
        description="NetReconLite - Educational Network Reconnaissance Toolkit",
        epilog="Note: This tool is for educational purposes only!"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Port scanner
    ps_parser = subparsers.add_parser('portscan', help='TCP port scanning')
    ps_parser.add_argument('target', help='IP address or domain name')
    ps_parser.add_argument('-p', '--ports', required=True, 
                          help='Port range (e.g., 80 or 1-100)')

    # WHOIS lookup
    whois_parser = subparsers.add_parser('whois', help='WHOIS domain lookup')
    whois_parser.add_argument('domain', help='Domain name to lookup')

    # Subdomain scanner
    sub_parser = subparsers.add_parser('subdomain', help='Subdomain enumeration')
    sub_parser.add_argument('domain', help='Base domain name')
    sub_parser.add_argument('-w', '--wordlist', default='wordlist.txt',
                           help='Path to subdomain wordlist')

    # GeoIP lookup
    geo_parser = subparsers.add_parser('geoip', help='GeoIP location lookup')
    geo_parser.add_argument('ip', help='IP address to locate')

    args = parser.parse_args()

    start_time = datetime.now()

    if args.command == 'portscan':
        try:
            target_ip = socket.gethostbyname(args.target)
            ports = parse_ports(args.ports)
            open_ports = port_scan(target_ip, ports)
            
            if open_ports:
                print("\n[+] Open ports found:")
                for port in open_ports:
                    print(f"  - Port {port}/TCP")
            else:
                print("\n[-] No open ports found")
                
        except socket.gaierror:
            print(f"Error: Could not resolve {args.target}")
        except ValueError:
            print("Error: Invalid port range format. Use '80' or '1-100'")

    elif args.command == 'whois':
        result = whois_lookup(args.domain)
        print("\nWHOIS Results:")
        print(result)

    elif args.command == 'subdomain':
        results = subdomain_scan(args.domain, args.wordlist)
        if isinstance(results, list):
            print("\n[+] Active subdomains:")
            for sub in results:
                print(f"  - {sub}")
        else:
            print(results)

    elif args.command == 'geoip':
        location = geoip_lookup(args.ip)
        print(f"\nGeoIP Location for {args.ip}:")
        print(f"  Country: {location.get('country', 'Unknown')}")
        print(f"  City: {location.get('city', 'Unknown')}")

    elapsed = datetime.now() - start_time
    print(f"\nScan completed in {elapsed.total_seconds():.2f} seconds")

if __name__ == "__main__":
    main()
