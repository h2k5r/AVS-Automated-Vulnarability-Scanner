import socket
import nmap
import requests
from concurrent.futures import ThreadPoolExecutor

class VulnerabilityScanner:
    def __init__(self, targets, scan_type='-sV'):
        self.targets = targets
        self.scan_results = {}
        self.nm = nmap.PortScanner()
        self.scan_type = scan_type

    def resolve_target(self, target):
        try:
            ip_address = socket.gethostbyname(target)
            print(f"[+] Resolved {target} to {ip_address}")
            return ip_address
        except socket.error as err:
            print(f"[-] Cannot resolve {target}: {err}")
            return None

    def scan_ports(self, ip):
        print(f"[+] Scanning ports on {ip} with scan type '{self.scan_type}'")
        self.nm.scan(ip, '1-1024', self.scan_type)
        if ip in self.nm.all_hosts():
            return self.nm[ip]
        else:
            print(f"[-] No scan results for {ip}")
            return None

    def map_service_to_ecosystem_and_package(self, service_name):
        """Map service names to OSV ecosystems and package names."""
        service_name = service_name.lower()
        # Example mappings
        if 'apache httpd' in service_name or 'apache' in service_name:
            return 'Debian', 'apache2'
        elif 'nginx' in service_name:
            return 'Debian', 'nginx'
        elif 'openssh' in service_name:
            return 'Debian', 'openssh'
        elif 'vsftpd' in service_name:
            return 'Debian', 'vsftpd'
        elif 'ssh' in service_name:
            return 'Debian', 'openssh'
        elif 'ftp' in service_name:
            return 'Debian', 'vsftpd'
        elif 'mysql' in service_name:
            return 'Debian', 'mysql-server'
        elif 'postgresql' in service_name:
            return 'Debian', 'postgresql'
        elif 'iis' in service_name:
            return 'Windows', 'iis'
        elif 'ssl' in service_name or 'tls' in service_name:
            return 'Debian', 'openssl'
        # Add more mappings as needed
        else:
            return None, None

    def lookup_vulnerability_osv(self, service, version):
        """Lookup known vulnerabilities using the OSV.dev API by version number."""
        ecosystem, package_name = self.map_service_to_ecosystem_and_package(service)
        if not ecosystem or not package_name:
            print(f"[-] Could not map service '{service}' to an OSV ecosystem and package.")
            return None

        query = {
            "version": version,
            "package": {
                "name": package_name,
                "ecosystem": ecosystem
            }
        }

        try:
            headers = {
                'User-Agent': 'VulnerabilityScanner/1.0'
            }
            response = requests.post("https://api.osv.dev/v1/query", json=query, headers=headers)
            if response.status_code == 200:
                data = response.json()
                if 'vulns' in data:
                    vulnerabilities = []
                    for vuln in data['vulns']:
                        vuln_info = {
                            'id': vuln.get('id'),
                            'summary': vuln.get('summary', ''),
                            'details': vuln.get('details', ''),
                            'references': vuln.get('references', [])
                        }
                        vulnerabilities.append(vuln_info)
                    return vulnerabilities
                else:
                    print(f"[+] No vulnerabilities found for {package_name} {version}")
            else:
                print(f"[-] OSV API request failed with status code {response.status_code}")
        except requests.RequestException as e:
            print(f"[-] Error querying OSV API: {e}")
        return None

    def check_vulnerabilities(self, port_info):
        """Check for known vulnerabilities based on service and version."""
        vulnerabilities = []
        for proto in port_info.all_protocols():
            lport = port_info[proto].keys()
            for port in lport:
                service = port_info[proto][port].get('product', '') or port_info[proto][port].get('name', '')
                version = port_info[proto][port].get('version', '')
                if not service or not version:
                    continue
                print(f"[+] Checking {service} {version} on port {port}")

                # Use the OSV lookup function
                vulns = self.lookup_vulnerability_osv(service, version)
                if vulns:
                    for vuln in vulns:
                        vulnerabilities.append({
                            'port': port,
                            'service': service,
                            'version': version,
                            'vulnerability': vuln
                        })
        return vulnerabilities

    def scan_target(self, target):
        """Perform the scanning process for a single target."""
        ip = self.resolve_target(target)
        if not ip:
            return
        port_info = self.scan_ports(ip)
        if not port_info:
            return
        vulnerabilities = self.check_vulnerabilities(port_info)
        self.scan_results[target] = {
            'ip': ip,
            'port_info': port_info,
            'vulnerabilities': vulnerabilities
        }

    def run(self):
        """Run the scanner concurrently on all targets."""
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(self.scan_target, self.targets)
        self.generate_report()

    def generate_report(self):
        """Generate a detailed report of the scan results."""
        print("\n[+] Vulnerability Scan Report")
        for target, data in self.scan_results.items():
            print(f"\nTarget: {target}")
            print(f"IP Address: {data['ip']}")
            print("Open Ports and Services:")
            for proto in data['port_info'].all_protocols():
                lport = data['port_info'][proto].keys()
                for port in sorted(lport):
                    state = data['port_info'][proto][port]['state']
                    service = data['port_info'][proto][port].get('product', '') or data['port_info'][proto][port].get('name', '')
                    version = data['port_info'][proto][port].get('version', '')
                    print(f" - Port {port}/{proto} {state}: {service} {version}")
            if data['vulnerabilities']:
                print("Vulnerabilities Found:")
                for vuln_data in data['vulnerabilities']:
                    vuln = vuln_data['vulnerability']
                    print(f" - {vuln_data['service']} {vuln_data['version']} on port {vuln_data['port']}:")
                    print(f"   ID: {vuln['id']}")
                    print(f"   Summary: {vuln['summary']}")
                    print(f"   Details: {vuln['details']}")
                    if vuln['references']:
                        print("   References:")
                        for ref in vuln['references']:
                            print(f"     - {ref.get('url')}")
            else:
                print("No known vulnerabilities found.")

if __name__ == "__main__":
    # Input Targets to scan
    targets_input = input("Enter Domain name or IP address of the target(s) (separated by commas): ")
    targets = [target.strip() for target in targets_input.split(',')]

    # Select the scan type
    print("\nSelect Nmap scan type:")
    print("1. TCP SYN Scan (Default)")
    print("2. TCP Connect Scan")
    print("3. UDP Scan")
    print("4. Comprehensive Scan")
    choice = input("Enter choice (1-4): ")

    if choice == '1':
        scan_type = '-sS -sV'  # TCP SYN Scan with service detection
    elif choice == '2':
        scan_type = '-sT -sV'  # TCP Connect Scan with service detection
    elif choice == '3':
        scan_type = '-sU -sV'  # UDP Scan with service detection
    elif choice == '4':
        scan_type = '-sS -sV -sC -A -O'  # Comprehensive scan
    else:
        print("Invalid choice. Using default scan type.")
        scan_type = '-sV'  # Default service version detection

    scanner = VulnerabilityScanner(targets, scan_type=scan_type)
    scanner.run()
