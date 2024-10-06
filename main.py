import socket
import nmap
from concurrent.futures import ThreadPoolExecutor

class VulnerabilityScanner:
    def __init__(self, targets, scan_type='-sV'):
        """
        Initializes the VulnerabilityScanner.

        :param targets: List of domain names or IP addresses to scan.
        :param scan_type: Nmap scan type options (default is '-sV').
        """
        self.targets = targets
        self.scan_results = {}
        self.nm = nmap.PortScanner()
        self.scan_type = scan_type  # Nmap scan type options

    def resolve_target(self, target):
        """Resolve the domain name to an IP address."""
        try:
            ip_address = socket.gethostbyname(target)
            print(f"[+] Resolved {target} to {ip_address}")
            return ip_address
        except socket.error as err:
            print(f"[-] Cannot resolve {target}: {err}")
            return None

    def scan_ports(self, ip):
        """Scan ports on the given IP address using the specified scan type."""
        print(f"[+] Scanning ports on {ip} with scan type '{self.scan_type}'")
        # Scanning common ports (1-1024), can be adjusted
        self.nm.scan(ip, '1-1024', self.scan_type)
        if ip in self.nm.all_hosts():
            return self.nm[ip]
        else:
            print(f"[-] No scan results for {ip}")
            return None

    def check_vulnerabilities(self, port_info):
        """Check for known vulnerabilities based on service and version."""
        vulnerabilities = []
        for proto in port_info.all_protocols():
            lport = port_info[proto].keys()
            for port in lport:
                service = port_info[proto][port]['name']
                version = port_info[proto][port]['version']
                print(f"[+] Checking {service} {version} on port {port}")
                vuln = self.lookup_vulnerability(service, version)
                if vuln:
                    vulnerabilities.append({
                        'port': port,
                        'service': service,
                        'version': version,
                        'vulnerability': vuln
                    })
        return vulnerabilities

    def lookup_vulnerability(self, service, version):
        """Lookup known vulnerabilities from a predefined database."""
        # Placeholder for vulnerability lookup logic
        # In practice, query a real vulnerability database or API

        known_vulns = {
            'ftp': {'vsftpd 2.3.4': 'CVE-2011-2523'},
            'ssh': {'openssh 7.2p2': 'CVE-2016-3115'},
            'http': {'apache httpd 2.4.49': 'CVE-2021-41773'},
        }
        service = service.lower()
        version = version.lower()
        if service in known_vulns and version in known_vulns[service]:
            return known_vulns[service][version]
        return None

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
                    service = data['port_info'][proto][port]['name']
                    version = data['port_info'][proto][port]['version']
                    print(f" - Port {port}/{proto} {state}: {service} {version}")
            if data['vulnerabilities']:
                print("Vulnerabilities Found:")
                for vuln in data['vulnerabilities']:
                    print(f" - {vuln['service']} {vuln['version']} on port {vuln['port']}: {vuln['vulnerability']}")
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
