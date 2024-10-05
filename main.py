import socket
import nmap
import threading

class VulnerabilityScanner:
    def __init__(self, targets, scan_type='-sV'):
        self.targets = targets
        self.scan_type = scan_type
        self.scan_results = {}
        self.nm = nmap.PortScanner()

    def resolve_target(self, target):
        try:
            ip_address = socket.gethostbyname(target)
            print(f"[+] Resolved {target} to {ip_address}")
            return ip_address
        except socket.error as err:
            print(f"[-] Cannot resolve {target}: {err}")
            return None

    def scan_ports(self, ip):
        print(f"[+] Scanning ports on {ip} with options '{self.scan_type}'")
        self.nm.scan(ip, '1-1024', arguments=self.scan_type)
        if ip in self.nm.all_hosts():
            return self.nm[ip]
        else:
            print(f"[-] No scan results for {ip}")
            return None

    def check_vulnerabilities(self, port_info):
        vulnerabilities = []
        for proto in port_info.all_protocols():
            lport = port_info[proto].keys()
            for port in lport:
                service = port_info[proto][port]['name']
                version = port_info[proto][port].get('version', '')
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
        known_vulns = {
            'ftp': {'vsftpd 2.3.4': 'CVE-2011-2523'},
            'ssh': {'openssh 7.2p2': 'CVE-2016-3115'},
        }
        service = service.lower()
        version = version.lower()
        if service in known_vulns and version in known_vulns[service]:
            return known_vulns[service][version]
        return None

    def scan_target(self, target):
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
        threads = []
        for target in self.targets:
            t = threading.Thread(target=self.scan_target, args=(target,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        self.generate_report()

    def generate_report(self):
        print("\n[+] Vulnerability Scan Report")
        for target, data in self.scan_results.items():
            print(f"\nTarget: {target}")
            print(f"IP Address: {data['ip']}")
            print("Open Ports and Services:")
            for proto in data['port_info'].all_protocols():
                lport = data['port_info'][proto].keys()
                for port in lport:
                    state = data['port_info'][proto][port]['state']
                    service = data['port_info'][proto][port]['name']
                    version = data['port_info'][proto][port].get('version', '')
                    print(f" - Port {port}/{proto} {state}: {service} {version}")
            if data['vulnerabilities']:
                print("Vulnerabilities Found:")
                for vuln in data['vulnerabilities']:
                    print(f" - {vuln['service']} {vuln['version']} on port {vuln['port']}: {vuln['vulnerability']}")
            else:
                print("No known vulnerabilities found.")

if __name__ == "__main__":
    # Example targets; replace with your actual targets
    targets = ['example.com', 'scanme.nmap.org']
    
    # Prompt the user to select the scan type
    print("Select the type of Nmap scan to perform:")
    print("1. SYN Scan (-sS)")
    print("2. Service Version Detection (-sV)")
    print("3. OS Detection (-O)")
    print("4. UDP Scan (-sU)")
    print("5. Comprehensive Scan (-sC -sV -A)")
    
    scan_option = input("Enter the number of your choice (1-5): ")
    
    scan_types = {
        '1': '-sS',
        '2': '-sV',
        '3': '-O',
        '4': '-sU',
        '5': '-sC -sV -A'
    }
    
    scan_type = scan_types.get(scan_option, '-sV')  # Default to '-sV' if invalid input
    
    scanner = VulnerabilityScanner(targets, scan_type)
    scanner.run()
