import cmd
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

import nmap


class VScanScanner:
    SEARCHSPLOIT_MAX_RESULTS = 3
    SCAN_TYPE_MAP = {
        # Scan techniques
        "syn": "-sS -sV",
        "connect": "-sT -sV",
        "udp": "-sU -sV",
        "ack": "-sA -sV",
        "window": "-sW -sV",
        "maimon": "-sM -sV",
        "null": "-sN -sV",
        "fin": "-sF -sV",
        "xmas": "-sX -sV",
        "idle": "-sI zombie-host -sV",
        "ipproto": "-sO",
        "sctp-init": "-sY",
        "sctp-cookie": "-sZ",
        "bounce": "-b anonymous:pass@ftp.example.com",
        # Discovery / utility modes
        "list": "-sL",
        "ping": "-sn",
        "tcp-ping": "-PS80,443",
        "ack-ping": "-PA80,443",
        "udp-ping": "-PU53,161",
        "sctp-ping": "-PY80",
        "traceroute": "--traceroute",
        # Detection/enumeration modes
        "os": "-O",
        "version": "-sV",
        "scripts": "-sC",
        "vuln": "-sV --script vuln",
        "aggressive": "-A",
        "comprehensive": "-sS -sV -sC -A -O",
    }
    SCAN_TYPE_DESCRIPTIONS = {
        "ack": "ACK scan for firewall rule mapping (non-open/closed discovery).",
        "ack-ping": "Host discovery using TCP ACK probes.",
        "aggressive": "Aggressive mode: OS detect, version detect, script scan, traceroute.",
        "bounce": "FTP bounce scan via FTP relay (legacy/specialized).",
        "comprehensive": "Broad scan with SYN + version + scripts + OS detection.",
        "connect": "TCP connect scan using full TCP handshake.",
        "fin": "FIN stealth scan (often filtered by modern stacks/firewalls).",
        "idle": "Idle scan using zombie host for spoofed stealth scanning.",
        "ipproto": "IP protocol scan (discover supported IP protocols).",
        "list": "List targets only; no packets sent to targets.",
        "maimon": "Maimon scan variant (similar edge-case behavior to FIN/NULL/XMAS).",
        "null": "NULL stealth scan with no TCP flags set.",
        "os": "OS detection fingerprinting.",
        "ping": "Host discovery only (ping scan), no port scan.",
        "scripts": "Default NSE script scan.",
        "sctp-cookie": "SCTP COOKIE-ECHO scan.",
        "sctp-init": "SCTP INIT scan.",
        "sctp-ping": "Host discovery using SCTP INIT probes.",
        "syn": "TCP SYN stealth scan with service version detection.",
        "tcp-ping": "Host discovery using TCP SYN probes.",
        "traceroute": "Trace network path to targets.",
        "udp": "UDP port scan with service version detection.",
        "udp-ping": "Host discovery using UDP probes.",
        "version": "Service/version detection only.",
        "vuln": "Version scan plus NSE vuln scripts.",
        "window": "TCP Window scan (firewall/filter inference).",
        "xmas": "XMAS stealth scan with FIN/PSH/URG flags set.",
    }

    def __init__(self):
        """Initialize scanner state. Runtime options are provided by console commands."""
        self.targets = []
        self.scan_results = {}
        self.scan_type = "syn"
        self.scan_args = self.SCAN_TYPE_MAP["syn"]
        self.ports = "1-1024"
        self.output = None
        self.threads = 10
        self.searchsploit = True
        self.searchsploit_max_results = self.SEARCHSPLOIT_MAX_RESULTS
        self._searchsploit_available = shutil.which("searchsploit") is not None
        self._searchsploit_warned = False
        self._searchsploit_cache = {}

    def configure(self, options):
        """Load runtime options from global console state."""
        self.targets = self.parse_targets(options.get("TARGETS", ""))
        self.scan_type = options.get("SCAN_TYPE", "syn").lower()
        self.scan_args = self.resolve_scan_args(self.scan_type)
        self.ports = options.get("PORTS", "1-1024")
        self.output = options.get("OUTPUT")
        self.threads = int(options.get("THREADS", 10))
        self.searchsploit = self._to_bool(options.get("SEARCHSPLOIT", True), default=True)
        self.searchsploit_max_results = self._to_int(
            options.get("SEARCHSPLOIT_MAX", self.SEARCHSPLOIT_MAX_RESULTS),
            default=self.SEARCHSPLOIT_MAX_RESULTS,
            minimum=1,
        )
        self.scan_results = {}
        self._searchsploit_cache = {}

    @staticmethod
    def _to_bool(value, default=False):
        """Parse common boolean-like values from console options."""
        if isinstance(value, bool):
            return value
        if value is None:
            return default
        normalized = str(value).strip().lower()
        if normalized in {"1", "true", "yes", "y", "on", "enable", "enabled"}:
            return True
        if normalized in {"0", "false", "no", "n", "off", "disable", "disabled"}:
            return False
        return default

    @staticmethod
    def _to_int(value, default=1, minimum=1):
        """Parse integer-like values with minimum bound."""
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return default
        return parsed if parsed >= minimum else default

    def resolve_scan_args(self, scan_type):
        """Resolve scan profile to nmap args. Supports custom:<raw nmap args>."""
        if scan_type.startswith("custom:"):
            custom_args = scan_type.split("custom:", 1)[1].strip()
            if custom_args:
                return custom_args
        return self.SCAN_TYPE_MAP.get(scan_type, self.SCAN_TYPE_MAP["syn"])

    @staticmethod
    def parse_targets(targets):
        """Parse comma-separated targets into a normalized list."""
        if isinstance(targets, list):
            return [target.strip() for target in targets if target.strip()]
        return [target.strip() for target in str(targets).split(",") if target.strip()]

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
        """Scan ports on the given IP address using configured Nmap options."""
        print(f"[+] Scanning ports on {ip} with scan type '{self.scan_type}' ({self.scan_args})")
        scanner = nmap.PortScanner()
        try:
            scanner.scan(ip, self.ports, self.scan_args)
        except Exception as err:
            print(f"[-] Scan failed for {ip}: {err}")
            return None

        if ip in scanner.all_hosts():
            return scanner[ip]

        print(f"[-] No scan results for {ip}")
        return None

    def check_vulnerabilities(self, port_info):
        """Check for known vulnerabilities based on service and version."""
        vulnerabilities = []
        for proto in port_info.all_protocols():
            lport = port_info[proto].keys()
            for port in lport:
                service = port_info[proto][port].get("name", "")
                version = port_info[proto][port].get("version", "")
                print(f"[+] Checking {service} {version} on port {port}")
                vuln = self.lookup_vulnerability(service, version)
                if vuln:
                    vulnerabilities.append(
                        {
                            "port": port,
                            "service": service,
                            "version": version,
                            "source": "known-cve",
                            "vulnerability": vuln,
                        }
                    )

                searchsploit_matches = self.lookup_searchsploit(service, version)
                for match in searchsploit_matches:
                    vulnerabilities.append(
                        {
                            "port": port,
                            "service": service,
                            "version": version,
                            "source": "searchsploit",
                            "vulnerability": match.get("title", "Unknown exploit title"),
                            "exploit_db_id": match.get("exploit_db_id", ""),
                            "exploit_path": match.get("path", ""),
                        }
                    )
        return vulnerabilities

    def lookup_searchsploit(self, service, version):
        """Lookup exploit candidates via searchsploit for each discovered service."""
        if not self.searchsploit:
            return []

        if not self._searchsploit_available:
            if not self._searchsploit_warned:
                print("[-] searchsploit not found. Skipping exploit-db lookups.")
                self._searchsploit_warned = True
            return []

        query = self._build_searchsploit_query(service, version)
        if not query:
            return []

        if query in self._searchsploit_cache:
            return self._searchsploit_cache[query]

        try:
            result = subprocess.run(
                ["searchsploit", "--json", query],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except Exception as err:
            print(f"[-] searchsploit lookup failed for '{query}': {err}")
            self._searchsploit_cache[query] = []
            return []

        if result.returncode != 0 or not result.stdout.strip():
            self._searchsploit_cache[query] = []
            return []

        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            self._searchsploit_cache[query] = []
            return []

        parsed_results = []
        entries = payload.get("RESULTS_EXPLOIT", [])
        if isinstance(entries, list):
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                parsed_results.append(
                    {
                        "title": entry.get("Title", ""),
                        "exploit_db_id": entry.get("EDB-ID", ""),
                        "path": entry.get("Path", ""),
                    }
                )

        parsed_results = self._rank_and_filter_searchsploit(parsed_results, service, version)

        self._searchsploit_cache[query] = parsed_results
        return parsed_results

    @staticmethod
    def _build_searchsploit_query(service, version):
        """Build focused search query from service/version."""
        service = (service or "").strip()
        version = (version or "").strip()
        if service and version:
            return f"{service} {version}"
        return service

    @staticmethod
    def _sanitize_version_tokens(version):
        """Extract useful version tokens for relevance scoring."""
        if not version:
            return []
        candidates = re.findall(r"\d+(?:\.\d+)+", version)
        return candidates[:2]

    def _rank_and_filter_searchsploit(self, matches, service, version):
        """Deduplicate and keep most relevant searchsploit matches."""
        service_token = (service or "").strip().lower()
        version_tokens = self._sanitize_version_tokens(version)
        unique = {}

        for match in matches:
            title = (match.get("title") or "").strip()
            exploit_id = (match.get("exploit_db_id") or "").strip()
            path = (match.get("path") or "").strip()
            key = exploit_id or f"{title}|{path}"

            haystack = f"{title} {path}".lower()
            score = 0
            if service_token and service_token in haystack:
                score += 3
            for token in version_tokens:
                if token in haystack:
                    score += 2
            if "shellcode" in haystack:
                score -= 2
            if "dos" in haystack:
                score -= 1

            normalized = {
                "title": title,
                "exploit_db_id": exploit_id,
                "path": path,
                "score": score,
            }

            previous = unique.get(key)
            if previous is None or normalized["score"] > previous["score"]:
                unique[key] = normalized

        ranked = sorted(
            unique.values(),
            key=lambda item: (item["score"], bool(item["exploit_db_id"]), item["title"]),
            reverse=True,
        )

        relevant = [item for item in ranked if item["score"] > 0]
        selected = relevant or ranked
        return selected[: self.searchsploit_max_results]

    @staticmethod
    def _shorten_text(value, max_len=90):
        """Shorten long strings for readable terminal/text report output."""
        value = (value or "").strip()
        if len(value) <= max_len:
            return value
        return value[: max_len - 3] + "..."

    @staticmethod
    def _compact_path(path):
        """Compact exploit path for display while preserving context."""
        if not path:
            return ""
        normalized = path.replace("\\", "/")
        base = os.path.basename(normalized)
        parent = os.path.basename(os.path.dirname(normalized))
        if parent:
            return f"{parent}/{base}"
        return base

    def lookup_vulnerability(self, service, version):
        """Lookup known vulnerabilities from a predefined database."""
        known_vulns = {
            "ftp": {"vsftpd 2.3.4": "CVE-2011-2523"},
            "ssh": {"openssh 7.2p2": "CVE-2016-3115"},
            "http": {"apache httpd 2.4.49": "CVE-2021-41773"},
        }
        service = service.lower()
        version = version.lower()
        if service in known_vulns and version in known_vulns[service]:
            return known_vulns[service][version]
        return None

    def scan_target(self, target):
        """Perform the scanning process for a single target."""
        print(f"[*] Starting target scan: {target}")
        ip = self.resolve_target(target)
        if not ip:
            return
        port_info = self.scan_ports(ip)
        if not port_info:
            return
        vulnerabilities = self.check_vulnerabilities(port_info)
        self.scan_results[target] = {
            "ip": ip,
            "port_info": port_info,
            "vulnerabilities": vulnerabilities,
        }

    def run(self, options):
        """Run the scanner concurrently on all configured targets."""
        self.configure(options)
        if not self.targets:
            print("[-] No targets configured. Use: set TARGETS <ip1,ip2,domain>")
            return

        print(f"[*] Starting scan on {', '.join(self.targets)}")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.scan_target, target) for target in self.targets]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as err:
                    print(f"[-] Worker error: {err}")

        self.generate_report()

    def _serialize_port_info(self, port_info):
        """Convert python-nmap host result to JSON-safe structure."""
        serialized = {}
        for proto in port_info.all_protocols():
            serialized[proto] = {}
            for port in sorted(port_info[proto].keys()):
                entry = port_info[proto][port]
                serialized[proto][str(port)] = {
                    "state": entry.get("state", ""),
                    "name": entry.get("name", ""),
                    "product": entry.get("product", ""),
                    "version": entry.get("version", ""),
                    "extrainfo": entry.get("extrainfo", ""),
                }
        return serialized

    def _build_serializable_report(self):
        """Build JSON-safe report payload from scan results."""
        report = {}
        for target, data in self.scan_results.items():
            report[target] = {
                "ip": data["ip"],
                "port_info": self._serialize_port_info(data["port_info"]),
                "vulnerabilities": data["vulnerabilities"],
            }
        return report

    def _write_json_report(self, report_payload):
        with open(self.output, "w", encoding="utf-8") as report_file:
            json.dump(report_payload, report_file, indent=2)

    def _write_txt_report(self):
        with open(self.output, "w", encoding="utf-8") as report_file:
            report_file.write("Vulnerability Scan Report\n")
            report_file.write("=" * 28 + "\n")
            for target, data in self.scan_results.items():
                report_file.write(f"\nTarget: {target}\n")
                report_file.write(f"IP Address: {data['ip']}\n")
                report_file.write("Open Ports and Services:\n")
                for proto in data["port_info"].all_protocols():
                    lport = data["port_info"][proto].keys()
                    for port in sorted(lport):
                        state = data["port_info"][proto][port].get("state", "")
                        service = data["port_info"][proto][port].get("name", "")
                        version = data["port_info"][proto][port].get("version", "")
                        report_file.write(f" - Port {port}/{proto} {state}: {service} {version}\n")

                if data["vulnerabilities"]:
                    report_file.write("Vulnerabilities Found:\n")
                    for vuln in data["vulnerabilities"]:
                        source = vuln.get("source", "lookup")
                        extra = ""
                        title = self._shorten_text(vuln.get("vulnerability", ""))
                        if source == "searchsploit":
                            exploit_id = vuln.get("exploit_db_id", "")
                            exploit_path = vuln.get("exploit_path", "")
                            compact_path = self._compact_path(exploit_path)
                            extra = f" [EDB-ID: {exploit_id}] {compact_path}".strip()
                        report_file.write(
                            f" - {vuln['service']} {vuln['version']} "
                            f"on port {vuln['port']} ({source}): {title} {extra}\n"
                        )
                else:
                    report_file.write("No known vulnerabilities found.\n")

    def _write_csv_report(self):
        with open(self.output, "w", encoding="utf-8") as report_file:
            report_file.write(
                "target,ip,proto,port,state,service,version,vulnerability,source,exploit_db_id,exploit_path,score\n"
            )
            for target, data in self.scan_results.items():
                for proto in data["port_info"].all_protocols():
                    lport = data["port_info"][proto].keys()
                    for port in sorted(lport):
                        entry = data["port_info"][proto][port]
                        service = entry.get("name", "")
                        version = entry.get("version", "")
                        vulnerability = ""
                        source = ""
                        exploit_db_id = ""
                        exploit_path = ""
                        score = ""
                        for vuln in data["vulnerabilities"]:
                            if (
                                vuln.get("port") == port
                                and vuln.get("service") == service
                                and vuln.get("version") == version
                            ):
                                vulnerability = vuln.get("vulnerability", vulnerability)
                                source = vuln.get("source", "")
                                exploit_db_id = vuln.get("exploit_db_id", "")
                                exploit_path = vuln.get("exploit_path", "")
                                score = str(vuln.get("score", ""))
                                break
                        row = [
                            target,
                            data["ip"],
                            proto,
                            str(port),
                            entry.get("state", ""),
                            service,
                            version,
                            vulnerability,
                            source,
                            exploit_db_id,
                            exploit_path,
                            score,
                        ]
                        escaped = [value.replace('"', '""') for value in row]
                        report_file.write('"' + '","'.join(escaped) + '"\n')

    def _write_html_report(self):
        with open(self.output, "w", encoding="utf-8") as report_file:
            report_file.write("<html><head><meta charset='utf-8'><title>VScan Report</title></head><body>")
            report_file.write("<h1>Vulnerability Scan Report</h1>")
            for target, data in self.scan_results.items():
                report_file.write(f"<h2>Target: {target}</h2>")
                report_file.write(f"<p><strong>IP Address:</strong> {data['ip']}</p>")
                report_file.write(
                    "<table border='1' cellpadding='6' cellspacing='0'>"
                    "<tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Version</th></tr>"
                )
                for proto in data["port_info"].all_protocols():
                    lport = data["port_info"][proto].keys()
                    for port in sorted(lport):
                        state = data["port_info"][proto][port].get("state", "")
                        service = data["port_info"][proto][port].get("name", "")
                        version = data["port_info"][proto][port].get("version", "")
                        report_file.write(
                            f"<tr><td>{port}</td><td>{proto}</td><td>{state}</td>"
                            f"<td>{service}</td><td>{version}</td></tr>"
                        )
                report_file.write("</table>")

                if data["vulnerabilities"]:
                    report_file.write("<h3>Vulnerabilities Found</h3><ul>")
                    for vuln in data["vulnerabilities"]:
                        source = vuln.get("source", "lookup")
                        exploit_id = vuln.get("exploit_db_id", "")
                        exploit_path = vuln.get("exploit_path", "")
                        title = self._shorten_text(vuln.get("vulnerability", ""), max_len=120)
                        suffix = ""
                        if source == "searchsploit":
                            suffix = f" [EDB-ID: {exploit_id}] {self._compact_path(exploit_path)}".strip()
                        report_file.write(
                            f"<li>{vuln['service']} {vuln['version']} on port {vuln['port']}: "
                            f"{title} ({source}) {suffix}</li>"
                        )
                    report_file.write("</ul>")
                else:
                    report_file.write("<p>No known vulnerabilities found.</p>")
            report_file.write("</body></html>")

    def _write_report_file(self):
        """Write report according to OUTPUT file extension."""
        if not self.output:
            return

        extension = self.output.rsplit(".", 1)[-1].lower() if "." in self.output else "json"
        report_payload = self._build_serializable_report()

        if extension == "json":
            self._write_json_report(report_payload)
        elif extension == "txt":
            self._write_txt_report()
        elif extension == "csv":
            self._write_csv_report()
        elif extension in {"html", "htm"}:
            self._write_html_report()
        else:
            raise ValueError(
                "Unsupported output extension. Use .json, .txt, .csv, .html, or .htm"
            )

    def generate_report(self):
        """Generate a detailed report of the scan results and optionally save it."""
        print("\n[+] Vulnerability Scan Report")
        if not self.scan_results:
            print("[-] No results to display.")
            return

        for target, data in self.scan_results.items():
            print(f"\nTarget: {target}")
            print(f"IP Address: {data['ip']}")
            print("Open Ports and Services:")
            for proto in data["port_info"].all_protocols():
                lport = data["port_info"][proto].keys()
                for port in sorted(lport):
                    state = data["port_info"][proto][port].get("state", "")
                    service = data["port_info"][proto][port].get("name", "")
                    version = data["port_info"][proto][port].get("version", "")
                    print(f" - Port {port}/{proto} {state}: {service} {version}")

            if data["vulnerabilities"]:
                print("Vulnerabilities Found:")
                for vuln in data["vulnerabilities"]:
                    source = vuln.get("source", "lookup")
                    title = self._shorten_text(vuln.get("vulnerability", ""))
                    suffix = ""
                    if source == "searchsploit":
                        exploit_id = vuln.get("exploit_db_id", "")
                        exploit_path = vuln.get("exploit_path", "")
                        suffix = f" [EDB-ID: {exploit_id}] {self._compact_path(exploit_path)}".strip()
                    print(
                        f" - {vuln['service']} {vuln['version']} "
                        f"on port {vuln['port']} ({source}): {title} {suffix}"
                    )
            else:
                print("No known vulnerabilities found.")

        if self.output:
            try:
                self._write_report_file()
                print(f"[+] Report written to {self.output}")
            except (OSError, ValueError) as err:
                print(f"[-] Failed to write report file '{self.output}': {err}")


class VScanConsole(cmd.Cmd):
    """Interactive VScan console for configuring and running vulnerability scans."""

    intro = "VScan interactive console. Type help or ? to list commands."
    prompt = "vscan > "
    OUTPUT_HELP = (
        "OUTPUT controls report export file. Supported types by extension: "
        ".json, .txt, .csv, .html/.htm. "
        "Use null, none, or 0 to disable file output."
    )

    def __init__(self):
        super().__init__()
        self.options = {
            "TARGETS": "",
            "SCAN_TYPE": "syn",
            "PORTS": "1-1024",
            "OUTPUT": None,
            "THREADS": 10,
            "SEARCHSPLOIT": True,
            "SEARCHSPLOIT_MAX": 3,
        }
        self.scanner = VScanScanner()

    def emptyline(self):
        """Keep console idle when an empty line is entered."""
        return

    def do_show(self, arg):
        """show options: Display current global scanner configuration."""
        if arg.strip().lower() != "options":
            print("[-] Usage: show options")
            return

        print("\nGlobal Options")
        print("==============")
        for key, value in self.options.items():
            display_value = "None" if value is None else value
            print(f"{key:<10} : {display_value}")

    def do_set(self, arg):
        """set <OPTION> <VALUE>: Set TARGETS, SCAN_TYPE, PORTS, OUTPUT, THREADS. Use help output for file types."""
        parts = shlex.split(arg)
        if len(parts) < 2:
            print("[-] Usage: set <OPTION> <VALUE>")
            return

        option = parts[0].upper()
        value = " ".join(parts[1:]).strip()

        if option not in self.options:
            print(
                "[-] Unknown option. Valid options: TARGETS, SCAN_TYPE, PORTS, "
                "OUTPUT, THREADS, SEARCHSPLOIT, SEARCHSPLOIT_MAX"
            )
            return

        if option == "SCAN_TYPE":
            scan_type = value.lower()
            if not (scan_type in VScanScanner.SCAN_TYPE_MAP or scan_type.startswith("custom:")):
                print("[-] Invalid SCAN_TYPE.")
                print("[+] Use: help scan_types")
                print("[+] Or custom nmap args: set SCAN_TYPE custom:-sS -Pn -sV")
                return
            self.options[option] = scan_type
        elif option == "THREADS":
            try:
                threads = int(value)
            except ValueError:
                print("[-] THREADS must be an integer.")
                return
            if threads <= 0:
                print("[-] THREADS must be greater than 0.")
                return
            self.options[option] = threads
        elif option == "OUTPUT":
            self.options[option] = None if value.lower() in {"none", "null", "0", ""} else value
        elif option == "SEARCHSPLOIT":
            self.options[option] = VScanScanner._to_bool(value, default=True)
        elif option == "SEARCHSPLOIT_MAX":
            try:
                limit = int(value)
            except ValueError:
                print("[-] SEARCHSPLOIT_MAX must be an integer.")
                return
            if limit < 1:
                print("[-] SEARCHSPLOIT_MAX must be greater than 0.")
                return
            self.options[option] = limit
        else:
            self.options[option] = value

        print(f"{option} => {self.options[option]}")

    def help_output(self):
        """Show output file help and supported formats."""
        print(self.OUTPUT_HELP)

    def _print_scan_types_help(self):
        print("Available SCAN_TYPE profiles:")
        print("Args                          Description")
        print("----------                  ------------------------------------------------------")
        for scan_type in sorted(VScanScanner.SCAN_TYPE_MAP.keys()):
            description = VScanScanner.SCAN_TYPE_DESCRIPTIONS.get(
                scan_type, "No description available."
            )
            print(f"{scan_type:<30}{description}")
        print(f"{'custom:<nmap-args>':<30}Use any custom raw nmap arguments.")

    def do_scan_types(self, arg):
        """scan_types: List all supported scan types with descriptions and nmap arguments."""
        _ = arg
        self._print_scan_types_help()

    def help_scan_types(self):
        """Help topic for selecting SCAN_TYPE values."""
        self._print_scan_types_help()

    def do_run(self, arg):
        """run: Execute a vulnerability scan using current global options."""
        _ = arg
        self.scanner.run(self.options)

    def do_scan(self, arg):
        """scan: Alias for run."""
        self.do_run(arg)

    def do_exploit(self, arg):
        """exploit: Alias for run."""
        self.do_run(arg)

    def do_exit(self, arg):
        """exit: Quit the Vscan console."""
        _ = arg
        print("[*] Exiting VScan console.")
        return True

    def do_EOF(self, arg):
        """Handle Ctrl-D to exit the VScan console."""
        _ = arg
        print()
        return self.do_exit("")


if __name__ == "__main__":
    VScanConsole().cmdloop()
