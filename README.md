# VScan

An interactive vulnerability scanning console.

`vscan >` Interactive CLI to configure targets, scan profiles, concurrent scans, and reports.

## Features

- Interactive console experience (like recon-ng): set options once, run repeatedly
- Multi-target scanning with concurrency controls
- Built-in Nmap scan profiles
- Custom Nmap argument support  `custom:<args>`
- Service/version collection and basic CVE matching from Exploit-DB
- Report export to JSON, TXT, CSV, and HTML

## Requirements

- Linux (recommended)
- Python 3.9+
- Nmap installed and available in PATH
- `searchsploit` (Exploit-DB package) for exploit lookup integration

## Installation

1. Clone the project.
2. Install Python dependencies:

```bash
pip install -r requirements.txt
```

3. Optional Dependencies check:
```bash
nmap --version
```

```bash
searchsploit --version
```

## Usage

```bash
sudo python vscan.py
```

> `sudo` is often required for privileged scan types.
<img width="1060" height="742" alt="image" src="https://github.com/user-attachments/assets/6e8ad798-5d27-4b6d-bead-4a2e083a538d" />

## Interactive Commands

- `show options` — display current global options
- `set <OPTION> <VALUE>` — set an option
- `run` — start scan with current options
- `scan` — alias for `run`
- `exploit` — alias for `run`
- `scan_types` — list available scan types
- `help scan_types` — help table for scan types
- `help output` — output file format guidance
- `exit` — quit console

## Global Options

- `TARGETS` (default: empty)
	- Comma-separated list of targets
	- Example: `set TARGETS 192.168.1.10,scanme.nmap.org`

- `SCAN_TYPE` (default: `syn`)
	- Uses built-in profiles or custom args
	- Example: `set SCAN_TYPE comprehensive`
	- Custom example: `set SCAN_TYPE custom:-sS -Pn -sV --script vuln`

- `PORTS` (default: `1-1024`)
	- Nmap ports syntax
	- Example: `set PORTS 1-65535`

- `THREADS` (default: `10`)
	- Max number of targets scanned in parallel
	- Does not need to equal number of targets

- `OUTPUT` (default: `None`)
	- Report output file path
	- Supported extensions: `.json`, `.txt`, `.csv`, `.html`, `.htm`
	- Disable output with: `none`, `null`, or `0`

- `SEARCHSPLOIT` (default: `True`)
	- Enables/disables searchsploit enrichment for discovered services
	- Example: `set SEARCHSPLOIT false`

- `SEARCHSPLOIT_MAX` (default: `3`)
	- Maximum number of ranked searchsploit matches shown per discovered service
	- Must be an integer greater than `0`
	- Example: `set SEARCHSPLOIT_MAX 5`

## Typical Workflow

```text
vscan > set TARGETS 192.168.1.10, scanme.nmap.org
vscan > set SCAN_TYPE syn
vscan > set PORTS 1-1000
vscan > set THREADS 5
vscan > set SEARCHSPLOIT true
vscan > set SEARCHSPLOIT_MAX 3
vscan > set OUTPUT report.json
vscan > run
```

## Output and Reporting

- Console output shows discovered services and matched findings.
- If `OUTPUT` is set, a report file is generated.
- Findings may include:
	- source type (`known-cve` or `searchsploit`)
	- exploit DB ID and path (when available)
- Searchsploit entries are filtered and ranked to reduce noisy matches.
- `SEARCHSPLOIT_MAX` controls how many searchsploit entries are shown per service.

## VScan test run against metasploitable2 
<img width="1051" height="282" alt="image" src="https://github.com/user-attachments/assets/edd8e5b7-20b3-49f8-a0cc-ebcb974f3f8f" />
<img width="1047" height="522" alt="image" src="https://github.com/user-attachments/assets/67d7d3ac-6926-42bc-a43d-137626003b48" />

## Sample HTML Report output:
  <img width="1417" height="670" alt="image" src="https://github.com/user-attachments/assets/febbbac8-2eb6-4384-9bfb-0a74dc7d03c8" />
<img width="1597" height="518" alt="image" src="https://github.com/user-attachments/assets/ed824c0c-e048-4462-a8aa-6a3686863fc5" />

## Troubleshooting

- `Import "nmap" could not be resolved`
	- Install dependencies from `requirements.txt`
	- Verify you are using the same Python environment where `python-nmap` is installed

- `searchsploit not found`
	- Install searchsploit or disable with: `set SEARCHSPLOIT false`

- Too many / too few exploit suggestions
	- Tune with: `set SEARCHSPLOIT_MAX <number>`



### Only scan systems you own or have explicit permission to test.
