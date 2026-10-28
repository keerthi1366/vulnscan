# VulnScan — Automated Vulnerability Assessment Tool

VulnScan is a beginner-friendly, read-only tool for assessing the local computer. It collects system and software inventory, records selected security settings, and can compare supported products with data from the NIST National Vulnerability Database (NVD).

It does not exploit vulnerabilities, scan other hosts, or change system settings.

## Features

- Collects operating system and installed-software names and versions using read-only queries.
- Records Windows Firewall or Linux UFW status and the state of selected services as observations.
- Optionally looks up explicitly mapped products using the NVD API 2.0.
- Compares detected versions with NVD affected-version ranges. Results are potential matches, not confirmation that a system is vulnerable; uncertain comparisons are labeled accordingly.
- Includes available CVSS scores, severity, CVE links, and match evidence in findings.
- Generates timestamped JSON and CSV reports.
- Includes unit tests for inventory, security checks, version matching, NVD handling, and report generation.

## Requirements

- Python 3.10 or newer
- Windows 10/11 or Linux
- No third-party Python packages required
- Optional: an NVD API key set as the `NVD_API_KEY` environment variable

## Run

Open PowerShell in the project’s root folder—the folder containing `README.md`—and run:

```powershell
py -m vulnscan --out .\reports
```

To enable NVD lookups for supported products:

```powershell
py -m vulnscan --nvd --out .\reports
```

An API key is optional. To use one for the current PowerShell session:

```powershell
$env:NVD_API_KEY = "your-key"
py -m vulnscan --nvd --out .\reports
```

Run the tests from the project’s root folder:

```powershell
py -m unittest discover -s tests -v
```

If `py` is unavailable, try `python` instead.

## Inventory and NVD matching

On Windows, installed-software inventory uses read-only registry queries. On Linux, it uses `dpkg-query` or `rpm` when available. Firewall checks read Windows Defender Firewall profile status or Linux UFW status when available. Selected service checks report service state and startup mode as observations; a running service is not treated as a vulnerability.

NVD lookup is opt-in. When enabled, VulnScan sends only the CPE names and versions for explicitly mapped products to NVD; it does not send the local hostname or full inventory. Products without an explicit mapping are skipped rather than guessed.

NVD range matches are potential findings, not proof of exploitability or exposure. Product identity, vendor packaging, backported fixes, architecture, configuration, and incomplete version information can affect applicability. Missing or failed collection is reported as unknown, not secure.

## Safety

VulnScan is intended for devices you own or are authorized to assess. It performs read-only collection and does not change firewall, service, registry, or package settings. Do not commit API keys or personal scan reports to source control.

## Data source

- [NIST NVD Vulnerability API](https://nvd.nist.gov/developers/vulnerabilities)
- [NIST NVD CPE and Match Criteria APIs](https://nvd.nist.gov/developers/products)

NVD data may include CVSS metrics and affected-version boundaries. VulnScan preserves the available CVSS source and applicability evidence. The client spaces product lookups by six seconds; requests may still be rate-limited.

## Project layout

```text
vulnscan/
├── vulnscan/
├── tests/
└── README.md
```
