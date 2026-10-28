# VulnScan — Automated Vulnerability Assessment Tool

A beginner-friendly, read-only local assessment tool. VulnScan inventories this machine, checks a small set of security settings, and can compare supported products with NIST NVD data. It does not exploit vulnerabilities, scan other hosts, or change system settings.

## Status

Inventory, selected read-only checks, conservative version-range matching, JSON/CSV reporting, unit tests, and opt-in NVD API 2.0 lookups are included. The explicit NVD map currently covers selected products including Python, .NET, Microsoft Edge, Visual Studio Code, MySQL Server, MySQL Workbench/Shell, VirtualBox, 7-Zip, Firefox, Chrome, VLC, Git, and Node.js. Other inventory items are skipped rather than guessed, and the report lists the skipped count and examples.

## Requirements

- Python 3.10 or newer
- Windows 10/11 or Linux
- Optional NVD API key in `NVD_API_KEY` for live lookups (the key is not included in this project)

No third-party packages are required for this starter.

## Run

From PowerShell:

```powershell
cd .\work\vulnscan
py -m vulnscan --out .\reports
```

To opt into NVD lookups for supported products:

```powershell
py -m vulnscan --nvd --out .\reports
```

An API key is optional. If you have one, set it for the current PowerShell session before scanning (do not paste it into chat or save it in source):

```powershell
$env:NVD_API_KEY = "your-key"
py -m vulnscan --nvd --out .\reports
```

If `py` is unavailable, use `python` in its place. To run the tests:

```powershell
py -m unittest discover -s tests -v
```

The program prints a summary and writes timestamped JSON and CSV reports. Windows installed-software inventory uses read-only registry queries. Linux inventory uses `dpkg-query` or `rpm`; unavailable package managers are reported as a collection limitation. Firewall checks read Windows Defender Firewall profile state or Linux UFW status when available. Selected service checks inspect a short allowlist and report state/startup mode as observations; a running service is not called a vulnerability. With `--nvd`, only mapped product CPE names and versions are sent to NVD; the local hostname and full inventory are not sent.

## Features and implementation details

- **System inventory:** Collects the operating system and installed software names and versions using read-only queries.
- **Security checks:** Records Windows Firewall or Linux UFW status and the state of selected services as observations.
- **Optional vulnerability lookup:** Queries the NIST National Vulnerability Database (NVD) API 2.0 when run with `--nvd`. Only explicitly mapped products are looked up.
- **Version-range matching:** Compares detected versions with affected-version ranges in NVD data. Results are reported as potential matches or uncertain matches; they do not confirm that a system is vulnerable.
- **Prioritization and evidence:** Includes available CVSS scores and severity, CVE links, and match details in findings.
- **Reports:** Generates timestamped JSON and CSV reports, including assessment details and collection limitations.
- **Unit tests:** Covers inventory, security checks, version matching, NVD handling, and report generation.

## Safety and limitations

VulnScan is a read-only local assessment tool. It does not exploit vulnerabilities, scan other hosts, or change system settings. Software without an explicit product mapping is skipped. NVD lookup is optional and enabled with `--nvd`; an API key can be provided through the `NVD_API_KEY` environment variable.

**Limitations and future work:** Product mapping is limited; unmapped software is skipped. Broader product coverage, response caching, and more detailed configuration evaluation are future improvements.
NVD API reference: [Vulnerability API](https://nvd.nist.gov/developers/vulnerabilities) and [CPE / Match Criteria APIs](https://nvd.nist.gov/developers/products). NVD responses can express affected version boundaries and may include CVSS metrics; the implementation preserves the source CVSS version and applicability evidence. NVD documents API-key use and request limits; the client uses a six-second gap between product lookups to keep requests deliberate.

## Safety and interpretation

- Only assess a device you own or are authorized to assess.
- All collection in this scaffold is read-only; it makes no firewall, service, registry, or package changes.
- An NVD range match is a potential affected-version match, not proof of exploitability or exposure. Distribution backports, vendor packaging, architecture, configuration, and product identity can change applicability.
- Missing or failed collection is recorded as unknown, not as secure.
- Do not put API keys or personal data in reports or source control.

## Project layout

```text
vulnscan/
├── vulnscan/
├── tests/
└── README.md
```
