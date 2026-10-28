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

## Build plan

1. **Inventory (starter):** collect OS identity and installed software names/versions with platform-native read-only queries.
2. **Security checks (starter):** record firewall profile/status evidence and read-only state for selected services. These are observations, not compliance conclusions.
3. **NVD integration (starter):** query the NIST NVD 2.0 API only when `--nvd` is supplied; use an optional API key from `NVD_API_KEY`, a request timeout, and conservative spacing. NVD responses are live, can be rate-limited, and may lack analysis for some CVEs.
4. **Matching and prioritization (starter):** map a limited set of product names to verified CPE names before matching. Evaluate NVD start/end version bounds including inclusive/exclusive semantics. If product identity, version format, Boolean configuration, or range cannot be resolved, label it `uncertain`. Show the CVSS source, version, score and severity when supplied; do not invent a score. Python's Windows installer build number is normalized to the release in its display name, duplicate component CPEs are queried once, pagination is handled, and unbounded ranges that cross minor release lines are marked uncertain. Broader map coverage, response caching, and detailed configuration-tree evaluation remain useful future improvements.
5. **Evidence and remediation (starter):** potential matches include the exact installed product/version, NVD criterion and matched range, CVE source URL, and a vendor-reference link when supplied. Guidance is a prompt to review a supported vendor update; it is not a confirmed fix or an automatic change.
6. **Reports and tests (starter):** JSON and CSV include assessment time, host/OS inventory, observations, limitations, and findings. Tests cover parsing, version bounds, uncertain matches, and report output.

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
  vulnscan/       application modules
  tests/          standard-library unit tests
  README.md
```
