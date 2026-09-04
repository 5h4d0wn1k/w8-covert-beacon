# W8 — Management-frame covert channel (exfil + detection) — w8-covert-beacon

Pure-Python 802.11 beacon/probe-response covert encoder and IE-entropy detector for exfiltrating data via vendor Information Elements and detecting such covert channels.

## Overview

This project implements a two-sided toolset:

1. **Covert encoder** — hides arbitrary bytes in vendor Information Element (IE) fields of beacon/probe-response frames, producing a stream of fake beacon IE blobs with configurable throughput.
2. **IE entropy detector** — computes per-frame IE-length entropy and vendor-IE payload entropy to flag anomalous frames indicative of a covert channel (doubles as rogue-AP detector).

## Features

- Vendor-IE encoding with configurable XOR key for optional confidentiality
- Shannon-entropy analysis of IE length distributions
- Vendor-payload entropy scoring per frame
- Automatic verdict: normal / suspect / covert with confidence score
- Clean beacon generator for control-group testing
- Fully offline — no network or hardware required
- Python ≥ 3.8, standard library only

## Installation

```bash
# No installation required
python3 firmware/covert_beacon.py
```

## Usage

```python
from firmware.covert_beacon import encode_payload, analyze_frames

# Encode a covert payload
result = encode_payload(b"secret data", max_ies=10)
print(result["ies"], result["throughput"], result["stealth_idx"])

# Analyse a list of beacon IE hex strings
report = analyze_frames(result["ies"])
print(report["verdict"], report["confidence"])
```

## Example Output

```
==============================================================
 W8 — Management-frame covert channel (exfil + detection)
==============================================================

[Encoder] payload (28 bytes): b'TOP SECRET: 42.3601,-71.0589'
  IEs generated : 1
  Throughput    : 28.0 bytes/IE
  Stealth index : 0.875

[Detector] analysed 31 frames
  IE-length entropy (mean)        : 5.8231
  Vendor-payload entropy (mean)   : 6.1402
  Flagged frames                  : 1
  Verdict                         : covert
  Confidence                      : 0.0323

[Control] 30 clean frames → normal (confidence 0.0)

==============================================================
 Result: PASS
==============================================================
```

## IMPORTANT: Read before use.

### Authorization Requirements

You must have explicit written authorization from the network owner before using this tool on any wireless network. Unauthorised interception or manipulation of network traffic is illegal in most jurisdictions.

### Legal Framework

This tool interacts with 802.11 management frames. In the United States, the Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030, criminalises unauthorised access to computer networks and interception of electronic communications. Similar statutes exist in the EU (Directive 2013/40/EU), UK (Computer Misuse Act 1990), and most other jurisdictions. Violations may result in criminal prosecution and civil liability.

### Acceptable Use

Use this tool only on networks you own or for which you have written permission to test. Acceptable scenarios include: authorised penetration testing, security research in isolated lab environments, and academic study of wireless covert channels.

### Prohibited Use

Do not use this tool to exfiltrate data from networks you do not own, to evade corporate data-loss prevention systems without authorisation, or to intercept communications without consent. Any use that violates applicable law or organisational policy is strictly prohibited.

### No Warranty

This software is provided "as is" without warranty of any kind. The authors assume no liability for misuse, damage, or legal consequences arising from the use of this tool.

### Responsible Disclosure

If you discover vulnerabilities using this tool, report them to the affected vendor or network operator privately. Allow reasonable time for remediation before public disclosure. Follow coordinated vulnerability disclosure (CVD) best practices.

## License

MIT
