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

Do not use this tool to exfiltrate data from networks you do not own, to evade corporate data-loss prevention systems without authorisation, or to intercept communications without consent. Do not radiate covert beacons on any real channel outside a licensed, authorized, shield-attenuated lab. Any use that violates applicable law or organisational policy is strictly prohibited. Operating an intentional radiator outside FCC/regulatory limits is prohibited.

### Regulatory Framework
- **Federal Communications Act (47 U.S.C. § 333)**: Willful interference with authorized radio communications is prohibited.
- **47 CFR Part 15 / Part 18**: Unauthorized intentional radiators and out-of-spec electromagnetic emissions are regulated.
- **Computer Fraud and Abuse Act (CFAA, 18 U.S.C. § 1030)** and state computer-crime laws apply to unauthorized data access.

### No Warranty

This software is provided "as is" without warranty of any kind. The authors assume no liability for misuse, damage, or legal consequences arising from the use of this tool.

### Responsible Disclosure

If you discover vulnerabilities using this tool, report them to the affected vendor or network operator privately. Allow reasonable time for remediation before public disclosure. Follow coordinated vulnerability disclosure (CVD) best practices.

## Live Lab Test Plan

This repo is a byte-level covert-channel *engineering* tool: the C2 beacon frames are built,
parsed, and carried over pcap fixtures entirely offscreen — no radio.

Offline (this repo, no radio):
1. `python3 firmware/covert_beacon.py encode --message "hello" --pcap-out reports/c2.pcap --json reports/w8.json`
   — build the beacon-as-C2 frames; then
   `python3 firmware/covert_beacon.py decode --pcap reports/c2.pcap` — recover the payload (exit 0).
2. `python3 firmware/covert_beacon.py detect --ies ...` — run the IE-entropy detector and
   confirm covert frames are flagged while clean controls are not (exit 0).
3. `python3 -m unittest discover -s tests` — byte-exact unit tests pass (exit 0).

Authorized lab (only with written scope + shield + authorized channel):
4. Transmit the exact beacon bytes in a shielded enclosure and decode them with a lab monitor
   running `decode --pcap` — confirm byte-identical payload recovery.
5. `green = permitted`: any real-air covert transmission requires written lab authorization,
   an air-gapped/shielded bench, an authorized channel, and no use against networks you don't own.

## Metrics

- Beacon-as-C2: payload chunked into vendor-specific IEs (element 221, OUI FA:D4:02, type 0x77)
  carried in full 802.11 beacon frames; XOR key option
- Frame type engineered byte-exact: beacon (subtype 8); FCS append + verify
- IE-entropy detector: flags vendor-IE payloads above entropy 4.5; verdict normal/suspect/covert
- pcap round-trip: encode -> fixture -> decode, deterministic
- Offline: all frames synthesized as bytes; no wall-clock randomness in the engine path

- Test suite: `python3 -m unittest discover -s tests`
- Reports: `reports/` (gitignored)

## License

MIT
