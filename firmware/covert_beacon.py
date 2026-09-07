#!/usr/bin/env python3
"""
W8 — Management-frame covert channel (exfil + detection)

Pure-Python 802.11 beacon/probe-response covert encoder and IE-entropy
detector.  Encodes arbitrary bytes into vendor Information Element (IE)
fields; then detects covert frames by computing per-frame IE-length
entropy and vendor-IE payload entropy.

No external dependencies required — Python >= 3.8 stdlib only.
"""

from __future__ import annotations

import base64
import collections
import hashlib
import json
import math
import os
import random
import secrets
import struct
import sys
from typing import Dict, List, Optional, Sequence, Tuple

# ─────────────────────────── constants ────────────────────────────

# Fake OUI prefixes used for vendor IE encoding (24-bit OUI)
_OUI_TABLE: List[bytes] = [
    bytes([0xFA, 0xD4, 0x01]),
    bytes([0xFA, 0xD4, 0x02]),
    bytes([0xFA, 0xD4, 0x03]),
    bytes([0xFA, 0xD4, 0x04]),
    bytes([0xFA, 0xD4, 0x05]),
    bytes([0xFA, 0xD4, 0x06]),
    bytes([0xFA, 0xD4, 0x07]),
    bytes([0xFA, 0xD4, 0x08]),
]

# Maximum bytes a single vendor IE can carry (IE header 2 + OUI 3 + type 1 = 6 overhead;
# max IE length field is 255, so 255 - 6 = 249 data bytes per IE)
_MAX_IE_DATA = 249

# ─────────────────────────── covert encoder ────────────────────────

def _chunk(data: bytes, size: int) -> List[bytes]:
    """Split *data* into chunks of at most *size* bytes."""
    return [data[i : i + size] for i in range(0, len(data), size)]


def encode_payload(
    payload: bytes,
    *,
    max_ies: int = 64,
    key: Optional[bytes] = None,
) -> Dict[str, object]:
    """Encode *payload* into a list of fake beacon vendor-IE blobs.

    Parameters
    ----------
    payload : bytes
        Arbitrary data to exfiltrate.
    max_ies : int
        Maximum number of IEs to produce.
    key : bytes or None
        Optional XOR key applied before encoding (adds confidentiality).

    Returns
    -------
    dict with keys:
        ies          – list of hex-encoded IE byte-strings
        ie_count     – number of IEs used
        throughput   – bytes per IE (payload size / ie_count)
        stealth_idx – 0‑1 lower is stealthier (ratio of total IE bytes to
                      min possible for clean beacons)
    """
    if key:
        payload = bytes(b ^ key[i % len(key)] for i, b in enumerate(payload))

    chunks = _chunk(payload, _MAX_IE_DATA)
    if len(chunks) > max_ies:
        raise ValueError(
            f"Payload requires {len(chunks)} IEs but max_ies={max_ies}"
        )

    ies: List[str] = []
    for idx, chunk in enumerate(chunks):
        oui = _OUI_TABLE[idx % len(_OUI_TABLE)]
        ie_type = 0xDD  # vendor-specific IE
        ie_len = len(chunk) + 3 + 1  # OUI(3) + type(1) + data
        raw = struct.pack("!BB", ie_type, ie_len) + oui + b"\x01" + chunk
        ies.append(raw.hex())

    total_ie_bytes = sum(len(bytes.fromhex(h)) for h in ies)
    min_beacon_ie_overhead = 12  # typical minimum for a clean beacon
    stealth_idx = min(total_ie_bytes / max(min_beacon_ie_overhead * len(ies), 1), 1.0)

    return {
        "ies": ies,
        "ie_count": len(ies),
        "throughput": len(payload) / max(len(ies), 1),
        "stealth_idx": round(stealth_idx, 4),
    }


# ─────────────────────────── IE‑entropy detector ───────────────────

def _byte_entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence (0–8 bits)."""
    if not data:
        return 0.0
    freq = collections.Counter(data)
    length = len(data)
    return -sum(
        (c / length) * math.log2(c / length) for c in freq.values()
    )


def _ie_lengths_from_hex(ie_hex: str) -> List[int]:
    """Parse a flat hex string of concatenated IEs, return list of IE lengths."""
    raw = bytes.fromhex(ie_hex)
    lengths: List[int] = []
    i = 0
    while i + 1 < len(raw):
        ie_len = raw[i + 1]
        lengths.append(ie_len)
        i += 2 + ie_len
    return lengths


def _vendor_payloads_from_hex(ie_hex: str) -> List[bytes]:
    """Extract vendor-IE payload bytes from a flat hex IE string."""
    raw = bytes.fromhex(ie_hex)
    payloads: List[bytes] = []
    i = 0
    while i + 1 < len(raw):
        ie_len = raw[i + 1]
        total = 2 + ie_len
        ie_raw = raw[i : i + total]
        if len(ie_raw) >= 6 and ie_raw[0] == 0xDD:
            vendor_payload = ie_raw[6:]  # skip type + len + OUI(3) + sub-type(1)
            if vendor_payload:
                payloads.append(vendor_payload)
        i += total
    return payloads


def analyze_frames(frame_ies: List[str]) -> Dict[str, object]:
    """Analyse a list of hex-encoded IE blobs for covert-channel indicators.

    Parameters
    ----------
    frame_ies : list[str]
        Each element is the hex string of IEs from one beacon frame.

    Returns
    -------
    dict with:
        frames_analysed
        mean_ie_len_entropy
        mean_vendor_payload_entropy
        flagged_count
        flagged_frames – list of indices
        verdict        – "normal" | "suspect" | "covert"
        confidence     – 0‑1
    """
    if not frame_ies:
        return {
            "frames_analysed": 0,
            "mean_ie_len_entropy": 0.0,
            "mean_vendor_payload_entropy": 0.0,
            "flagged_count": 0,
            "flagged_frames": [],
            "verdict": "normal",
            "confidence": 0.0,
        }

    len_entropies: List[float] = []
    vendor_entropies: List[float] = []

    for ie_hex in frame_ies:
        lengths = _ie_lengths_from_hex(ie_hex)
        len_bytes = bytes(lengths)
        len_entropies.append(_byte_entropy(len_bytes))

        payloads = _vendor_payloads_from_hex(ie_hex)
        if payloads:
            combined = b"".join(payloads)
            vendor_entropies.append(_byte_entropy(combined))
        else:
            vendor_entropies.append(0.0)

    mean_len_ent = sum(len_entropies) / len(len_entropies)
    mean_vend_ent = sum(vendor_entropies) / len(vendor_entropies)

    # Flag frames where vendor-payload entropy is suspiciously high
    # (covert-encoded binary data has near-maximum entropy)
    flagged: List[int] = []
    for i, (le, ve) in enumerate(zip(len_entropies, vendor_entropies)):
        if ve > 4.5:
            flagged.append(i)

    flagged_count = len(flagged)
    confidence = min(flagged_count / max(len(frame_ies), 1), 1.0)

    if confidence > 0.5:
        verdict = "covert"
    elif confidence > 0.2:
        verdict = "suspect"
    else:
        verdict = "normal"

    return {
        "frames_analysed": len(frame_ies),
        "mean_ie_len_entropy": round(mean_len_ent, 4),
        "mean_vendor_payload_entropy": round(mean_vend_ent, 4),
        "flagged_count": flagged_count,
        "flagged_frames": flagged,
        "verdict": verdict,
        "confidence": round(confidence, 4),
    }


# ─────────────────────── beacon-as-C2 frame layer ─────────────────

try:
    from firmware import frame_core as fc  # type: ignore
except ImportError:
    try:
        import frame_core as fc  # type: ignore
    except ImportError:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        import frame_core as fc  # type: ignore

_C2_OUI = b"\xfa\xd4\x02"        # fake OUI prefix used for C2 vendor IE
_C2_TYPE = 0x77                   # sub-type byte discriminating C2 from ambient vendor IEs


def encode_to_beacons(
    payload: bytes,
    bssid: str = "00:11:22:33:44:55",
    ssid: str = "lab-test-net",
    seq_start: int = 1,
    key: Optional[bytes] = None,
) -> List[bytes]:
    """Encode *payload* across a sequence of full 802.11 beacon *frames*.

    Each beacon carries one chunk of the payload inside a vendor-specific
    IE (element 221, OUI 0xFA:D4:02, type 0x77) — the C2 pattern.  The
    beacons are pure bytes; nothing is radiated.
    """
    chunks = _chunk(payload, _MAX_IE_DATA)
    frames: List[bytes] = []
    for idx, chunk in enumerate(chunks):
        if key:
            chunk = bytes(b ^ key[i % len(key)] for i, b in enumerate(chunk))
        c2_ie = struct.pack("!B", fc.IE_VENDOR) + struct.pack("!B", len(chunk) + 4)
        c2_ie += _C2_OUI + bytes([_C2_TYPE]) + chunk
        beacon = fc.build_beacon(bssid, ssid=ssid, timestamp=1000 + idx,
                                 beacon_interval=100, seq_num=(seq_start + idx) % 4096,
                                 vendor=c2_ie[2:])
        frames.append(beacon)
    return frames


def decode_from_beacons(frames: Sequence[bytes], key: Optional[bytes] = None) -> bytes:
    """Decode a C2 payload out of a sequence of full beacon frames.

    Pass ``key`` (same XOR key used at encode time) to un-scramble the data.
    """
    chunks: List[bytes] = []
    for frame in frames:
        if fc.verify_fcs(frame):
            frame = frame[:-4]
        fields, ies = fc.parse_beacon(frame)
        if fields["subtype_val"] != fc.FC_SUBTYPE_BEACON:
            continue
        for ie in ies:
            if ie["id"] != fc.IE_VENDOR or ie["malformed"]:
                continue
            v = ie["value"]
            if len(v) >= 4 and v[0:3] == _C2_OUI and v[3] == _C2_TYPE:
                chunks.append(v[4:])
    payload = b"".join(chunks)
    if key:
        payload = bytes(b ^ key[i % len(key)] for i, b in enumerate(payload))
    return payload


def encode_c2_to_pcap(payload: bytes, path: str, **kw) -> int:
    frames = encode_to_beacons(payload, **kw)
    fc.write_pcap(path, frames, ts=1700000000.0)
    return len(frames)


def decode_c2_from_pcap(path: str, key: Optional[bytes] = None) -> bytes:
    records = fc.read_pcap(path)
    frames = [r["data"] for r in records]
    return decode_from_beacons(frames, key=key)


# ─────────────────────────── offline demo ──────────────────────────

def _generate_clean_beacon_ies(count: int, rng: random.Random) -> List[str]:
    """Generate plausible-looking (non-covert) beacon IE hex strings."""
    result: List[str] = []
    for _ in range(count):
        # Random vendor IE with low-entropy payload
        oui = secrets.token_bytes(3)
        payload_len = rng.randint(4, 32)
        # Low-entropy payload: repeating or small-alphabet
        alphabet = bytes([rng.randint(0x41, 0x5A)])
        payload = alphabet * payload_len
        ie_type = 0xDD
        ie_len = len(payload) + 4
        raw = struct.pack("!BB", ie_type, ie_len) + oui + b"\x00" + payload
        result.append(raw.hex())
    return result


def run_demo_self_test() -> int:
    """Offline self-test: encode a covert payload then detect it."""
    print("=" * 62)
    print(" W8 — Management-frame covert channel (exfil + detection)")
    print("=" * 62)

    # --- encoder demo ---
    secret = b"TOP SECRET: 42.3601,-71.0589"
    enc_key = b"\xAA\x55\x3C\xB1"
    print(f"\n[Encoder] payload ({len(secret)} bytes): {secret!r}")

    enc = encode_payload(secret, max_ies=10, key=enc_key)
    print(f"  IEs generated : {enc['ie_count']}")
    print(f"  Throughput    : {enc['throughput']:.1f} bytes/IE")
    print(f"  Stealth index : {enc['stealth_idx']}")

    # --- build a mixed frame list (clean + covert) ---
    rng = random.Random(0xDEADBEEF)
    clean = _generate_clean_beacon_ies(30, rng)
    covert = enc["ies"]
    mixed = clean + covert
    rng.shuffle(mixed)

    # --- detector demo ---
    analysis = analyze_frames(mixed)
    print(f"\n[Detector] analysed {analysis['frames_analysed']} frames")
    print(f"  IE-length entropy (mean)        : {analysis['mean_ie_len_entropy']}")
    print(f"  Vendor-payload entropy (mean)   : {analysis['mean_vendor_payload_entropy']}")
    print(f"  Flagged frames                  : {analysis['flagged_count']}")
    print(f"  Verdict                         : {analysis['verdict']}")
    print(f"  Confidence                      : {analysis['confidence']}")

    # --- pure-clean control ---
    clean_only = _generate_clean_beacon_ies(30, rng)
    ctrl = analyze_frames(clean_only)
    print(f"\n[Control] {ctrl['frames_analysed']} clean frames → {ctrl['verdict']} "
          f"(confidence {ctrl['confidence']})")

    # --- assertions ---
    errors = 0
    if analysis["flagged_count"] == 0:
        print("\nFAIL: detector did not flag any covert frames")
        errors += 1
    if ctrl["flagged_count"] != 0:
        print("FAIL: control frames were falsely flagged")
        errors += 1

    status = "PASS" if errors == 0 else "FAIL"
    print(f"\n{'=' * 62}")
    print(f" Result: {status}")
    print("=" * 62)
    return 0 if errors == 0 else 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI: beacon-as-C2 encode/decode over frame bytes + pcap fixtures."""
    import argparse

    parents = argparse.ArgumentParser(add_help=False)
    parents.add_argument("--json", metavar="PATH", help="write JSON report")

    p = argparse.ArgumentParser(
        prog="w8-covert-beacon",
        parents=[parents],
        description="Beacon-as-C2 covert-channel encoder/decoder over byte-exact 802.11 "
                    "beacons (pure-stdlib bytes; offline; no radio).")
    sub = p.add_subparsers(dest="cmd", required=True)

    en = sub.add_parser("encode", parents=[parents], help="encode payload into beacon frames")
    en.add_argument("--message", default="TOP SECRET: 42.3601,-71.0589",
                    help="payload to hide")
    en.add_argument("--key", default=None, help="XOR key (hex)")
    en.add_argument("--pcap-out", metavar="PATH", help="write beacon frames to pcap")

    de = sub.add_parser("decode", parents=[parents], help="decode payload from beacon frames")
    de.add_argument("--pcap", metavar="PATH", help="pcap fixture of beacons")
    de.add_argument("--hex", metavar="HEX", help="space-separated hex beacon frames")
    de.add_argument("--key", default=None, help="XOR key (hex), if applied at encode time")

    det = sub.add_parser("detect", parents=[parents], help="IE-entropy detector over IE hex blobs")
    det.add_argument("--ies", nargs="*", help="space-separated hex IE blobs")

    args = p.parse_args(argv)
    result: Dict[str, object] = {"cmd": args.cmd, "radio_emitted": False}

    if args.cmd == "encode":
        payload = args.message.encode("utf-8")
        key = bytes.fromhex(args.key) if args.key else None
        frames = encode_to_beacons(payload, key=key)
        enc = encode_payload(payload, key=key)
        result["payload"] = args.message
        result["frame_count"] = len(frames)
        result["per_frame_hex"] = [f.hex() for f in frames]
        result.update(enc)
        print("=" * 62)
        print(" W8 — Beacon-as-C2 encoder (byte-exact beacons)")
        print("=" * 62)
        print(f"\n[+] payload ({len(payload)} bytes): {args.message!r}")
        print(f"[+] {len(frames)} beacon frames carry 1 C2 vendor IE each\n")
        for i, f in enumerate(frames, 1):
            print(f"  beacon #{i}: {f.hex()}")
        if args.pcap_out:
            encode_c2_to_pcap(payload, args.pcap_out, key=key)
            print(f"\n[+] -> {args.pcap_out}")
        print("\nNo radio emitted — frames exist as bytes only.")
        print("=" * 62)
    elif args.cmd == "decode":
        key = bytes.fromhex(args.key) if args.key else None
        if args.pcap:
            payload = decode_c2_from_pcap(args.pcap, key=key)
            origin = args.pcap
        elif args.hex:
            frames = [bytes.fromhex(h) for h in args.hex.split()]
            payload = decode_from_beacons(frames, key=key)
            origin = "inline-hex"
        else:
            print("decode requires --pcap or --hex", file=sys.stderr)
            return 2
        result["origin"] = origin
        result["decoded_b64"] = base64.b64encode(payload).decode()
        result["decoded_utf8"] = payload.decode("utf-8", errors="replace")
        print("=" * 62)
        print(" W8 — Beacon-as-C2 decoder")
        print("=" * 62)
        print(f"\n[+] source: {origin}")
        print(f"[+] recovered ({len(payload)} bytes): {payload!r}")
        print("=" * 62)
    elif args.cmd == "detect":
        mixed = args.ies or []
        analysis = analyze_frames(mixed)
        result.update(analysis)
        print("=" * 62)
        print(" W8 — IE-entropy covert detector")
        print("=" * 62)
        print(f"\n[+] frames analysed: {analysis['frames_analysed']}")
        print(f"[+] vendor-payload entropy (mean): {analysis['mean_vendor_payload_entropy']}")
        print(f"[+] flagged: {analysis['flagged_count']}")
        print(f"[+] verdict: {analysis['verdict']} (confidence {analysis['confidence']})")
        print("=" * 62)

    if args.json:
        d = os.path.dirname(args.json)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(args.json, "w") as f:
            json.dump(result, f, indent=2, default=str)
    return 0


def run_demo() -> int:
    """Offline demo (exit 0): encode, decode, detect."""
    print("=" * 62)
    print(" W8 — Management-frame covert channel (exfil + detection)")
    print("=" * 62)

    secret = b"TOP SECRET: 42.3601,-71.0589"
    enc_key = b"\xAA\x55\x3C\xB1"
    print(f"\n[Encoder] payload ({len(secret)} bytes): {secret!r}")

    enc = encode_payload(secret, max_ies=10, key=enc_key)
    print(f"  IEs generated : {enc['ie_count']}")
    print(f"  Stealth index : {enc['stealth_idx']}")

    frames = encode_to_beacons(secret, key=enc_key)
    recovered = decode_from_beacons(frames, key=enc_key)
    print(f"[Beacon-as-C2] {len(frames)} beacons -> recovered {len(recovered)} bytes: {recovered!r}")
    ok_bytes = recovered == secret

    rng = random.Random(0xDEADBEEF)
    clean = _generate_clean_beacon_ies(30, rng)
    covert = enc["ies"]
    mixed = clean + covert
    rng.shuffle(mixed)
    analysis = analyze_frames(mixed)
    print(f"\n[Detector] analysed {analysis['frames_analysed']} frames")
    print(f"  Verdict    : {analysis['verdict']} (confidence {analysis['confidence']})")
    clean_only = _generate_clean_beacon_ies(30, rng)
    ctrl = analyze_frames(clean_only)
    print(f"[Control] {ctrl['frames_analysed']} clean frames -> {ctrl['verdict']}")

    ok = ok_bytes and analysis["flagged_count"] > 0 and ctrl["flagged_count"] == 0
    print(f"\n{'=' * 62}")
    print(f" Result: {'PASS' if ok else 'FAIL'}")
    print("=" * 62)
    return 0 if ok else 1


if __name__ == "__main__":
    if len(sys.argv) > 1:
        sys.exit(main())
    sys.exit(run_demo())
