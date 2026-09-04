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


def main() -> int:
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


if __name__ == "__main__":
    sys.exit(main())
