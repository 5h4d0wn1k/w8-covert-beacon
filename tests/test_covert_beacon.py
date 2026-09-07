#!/usr/bin/env python3
"""Byte-exact unit tests for w8-covert-beacon."""

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from firmware import covert_beacon as cb
from firmware import frame_core as fc


class BeaconC2EncodeDecodeTest(unittest.TestCase):
    def test_roundtrip_short(self):
        payload = b"TOP SECRET: 42.3601,-71.0589"
        frames = cb.encode_to_beacons(payload)
        self.assertTrue(all(len(f) > 24 for f in frames))
        self.assertEqual(cb.decode_from_beacons(frames), payload)

    def test_roundtrip_long_payload_chunked(self):
        payload = (b"flag{" + b"A" * 600 + b"}")   # exceeds one IE, needs chunking
        frames = cb.encode_to_beacons(payload)
        self.assertGreater(len(frames), 1)
        self.assertEqual(cb.decode_from_beacons(frames), payload)

    def test_beacon_frames_parse_cleanly(self):
        payload = b"hello c2"
        frames = cb.encode_to_beacons(payload)
        for f in frames:
            fields, _ies = fc.parse_beacon(f)   # must not raise
            self.assertEqual(fields["subtype_val"], fc.FC_SUBTYPE_BEACON)
            self.assertEqual(fields["bssid"], "00:11:22:33:44:55")

    def test_xor_key_matches_encode_payload(self):
        key = b"\xaa\x55\x3c\xb1"
        payload = b"secret-data-123"
        frames = cb.encode_to_beacons(payload, key=key)
        self.assertEqual(cb.decode_from_beacons(frames, key=key), payload)
        # without the key the raw recovered bytes differ from plaintext
        self.assertNotEqual(cb.decode_from_beacons(frames), payload)

    def test_decoding_empty_gives_empty(self):
        self.assertEqual(cb.decode_from_beacons([]), b"")


class PcapRoundtripTest(unittest.TestCase):
    def test_pcap_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "c2.pcap")
            payload = b"covert over pcap"
            n = cb.encode_c2_to_pcap(payload, path)
            self.assertGreater(n, 0)
            self.assertEqual(cb.decode_c2_from_pcap(path), payload)


class DetectorTest(unittest.TestCase):
    def test_detector_flags_covert(self):
        import random as _r
        rng = _r.Random(0xDEADBEEF)
        payload = os.urandom(500)   # genuinely high-entropy covert payload
        enc = cb.encode_payload(payload, max_ies=10, key=b"\x3c\xb1\xaa\x55")
        cov = enc["ies"]
        # covert-heavy capture -> detector must flag at least one and call covert/suspect
        analysis = cb.analyze_frames(cov + cb._generate_clean_beacon_ies(2, rng))
        self.assertGreater(analysis["flagged_count"], 0)
        self.assertIn(analysis["verdict"], ("covert", "suspect"))

    def test_control_clean_frames_not_flagged(self):
        import random as _r
        rng = _r.Random(0xDEADBEEF)
        clean = cb._generate_clean_beacon_ies(30, rng)
        ctrl = cb.analyze_frames(clean)
        self.assertEqual(ctrl["flagged_count"], 0)


class CLITest(unittest.TestCase):
    def test_encode_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "o.json")
            rc = cb.main(["encode", "--message", "hi", "--json", out])
            self.assertEqual(rc, 0)

    def test_decode_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "c2.pcap")
            cb.encode_c2_to_pcap(b"round trip via cli", path)
            out = os.path.join(tmp, "o.json")
            rc = cb.main(["decode", "--pcap", path, "--json", out])
            self.assertEqual(rc, 0)
            with open(out) as f:
                data = json.load(f)
            import base64
            self.assertEqual(data["decoded_b64"],
                             base64.b64encode(b"round trip via cli").decode())

    def test_demo_exit_zero(self):
        self.assertEqual(cb.run_demo(), 0)


if __name__ == "__main__":
    unittest.main()