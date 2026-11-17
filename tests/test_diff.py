"""Differential / reproducibility tests for urlhost-drift-audit.

Run from the project root:

    python -m unittest discover -s tests -t . -v
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from urlhostdrift.audit import audit, canon, classify, verify_ipv4_oracle
from urlhostdrift.corpus import build_corpus
from urlhostdrift.ipv4_whatwg import parse_ipv4
from urlhostdrift.parsers import parse_python, parse_reference

ROOT = Path(__file__).resolve().parent.parent
COMMITTED = ROOT / "evidence" / "summary.json"


class TestCorpus(unittest.TestCase):
    def test_unique_inputs_at_least_1000(self):
        corpus = build_corpus()
        self.assertGreaterEqual(corpus["unique"], 1000)
        self.assertEqual(corpus["raw"] - corpus["duplicates"], corpus["unique"])

    def test_corpus_deterministic(self):
        self.assertEqual(build_corpus()["corpus_sha256"], build_corpus()["corpus_sha256"])

    def test_corpus_sha256_is_dedupe_key(self):
        corpus = build_corpus()
        self.assertEqual(len(set(corpus["urls"])), corpus["unique"])
        self.assertEqual(len(set(hashlib_sha(u) for u in corpus["urls"])), corpus["unique"])


def hashlib_sha(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode()).hexdigest()


class TestIpv4Oracle(unittest.TestCase):
    def test_spec_examples(self):
        cases = {
            "0177.0.0.1": "127.0.0.1",
            "2130706433": "127.0.0.1",
            "0x7f.1": "127.0.0.1",
            "127.1": "127.0.0.1",
            "0": "0.0.0.0",
            "0300.0250.0001.0001": "192.168.1.1",
            "127.0.0.1%2e": "127.0.0.1",
            "127.0.0.1.": "127.0.0.1",
            "192.168.0.1": "192.168.0.1",
            "1.2.65535": "1.2.255.255",
            "4294967295": "255.255.255.255",
            "0xffffffff": "255.255.255.255",
        }
        for token, expected in cases.items():
            self.assertEqual(parse_ipv4(token), expected, token)
        for bad in ("256.0.0.1", "300.1.2.3", "1.2.65536", "4294967296",
                    "1.2.3.4.5", "0x100000000", "good.com", ""):
            self.assertIsNone(parse_ipv4(bad), bad)

    def test_oracle_matches_reference_on_corpus(self):
        corpus = build_corpus()
        refs = parse_reference(corpus["urls"])
        result = verify_ipv4_oracle(corpus["urls"], refs)
        self.assertGreaterEqual(result["checked"], 100)
        self.assertEqual(result["mismatch_count"], 0, result["mismatches"])


class TestSpecificWitnesses(unittest.TestCase):
    def test_backslash_stdlib_vs_urllib3_and_browser(self):
        url = "http://evil.com\\@good.com/"
        py = parse_python(url)
        ref = parse_reference([url])[url]
        self.assertEqual(py["stdlib"]["host"], "good.com")
        self.assertEqual(py["urllib3"]["host"], "evil.com")
        self.assertEqual(ref["host"], "evil.com")

    def test_ipv4_alternate_notation_is_semantic(self):
        self.assertNotEqual(canon("0177.0.0.1"), canon("127.0.0.1"))
        self.assertEqual(canon("[::1]"), canon("::1"))
        self.assertEqual(canon("GOOD.com."), canon("good.com"))

    def test_reference_normalises_ipv4_and_we_do_not(self):
        urls = ["http://0177.0.0.1/", "http://2130706433/", "http://0x7f.1/"]
        refs = parse_reference(urls)
        for url in urls:
            py = parse_python(url)
            self.assertEqual(refs[url]["host"], "127.0.0.1")
            self.assertNotEqual(py["stdlib"]["host"], "127.0.0.1")
            self.assertNotEqual(py["yarl"]["host"], "127.0.0.1")

    def test_unicode_dot_urllib3_vs_yarl(self):
        url = "ftp://good。com/f"
        py = parse_python(url)
        self.assertEqual(py["yarl"]["host"], "good.com")
        self.assertEqual(py["urllib3"]["host"], "good。com")


class TestGuard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.summary = audit()

    def test_allowlist_browser_bypass_count(self):
        g = self.summary["guard"]["allowlist_vs_browser"]
        self.assertEqual(g["stdlib"]["count"], 7)
        self.assertEqual(g["urllib3"]["count"], 0)
        self.assertEqual(g["yarl"]["count"], 0)
        urls = {w["url"] for w in g["stdlib"]["witnesses"]}
        self.assertIn("http://evil.com\\@good.com/", urls)

    def test_allowlist_client_bypass_yarl_unicode_dot(self):
        g = self.summary["guard"]["allowlist_vs_client"]
        self.assertEqual(g["stdlib"]["count"], 7)
        self.assertGreaterEqual(g["yarl"]["count"], 6)

    def test_deny_loopback_bypasses_exist_for_every_parser(self):
        g = self.summary["guard"]["deny_loopback_strings"]
        for parser in ("stdlib", "urllib3", "yarl"):
            self.assertGreaterEqual(g[parser]["count"], 100, parser)
        stdlib_urls = {w["url"] for w in g["stdlib"]["witnesses"]}
        self.assertIn("http://0177.0.0.1/", stdlib_urls)
        self.assertIn("http://2130706433/", stdlib_urls)

    def test_allowlist_witnesses_are_semantic(self):
        for policy in ("allowlist_vs_client", "allowlist_vs_browser"):
            for parser, block in self.summary["guard"][policy].items():
                for w in block["witnesses"]:
                    other = w.get("browser_host") or w.get("client_host")
                    self.assertNotEqual(canon(w["validator_host"]), canon(other),
                                        (policy, parser, w))

    def test_deny_witnesses_are_string_blocklist_misses(self):
        loopback_canons = {"127.0.0.1", "::1", "0.0.0.0"}
        loopback_strings = {"127.0.0.1", "localhost", "::1", "[::1]", "0.0.0.0",
                            "[0:0:0:0:0:0:0:1]"}
        for parser, block in self.summary["guard"]["deny_loopback_strings"].items():
            for w in block["witnesses"]:
                self.assertIn(canon(w["browser_host"]), loopback_canons, (parser, w))
                self.assertNotIn(w["validator_host"], loopback_strings, (parser, w))

    def test_canon_defeated_subset_excludes_representation_only(self):
        block = self.summary["guard"]["deny_loopback_strings"]["stdlib"]
        self.assertLessEqual(block["canon_defeated_count"], block["count"])
        self.assertGreater(block["canon_defeated_count"], 0)
        for w in block["witnesses"]:
            if w["canon_defeated"]:
                self.assertNotIn(w["validator_canon"], {"127.0.0.1", "::1", "0.0.0.0"})

    def test_classification_partition_covers_corpus(self):
        corpus = build_corpus()
        total = sum(self.summary["classes"]["stdlib"].values())
        self.assertEqual(total, corpus["unique"])


class TestReproducibility(unittest.TestCase):
    def test_report_is_deterministic_across_runs(self):
        self.assertEqual(audit()["report_sha256"], audit()["report_sha256"])

    def test_committed_report_matches_live_run(self):
        self.assertTrue(COMMITTED.exists(), "evidence/summary.json missing")
        committed = json.loads(COMMITTED.read_text())
        live = audit()
        self.assertEqual(committed["report_sha256"], live["report_sha256"])
        self.assertEqual(committed["guard"], live["guard"])
        self.assertEqual(committed["classes"], live["classes"])
        self.assertEqual(committed["ipv4_oracle"], live["ipv4_oracle"])

    def test_oracle_result_is_committed(self):
        committed = json.loads(COMMITTED.read_text())
        self.assertEqual(committed["ipv4_oracle"]["checked"], 154)
        self.assertEqual(committed["ipv4_oracle"]["mismatch_count"], 0)

    def test_report_hash_excludes_nothing_volatile(self):
        first = audit()
        second = audit()
        self.assertEqual(first["meta"], second["meta"])
        self.assertEqual(first["witnesses"], second["witnesses"])


if __name__ == "__main__":
    unittest.main(verbosity=2)