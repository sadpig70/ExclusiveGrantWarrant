"""Tests for ExclusiveGrantWarrant (stdlib unittest)."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import exclusive_grant_warrant as E  # noqa: E402


class TestExamples(unittest.TestCase):
    def test_example_verdicts(self):
        self.assertEqual(E.evaluate(E.EXAMPLES["cleared"])["verdict"], "cleared")
        self.assertEqual(E.evaluate(E.EXAMPLES["partial"])["verdict"], "partial")
        self.assertEqual(E.evaluate(E.EXAMPLES["void"])["verdict"], "void")

    def test_all_three_verdicts_present(self):
        verdicts = {E.evaluate(r)["verdict"] for r in E.EXAMPLES.values()}
        self.assertEqual(verdicts, set(E.VERDICTS))


class TestDeterminism(unittest.TestCase):
    def test_same_input_same_output(self):
        a = E.evaluate(E.EXAMPLES["cleared"])
        b = E.evaluate(E.EXAMPLES["cleared"])
        self.assertEqual(E.canonical_json(a), E.canonical_json(b))

    def test_warrant_hash_stable(self):
        w1 = E.evaluate(E.EXAMPLES["cleared"])["warrants"]
        w2 = E.evaluate(E.EXAMPLES["cleared"])["warrants"]
        self.assertEqual([w["warrant_sha256"] for w in w1], [w["warrant_sha256"] for w in w2])


class TestExclusivity(unittest.TestCase):
    def test_no_double_grant(self):
        """Two bids requesting the same right never both appear in the allocation."""
        round_obj = {
            "round_id": "T",
            "rights_pool": ["x", "y"],
            "bids": [
                {"bid_id": "hi", "holder": "h1", "rights": ["x"], "price_per_unit": 5, "priority": 9,
                 "provenance": {"attestation_sha256": "a" * 64, "evidence": ["e"]}},
                {"bid_id": "lo", "holder": "h2", "rights": ["x", "y"], "price_per_unit": 5, "priority": 1,
                 "provenance": {"attestation_sha256": "b" * 64, "evidence": ["e"]}},
            ],
        }
        result = E.evaluate(round_obj)
        granted_rights = [r for g in result["allocation"] for r in g["rights"]]
        self.assertEqual(len(granted_rights), len(set(granted_rights)))  # no right twice
        self.assertEqual(result["verdict"], "partial")  # lo bid unmet -> partial
        self.assertIn("hi", [g["bid_id"] for g in result["allocation"]])  # higher priority wins

    def test_priority_order_deterministic(self):
        round_obj = {
            "round_id": "T", "rights_pool": ["x"],
            "bids": [
                {"bid_id": "b1", "holder": "h1", "rights": ["x"], "price_per_unit": 5, "priority": 3,
                 "provenance": {"attestation_sha256": "a" * 64, "evidence": ["e"]}},
                {"bid_id": "b2", "holder": "h2", "rights": ["x"], "price_per_unit": 9, "priority": 3,
                 "provenance": {"attestation_sha256": "b" * 64, "evidence": ["e"]}},
            ],
        }
        # same priority -> higher price wins (b2)
        self.assertEqual(E.evaluate(round_obj)["allocation"][0]["bid_id"], "b2")

    def test_right_outside_pool_unmet(self):
        round_obj = {
            "round_id": "T", "rights_pool": ["x"],
            "bids": [{"bid_id": "b1", "holder": "h", "rights": ["z"], "price_per_unit": 5, "priority": 1,
                      "provenance": {"attestation_sha256": "a" * 64, "evidence": ["e"]}}],
        }
        result = E.evaluate(round_obj)
        self.assertEqual(result["verdict"], "void")  # no grant possible
        self.assertEqual(result["allocation"], [])


class TestProvenance(unittest.TestCase):
    def test_granted_without_provenance_is_void(self):
        round_obj = {
            "round_id": "T", "rights_pool": ["x"],
            "bids": [{"bid_id": "b1", "holder": "h", "rights": ["x"], "price_per_unit": 5, "priority": 1,
                      "provenance": {"attestation_sha256": "not-a-hash", "evidence": []}}],
        }
        self.assertEqual(E.evaluate(round_obj)["verdict"], "void")


class TestClearingPrice(unittest.TestCase):
    def test_average_mechanism(self):
        round_obj = {
            "round_id": "T", "rights_pool": ["x"],
            "bids": [
                {"bid_id": "win", "holder": "h1", "rights": ["x"], "price_per_unit": 10, "priority": 5,
                 "provenance": {"attestation_sha256": "a" * 64, "evidence": ["e"]}},
                {"bid_id": "lose", "holder": "h2", "rights": ["x"], "price_per_unit": 6, "priority": 1,
                 "provenance": {"attestation_sha256": "b" * 64, "evidence": ["e"]}},
            ],
        }
        # lowest_accepted=10, highest_rejected(conflict)=6 < 10 -> average 8.0
        self.assertEqual(E.evaluate(round_obj)["clearing_price"], 8.0)


class TestLedger(unittest.TestCase):
    def test_append_and_verify(self):
        with tempfile.TemporaryDirectory() as d:
            ledger = Path(d) / "warrants.jsonl"
            E.append_ledger(ledger, E.evaluate(E.EXAMPLES["cleared"]))
            E.append_ledger(ledger, E.evaluate(E.EXAMPLES["partial"]))
            v = E.verify_ledger(ledger)
            self.assertTrue(v["valid"])
            self.assertEqual(v["entries"], 2)

    def test_tamper_detected(self):
        with tempfile.TemporaryDirectory() as d:
            ledger = Path(d) / "warrants.jsonl"
            E.append_ledger(ledger, E.evaluate(E.EXAMPLES["cleared"]))
            E.append_ledger(ledger, E.evaluate(E.EXAMPLES["partial"]))
            lines = ledger.read_text(encoding="utf-8").splitlines()
            first = json.loads(lines[0])
            first["verdict"] = "void"  # tamper
            lines[0] = E.canonical_json(first)
            ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")
            self.assertFalse(E.verify_ledger(ledger)["valid"])


class TestReasonsCollectAll(unittest.TestCase):
    def test_does_not_stop_at_first_failure(self):
        # empty pool + bad provenance -> multiple channels fail, all collected
        round_obj = {"round_id": "T", "rights_pool": [],
                     "bids": [{"bid_id": "b", "holder": "h", "rights": ["x"], "price_per_unit": 1, "priority": 1,
                               "provenance": {"attestation_sha256": "", "evidence": []}}]}
        reasons = E.evaluate(round_obj)["reasons"]
        self.assertTrue(any("rights_pool is empty" in r for r in reasons))


if __name__ == "__main__":
    unittest.main()
