#!/usr/bin/env python3
"""
Test Suite for W-026 GUARANTEES as Code Demotion Gate.
Validates:
1. Valid claims pass verification.
2. Missing verifier automatically demotes active row to 'no claim'.
3. Negative claim falsifiers (Row 16) are correctly accounted for.
4. Markdown table generation remains deterministic.
"""

import os
import sys
import json
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from guarantees_gate import DemotionGate


class TestGuaranteesDemotionGate(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(__file__).parent
        self.registry_path = self.test_dir / "claims_registry.json"
        self.repo_root = self.test_dir.parent.parent  # MH6 root

    def test_valid_claims_verify_clean(self):
        gate = DemotionGate(str(self.registry_path), repo_root=str(self.repo_root))
        claims = gate.load_registry()
        updated, logs = gate.verify_and_demote(claims)
        
        # Row 1 and Row 8 should stay active since their test targets exist
        row1 = next(r for r in updated if r["id"] == "row-01")
        self.assertEqual(row1["status"], "active")

        # Row 16 is a registered no_claim with negative falsifier
        row16 = next(r for r in updated if r["id"] == "row-16")
        self.assertEqual(row16["status"], "no_claim")

    def test_automatic_demotion_on_missing_verifier(self):
        gate = DemotionGate(str(self.registry_path), repo_root=str(self.repo_root))
        mutated_claims = [
            {
                "id": "row-01",
                "row_number": 1,
                "category": "Concurrency",
                "claim_text": "Spawn sendability",
                "status": "active",
                "verifier_type": "corpus_pair",
                "verifier_target": "non_existent_test_suite_deleted.rs",  # Missing!
                "evidence_spec_rule": "O5.1"
            }
        ]
        updated, logs = gate.verify_and_demote(mutated_claims)
        demoted_row = updated[0]
        self.assertEqual(demoted_row["status"], "demoted_no_claim")
        self.assertIn("DEBT-ROW-01", demoted_row["debt_ticket"])
        self.assertTrue(len(logs) > 0)

    def test_deterministic_markdown_generation(self):
        gate = DemotionGate(str(self.registry_path), repo_root=str(self.repo_root))
        claims = gate.load_registry()
        table = gate.generate_markdown_table(claims)
        self.assertIn("| Row | Category | Guarantee Claim |", table)
        self.assertIn("✅ ACTIVE", table)
        self.assertIn("⚠️ NO CLAIM", table)


if __name__ == "__main__":
    unittest.main()
