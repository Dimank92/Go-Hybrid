#!/usr/bin/env python3
"""
GUARANTEES as Code — Claim Registry & Automatic Demotion Gate
Deterministic verification engine (< 200 LOC) for W-026.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Any, Tuple


class DemotionGate:
    def __init__(self, registry_path: str, repo_root: str = "."):
        self.registry_path = Path(registry_path)
        self.repo_root = Path(repo_root)

    def load_registry(self) -> List[Dict[str, Any]]:
        with open(self.registry_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def verify_and_demote(self, claims: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[str]]:
        """
        Evaluates each claim row against repository evidence.
        If target verifier is missing, demotes row automatically to 'no claim'.
        """
        demoted_logs = []
        updated_claims = []

        for row in claims:
            row_id = row.get("id")
            status = row.get("status")
            target = row.get("verifier_target")
            v_type = row.get("verifier_type")

            # Check if verifier target exists on filesystem
            target_path = self.repo_root / target if target else None
            exists = target_path.exists() if target_path else False

            if not exists and status == "active":
                # Automatic Demotion
                row["status"] = "demoted_no_claim"
                row["demotion_reason"] = f"Missing verifier target: {target}"
                row["debt_ticket"] = f"DEBT-{row_id.upper()}"
                demoted_logs.append(f"DEMOTED {row_id}: Missing verifier '{target}' -> downgraded to 'no claim'")
            elif exists and status == "demoted_no_claim":
                # Restored if verifier reappears
                row["status"] = "active"
                row.pop("demotion_reason", None)
                row.pop("debt_ticket", None)

            updated_claims.append(row)

        return updated_claims, demoted_logs

    def generate_markdown_table(self, claims: List[Dict[str, Any]]) -> str:
        """Generates the Markdown table suitable for GUARANTEES.md."""
        header = "| Row | Category | Guarantee Claim | Evidence / Spec Rule | Status | Gate Verifier |\n"
        separator = "|---|---|---|---|---|---|\n"
        lines = [header, separator]

        for r in claims:
            row_num = r.get("row_number", "?")
            cat = r.get("category", "")
            claim = r.get("claim_text", "")
            rule = r.get("evidence_spec_rule", "")
            status = r.get("status", "unknown")
            v_type = r.get("verifier_type", "")
            target = r.get("verifier_target", "")

            badge = "✅ ACTIVE" if status == "active" else ("❌ DEMOTED" if "demoted" in status else "⚠️ NO CLAIM")
            lines.append(f"| {row_num} | {cat} | {claim} | `{rule}` | {badge} | `{v_type}`: {target} |\n")

        return "".join(lines)


if __name__ == "__main__":
    gate = DemotionGate("claims_registry.json")
    claims = gate.load_registry()
    updated, logs = gate.verify_and_demote(claims)
    for log in logs:
        print(log)
    print("\nGenerated Markdown Table:\n")
    print(gate.generate_markdown_table(updated))
