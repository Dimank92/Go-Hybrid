# W-026: GUARANTEES as Code — Claim-Carrying Corpus & Automatic Demotion Gate

**Proposal:** [Issue #2220](https://github.com/limitlessprojects/Go-Hybrid/issues/2220) — *GUARANTEES as code: claim-carrying corpus and an automatic demotion gate*  
**Author:** `@wilberforcem`  
**Track:** Wildcard Track (M1 Intake / 2026-11-01 Review Window Slot 25)  

---

## 1. Core Hypothesis

Every row of `GUARANTEES.md` becomes a machine-readable claim record in `claims_registry.json` with an executable verifier. The table itself is generated from that registry in CI. A row that cannot point at an existing, verifiable test or falsifier is **automatically demoted to "no claim"** with an owner, a dated debt ticket, and a scheduled review date — eliminating narrative drift and unbacked marketing claims.

---

## 2. Verifier Types & Falsifiers

| Verifier Type | Scope | Behavior |
|---|---|---|
| `corpus_pair` | Positive claim (e.g. Row 1: spawn sendability) | Expects compile accept for valid, reject (HYB-E3004) for moved alias. |
| `run_gate` | Boundary enforcement (e.g. Row 8: managed block) | Validates gate runner passes without bypass permits. |
| `runtime_pin` | Negative claim falsifier (e.g. Row 16: send-on-closed) | Confirms negative baseline behaves as documented (e.g. runtime panic under race detector). |
| `prose_only` | Temporary debt | Carries owner, debt ticket, and mandatory review expiration date. |

---

## 3. Demotion Gate Protocol

When `guarantees_gate.py` executes in CI:
1. Validates all registry entries against repository verifier targets.
2. If any target is missing, renamed, or fails execution, the row is **automatically demoted** to `no claim (demoted: missing verifier)`.
3. Verifies that the committed `GUARANTEES.md` matches the generated table (drift check).

---

## 4. Verification Suite

Run the hermetic test suite:
```bash
python test_guarantees_gate.py
```
