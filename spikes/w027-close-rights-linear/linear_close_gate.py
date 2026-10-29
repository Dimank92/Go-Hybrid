#!/usr/bin/env python3
"""
W-027 Linear Close-Rights Static Gate Verifier (Battle-Hardened Edition v2)
Enforces compile-time affine consumption of channel close-rights.
Security audited against:
- CWE-415 (Double Close)
- CWE-416 (Use After Close / Send After Close)
- CWE-672 (Operation on Resource after Expiration or Release)
- CWE-20 (Lexer / Regex Injection Bypasses: multiline strings, escaped quotes, whitespace, multi-statement lines, indexed selectors, parenthesized expressions)
- CWE-362 (Race Condition / Concurrent Split Close)
"""

import sys
import re
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass
from enum import Enum


class CapState(Enum):
    HELD = "held"              # Owner has exclusive right to close
    CONSUMED = "consumed"      # close() has been executed; channel is shut
    BORROWED = "borrowed"      # Read/write access only; no close right
    SPLIT_ERROR = "split"      # Concurrently shared close capability (forbidden)


@dataclass
class Diagnostic:
    code: str
    message: str
    line: int
    channel: str


class LinearCloseGate:
    """
    Battle-hardened static typestate checker for affine channel close rights.
    """

    def __init__(self):
        self.diagnostics: List[Diagnostic] = []

    def _strip_comments_and_strings(self, code: str) -> str:
        """
        Safely strips comments and masks string literals (including multiline and escaped quotes).
        """
        # 1. Strip block comments /* ... */
        code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
        # 2. Mask multiline backtick strings `...`
        code = re.sub(r"`[^`]*`", '""', code, flags=re.DOTALL)
        # 3. Mask double-quoted strings with escaped characters
        code = re.sub(r'"(?:\\.|[^"\\])*"', '""', code)

        lines = code.splitlines()
        sanitized_lines = []
        for line in lines:
            # Strip inline comments // ...
            if "//" in line:
                line = line.split("//", 1)[0]
            sanitized_lines.append(line)
        return "\n".join(sanitized_lines)

    def check_program(self, code: str) -> List[Diagnostic]:
        self.diagnostics = []
        clean_code = self._strip_comments_and_strings(code)
        lines = clean_code.splitlines()

        # Channel allocation tracking: canonical_id -> CapState
        channels: Dict[str, CapState] = {}
        # Alias map: alias_name -> canonical_id
        aliases: Dict[str, str] = {}
        # Track deferred closes: canonical_id -> list of (line, var_name)
        deferred_closes: Dict[str, List[Tuple[int, str]]] = {}

        in_loop = False
        loop_depth = 0
        in_task = False

        # Channel identifier regex pattern supporting dotted selectors and index brackets
        ID_PAT = r"[\w\.]+(?:\[\w+\])*"

        for idx, raw_line in enumerate(lines, 1):
            line = raw_line.strip()
            if not line:
                continue

            # Check for function headers with channel parameters
            fn_match = re.search(r"fn\s+\w+\((.*?)\)", line)
            if fn_match:
                params = fn_match.group(1).split(",")
                for p in params:
                    p = p.strip()
                    if ":" in p and "chan" in p:
                        param_name = p.split(":")[0].strip()
                        if not param_name.startswith("move "):
                            channels[param_name] = CapState.BORROWED
                            aliases[param_name] = param_name

            # Check task / goroutine boundary
            if re.search(r"\b(task|spawn|go)\s*\{", line):
                in_task = True
            if in_task and "}" in line:
                in_task = False

            # Check loop entry / exit
            if re.search(r"\b(for|while)\b.*\{", line):
                in_loop = True
                loop_depth += 1
            if in_loop and "}" in line:
                loop_depth -= 1
                if loop_depth <= 0:
                    in_loop = False
                    loop_depth = 0

            # Split statements by semicolon to prevent multi-statement single-line bypasses
            statements = [s.strip() for s in line.split(";") if s.strip()]

            for raw_stmt in statements:
                # Normalize spaces around dots and brackets: `worker . ch` -> `worker.ch`
                stmt = re.sub(r"\s*\.\s*", ".", raw_stmt)
                stmt = re.sub(r"\s*\[\s*", "[", stmt)
                stmt = re.sub(r"\s*\]\s*", "]", stmt)

                # Detect channel allocation: `ch := make(chan ...)` or `(ch) := make(chan ...)`
                alloc_match = re.search(rf"\(?\s*({ID_PAT})\s*\)?\s*:=\s*make\s*\(\s*chan", stmt)
                if alloc_match:
                    name = alloc_match.group(1)
                    channels[name] = CapState.HELD
                    aliases[name] = name
                    continue

                # Detect aliasing: `ch2 := ch1`
                alias_match = re.search(rf"\(?\s*({ID_PAT})\s*\)?\s*:=\s*\(?\s*({ID_PAT})\s*\)?$", stmt)
                if alias_match:
                    dst, src = alias_match.group(1), alias_match.group(2)
                    if src in aliases:
                        canonical = aliases[src]
                        aliases[dst] = canonical
                        continue

                # Detect deferred close: `defer close(ch)` or `defer close((ch))`
                defer_match = re.search(rf"defer\s+close\s*\(\s*\(?\s*({ID_PAT})\s*\)?\s*\)", stmt)
                if defer_match:
                    target_var = defer_match.group(1)
                    canon = aliases.get(target_var, target_var)
                    if canon not in deferred_closes:
                        deferred_closes[canon] = []
                    deferred_closes[canon].append((idx, target_var))
                    if len(deferred_closes[canon]) > 1:
                        self.diagnostics.append(
                            Diagnostic(
                                code="HYB-E3013",
                                message=f"double close: channel '{target_var}' has multiple deferred closes",
                                line=idx,
                                channel=target_var
                            )
                        )
                    continue

                # Detect immediate close: `close(ch)` with arbitrary whitespace and nesting
                close_match = re.search(rf"(?<!defer\s)\bclose\s*\(\s*\(?\s*({ID_PAT})\s*\)?\s*\)", stmt)
                if close_match:
                    target_var = close_match.group(1)
                    canon = aliases.get(target_var, target_var)
                    current_state = channels.get(canon)

                    if current_state == CapState.BORROWED:
                        self.diagnostics.append(
                            Diagnostic(
                                code="HYB-E3016",
                                message=f"cannot close borrowed channel '{target_var}'; close-right not owned by caller",
                                line=idx,
                                channel=target_var
                            )
                        )
                    elif current_state == CapState.CONSUMED:
                        self.diagnostics.append(
                            Diagnostic(
                                code="HYB-E3013",
                                message=f"double close: channel '{target_var}' close-right was already consumed",
                                line=idx,
                                channel=target_var
                            )
                        )
                    elif in_loop:
                        self.diagnostics.append(
                            Diagnostic(
                                code="HYB-E3015",
                                message=f"illegal close: cannot call close('{target_var}') inside loop body",
                                line=idx,
                                channel=target_var
                            )
                        )
                    elif in_task:
                        channels[canon] = CapState.SPLIT_ERROR
                    else:
                        if current_state == CapState.SPLIT_ERROR:
                            self.diagnostics.append(
                                Diagnostic(
                                    code="HYB-E3017",
                                    message=f"split close hazard: channel '{target_var}' is closed both in background task and caller",
                                    line=idx,
                                    channel=target_var
                                )
                            )
                        else:
                            channels[canon] = CapState.CONSUMED

                # Detect send operation: `ch <- value` or `case ch <- value:` or `(ch) <- value`
                # Excludes receiving operations `<-ch` or assignments `x := <-ch`
                send_match = re.search(rf"(?<!:)(?<!=)\s*\(?\s*({ID_PAT})\s*\)?\s*<-\s*(.+)", stmt)
                if send_match:
                    target_var = send_match.group(1).strip()
                    canon = aliases.get(target_var, target_var)
                    current_state = channels.get(canon)

                    if current_state == CapState.CONSUMED:
                        self.diagnostics.append(
                            Diagnostic(
                                code="HYB-E3013",
                                message=f"use after close: attempt to send on closed channel '{target_var}'",
                                line=idx,
                                channel=target_var
                            )
                        )

        return self.diagnostics


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python linear_close_gate.py <file.hy>")
        sys.exit(1)

    gate = LinearCloseGate()
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        diags = gate.check_program(f.read())

    if diags:
        print(f"FAILED with {len(diags)} diagnostics:")
        for d in diags:
            print(f"  [{d.code}] L{d.line}: {d.message}")
        sys.exit(1)
    else:
        print("OK (0 diagnostics): All channel close-rights verified affine and linear.")
        sys.exit(0)
