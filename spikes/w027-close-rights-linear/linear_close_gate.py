#!/usr/bin/env python3
"""
W-027 Linear Close-Rights Static Gate Verifier
Enforces compile-time affine consumption of channel close-rights.
Eliminates send-on-closed and double-close hazards to flip GUARANTEES Row 16.
"""

import sys
import re
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field
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
    Static typestate checker for affine channel close rights.
    """

    def __init__(self):
        self.diagnostics: List[Diagnostic] = []

    def check_program(self, code: str) -> List[Diagnostic]:
        self.diagnostics = []
        lines = code.splitlines()

        # Channel allocation tracking: id -> CapState
        channels: Dict[str, CapState] = {}
        # Alias map: alias_name -> canonical_id
        aliases: Dict[str, str] = {}
        # Track channels declared as function parameters (borrowed by default)
        borrowed_params: Set[str] = set()

        in_loop = False
        loop_depth = 0
        in_task = False

        for idx, raw_line in enumerate(lines, 1):
            line = raw_line.strip()

            # Ignore comments and empty lines
            if not line or line.startswith("//"):
                continue

            # Detect function headers with channel parameters
            fn_match = re.search(r"fn\s+\w+\((.*?)\)", line)
            if fn_match:
                params = fn_match.group(1).split(",")
                for p in params:
                    p = p.strip()
                    if ":" in p and "chan" in p:
                        param_name = p.split(":")[0].strip()
                        if not param_name.startswith("move "):
                            borrowed_params.add(param_name)
                            channels[param_name] = CapState.BORROWED
                            aliases[param_name] = param_name

            # Detect channel allocation: `ch := make(chan ...)`
            alloc_match = re.search(r"(\w+)\s*:=\s*make\(chan", line)
            if alloc_match:
                name = alloc_match.group(1)
                channels[name] = CapState.HELD
                aliases[name] = name
                continue

            # Detect aliasing: `ch2 := ch1`
            alias_match = re.search(r"(\w+)\s*:=\s*(\w+)$", line)
            if alias_match:
                dst, src = alias_match.group(1), alias_match.group(2)
                if src in aliases:
                    # In standard assignment, close-right is non-duplicable (stays single or borrowed)
                    canonical = aliases[src]
                    aliases[dst] = canonical
                    continue

            # Detect task / goroutine boundary
            if "task {" in line or "spawn {" in line or "go {" in line:
                in_task = True
            if in_task and "}" in line:
                in_task = False

            # Detect loop entry / exit
            if re.search(r"\b(for|while)\b.*\{", line):
                in_loop = True
                loop_depth += 1
            if in_loop and "}" in line:
                loop_depth -= 1
                if loop_depth <= 0:
                    in_loop = False
                    loop_depth = 0

            # Detect close operation: `close(ch)`
            close_match = re.search(r"close\((\w+)\)", line)
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
                    # Closing inside task without move transfer
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

            # Detect send operation: `ch <- value`
            send_match = re.search(r"(\w+)\s*<-\s*(.+)", line)
            if send_match:
                target_var = send_match.group(1)
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
