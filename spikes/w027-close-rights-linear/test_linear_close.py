#!/usr/bin/env python3
"""
Test Suite for W-027 Linear Close-Rights Static Gate.
Covers 10 distinct verification angles and validates M1 milestone expectations:
- 4 Negative rejection tests (compile-fail falsifiers)
- Positive worker pool pattern acceptance
- Aliasing, loops, tasks, borrow semantics, and control-flow boundaries
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from linear_close_gate import LinearCloseGate


class TestLinearCloseRightsGate(unittest.TestCase):
    def setUp(self):
        self.gate = LinearCloseGate()

    # Angle 1: Negative Falsifier 1 - Double Close
    def test_angle_1_reject_double_close(self):
        code = """
        fn main() {
            ch := make(chan int)
            close(ch)
            close(ch)
        }
        """
        diags = self.gate.check_program(code)
        self.assertEqual(len(diags), 1)
        self.assertEqual(diags[0].code, "HYB-E3013")
        self.assertIn("double close", diags[0].message)

    # Angle 2: Negative Falsifier 2 - Send After Close
    def test_angle_2_reject_send_after_close(self):
        code = """
        fn main() {
            ch := make(chan int)
            close(ch)
            ch <- 42
        }
        """
        diags = self.gate.check_program(code)
        self.assertEqual(len(diags), 1)
        self.assertEqual(diags[0].code, "HYB-E3013")
        self.assertIn("attempt to send on closed channel", diags[0].message)

    # Angle 3: Aliasing Invariant - Close Via Alias
    def test_angle_3_alias_double_close(self):
        code = """
        fn main() {
            ch1 := make(chan int)
            ch2 := ch1
            close(ch1)
            close(ch2)
        }
        """
        diags = self.gate.check_program(code)
        self.assertEqual(len(diags), 1)
        self.assertEqual(diags[0].code, "HYB-E3013")

    # Angle 4: Negative Falsifier 3 - Borrowed Channel Close in Callee
    def test_angle_4_reject_close_borrowed(self):
        code = """
        fn worker(c: chan int) {
            close(c)
        }
        """
        diags = self.gate.check_program(code)
        self.assertEqual(len(diags), 1)
        self.assertEqual(diags[0].code, "HYB-E3016")
        self.assertIn("cannot close borrowed channel", diags[0].message)

    # Angle 5: Negative Falsifier 4 - Concurrent Split Close
    def test_angle_5_reject_split_close_tasks(self):
        code = """
        fn main() {
            ch := make(chan int)
            task {
                close(ch)
            }
            close(ch)
        }
        """
        diags = self.gate.check_program(code)
        self.assertEqual(len(diags), 1)
        self.assertEqual(diags[0].code, "HYB-E3017")
        self.assertIn("split close hazard", diags[0].message)

    # Angle 6: Loop Invariant - Reject Close Inside Loop
    def test_angle_6_reject_close_inside_loop(self):
        code = """
        fn main() {
            ch := make(chan int)
            for i := 0; i < 5; i++ {
                close(ch)
            }
        }
        """
        diags = self.gate.check_program(code)
        self.assertEqual(len(diags), 1)
        self.assertEqual(diags[0].code, "HYB-E3015")
        self.assertIn("cannot call close", diags[0].message)

    # Angle 7: Positive Acceptance - Idiomatic Worker Pool Shutdown
    def test_angle_7_accept_worker_pool(self):
        code = """
        fn main() {
            jobs := make(chan int, 100)
            for i := 0; i < 10; i++ {
                jobs <- i
            }
            close(jobs)
        }
        """
        diags = self.gate.check_program(code)
        self.assertEqual(len(diags), 0, "Worker pool pattern must compile with 0 diagnostics")

    # Angle 8: Positive Acceptance - Multiple Channels Managed Independently
    def test_angle_8_independent_channels(self):
        code = """
        fn main() {
            chA := make(chan string)
            chB := make(chan int)
            chA <- "hello"
            close(chA)
            chB <- 100
            close(chB)
        }
        """
        diags = self.gate.check_program(code)
        self.assertEqual(len(diags), 0)

    # Angle 9: Send After Close Across Aliases
    def test_angle_9_alias_send_after_close(self):
        code = """
        fn main() {
            ch1 := make(chan int)
            ch2 := ch1
            close(ch2)
            ch1 <- 999
        }
        """
        diags = self.gate.check_program(code)
        self.assertEqual(len(diags), 1)
        self.assertEqual(diags[0].code, "HYB-E3013")

    # Angle 10: Unclosed Channel Safe Drop (Affine Drop at Scope Exit)
    def test_angle_10_unclosed_channel_valid_drop(self):
        code = """
        fn main() {
            ch := make(chan int)
            ch <- 1
            // ch drops safely at function exit without explicit close
        }
        """
        diags = self.gate.check_program(code)
        self.assertEqual(len(diags), 0)

    # Angle 11: Security Audit - Multi-Statement Single-Line Bypass (CWE-20)
    def test_angle_11_multistatement_close_catch(self):
        code = """
        fn main() {
            ch := make(chan int)
            close(ch); close(ch)
        }
        """
        diags = self.gate.check_program(code)
        self.assertEqual(len(diags), 1)
        self.assertEqual(diags[0].code, "HYB-E3013")

    # Angle 12: Security Audit - String Literal Injection Masking (CWE-20)
    def test_angle_12_string_literal_masking(self):
        code = """
        fn main() {
            ch := make(chan int)
            msg := "close(ch)"
            ch <- 1
        }
        """
        diags = self.gate.check_program(code)
        self.assertEqual(len(diags), 0, "String literals must never poison typestate")

    # Angle 13: Security Audit - Defer Close Semantics
    def test_angle_13_defer_close_semantics(self):
        code = """
        fn main() {
            ch := make(chan int)
            defer close(ch)
            ch <- 1
            ch <- 2
        }
        """
        diags = self.gate.check_program(code)
        self.assertEqual(len(diags), 0, "Defer close executes at function exit, not prematurely")

    # Angle 14: Security Audit - Formatting Resilience (Arbitrary Whitespace)
    def test_angle_14_arbitrary_whitespace_close(self):
        code = """
        fn main() {
            ch := make(chan int)
            close  (  ch  )
            close(ch)
        }
        """
        diags = self.gate.check_program(code)
        self.assertEqual(len(diags), 1)
        self.assertEqual(diags[0].code, "HYB-E3013")

    # Angle 15: Security Audit - Struct & Dotted Field Path Tracking
    def test_angle_15_dotted_field_channel_close(self):
        code = """
        fn main() {
            worker.ch := make(chan int)
            close(worker.ch)
            close(worker.ch)
        }
        """
        diags = self.gate.check_program(code)
        self.assertEqual(len(diags), 1)
        self.assertEqual(diags[0].code, "HYB-E3013")


if __name__ == "__main__":
    unittest.main()

