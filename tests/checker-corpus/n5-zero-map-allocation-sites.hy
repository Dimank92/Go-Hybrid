// ============================================================================
// n5-zero-map-allocation-sites — Checker corpus (added WITH the #1206 fix).
//
// PURPOSE: pin N5 for allocation sites — make([]T, n[, c]) and [N]T elements
// auto-allocate zero maps so writes to their elements work where Go panics
// on a nil map (issue #1206).
//
// RULE CITATION: SPEC-LANGUAGE N5 — "`var m map[k]v; m[k] = v` works (first
//   write allocates), where Go panics on a nil map." T8 says the same; N3's
//   zero-value table gives maps "empty (`len` 0; first write allocates —
//   N5)" and a struct "field-wise zero values".
//
// ---- Tier-0 rule set applied ----
// Layer 1 (Go-side GC): gs, ms, bs, s, bs2, grid, arr, arr2, part — fresh locals,
//   written by one task; no spawn or send site, so no sendability class
//   applies.
// Layer 2 (Rust-side owned): none.
// Layer 3 (boundary handles): none.
//
// ---- Expected verdict (registered with the fix, 2026-10-22) ----
// EXPECTED-VERDICT: ACCEPT
//   ACCEPT — zero check-sites; each write is one N5 defines as valid.
// EXPECTED-OUTPUT: 10 1 1 1 2 1 10 1 1
//
// ---- Annotations / managed ----
// lifetime annotations: 0. `managed` blocks: 0.
// ============================================================================

import "fmt"

struct graph {
    nodes map[int]int
}

struct bag {
    label  string
    counts map[string]int
}

struct shelf {
    bags []bag
}

fn fill(bs []bag) {
    bs[1].counts["k"] = 2
}

fn main() {
    // A1: make([]graph, 2) element
    gs := make([]graph, 2)
    gs[0].nodes[1] = 10

    // A2: make([]map[string]int, 2) element (map elem type)
    ms := make([]map[string]int, 2)
    ms[0]["a"] = 1

    // A3: make([]bag, 0, 4) reslice exposes allocated capacity
    bs := make([]bag, 0, 4)
    bs = bs[:1]
    bs[0].counts["k"] = 1

    // A4: make inside struct literal
    s := shelf{bags: make([]bag, 3)}
    s.bags[2].counts["k"] = 1

    // A5: make element reaching callee
    bs2 := make([]bag, 2)
    fill(bs2)

    // A6: nested make
    grid := make([][]map[string]int, 1)
    grid[0] = make([]map[string]int, 1)
    grid[0][0]["k"] = 1

    // A7: array var
    var arr [2]graph
    arr[0].nodes[1] = 10

    // A8: array literal with elided elements
    arr2 := [2]bag{}
    arr2[1].counts["k"] = 1

    // Partial array literal with trailing elements padded
    part := [2]bag{bag{label: "p"}}
    part[1].counts["k"] = 1

    fmt.println(gs[0].nodes[1], ms[0]["a"], bs[0].counts["k"], s.bags[2].counts["k"], bs2[1].counts["k"], grid[0][0]["k"], arr[0].nodes[1], arr2[1].counts["k"], part[1].counts["k"])
}
