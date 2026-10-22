//! n5_zero_map_lowering.rs — emission pins for issue #645.
//!
//! SPEC-LANGUAGE N5: a Hybrid-declared map's zero value allocates on first
//! write, where Go panics on a nil map. The emitter used to lower every zero
//! map Go-exact; it now allocates zero maps where they are declared: `var`
//! locals, struct literals that leave a map field unkeyed (nested structs
//! included), and `new(T)`.
//!
//! The byte-exact runtime behaviour is pinned by the corpus program
//! `n5-zero-map-first-write.hy` (hyb/tests/spec_n5_zero_maps.rs).

use hy_emit::emit_go;
use hy_syntax::parse_file;

fn emit_src(src: &str) -> String {
    let ast = parse_file("test.hy", src).expect("parses");
    emit_go(&ast).expect("emits")
}

#[test]
fn n5_var_zero_map_allocates_at_declaration() {
    let go = emit_src(
        "type tally = map[string]int\n\nfn main() {\n    var m map[string]int\n    m[\"a\"] = 1\n    var t tally\n    t[\"b\"] = 2\n    var n int\n    fmt.println(len(m) + len(t) + n)\n}\n",
    );
    assert!(
        go.contains("var m map[string]int = map[string]int{}"),
        ":\n{go}"
    );
    assert!(go.contains("var t tally = tally{}"), ":\n{go}");
    // A type whose Go zero value already is Hybrid's stays untouched.
    assert!(go.contains("var n int\n"), ":\n{go}");
}

#[test]
fn n5_struct_zero_values_allocate_map_fields() {
    let go = emit_src(
        "\
struct bag {
    label  string
    counts map[string]int
}

struct shelf {
    top bag
    n   int
}

struct plain {
    n int
}

fn main() {
    var b bag
    keyed := bag{label: \"x\"}
    given := bag{counts: map[string]int{\"k\": 1}}
    var s shelf
    p := new(bag)
    var q plain
    q2 := plain{}
    bags := []bag{{label: \"e\"}}
    fmt.println(len(b.counts) + len(keyed.counts) + len(given.counts) + len(s.top.counts) + len(p.counts) + q.n + q2.n + len(bags))
}
",
    );
    for want in [
        "var b bag = bag{counts: map[string]int{}}",
        "keyed := bag{label: \"x\", counts: map[string]int{}}",
        // A keyed map field is the literal's own value — never doubled.
        "given := bag{counts: map[string]int{\"k\": 1}}",
        "var s shelf = shelf{top: bag{counts: map[string]int{}}}",
        "p := &bag{counts: map[string]int{}}",
        "var q plain\n",
        "q2 := plain{}",
        "bags := []bag{bag{label: \"e\", counts: map[string]int{}}}",
    ] {
        assert!(go.contains(want), "missing {want:?} in:\n{go}");
    }
}

#[test]
fn n5_leaves_generic_structs_alone() {
    // Generic struct fields need the literal's type arguments substituted;
    // they keep Go's zero value (a documented limit of this lowering).
    let go = emit_src(
        "\
struct box[t comparable] {
    m map[t]int
}

fn main() {
    b := box[int]{}
    fmt.println(len(b.m))
}
",
    );
    assert!(go.contains("b := box[int]{}"), ":\n{go}");
}

#[test]
fn n5_make_slice_allocates_zero_maps() {
    let go = emit_src(
        "\
struct graph {
    nodes map[int]int
}

struct bag {
    counts map[string]int
}

fn main() {
    gs := make([]graph, 2)
    ms := make([]map[string]int, 2)
    bs := make([]bag, 0, 4)
    plain := make([]int, 2)
    ch := make(chan map[string]int, 1)
    fmt.println(len(gs) + len(ms) + len(bs) + len(plain) + cap(ch))
}
",
    );
    assert!(
        go.contains("gs := hy_n5_make(func() graph { return graph{nodes: map[int]int{}} }, 2)"),
        ":\n{go}"
    );
    assert!(
        go.contains("ms := hy_n5_make(func() map[string]int { return map[string]int{} }, 2)"),
        ":\n{go}"
    );
    assert!(
        go.contains("bs := hy_n5_make(func() bag { return bag{counts: map[string]int{}} }, 0, 4)"),
        ":\n{go}"
    );
    assert!(go.contains("plain := make([]int, 2)"), ":\n{go}");
    assert!(go.contains("ch := make(chan map[string]int, 1)"), ":\n{go}");
    assert!(
        go.contains("func hy_n5_make[t any](init func() t, n int, cap ...int) []t {"),
        ":\n{go}"
    );
}

#[test]
fn n5_array_zero_values_allocate_map_elements() {
    let go = emit_src(
        "\
struct graph {
    nodes map[int]int
}

struct bag {
    counts map[string]int
}

struct shelf {
    bags [2]bag
}

fn main() {
    var arr [2]graph
    bs := [2]bag{}
    var s shelf
    grid := make([][2]graph, 2)
    var nums [2]int
    fmt.println(len(arr) + len(bs) + len(s.bags) + len(grid) + len(nums))
}
",
    );
    assert!(
        go.contains("var arr [2]graph = func() (hyArr [2]graph) { for i := range hyArr { hyArr[i] = graph{nodes: map[int]int{}} }; return hyArr }()"),
        ":\n{go}"
    );
    assert!(
        go.contains("bs := func() (hyArr [2]bag) { for i := range hyArr { hyArr[i] = bag{counts: map[string]int{}} }; return hyArr }()"),
        ":\n{go}"
    );
    assert!(
        go.contains("var s shelf = shelf{bags: func() (hyArr [2]bag) { for i := range hyArr { hyArr[i] = bag{counts: map[string]int{}} }; return hyArr }()}"),
        ":\n{go}"
    );
    assert!(
        go.contains("grid := hy_n5_make(func() [2]graph { return func() (hyArr [2]graph) { for i := range hyArr { hyArr[i] = graph{nodes: map[int]int{}} }; return hyArr }() }, 2)"),
        ":\n{go}"
    );
    assert!(go.contains("var nums [2]int\n"), ":\n{go}");
}

#[test]
fn n5_array_partial_literal_pads_trailing_elements() {
    let go = emit_src(
        "\
struct bag {
    label  string
    counts map[string]int
}

const n = 2

fn main() {
    bs := [3]bag{bag{label: \"first\"}}
    arr := [n]bag{bag{label: \"a\"}}
    fmt.println(len(bs) + len(arr))
}
",
    );
    assert!(
        go.contains("bs := [3]bag{bag{label: \"first\", counts: map[string]int{}}, bag{counts: map[string]int{}}, bag{counts: map[string]int{}}}"),
        ":\n{go}"
    );
    assert!(
        go.contains("arr := [n]bag{bag{label: \"a\", counts: map[string]int{}}, bag{counts: map[string]int{}}}"),
        ":\n{go}"
    );
}

