// SPDX-License-Identifier: BSD-3-Clause
//! `compile::parse_macros` over arbitrary bytes, read as chard reads a `-dM -E` dump: decoded
//! as UTF-8 lossily and trimmed at the end (`compile::invoke`). The compiler sits inside the
//! trust boundary (THREAT_MODEL.md, "The operator chose the toolchain"), so a failure here is a
//! defect in chard's reader and not an attack.
//!
//! What the function promises, and so what is held for every input:
//!
//! - it returns, without a panic;
//! - it is deterministic: the same text parses to the same map twice;
//! - a key is the text after `#define ` up to the first space, so it holds no space and no line
//!   break, and some line of the input is `#define KEY` alone or `#define KEY ` followed by the
//!   rest; a value is trimmed and holds no line break;
//! - the map has at most one entry per `#define ` line;
//! - the map rendered back as `#define KEY VALUE` lines, the space written even before an
//!   empty value, parses to the same map.
//!
//! Not asserted: that a key is a non-empty identifier. The function records whatever the line
//! names, since a function-like macro keeps its parameter list in the key (`__has_builtin(x)`),
//! and it does not validate the name: by its body, `#define  x` yields the empty key and
//! `#define 1+1 2` the key `1+1`. The compilers checked print one space after the name, none
//! inside a parameter list, and a trailing space after an empty replacement list: on
//! 2026-09-30, Apple clang 21.0.0 on Darwin arm64, gcc 16.1.1 and clang 22.1.8 on Fedora 44
//! x86_64, and gcc 16.2.1 and clang 22.1.8 on Fedora 44 aarch64 each printed
//! `#define F(a,b) ((a)+(b))` for a source `#define F(a, b) ((a)+(b))`, and `#define E ` for a
//! source `#define E`. Such keys come only from text none of them printed, and a lookup by a
//! real macro name matches none.
//!
//! Nor is the round trip asserted in the form `#define KEY` for an empty value: a key may end
//! in a carriage return (by the function's body, the line `#define A\r\r\n` yields `A\r`),
//! and `#define A\r` followed by a line feed reads back as `A`, since `str::lines` strips a
//! `\r\n` pair.

#![no_main]

use std::collections::{BTreeMap, BTreeSet};

use chard::compile::parse_macros;
use libfuzzer_sys::fuzz_target;

fn render(map: &BTreeMap<String, String>) -> String {
    let mut text = String::new();
    for (name, value) in map {
        text.push_str("#define ");
        text.push_str(name);
        text.push(' ');
        text.push_str(value);
        text.push('\n');
    }
    text
}

fuzz_target!(|data: &[u8]| {
    let lossy = String::from_utf8_lossy(data);
    let text = lossy.trim_end();
    let map = parse_macros(text);
    assert_eq!(parse_macros(text), map, "a second parse differs");

    // What each `#define ` line names: the text before its first space, or all of it. A key
    // with no space is among these exactly when some line is `#define KEY` alone or
    // `#define KEY ` and the rest. A set, since a dump runs to thousands of lines.
    let mut lines = 0usize;
    let mut named = BTreeSet::new();
    for rest in text.lines().filter_map(|l| l.strip_prefix("#define ")) {
        lines += 1;
        named.insert(rest.split_once(' ').map_or(rest, |(head, _)| head));
    }
    assert!(
        map.len() <= lines,
        "{} entries from {lines} #define lines",
        map.len()
    );
    for (name, value) in &map {
        assert!(!name.contains(' '), "a key holds a space: {name:?}");
        assert!(!name.contains('\n'), "a key holds a line feed: {name:?}");
        assert!(
            !value.contains('\n'),
            "a value holds a line feed: {value:?}"
        );
        assert_eq!(value.trim(), value, "a value is not trimmed: {value:?}");
        assert!(
            named.contains(name.as_str()),
            "no #define line names {name:?}"
        );
    }

    assert_eq!(
        parse_macros(&render(&map)),
        map,
        "the map rendered as #define lines parses to another map"
    );
});
