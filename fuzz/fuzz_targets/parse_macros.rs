// SPDX-License-Identifier: BSD-3-Clause
//! `compile::parse_macros` over arbitrary bytes, read as chard reads a `-dM -E` dump: decoded
//! as UTF-8 lossily and trimmed at the end (`compile::invoke`). The compiler sits inside the
//! trust boundary (`THREAT_MODEL.md`, "The operator chose the toolchain"), so a failure here is a
//! defect in chard's reader and not an attack.

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

    // What each `#define ` line names: the text before its first space, or all of it.
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
