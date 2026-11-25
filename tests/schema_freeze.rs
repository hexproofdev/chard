// SPDX-License-Identifier: BSD-3-Clause

//! The contract's bump rule, held to the shapes of the release this tree is cut for.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::string_slice,
    reason = "test code lays out fixture bytes, counts results and slices text at offsets it \
              found in the same string, from constants and the sizes of data in memory; the \
              test profile keeps overflow checks, and an overflow, or a slice off a character \
              boundary or past the end, panics and fails the test. Its casts widen a length or \
              a u32, take the offset between two addresses in one string, or name a function \
              pointer type or a closure's trait object. clippy has no test knob for these three \
              lints, and src/lib.rs's crate-root relief does not reach tests/"
)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::Value;

mod common;

/// The output schemas, by the name their files carry.
const SCHEMAS: [&str; 4] = ["report", "matrix", "detect", "error"];

/// The open enumerations: names of things chard has, where an added value is allowed. Each is a
/// JSON pointer into its schema.
const OPEN: &[(&str, &str)] = &[
    (
        "report",
        "/properties/environment/properties/libc/properties/impl",
    ),
    (
        "report",
        "/properties/coverage/properties/gate/properties/allowed/items",
    ),
    (
        "report",
        "/properties/coverage/properties/gate/properties/excused/items/properties/rule",
    ),
    (
        "report",
        "/properties/toolchain/properties/target/properties/agreement",
    ),
    (
        "report",
        "/properties/toolchain/properties/target/properties/abi/properties/agreement",
    ),
    (
        "report",
        "/properties/toolchain/properties/target/properties/macros/properties/agreement",
    ),
    (
        "report",
        "/properties/toolchain/properties/target/properties/profile_macros/properties/agreement",
    ),
    (
        "report",
        "/properties/toolchain/properties/target/properties/profile_macros_cxx/properties/agreement",
    ),
    ("report", "/$defs/linker/properties/kind"),
    (
        "report",
        "/$defs/linker/properties/artifact/properties/agreement",
    ),
    (
        "report",
        "/$defs/controls/properties/positive/properties/outcome",
    ),
    (
        "report",
        "/$defs/controls/properties/negative/properties/outcome",
    ),
    (
        "report",
        "/$defs/controls/properties/regime_negative/properties/outcome",
    ),
    ("report", "/$defs/controls/properties/withheld_because"),
    (
        "report",
        "/$defs/observation/properties/gating/properties/rule",
    ),
    // Check ids, open as `gating.rule` is: the ids name the checks this corpus has, so a
    // report of this chard_schema may carry a check a later chard adds.
    ("report", "/$defs/observation/properties/check"),
    // Elf fields, the predicate language's terms: a predicate a later chard publishes
    // may read a field this schema does not list, as the predicate language's own
    // version decides.
    ("report", "/$defs/elf_field"),
    (
        "report",
        "/$defs/observation/properties/structured_diagnostics/properties/arms/additionalProperties/properties/outcome",
    ),
    ("report", "/$defs/decoded/properties/outcome"),
];

/// The closed enumerations a consumer decides on, held closed: an added value raises
/// `chard_schema`.
const NAMED_CLOSED: &[(&str, &str)] = &[
    ("report", "/$defs/verdict"),
    ("report", "/$defs/observation/properties/polarity"),
    ("report", "/$defs/observation/properties/observes"),
    (
        "report",
        "/properties/defect_coverage/additionalProperties/properties/status",
    ),
    ("report", "/properties/consistency/properties/status"),
    (
        "matrix",
        "/properties/variance/additionalProperties/properties/strength",
    ),
    ("error", "/properties/error/properties/code"),
    ("detect", "/$defs/outcome"),
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &PathBuf) -> Value {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn current(name: &str) -> Value {
    read(&root().join(format!("schema/chard-{name}.schema.json")))
}

/// The values of a node's enumeration and whether it is open, or `None` where the node is no
/// enumeration. Open is exactly `anyOf: [{enum: [...]}, {type: "string"}]`.
fn vocabulary(node: &Value) -> Option<(BTreeSet<String>, bool)> {
    let values = |v: &Value| -> BTreeSet<String> {
        v.as_array()
            .expect("an enum is an array")
            .iter()
            .map(|x| x.as_str().map_or_else(|| x.to_string(), ToOwned::to_owned))
            .collect()
    };
    if let Some(e) = node.get("enum") {
        return Some((values(e), false));
    }
    let branches = node.get("anyOf")?.as_array()?;
    match branches.as_slice() {
        [known, any] if any == &serde_json::json!({ "type": "string" }) => {
            Some((values(known.get("enum")?), true))
        }
        _ => None,
    }
}

/// The breaking differences of `now` from `then`, the node at `at`: a key under `properties` or
/// `$defs` gone, a required key made optional, a `type`, `const` or `$ref` changed, an
/// enumeration value gone, or a closed enumeration's value added. It walks `properties`, `$defs`,
/// `items`, `additionalProperties`, `prefixItems`, `oneOf`, `anyOf` and `allOf`.
fn breaking(then: &Value, now: &Value, at: &str, out: &mut Vec<String>) {
    let Some(old) = then.as_object() else { return };
    let names = |v: Option<&Value>| -> BTreeSet<String> {
        v.and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };
    for gone in names(old.get("required")).difference(&names(now.get("required"))) {
        out.push(format!("{at}: {gone} is no longer required"));
    }
    for keyword in ["const", "$ref"] {
        if let Some(t) = old.get(keyword)
            && now.get(keyword) != Some(t)
        {
            out.push(format!("{at}: {keyword} {t} became {:?}", now.get(keyword)));
        }
    }
    if let Some((was, _)) = vocabulary(then) {
        match vocabulary(now) {
            None => out.push(format!("{at}: no longer an enumeration")),
            Some((is, open)) => {
                for gone in was.difference(&is) {
                    out.push(format!("{at}: the value {gone} was removed"));
                }
                if !open {
                    for added in is.difference(&was) {
                        out.push(format!(
                            "{at}: the value {added} was added to a closed enumeration"
                        ));
                    }
                }
            }
        }
    }
    // An enumeration opened keeps its type in the `anyOf`; any other node keeps its own.
    if let Some(t) = old.get("type") {
        let opened = vocabulary(now).is_some_and(|(_, open)| open) && now.get("type").is_none();
        if !opened && now.get("type") != Some(t) {
            out.push(format!("{at}: type {t} became {:?}", now.get("type")));
        }
    }
    for container in ["properties", "$defs"] {
        let Some(children) = old.get(container).and_then(Value::as_object) else {
            continue;
        };
        for (key, child) in children {
            match now.get(container).and_then(|c| c.get(key)) {
                Some(n) => breaking(child, n, &format!("{at}/{container}/{key}"), out),
                None => out.push(format!("{at}/{container}/{key}: removed or renamed")),
            }
        }
    }
    for single in ["items", "additionalProperties"] {
        if let (Some(t), Some(n)) = (old.get(single), now.get(single))
            && t.is_object()
        {
            breaking(t, n, &format!("{at}/{single}"), out);
        }
    }
    for list in ["oneOf", "anyOf", "allOf", "prefixItems"] {
        if vocabulary(then).is_some() && list == "anyOf" {
            continue;
        }
        if let (Some(t), Some(n)) = (
            old.get(list).and_then(Value::as_array),
            now.get(list).and_then(Value::as_array),
        ) {
            if t.len() != n.len() {
                out.push(format!(
                    "{at}/{list}: {} branches became {}",
                    t.len(),
                    n.len()
                ));
                continue;
            }
            for (i, (a, b)) in t.iter().zip(n).enumerate() {
                breaking(a, b, &format!("{at}/{list}/{i}"), out);
            }
        }
    }
}

#[test]
fn the_open_enumerations_are_the_named_ones() {
    let mut open = BTreeSet::new();
    for name in SCHEMAS {
        let mut found = Vec::new();
        open_paths(&current(name), "", &mut found);
        open.extend(found.into_iter().map(|p| (name, p)));
    }
    let named: BTreeSet<(&str, String)> = OPEN.iter().map(|(s, p)| (*s, (*p).to_owned())).collect();
    assert_eq!(
        open, named,
        "the schemas' open enumerations and OPEN differ"
    );
    for (name, pointer) in NAMED_CLOSED {
        let node = current(name)
            .pointer(pointer)
            .cloned()
            .unwrap_or_else(|| panic!("{name}: no node at {pointer}"));
        assert_eq!(
            vocabulary(&node).map(|(_, open)| open),
            Some(false),
            "{name}{pointer}: a closed enumeration a consumer decides on"
        );
    }
}

fn open_paths(node: &Value, at: &str, out: &mut Vec<String>) {
    match node {
        Value::Object(map) => {
            if vocabulary(node).is_some_and(|(_, open)| open) {
                out.push(at.to_owned());
            }
            for (key, child) in map {
                open_paths(
                    child,
                    &format!("{at}/{}", key.replace('~', "~0").replace('/', "~1")),
                    out,
                );
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                open_paths(item, &format!("{at}/{i}"), out);
            }
        }
        _ => {}
    }
}

/// An edit to a schema, named.
type Edit<'a> = (&'a str, Box<dyn Fn(&mut Value) + 'a>);

#[test]
fn breaking_names_each_breaking_difference_and_admits_the_rest() {
    use serde_json::json;
    let base = json!({
        "type": "object",
        "required": ["kept", "verdict"],
        "properties": {
            "kept": {"type": "string"},
            "verdict": {"enum": ["on", "off"]},
            "rule": {"anyOf": [{"enum": ["a", "b"]}, {"type": "string"}]},
            "kind": {"const": "report"},
            "pair": {"prefixItems": [{"type": "string"}, {"type": "integer"}]},
            "link": {"$ref": "#/$defs/x"}
        },
        "$defs": {"x": {"type": "string"}, "y": {"type": "string"}}
    });
    let differs = |edit: &dyn Fn(&mut Value)| -> Vec<String> {
        let mut now = base.clone();
        edit(&mut now);
        let mut out = Vec::new();
        breaking(&base, &now, "", &mut out);
        out
    };
    let breaks: [Edit<'_>; 9] = [
        (
            "a key removed",
            Box::new(|v| {
                v["properties"].as_object_mut().unwrap().remove("kept");
            }),
        ),
        (
            "a $defs entry removed",
            Box::new(|v| {
                v["$defs"].as_object_mut().unwrap().remove("y");
            }),
        ),
        (
            "a required key made optional",
            Box::new(|v| v["required"] = json!(["verdict"])),
        ),
        (
            "a type changed",
            Box::new(|v| v["properties"]["kept"]["type"] = json!("integer")),
        ),
        (
            "a closed value added",
            Box::new(|v| v["properties"]["verdict"]["enum"] = json!(["on", "off", "maybe"])),
        ),
        (
            "a closed value removed",
            Box::new(|v| v["properties"]["verdict"]["enum"] = json!(["on"])),
        ),
        (
            "an open value removed",
            Box::new(|v| v["properties"]["rule"]["anyOf"][0]["enum"] = json!(["a"])),
        ),
        (
            "a const changed",
            Box::new(|v| v["properties"]["kind"]["const"] = json!("matrix")),
        ),
        (
            "a $ref retargeted",
            Box::new(|v| v["properties"]["link"]["$ref"] = json!("#/$defs/y")),
        ),
    ];
    for (label, edit) in &breaks {
        assert!(
            !differs(edit.as_ref()).is_empty(),
            "{label} is not reported"
        );
    }
    let tuple = differs(&|v| v["properties"]["pair"]["prefixItems"][1]["type"] = json!("string"));
    assert!(
        !tuple.is_empty(),
        "a prefixItems element's type changed is not reported"
    );
    let admitted: [Edit<'_>; 3] = [
        (
            "a key added",
            Box::new(|v| v["properties"]["new"] = json!({"type": "string"})),
        ),
        (
            "an open value added",
            Box::new(|v| v["properties"]["rule"]["anyOf"][0]["enum"] = json!(["a", "b", "c"])),
        ),
        (
            "a key made required",
            Box::new(|v| v["required"] = json!(["kept", "verdict", "rule"])),
        ),
    ];
    for (label, edit) in &admitted {
        let out = differs(edit.as_ref());
        assert!(out.is_empty(), "{label} is reported: {out:?}");
    }
}
