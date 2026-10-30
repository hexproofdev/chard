// SPDX-License-Identifier: BSD-3-Clause

//! A JSON Schema validator for the keywords chard's schemas use, and no others.
//!
//! Shared by `tests/schema_conformance.rs`, which holds reports and matrices to their
//! schemas, and `tests/predicate_language.rs`, which holds predicates to theirs. The
//! rationale for a small hand-written validator, and the history of the keywords it once
//! dropped, is in `tests/schema_conformance.rs`'s module documentation. A keyword outside
//! the implemented set panics rather than passing.

use std::collections::BTreeSet;

use serde_json::Value;

/// How an object that declares `additionalProperties: true` beside its `properties` is
/// read.
///
/// The shipped report, matrix, `detect` and envelope schemas declare it on every object, so a
/// consumer's validator admits a key a later chard adds (the rule `chard --help` states). Read
/// as a consumer reads it, that object admits any key. Read as chard's producer, it admits
/// none it does not declare: a field chard emits and the schema does not declare is the drift
/// `tests/schema_conformance.rs` exists to catch, as it would for a closed object
/// (`additionalProperties: false`). An object meant to stay open to chard's own output as well
/// declares no `additionalProperties`, or a schema for its other members
/// (`additionalProperties: {}` for any), and is open in both readings.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reading {
    Producer,
    Consumer,
}

/// Validate `instance` against `schema` as chard's producer (see [`Reading`]), appending
/// human-readable problems to `errors`. `path` is the JSON pointer walked so far, so a
/// failure names the field rather than just the type.
pub fn validate(
    instance: &Value,
    schema: &Value,
    root: &Value,
    path: &str,
    errors: &mut Vec<String>,
) {
    walk(instance, schema, root, path, errors, Reading::Producer);
}

/// [`validate`] as a consumer pinned to the published schema reads it, admitting a key the
/// schema does not declare wherever the object declares `additionalProperties: true`.
pub fn validate_as_published(
    instance: &Value,
    schema: &Value,
    root: &Value,
    path: &str,
    errors: &mut Vec<String>,
) {
    walk(instance, schema, root, path, errors, Reading::Consumer);
}

fn walk(
    instance: &Value,
    schema: &Value,
    root: &Value,
    path: &str,
    errors: &mut Vec<String>,
    reading: Reading,
) {
    refuse_unimplemented_keywords(schema, path);

    // $ref: these schemas only ever point into #/$defs.
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let Some(target) = resolve(reference, root) else {
            errors.push(format!("{path}: unresolvable $ref {reference}"));
            return;
        };
        walk(instance, target, root, path, errors, reading);
        return;
    }

    if let Some(branches) = schema.get("oneOf").and_then(Value::as_array) {
        let passing = branches
            .iter()
            .filter(|branch| {
                let mut branch_errors = Vec::new();
                walk(instance, branch, root, path, &mut branch_errors, reading);
                branch_errors.is_empty()
            })
            .count();
        if passing != 1 {
            errors.push(format!(
                "{path}: {instance} matches {passing} of the {} oneOf branches, not exactly one",
                branches.len()
            ));
        }
    }

    if let Some(expected) = schema.get("const")
        && instance != expected
    {
        errors.push(format!("{path}: expected const {expected}, got {instance}"));
    }

    if let Some(options) = schema.get("enum").and_then(Value::as_array)
        && !options.contains(instance)
    {
        errors.push(format!("{path}: {instance} is not one of {options:?}"));
    }

    if let Some(declared) = schema.get("type") {
        let allowed: Vec<&str> = match declared {
            Value::String(one) => vec![one.as_str()],
            Value::Array(many) => many.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        if !allowed.is_empty() && !allowed.iter().any(|t| type_matches(t, instance)) {
            errors.push(format!(
                "{path}: expected type {allowed:?}, got {}",
                type_name(instance)
            ));
            // Type is wrong, so descending would only produce noise.
            return;
        }
    }

    if let Some(object) = instance.as_object() {
        check_object(object, schema, root, path, errors, reading);
    }

    if let Some(array) = instance.as_array() {
        check_array(array, schema, root, path, errors, reading);
    }

    check_scalar_constraints(instance, schema, path, errors);
}

/// The keywords that constrain an object: its property count, the properties it
/// requires, and the schema each property meets.
fn check_object(
    object: &serde_json::Map<String, Value>,
    schema: &Value,
    root: &Value,
    path: &str,
    errors: &mut Vec<String>,
    reading: Reading,
) {
    let properties = schema.get("properties").and_then(Value::as_object);

    for required in schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        if !object.contains_key(required) {
            errors.push(format!("{path}: missing required property `{required}`"));
        }
    }

    let count = object.len() as u64;
    if let Some(least) = schema.get("minProperties").and_then(Value::as_u64)
        && count < least
    {
        errors.push(format!(
            "{path}: has {count} properties, minProperties is {least}"
        ));
    }
    if let Some(most) = schema.get("maxProperties").and_then(Value::as_u64)
        && count > most
    {
        errors.push(format!(
            "{path}: has {count} properties, maxProperties is {most}"
        ));
    }

    let known: BTreeSet<&str> = properties
        .map(|p| p.keys().map(String::as_str).collect())
        .unwrap_or_default();

    let closed = match schema.get("additionalProperties") {
        Some(Value::Bool(false)) => true,
        Some(Value::Bool(true)) => {
            reading == Reading::Producer && schema.get("properties").is_some()
        }
        _ => false,
    };
    match schema.get("additionalProperties") {
        Some(Value::Bool(_)) if closed => {
            for key in object.keys() {
                if !known.contains(key.as_str()) {
                    errors.push(format!(
                        "{path}: property `{key}` is not declared and \
                         the object is closed to chard's own output"
                    ));
                }
            }
        }
        // A schema for the extra properties, e.g. verdict_counts' integers.
        Some(extra @ Value::Object(_)) => {
            for (key, value) in object {
                if !known.contains(key.as_str()) {
                    walk(
                        value,
                        extra,
                        root,
                        &format!("{path}/{key}"),
                        errors,
                        reading,
                    );
                }
            }
        }
        _ => {}
    }

    if let Some(properties) = properties {
        for (key, value) in object {
            if let Some(sub) = properties.get(key) {
                walk(value, sub, root, &format!("{path}/{key}"), errors, reading);
            }
        }
    }
}

/// The keywords that constrain an array: its length and the schema each item meets.
fn check_array(
    array: &[Value],
    schema: &Value,
    root: &Value,
    path: &str,
    errors: &mut Vec<String>,
    reading: Reading,
) {
    let prefix = schema
        .get("prefixItems")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    for (i, (value, sub)) in array.iter().zip(prefix).enumerate() {
        walk(value, sub, root, &format!("{path}/{i}"), errors, reading);
    }
    if let Some(items) = schema.get("items") {
        for (i, value) in array.iter().enumerate().skip(prefix.len()) {
            walk(value, items, root, &format!("{path}/{i}"), errors, reading);
        }
    }
    if let Some(least) = schema.get("minItems").and_then(Value::as_u64)
        && (array.len() as u64) < least
    {
        errors.push(format!(
            "{path}: has {} items, minItems is {least}",
            array.len()
        ));
    }
    if let Some(most) = schema.get("maxItems").and_then(Value::as_u64)
        && (array.len() as u64) > most
    {
        errors.push(format!(
            "{path}: has {} items, maxItems is {most}",
            array.len()
        ));
    }
}

/// The keywords that constrain a single number or string, kept out of [`validate`] so
/// that walking the document and bounding a leaf stay separately readable.
pub fn check_scalar_constraints(
    instance: &Value,
    schema: &Value,
    path: &str,
    errors: &mut Vec<String>,
) {
    if let Some(number) = instance.as_f64() {
        if let Some(least) = schema.get("minimum").and_then(Value::as_f64)
            && number < least
        {
            errors.push(format!("{path}: {number} is below minimum {least}"));
        }
        if let Some(most) = schema.get("maximum").and_then(Value::as_f64)
            && number > most
        {
            errors.push(format!("{path}: {number} is above maximum {most}"));
        }
    }

    if let Some(text) = instance.as_str() {
        // JSON Schema counts a string's length in code points.
        let length = text.chars().count() as u64;
        if let Some(least) = schema.get("minLength").and_then(Value::as_u64)
            && length < least
        {
            errors.push(format!(
                "{path}: {text:?} is shorter than minLength {least}"
            ));
        }
        if let Some(most) = schema.get("maxLength").and_then(Value::as_u64)
            && length > most
        {
            errors.push(format!("{path}: {text:?} is longer than maxLength {most}"));
        }
        if let Some(pattern) = schema.get("pattern").and_then(Value::as_str)
            && !matches_pattern(pattern, text)
        {
            errors.push(format!("{path}: {text:?} does not match pattern {pattern}"));
        }
        if let Some(format) = schema.get("format").and_then(Value::as_str)
            && !matches_format(format, text)
        {
            errors.push(format!("{path}: {text:?} is not a valid {format}"));
        }
    }
}

/// Does `text` match `pattern`, for the sliver of regular-expression syntax this
/// schema uses?
///
/// Deliberately not a regex engine, and deliberately not a dependency. The schemas'
/// patterns take three forms. `profile.id`'s is an anchored alternation of literals where
/// one branch ends in a character class. The digests' and the like are an anchored
/// `[class]+` or `[class]{n}`, which the branch form below reads as an empty literal
/// prefix. The predicate schema's are `^[^@]`, a first character outside a literal set, and
/// `\S`, some character outside ECMA-262's `\s`; the report schema embeds the predicate
/// schema's `$defs/clause`, so it holds those two as well. Supporting those is sixty lines;
/// `regex` would be a fifth direct dependency and 200-odd transitive crates for a handful
/// of strings.
///
/// `profile.id`'s pattern ends in an optional group, `(\+env:[0-9a-f]{12})?`: one branch
/// of the same form, whose literal may escape a
/// character with `\` and whose class may be counted `{n}` as well as `+`. The text matches
/// the alternation alone, or the alternation followed by the group.
///
/// # Panics
///
/// On any construct outside the supported subset. That is the whole design: an
/// unimplemented keyword silently ignores the schema's constraint, and a malformed
/// `profile.id` would conform. Refusing loudly cannot do that, whereas returning `true` on an
/// unrecognised pattern could.
pub fn matches_pattern(pattern: &str, text: &str) -> bool {
    // `\S`, unanchored: some character is outside ECMA-262's `\s`.
    if pattern == r"\S" {
        return text.chars().any(|c| !is_ecma_whitespace(c));
    }
    // `^[^...]`, anchored at the start only: a first character outside a literal set.
    if let Some(class) = pattern
        .strip_prefix("^[^")
        .and_then(|p| p.strip_suffix(']'))
    {
        assert!(
            !class.is_empty() && !class.contains(['[', ']', '\\', '-', '^']),
            "unsupported negated class in {pattern}: literal characters only"
        );
        return text.chars().next().is_some_and(|c| !class.contains(c));
    }
    let body = pattern
        .strip_prefix('^')
        .and_then(|p| p.strip_suffix('$'))
        .unwrap_or_else(|| panic!("unsupported pattern (must be anchored): {pattern}"));
    if let Some(open) = body
        .strip_suffix(")?")
        .and_then(|b| b.rfind('(').map(|i| (b, i)))
    {
        let (head, start) = open;
        let group = &head[start + 1..];
        let base = format!("^{}$", &head[..start]);
        assert!(
            !group.contains(['(', ')', '|', '*', '?']),
            "unsupported optional group in {pattern}: one branch only"
        );
        return matches_pattern(&base, text)
            || text.char_indices().any(|(i, _)| {
                i > 0 && matches_pattern(&base, &text[..i]) && matches_branch(group, &text[i..])
            });
    }
    let body = body
        .strip_prefix('(')
        .and_then(|b| b.strip_suffix(')'))
        .unwrap_or(body);
    assert!(
        !body.contains(['(', ')', '*', '?', '{', '\\']),
        "unsupported pattern construct in {pattern}: this validator handles anchored \
         alternations of literals with an optional trailing `[class]+` only"
    );
    body.split('|').any(|branch| matches_branch(branch, text))
}

/// One alternation branch: literal characters, a `\` escaping the one after it, optionally
/// ending in `[class]+` or `[class]{n}`.
fn matches_branch(branch: &str, text: &str) -> bool {
    let (literal, class) = match branch.find('[') {
        Some(open) => (&branch[..open], Some(&branch[open..])),
        None => (branch, None),
    };
    let mut prefix = String::new();
    let mut chars = literal.chars();
    while let Some(c) = chars.next() {
        prefix.push(if c == '\\' {
            chars
                .next()
                .unwrap_or_else(|| panic!("a trailing `\\` in {branch}"))
        } else {
            c
        });
    }
    let Some(class) = class else {
        return prefix == text;
    };
    let close = class
        .find(']')
        .unwrap_or_else(|| panic!("unterminated character class in {branch}"));
    let count = match &class[close + 1..] {
        "+" => None,
        quantifier => Some(
            quantifier
                .strip_prefix('{')
                .and_then(|q| q.strip_suffix('}'))
                .and_then(|n| n.parse::<usize>().ok())
                .unwrap_or_else(|| {
                    panic!("a character class must be terminal and `+`- or `{{n}}`-quantified in {branch}")
                }),
        ),
    };
    let Some(rest) = text.strip_prefix(prefix.as_str()) else {
        return false;
    };
    let body = &class[1..close];
    !rest.is_empty()
        && count.is_none_or(|n| rest.chars().count() == n)
        && rest.chars().all(|c| class_contains(body, c))
}

/// Is `c` in a character class body like `A-Za-z0-9._-`?
fn class_contains(class: &str, c: char) -> bool {
    let chars: Vec<char> = class.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        // A `-` is a range only between two characters; trailing `-` is a literal.
        if i + 2 < chars.len() && chars[i + 1] == '-' {
            if c >= chars[i] && c <= chars[i + 2] {
                return true;
            }
            i += 3;
        } else {
            if c == chars[i] {
                return true;
            }
            i += 1;
        }
    }
    false
}

/// Does `text` satisfy `format`?
///
/// # Panics
///
/// On a format this validator does not implement, for the reason [`matches_pattern`]
/// panics: an unimplemented keyword that returns `true` is indistinguishable from a
/// constraint that passed.
pub fn matches_format(format: &str, text: &str) -> bool {
    assert!(
        format == "date-time",
        "unsupported format `{format}`: implement it or stop declaring it"
    );
    // RFC 3339, in the one shape `iso8601_utc` emits: YYYY-MM-DDTHH:MM:SSZ. Deliberately
    // strict about the `Z`: chard timestamps are UTC by construction, and an offset
    // here would mean something upstream started guessing.
    let bytes = text.as_bytes();
    if bytes.len() != 20 || bytes[19] != b'Z' {
        return false;
    }
    let shape = |i: usize, want: u8| bytes[i] == want;
    if !(shape(4, b'-') && shape(7, b'-') && shape(10, b'T') && shape(13, b':') && shape(16, b':'))
    {
        return false;
    }
    if ![0..4, 5..7, 8..10, 11..13, 14..16, 17..19]
        .into_iter()
        .all(|r| text[r].bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    // RFC 3339 section 5.7: the fields are ranges, not just digits. A shape-only check
    // passed `2026-13-45T25:61:61Z`, which any standard `date-time` validator rejects.
    // Seconds stop at 59 because `iso8601_utc` never emits a leap second.
    let field = |start: usize, end: usize| text[start..end].parse::<u32>().unwrap();
    let (year, month, day) = (field(0, 4), field(5, 7), field(8, 10));
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_length = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=month_length).contains(&day)
        && field(11, 13) < 24
        && field(14, 16) < 60
        && field(17, 19) < 60
}

pub fn resolve<'a>(reference: &str, root: &'a Value) -> Option<&'a Value> {
    let mut current = root;
    for segment in reference.trim_start_matches("#/").split('/') {
        current = current.get(segment)?;
    }
    Some(current)
}

pub fn type_matches(expected: &str, instance: &Value) -> bool {
    match expected {
        "object" => instance.is_object(),
        "array" => instance.is_array(),
        "string" => instance.is_string(),
        "boolean" => instance.is_boolean(),
        // JSON Schema's `integer` accepts a number with no fractional part.
        "integer" => instance.as_f64().is_some_and(|n| n.fract() == 0.0),
        "number" => instance.is_number(),
        "null" => instance.is_null(),
        other => panic!(
            "type {other:?} is not implemented by this validator; implement it or fix the schema"
        ),
    }
}

pub fn type_name(instance: &Value) -> &'static str {
    match instance {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// ECMA-262's `\s`, which JSON Schema's `pattern` uses: the `WhiteSpace` and `LineTerminator`
/// code points, spelt out here rather than borrowed from the code under test.
pub fn is_ecma_whitespace(c: char) -> bool {
    matches!(
        c,
        '\u{9}'..='\u{d}'
            | ' '
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
            | '\u{feff}'
    )
}

/// The keywords [`validate`] evaluates, and the annotations it may pass over.
const IMPLEMENTED: &[&str] = &[
    "$ref",
    "oneOf",
    "const",
    "enum",
    "type",
    "required",
    "properties",
    "additionalProperties",
    "minProperties",
    "maxProperties",
    "items",
    "prefixItems",
    "minItems",
    "maxItems",
    "minimum",
    "maximum",
    "minLength",
    "maxLength",
    "pattern",
    "format",
];
const ANNOTATIONS: &[&str] = &[
    "$schema",
    "$id",
    "title",
    "description",
    "$defs",
    "x-volatile",
    "x-volatile-readings",
];

/// Panic on a keyword [`validate`] does not evaluate. The validator once dropped
/// `minimum`, `pattern` and `format` without a word, so a declared constraint was
/// enforced on nothing; a keyword it cannot evaluate now stops the test instead.
fn refuse_unimplemented_keywords(schema: &Value, path: &str) {
    for key in schema.as_object().into_iter().flat_map(|o| o.keys()) {
        assert!(
            IMPLEMENTED.contains(&key.as_str()) || ANNOTATIONS.contains(&key.as_str()),
            "{path}: keyword `{key}` is not implemented by this validator; implement it or \
             stop declaring it"
        );
    }
}
