// SPDX-License-Identifier: BSD-3-Clause
//! A JSON-aware mutator for the targets whose input is JSON (`detect_evidence`, `predicate`,
//! `report_render`, `attestation`, `report_digest`), installed through libFuzzer's
//! `LLVMFuzzerCustomMutator`.

use serde_json::{Value, json};

/// Words chard's readers branch on, offered as replacement values and keys.
const WORDS: &[&str] = &[
    "on",
    "off",
    "partial",
    "unsupported",
    "not-applicable",
    "indeterminate",
    "probe-invalid",
    "build-failed",
    "run-failed",
    "present",
    "absent",
    "elf",
    "elf-delta",
    "unreadable",
    "macro-dump",
    "preprocessor",
    "compiled-artifact",
    "measured",
    "positive",
    "negative",
    "regime",
    "chard_schema",
    "observations",
    "facts",
    "controls",
    "decoded",
    "decoders",
    "predicates",
    "kind",
    "verdict",
    "level",
    "outcome",
    "gating",
    "rule",
    "check",
    "probe",
    "channel",
    "macro",
    "elf-static",
    "runtime",
    "compiler-diag",
    "clauses",
    "when",
    "then",
    "otherwise",
    "because",
    "tables",
    "defined",
    "c-int",
    "eq",
    "any",
    "all",
    "none-of",
    "symbol",
    "word",
    "value",
    "truncations",
    "watched_symbols",
    "self_report",
    "base",
    "elf_changes",
    "artifact_sha256",
    "stdout_sha256",
    "macro_source",
    "macro_dump",
    "run",
    "build",
    "toolchain",
    "profile",
    "id",
    "environment",
    "composites",
    "coverage",
];

/// Numbers at the edges an offset, count, width or digest length meets.
const NUMBERS: &[&str] = &[
    "0",
    "-1",
    "1",
    "255",
    "256",
    "65535",
    "65536",
    "4294967295",
    "4294967296",
    "9223372036854775807",
    "18446744073709551615",
    "-9223372036854775808",
    "1e308",
    "0.5",
];

/// xorshift64*, seeded by libFuzzer; no dependency, and deterministic for a given seed. It
/// carries the target's own words, drawn from as if appended to [`WORDS`].
struct Rng(u64, &'static [&'static str]);

impl Rng {
    fn new(seed: u32, extra: &'static [&'static str]) -> Self {
        Self(
            u64::from(seed).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1,
            extra,
        )
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the remainder is below n, a usize, so the cast keeps every bit of it"
    )]
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
    #[expect(
        clippy::indexing_slicing,
        reason = "i is below the two lists' summed length, and past WORDS where it is read"
    )]
    fn word(&mut self) -> &'static str {
        let i = self.below(WORDS.len() + self.1.len());
        WORDS
            .get(i)
            .copied()
            .unwrap_or_else(|| self.1[i - WORDS.len()])
    }
}

fn count(v: &Value) -> usize {
    1 + match v {
        Value::Array(a) => a.iter().map(count).sum(),
        Value::Object(o) => o.values().map(count).sum(),
        _ => 0,
    }
}

fn nth(v: &Value, n: &mut usize) -> Option<Value> {
    if *n == 0 {
        return Some(v.clone());
    }
    *n -= 1;
    match v {
        Value::Array(a) => a.iter().find_map(|c| nth(c, n)),
        Value::Object(o) => o.values().find_map(|c| nth(c, n)),
        _ => None,
    }
}

/// A node reached by walking down from the root, stopping at each level with probability
/// one in three.
#[expect(
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::unreachable,
    reason = "i is below the child count read just above, and a scalar, which has none, returned there"
)]
fn descend<'a>(mut v: &'a mut Value, rng: &mut Rng) -> &'a mut Value {
    loop {
        let children = match &v {
            Value::Array(a) => a.len(),
            Value::Object(o) => o.len(),
            _ => 0,
        };
        if children == 0 || rng.below(3) == 0 {
            return v;
        }
        let i = rng.below(children);
        v = match v {
            Value::Array(a) => &mut a[i],
            Value::Object(o) => o.values_mut().nth(i).expect("i is below the length"),
            _ => unreachable!("a scalar has no children"),
        };
    }
}

fn scalar(rng: &mut Rng) -> Value {
    match rng.below(6) {
        0 => Value::Null,
        1 => Value::Bool(rng.below(2) == 0),
        2 => NUMBERS
            .get(rng.below(NUMBERS.len()))
            .and_then(|n| serde_json::from_str(n).ok())
            .unwrap_or(Value::Null),
        3 => json!({}),
        4 => json!([]),
        _ => Value::String(rng.word().to_owned()),
    }
}

/// One structural edit to `node`; `graft` is a copy of another node of the document.
fn edit(node: &mut Value, graft: Option<Value>, rng: &mut Rng) {
    match rng.below(7) {
        0 => *node = Value::String(rng.word().to_owned()),
        1 => *node = scalar(rng),
        2 => {
            if let Some(g) = graft {
                *node = g;
            }
        }
        _ => match node {
            Value::Object(o) if !o.is_empty() => {
                let key = o
                    .keys()
                    .nth(rng.below(o.len()))
                    .cloned()
                    .unwrap_or_default();
                if rng.below(2) == 0 {
                    o.remove(&key);
                } else {
                    let value = scalar(rng);
                    o.insert(rng.word().to_owned(), value);
                }
            }
            Value::Array(a) if !a.is_empty() => match rng.below(3) {
                0 => {
                    let i = rng.below(a.len());
                    a.remove(i);
                }
                1 => {
                    let i = rng.below(a.len());
                    if let Some(copy) = a.get(i).cloned() {
                        a.insert(i, copy);
                    }
                }
                _ => {
                    let keep = rng.below(a.len());
                    a.truncate(keep);
                }
            },
            Value::String(s) => {
                if rng.below(4) == 0 {
                    let times = 1 << rng.below(12);
                    *s = s.repeat(times.min(4096 / s.len().max(1)).max(1));
                } else {
                    let mut bytes = s.clone().into_bytes();
                    let len = bytes.len();
                    bytes.resize(len + 16, 0);
                    let new = libfuzzer_sys::fuzzer_mutate(&mut bytes, len, len + 16);
                    bytes.truncate(new);
                    *s = String::from_utf8_lossy(&bytes).into_owned();
                }
            }
            Value::Object(o) => {
                let value = scalar(rng);
                o.insert(rng.word().to_owned(), value);
            }
            Value::Array(a) => a.push(scalar(rng)),
            other => *other = scalar(rng),
        },
    }
}

/// Whether `CHARD_FUZZ_BYTES_ONLY` is set, read once: the byte-only arm of an A/B run of
/// this mutator against libFuzzer's own, from the same seeds for the same time. Read by the
/// fuzz harness only; chard reads no configuration from the environment.
fn bytes_only() -> bool {
    static ONCE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ONCE.get_or_init(|| std::env::var_os("CHARD_FUZZ_BYTES_ONLY").is_some())
}

/// libFuzzer's mutator entry: `data[..size]` is the input, `max_size` the room there is.
/// `extra` is the target's own words, offered beside [`WORDS`] as replacement values and
/// keys; a target with none passes `&[]` and draws from [`WORDS`] alone.
#[expect(
    clippy::indexing_slicing,
    reason = "libfuzzer-sys 0.4's fuzz_mutator! hands a buffer of max(size, max_size) bytes, and an edit is written back only where it fits in max_size"
)]
pub fn mutate(
    data: &mut [u8],
    size: usize,
    max_size: usize,
    seed: u32,
    extra: &'static [&'static str],
) -> usize {
    if bytes_only() {
        return libfuzzer_sys::fuzzer_mutate(data, size, max_size);
    }
    let mut rng = Rng::new(seed, extra);
    let parsed = serde_json::from_slice::<Value>(&data[..size]).ok();
    let Some(mut doc) = parsed.filter(|_| rng.below(5) != 0) else {
        return libfuzzer_sys::fuzzer_mutate(data, size, max_size);
    };
    let nodes = count(&doc);
    let graft = nth(&doc, &mut rng.below(nodes));
    edit(descend(&mut doc, &mut rng), graft, &mut rng);
    match serde_json::to_vec(&doc) {
        Ok(out) if out.len() <= max_size => {
            data[..out.len()].copy_from_slice(&out);
            out.len()
        }
        _ => libfuzzer_sys::fuzzer_mutate(data, size, max_size),
    }
}
