// SPDX-License-Identifier: BSD-3-Clause
//! `env::Attestation::from_json` over arbitrary text: the file `--image-attestation` names,
//! the one input of a measurement a fetcher outside chard writes. Bytes that are not UTF-8
//! are skipped, since `main` reads the file with `read_to_string` and refuses them before
//! the parser sees them.

#![no_main]

use chard::env::{
    Attestation, AttestationRefusal, AttestationStatus, ExecutionMode, ImageAttestation,
};
use chard::report::attestation_inputs;
use libfuzzer_sys::{fuzz_mutator, fuzz_target};
use serde_json::{Map, Value};

#[path = "json_mutator.rs"]
mod json_mutator;

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    json_mutator::mutate(data, size, max_size, seed, ATTESTATION_WORDS)
});

/// The attestation's keys and the digest kinds it knows, offered by the mutator beside its
/// own words, which every JSON target shares.
const ATTESTATION_WORDS: &[&str] = &[
    "digest",
    "digest_kind",
    "digest_matched",
    "manifest_fetched",
    "origin",
    "signer",
    "caveat",
    "installed_disk",
    "installed_at",
    "installed_from_digest",
    "sha256",
    "md5",
    "sha1",
    "sha384",
    "sha512",
    "blake2b",
    "not-recorded",
];

/// `RawAttestation`'s keys.
const KEYS: &[&str] = &[
    "verdict",
    "url",
    "served_by",
    "origin",
    "manifest_url",
    "digest_kind",
    "digest",
    "digest_matched",
    "manifest_fetched",
    "signature",
    "signer",
    "caveat",
    "installed_disk",
];

/// `RawInstalledDisk`'s keys.
const DISK_KEYS: &[&str] = &["sha256", "installed_at", "installed_from_digest"];

/// The digest lengths the parser's table holds, restated so a change to one is seen here.
const LENGTHS: &[(&str, usize)] = &[
    ("md5", 32),
    ("sha1", 40),
    ("sha256", 64),
    ("sha384", 96),
    ("sha512", 128),
    ("blake2b", 128),
];

fn lower_hex(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Hinnant's `days_from_civil`).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The civil date of a day count (Hinnant's `civil_from_days`).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// Whether `text` is `YYYY-MM-DDTHH:MM:SSZ` naming a real instant: the date survives a trip
/// through a day count unchanged, and the time is within a day with no leap second.
fn is_instant(text: &str) -> bool {
    let Ok(bytes) = <&[u8; 20]>::try_from(text.as_bytes()) else {
        return false;
    };
    if bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' {
        return false;
    }
    if bytes[13] != b':' || bytes[16] != b':' || bytes[19] != b'Z' {
        return false;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let digits = bytes.get(r)?;
        digits.iter().all(u8::is_ascii_digit).then(|| {
            digits
                .iter()
                .fold(0i64, |n, d| n * 10 + i64::from(d - b'0'))
        })
    };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        num(0..4),
        num(5..7),
        num(8..10),
        num(11..13),
        num(14..16),
        num(17..19),
    ) else {
        return false;
    };
    (1..=12).contains(&month)
        && (1..=31).contains(&day)
        && civil_from_days(days_from_civil(year, month, day)) == (year, month, day)
        && hour < 24
        && minute < 60
        && second < 60
}

/// What the parser documents doing to one input key's value.
fn expected(key: &str, value: &Value) -> Value {
    match (key, value) {
        ("digest", Value::String(s)) => Value::String(s.to_ascii_lowercase()),
        ("installed_disk", Value::Object(disk)) => {
            let mut out = Map::new();
            for (k, v) in disk {
                let v = match (k.as_str(), v) {
                    ("sha256" | "installed_from_digest", Value::String(s)) => {
                        Value::String(s.to_ascii_lowercase())
                    }
                    _ => v.clone(),
                };
                out.insert(k.clone(), v);
            }
            Value::Object(out)
        }
        _ => value.clone(),
    }
}

/// The `image_attestation.*` lines spelled from the parsed value, as `InputIdentity`
/// writes them; every value here is hex, digits or a status word, so none needs escaping.
fn spelled(status: AttestationStatus, a: &Attestation) -> String {
    let disk = a.installed_disk().map_or_else(String::new, |disk| {
        format!(
            "image_attestation.installed_disk.sha256={}\n\
             image_attestation.installed_disk.installed_at={}\n\
             image_attestation.installed_disk.installed_from_digest={}\n",
            disk.sha256(),
            disk.installed_at(),
            disk.installed_from_digest()
        )
    });
    format!(
        "image_attestation.status={}\nimage_attestation.digest={}\n{disk}",
        status.as_str(),
        a.digest()
    )
}

#[expect(
    clippy::expect_used,
    reason = "a fuzz target reports a broken law by panicking; libFuzzer keeps the input as the crash"
)]
fn record(a: &Attestation) -> Value {
    serde_json::to_value(a).expect("an attestation serializes")
}

/// `classify` for a mode that carries an image: refused exactly on a mismatch with a fetched
/// manifest, `unattested` when no manifest was fetched, otherwise `attested`. A refusal is
/// stood in for by an `attested` record so the publication oracles below still run over it.
#[expect(
    clippy::panic,
    reason = "a fuzz target reports a broken law by panicking; libFuzzer keeps the input as the crash"
)]
fn imaged(
    mode: ExecutionMode,
    a: &Attestation,
    refused: bool,
    manifest_fetched: bool,
) -> ImageAttestation {
    match ImageAttestation::classify(mode, Some(a.clone())) {
        Err(AttestationRefusal::DigestMismatch(m)) => {
            assert!(refused, "{mode:?} refused a value that is no mismatch");
            assert_eq!(
                record(&m),
                record(a),
                "the refusal carries another attestation"
            );
            ImageAttestation {
                status: AttestationStatus::Attested,
                established_by: "fuzz",
                attestation: Some(a.clone()),
            }
        }
        Err(AttestationRefusal::NoImageToAttest) => panic!("{mode:?} has an image to attest"),
        Ok(image) => {
            assert!(!refused, "{mode:?} did not refuse a mismatch");
            let want = if manifest_fetched {
                AttestationStatus::Attested
            } else {
                AttestationStatus::Unattested
            };
            assert_eq!(
                image.status, want,
                "{mode:?} classified as {:?}",
                image.status
            );
            image
        }
    }
}

fuzz_target!(|data: &[u8]| {
    #![expect(
        clippy::expect_used,
        clippy::panic,
        reason = "a fuzz target reports a broken law by panicking; libFuzzer keeps the input as the crash"
    )]
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let parsed = Attestation::from_json(text);
    match (&parsed, Attestation::from_json(text)) {
        (Ok(a), Ok(b)) => assert_eq!(record(a), record(&b), "a second parse differs"),
        (Err(a), Err(b)) => assert_eq!(*a, b, "a second refusal differs"),
        _ => panic!("a second parse disagrees on acceptance"),
    }
    let Ok(a) = parsed else {
        return;
    };

    // The shape: an object of known keys, its disk an object of known keys.
    let input: Value = serde_json::from_str(text).expect("accepted text is JSON");
    let Some(input) = input.as_object() else {
        panic!("accepted {} where an object is published", kind(&input));
    };
    for key in input.keys() {
        assert!(
            KEYS.contains(&key.as_str()),
            "accepted the unknown key {key:?}"
        );
    }
    match input.get("installed_disk") {
        None | Some(Value::Null) => {}
        Some(Value::Object(disk)) => {
            for key in disk.keys() {
                assert!(
                    DISK_KEYS.contains(&key.as_str()),
                    "accepted the unknown installed_disk key {key:?}"
                );
            }
        }
        Some(other) => panic!("accepted an installed_disk that is {}", kind(other)),
    }

    // Nothing dropped or rewritten beyond what is documented.
    let out = record(&a);
    let out = out
        .as_object()
        .expect("an attestation serializes as an object");
    for (key, value) in input {
        if value.is_null() {
            assert!(
                matches!(key.as_str(), "signer" | "caveat" | "installed_disk"),
                "accepted null for {key:?}"
            );
            assert!(!out.contains_key(key), "a null {key:?} came out present");
        } else {
            assert_eq!(
                out.get(key),
                Some(&expected(key, value)),
                "{key:?} came out other than it went in"
            );
        }
    }
    for key in out.keys() {
        assert!(
            KEYS.contains(&key.as_str()),
            "wrote the unknown key {key:?}"
        );
    }
    if !input.contains_key("origin") {
        assert_eq!(out["origin"], "not-recorded", "an absent origin");
    }
    if !input.contains_key("manifest_fetched") {
        assert_eq!(out["manifest_fetched"], true, "an absent manifest_fetched");
    }

    // The refinements.
    let kind_lower = a.digest_kind().to_ascii_lowercase();
    let length = LENGTHS
        .iter()
        .find(|(name, _)| *name == kind_lower)
        .map_or_else(
            || panic!("accepted digest_kind {:?}", a.digest_kind()),
            |(_, n)| *n,
        );
    assert_eq!(a.digest().len(), length, "a digest of the wrong length");
    assert!(lower_hex(a.digest()), "a digest that is not lowercase hex");
    if let Some(disk) = a.installed_disk() {
        assert_eq!(
            disk.installed_from_digest(),
            a.digest(),
            "a disk from another artifact"
        );
        assert_eq!(
            disk.sha256().len(),
            64,
            "an installed disk sha256 of the wrong length"
        );
        assert!(
            lower_hex(disk.sha256()),
            "an installed disk sha256 that is not lowercase hex"
        );
        assert!(
            is_instant(disk.installed_at()),
            "accepted installed_at {:?}, which is no instant",
            disk.installed_at()
        );
    }

    // Written back, it parses to itself.
    let written = serde_json::to_string(&a).expect("an attestation serializes");
    let again = Attestation::from_json(&written)
        .unwrap_or_else(|e| panic!("its own serialization is refused: {e}"));
    assert_eq!(
        record(&again),
        Value::Object(out.clone()),
        "the round trip differs"
    );
    assert_eq!(
        serde_json::to_string(&again).expect("serializes"),
        written,
        "the round trip writes other text"
    );

    // Classified in each mode, and as a report publishes it.
    let digest_matched = out["digest_matched"] == true;
    let manifest_fetched = out["manifest_fetched"] == true;
    let refused = !digest_matched && manifest_fetched;
    match ImageAttestation::classify(ExecutionMode::Host, Some(a.clone())) {
        Err(AttestationRefusal::DigestMismatch(m)) => {
            assert!(
                refused,
                "a host refused as a mismatch with digest_matched {digest_matched}"
            );
            assert_eq!(
                record(&m),
                Value::Object(out.clone()),
                "the refusal carries another attestation"
            );
        }
        Err(AttestationRefusal::NoImageToAttest) => {
            assert!(!refused, "a mismatch on a host was refused as no image");
        }
        Ok(image) => panic!("a host accepted an attestation as {:?}", image.status),
    }
    let image = imaged(ExecutionMode::Vm, &a, refused, manifest_fetched);
    let container = imaged(ExecutionMode::Container, &a, refused, manifest_fetched);
    assert_eq!(
        serde_json::to_value(&container).expect("serializes"),
        serde_json::to_value(&image).expect("serializes"),
        "a container and a VM classify the same attestation differently"
    );
    let mut published = serde_json::to_value(&image).expect("an image attestation serializes");
    let block = published.as_object_mut().expect("an object");
    assert_eq!(
        block.remove("status"),
        Some(Value::from(image.status.as_str())),
        "the published status"
    );
    assert!(
        block.remove("established_by").is_some(),
        "no established_by"
    );
    let from_report = serde_json::to_string(&published).expect("serializes");
    let reread = Attestation::from_json(&from_report)
        .unwrap_or_else(|e| panic!("the published block is refused: {e}"));
    assert_eq!(
        record(&reread),
        Value::Object(out.clone()),
        "the published block differs"
    );

    // The lines it contributes to `run.inputs_sha256`.
    let lines = attestation_inputs(&image).canonical();
    assert_eq!(lines, spelled(image.status, &a), "inputs lines");
    let twin = ImageAttestation {
        status: image.status,
        established_by: image.established_by,
        attestation: Some(again),
    };
    assert_eq!(
        attestation_inputs(&twin).canonical(),
        lines,
        "the re-parsed value's lines"
    );
});

/// The JSON type of `value` with its article, for the oracle's panic text.
fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "a null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}
