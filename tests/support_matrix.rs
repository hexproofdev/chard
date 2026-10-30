// SPDX-License-Identifier: BSD-3-Clause
//! `SUPPORT.md`'s matrix is held to what the tree holds: the compiler versions each platform
//! row says are held are the oldest and newest of that platform in the fixture corpus, both
//! ways (a platform in the corpus has a row, a row's "none" has no fixture); every assumption
//! register entry a row cites exists; the tier words are the three it defines; no table cell
//! names a distribution or a verdict; a tier agrees with what is held; each row cites exactly
//! the register entries pinned for it here, the ones that identify the platform's
//! architecture, libc and kernel or decide what its kernel executes; libc++ is held where the
//! table says; `README.md` and `DESIGN.md` point to the table and carry no platform
//! sentences of their own; and the README's platform table is this table's
//! first two columns.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// A platform row's key in the fixture corpus: the system, the architecture label and the
/// libc token a fixture's toolchain id carries.
type Key = (&'static str, &'static str, &'static str);

/// The register entries that identify a platform's architecture, libc and kernel or decide
/// what its kernel executes: the arch gate's macro reading, which every platform's readings
/// pass through; a Linux kernel's spelling naming its byte order (`elf_data` gives the
/// comparison its fact), and an x86_64 one running i386; musl identified by its own macros; the
/// machine read as chard's own where `/proc` is absent, and the environment unobserved behind
/// `sysctl`, on the BSDs and macOS; OpenBSD's `PT_OPENBSD_NOBTCFI`, which decides what its kernel
/// enforces, on both of its architectures; macOS's `sysctl.proc_translated` read of 0 taken as a
/// native run. Left out on purpose: `profile-dump-names-the-selected-target`, which is about a
/// profile selecting a target other than the host's, not a platform a row stands for; the
/// register's other entries are one check's reading or a machine's capability.
const ARCH_GATE: &str = "arch-macros-name-the-target";
const BYTE_ORDER: &str = "kernel-spelling-names-its-byte-order";
const MUSL: &str = "need-macros-identify-musl";
const I386: &str = "x86-64-kernel-runs-i386-itself";
const NO_PROC: &str = "kernel-machine-is-chards-without-proc";
const UNOBSERVED: &str = "openbsd-environment-unobserved";
const NOBTCFI: &str = "nobtcfi-switches-off-ibt-on-amd64";
const TRANSLATED: &str = "proc-translated-zero-is-native";

/// The platform cell of each row, the fixture key it stands for, and the register entries
/// the row cites, exactly.
const PLATFORMS: &[(&str, Key, &[&str])] = &[
    (
        "Linux x86_64, glibc",
        ("linux", "x86_64", "glibc"),
        &[ARCH_GATE, BYTE_ORDER],
    ),
    (
        "Linux x86_64, musl",
        ("linux", "x86_64", "musl"),
        &[ARCH_GATE, BYTE_ORDER, MUSL],
    ),
    (
        "Linux i386, glibc",
        ("linux", "i386", "glibc"),
        &[ARCH_GATE, BYTE_ORDER, I386],
    ),
    (
        "Linux aarch64, glibc",
        ("linux", "aarch64", "glibc"),
        &[ARCH_GATE, BYTE_ORDER],
    ),
    (
        "Linux aarch64, musl",
        ("linux", "aarch64", "musl"),
        &[ARCH_GATE, BYTE_ORDER, MUSL],
    ),
    (
        "Linux arm, glibc",
        ("linux", "arm", "glibc"),
        &[ARCH_GATE, BYTE_ORDER],
    ),
    (
        "FreeBSD amd64",
        ("freebsd", "x86_64", "freebsd"),
        &[ARCH_GATE, NO_PROC, UNOBSERVED],
    ),
    (
        "OpenBSD amd64",
        ("openbsd", "x86_64", "openbsd"),
        &[ARCH_GATE, NO_PROC, UNOBSERVED, NOBTCFI],
    ),
    (
        "OpenBSD arm64",
        ("openbsd", "aarch64", "openbsd"),
        &[ARCH_GATE, NO_PROC, UNOBSERVED, NOBTCFI],
    ),
    (
        "macOS arm64",
        ("macos", "aarch64", "apple"),
        &[ARCH_GATE, NO_PROC, UNOBSERVED, TRANSLATED],
    ),
];

/// The platform libc++ builds are held on: the fixture rows whose artifact needs `libc++` or
/// whose macros name it as the standard library.
const LIBCXX_HELD: &[Key] = &[("linux", "x86_64", "musl")];

const TIERS: &[&str] = &["supported", "measured", "builds"];

/// Names a row must not carry, matched without regard to case: the table states tool
/// support, not where a measurement was taken (`DESIGN.md` and the ledger carry those
/// with their frames).
const DISTRIBUTIONS: &[&str] = &[
    "fedora",
    "ubuntu",
    "debian",
    "alpine",
    "arch linux",
    "gentoo",
    "wolfi",
    "chimera",
    "opensuse",
    "tumbleweed",
    "almalinux",
    "rocky",
    "centos",
    "red hat",
    "rhel",
    "nixos",
    "void linux",
    "slackware",
    "amazon linux",
    "oracle linux",
    "mageia",
    "manjaro",
    "linux mint",
    "clear linux",
    "openeuler",
];

/// Verdict words a table cell must not carry as a word of its own (`on` is a preposition
/// too, so it is held only in backticks).
const VERDICTS: &[&str] = &[
    "off",
    "partial",
    "unsupported",
    "not-applicable",
    "indeterminate",
    "probe-invalid",
    "build-failed",
    "run-failed",
];

/// The sentences the table replaced, which neither document may carry again.
const REPLACED: &[(&str, &str)] = &[
    (
        "README.md",
        "x86_64 is supported, and aarch64 is measured too",
    ),
    ("DESIGN.md", "is the only supported target"),
];

struct Row {
    platform: String,
    tier: String,
    gcc: String,
    clang: String,
    rests_on: Vec<String>,
}

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// The matrix's rows, from the one table whose header starts with `| Platform |`.
fn rows() -> Vec<Row> {
    let text = std::fs::read_to_string(root().join("SUPPORT.md")).expect("SUPPORT.md");
    let mut lines = text.lines().skip_while(|l| !l.starts_with("| Platform |"));
    let header = lines.next().expect("the matrix header");
    assert_eq!(
        header, "| Platform | Tier | gcc held | clang held | Rests on | Notes |",
        "the matrix columns moved; this test reads them by position"
    );
    lines.next().expect("the separator");
    lines
        .take_while(|l| l.starts_with('|'))
        .map(|line| {
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            assert_eq!(
                cells.len(),
                8,
                "a row with the wrong number of cells: {line}"
            );
            let rests_on = cells[5]
                .split(',')
                .map(|c| c.trim().trim_matches('`').to_owned())
                .filter(|c| !c.is_empty())
                .collect();
            Row {
                platform: cells[1].to_owned(),
                tier: cells[2].to_owned(),
                gcc: cells[3].to_owned(),
                clang: cells[4].to_owned(),
                rests_on,
            }
        })
        .collect()
}

/// A version as a comparable tuple of its numeric components, each written as the number
/// writes itself (no leading zero, so `16.2.01` is not a version).
fn version(v: &str) -> Vec<u64> {
    v.split('.')
        .map(|part| {
            let n: u64 = part
                .parse()
                .unwrap_or_else(|_| panic!("not a version component: {v}"));
            assert_eq!(
                n.to_string(),
                part,
                "a version component not written as itself: {v}"
            );
            n
        })
        .collect()
}

/// Whether `text` carries `word` as a word of its own, not inside another.
fn has_word(text: &str, word: &str) -> bool {
    text.match_indices(word).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at.saturating_add(word.len())..].chars().next();
        let boundary = |c: Option<char>| c.is_none_or(|c| !(c.is_alphanumeric() || c == '-'));
        boundary(before) && boundary(after)
    })
}

/// The fixture corpus's rows as JSON values, synthetic rows left out.
fn fixtures() -> Vec<serde_json::Value> {
    let text = std::fs::read_to_string(root().join("tests/fixtures/detectors.json"))
        .expect("the fixture corpus");
    let fixtures: serde_json::Value = serde_json::from_str(&text).expect("JSON");
    let rows = fixtures.as_array().expect("an array of fixtures");
    assert!(rows.len() > 1000, "the fixture corpus is not being read");
    rows.iter()
        .filter(|row| {
            !row["toolchain"]
                .as_str()
                .expect("a toolchain id")
                .starts_with("synthetic:")
        })
        .cloned()
        .collect()
}

/// A fixture's platform key and compiler family, from its toolchain id
/// (`gcc-12.2.0-glibc2.36-debian12`; the BSDs carry `openbsd` or `unknown` as the libc token
/// and `FreeBSD` names itself in the tail) and its architecture label.
fn fixture_key(row: &serde_json::Value) -> (Key, &'static str, String) {
    let id = row["toolchain"].as_str().expect("a toolchain id");
    let arch = row["arch"].as_str().expect("an arch");
    let mut parts = id.splitn(4, '-');
    let family = parts.next().unwrap_or("");
    let ver = parts.next().unwrap_or("");
    let libc_and_version = parts.next().unwrap_or("");
    let tail = parts.next().unwrap_or("");
    let libc: String = libc_and_version
        .chars()
        .take_while(char::is_ascii_alphabetic)
        .collect();
    let system = if tail.starts_with("freebsd") {
        "freebsd"
    } else if libc == "openbsd" {
        "openbsd"
    } else if libc == "apple" {
        "macos"
    } else {
        "linux"
    };
    // One FreeBSD row, `pie`'s bare build under clang 19.1.7, was recorded without its libc
    // identified and carries `unknown` as its libc token. The
    // system names the libc there: FreeBSD ships one, inseparable from the release.
    let libc = if system == "freebsd" {
        "freebsd".to_owned()
    } else {
        libc
    };
    let family: &'static str = match family {
        "gcc" => "gcc",
        "clang" => "clang",
        other => panic!("a fixture of a compiler family the matrix does not know: {other}"),
    };
    let key = PLATFORMS
        .iter()
        .map(|(_, k, _)| *k)
        .find(|(s, a, l)| *s == system && *a == arch && *l == libc)
        .unwrap_or_else(|| {
            panic!("a fixture from a platform the matrix has no row for: {id} on {arch}")
        });
    (key, family, ver.to_owned())
}

/// A "held" cell: `none`, one version, or `oldest to newest`.
fn held(cell: &str) -> Option<(String, String)> {
    if cell == "none" {
        return None;
    }
    let mut parts = cell.split(" to ");
    let oldest = parts.next().expect("a version").to_owned();
    let newest = parts.next().map_or_else(|| oldest.clone(), str::to_owned);
    assert!(
        parts.next().is_none(),
        "a held cell with more than two versions: {cell}"
    );
    assert!(
        version(&oldest) <= version(&newest),
        "a held cell whose oldest is newer than its newest: {cell}"
    );
    Some((oldest, newest))
}

/// The fixture corpus's versions by (platform key, compiler family).
fn fixture_versions() -> BTreeMap<(Key, &'static str), BTreeSet<Vec<u64>>> {
    let mut out: BTreeMap<(Key, &'static str), BTreeSet<Vec<u64>>> = BTreeMap::new();
    let mut fed = 0_usize;
    for row in fixtures() {
        let (key, family, ver) = fixture_key(&row);
        out.entry((key, family)).or_default().insert(version(&ver));
        fed = fed.saturating_add(1);
    }
    assert!(fed > 1000, "the fixtures were not fed: {fed}");
    out
}

/// Each row's held versions are the fixture corpus's oldest and newest for that platform and
/// family, and a `none` has no fixture; every fixture platform is a row.
#[test]
fn the_held_versions_are_the_fixture_corpus_bounds() {
    let versions = fixture_versions();
    let rows = rows();
    assert_eq!(
        rows.iter().map(|r| r.platform.as_str()).collect::<Vec<_>>(),
        PLATFORMS.iter().map(|(p, _, _)| *p).collect::<Vec<_>>(),
        "the matrix rows are not the platforms this test keys"
    );
    let mut fed = 0_usize;
    for row in &rows {
        let key = PLATFORMS
            .iter()
            .find(|(p, _, _)| *p == row.platform)
            .map(|(_, k, _)| *k)
            .expect("a keyed platform");
        for (family, cell) in [("gcc", &row.gcc), ("clang", &row.clang)] {
            let corpus = versions.get(&(key, family));
            match (held(cell), corpus) {
                (None, None) => {}
                (None, Some(held)) => panic!(
                    "{} says no {family} is held, and the fixture corpus holds {held:?}",
                    row.platform
                ),
                (Some((oldest, newest)), None) => panic!(
                    "{} says {family} {oldest} to {newest} is held, and the fixture corpus \
                     holds none",
                    row.platform
                ),
                (Some((oldest, newest)), Some(held)) => {
                    let first = held.iter().next().expect("a version");
                    let last = held.iter().next_back().expect("a version");
                    assert_eq!(
                        (&version(&oldest), &version(&newest)),
                        (first, last),
                        "{} {family}: the matrix says {oldest} to {newest}, the fixture corpus \
                         holds {held:?}",
                        row.platform
                    );
                }
            }
            fed = fed.saturating_add(1);
        }
    }
    assert_eq!(
        fed,
        PLATFORMS.len().saturating_mul(2),
        "every cell was compared"
    );
    for ((key, family), held) in &versions {
        assert!(
            PLATFORMS.iter().any(|(_, k, _)| k == key),
            "the fixture corpus holds {family} {held:?} on {key:?}, which has no row"
        );
    }
}

/// A tier agrees with what is held: `builds` holds nothing, `measured` holds something, and
/// `supported` holds both families.
#[test]
fn the_tiers_agree_with_what_is_held() {
    let mut supported = 0_usize;
    for row in rows() {
        let gcc = held(&row.gcc).is_some();
        let clang = held(&row.clang).is_some();
        match row.tier.as_str() {
            "builds" => assert!(
                !gcc && !clang,
                "{} builds and holds a compiler, which is measured",
                row.platform
            ),
            "measured" => assert!(
                gcc || clang,
                "{} is measured and holds no compiler",
                row.platform
            ),
            "supported" => {
                assert!(
                    gcc && clang,
                    "{} is supported and holds one family only",
                    row.platform
                );
                supported = supported.saturating_add(1);
            }
            other => panic!(
                "{} carries a tier outside the defined words: {other}",
                row.platform
            ),
        }
    }
    assert!(supported > 0, "no platform is supported");
}

/// libc++ is held on the platforms the table says and no other: a fixture whose artifact
/// needs `libc++` or whose macros name it as the standard library is on one of them, and each
/// of them has one.
#[test]
fn libcxx_is_held_where_the_table_says() {
    let mut held: BTreeSet<Key> = BTreeSet::new();
    for row in fixtures() {
        let needs = row["elf"]["needed"]
            .as_array()
            .is_some_and(|n| n.iter().any(|lib| lib.as_str() == Some("libc++.so.1")));
        let names = row["macros"]["_CXX_STDLIB"].as_str() == Some("libc++");
        if needs || names {
            held.insert(fixture_key(&row).0);
        }
    }
    assert_eq!(
        held.iter().copied().collect::<Vec<_>>(),
        LIBCXX_HELD,
        "the platforms with libc++ fixtures are not the ones the table names"
    );
    let text = std::fs::read_to_string(root().join("SUPPORT.md")).expect("SUPPORT.md");
    let bullet = text
        .lines()
        .find(|l| l.contains("libc++ is held"))
        .expect("the libc++ bullet");
    assert!(
        bullet.contains("Linux x86_64 with musl and nowhere else"),
        "the libc++ bullet does not say where it is held: {bullet}"
    );
}

/// Each row cites exactly the register entries pinned for it, each of which exists and is
/// cited once; every tier is one of the defined words; and no cell names a distribution or a
/// verdict.
#[test]
fn the_rows_cite_the_register_and_name_no_distribution_or_verdict() {
    let register: BTreeSet<&str> = chard::report::ASSUMPTIONS.iter().map(|a| a.id).collect();
    let text = std::fs::read_to_string(root().join("SUPPORT.md")).expect("SUPPORT.md");
    let rows = rows();
    assert!(!rows.is_empty());
    for row in &rows {
        assert!(
            TIERS.contains(&row.tier.as_str()),
            "{} carries a tier outside the defined words: {}",
            row.platform,
            row.tier
        );
        assert!(
            !row.rests_on.is_empty(),
            "{} rests on nothing",
            row.platform
        );
        let (_, _, required) = PLATFORMS
            .iter()
            .find(|(p, _, _)| *p == row.platform)
            .expect("a keyed platform");
        let distinct: BTreeSet<&str> = row.rests_on.iter().map(String::as_str).collect();
        assert_eq!(
            distinct.len(),
            row.rests_on.len(),
            "{} cites an entry twice",
            row.platform
        );
        for id in *required {
            assert!(
                register.contains(id),
                "the entry pinned for {} does not exist: {id}",
                row.platform
            );
        }
        assert_eq!(
            distinct,
            required.iter().copied().collect::<BTreeSet<&str>>(),
            "{} does not cite exactly the entries pinned for it",
            row.platform
        );
    }
    for line in text.lines().filter(|l| l.starts_with('|')) {
        let lower = line.to_lowercase();
        for name in DISTRIBUTIONS {
            assert!(
                !has_word(&lower, name),
                "a table cell names a distribution: {line}"
            );
        }
        for verdict in VERDICTS {
            assert!(
                !has_word(&lower, verdict),
                "a table cell carries a verdict: {line}"
            );
        }
        assert!(
            !line.contains("`on`"),
            "a table cell carries a verdict: {line}"
        );
    }
}
/// The README's quickstart lists each platform with its tier. It is this table's first two
/// columns, row for row, so a tier moved here moves there or this fails.
#[test]
fn the_readme_lists_the_platforms_and_tiers_of_the_table() {
    let text = std::fs::read_to_string(root().join("README.md")).expect("README.md");
    let mut lines = text.lines().skip_while(|l| *l != "| Platform | Tier |");
    assert!(
        lines.next().is_some(),
        "README.md has no table headed | Platform | Tier |"
    );
    lines.next().expect("the separator");
    let readme: Vec<(String, String)> = lines
        .take_while(|l| l.starts_with('|'))
        .map(|line| {
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            assert_eq!(
                cells.len(),
                4,
                "a README row with the wrong number of cells: {line}"
            );
            (cells[1].to_owned(), cells[2].to_owned())
        })
        .collect();
    let matrix: Vec<(String, String)> = rows().into_iter().map(|r| (r.platform, r.tier)).collect();
    assert!(!matrix.is_empty(), "the matrix has no rows");
    assert_eq!(
        readme, matrix,
        "README.md's platform table is not SUPPORT.md's platform and tier columns"
    );
}

/// `README.md` and `DESIGN.md` point to the table, and neither carries the platform
/// sentence the table replaced.
#[test]
fn the_documents_point_here_and_carry_no_replaced_sentence() {
    for (doc, replaced) in REPLACED {
        let text = std::fs::read_to_string(root().join(doc)).expect(doc);
        assert!(
            text.contains("SUPPORT.md"),
            "{doc} does not point to SUPPORT.md"
        );
        assert!(
            !text.contains(replaced),
            "{doc} still carries the sentence the matrix replaced: {replaced}"
        );
    }
}
