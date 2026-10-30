// SPDX-License-Identifier: BSD-3-Clause
//! The readers of the files chard describes its environment from, over arbitrary contents:
//! `env::read_uid_map` (`/proc/self/uid_map`), the execution-mode observer
//! `env::observe_execution_mode` over a whole `env::PlatformReads` (the runtime marker files,
//! `/run/systemd/container`, PID 1's `container=` word, `/proc/1/cgroup`, `/proc/1/comm` and
//! the uid map), and the kernel-spelling rules behind `/proc/sys/kernel/arch`
//! (`env::kernel_byte_order_as`, `env::runs_natively`). Inside a container these files are
//! the container owner's, so a reading here is one a third party wrote for, and the observer
//! decides `container`, which refuses an asserted `host` or `vm` through the consistency pass.
//!
//! The input is the reads: the bytes decoded as UTF-8 lossily and split at every record
//! separator (U+001E) into, in order, the uid map, `/run/systemd/container`, PID 1's
//! environment, `/proc/1/cgroup`, `/proc/1/comm`, the kernel's machine, the runtime marker
//! (`podman` or `docker` name one, anything else none), `os-release`, `cpuinfo` and the
//! kernel release. A field missing from the end, or one that is U+0018 alone, is a read the
//! platform did not make (`None`); a file read is U+0015 alone for an absent file and U+0006
//! alone for one that refused, with chard's own words for the refusal. Held for every input:
//!
//! - each reader returns without a panic, and returns the same reading twice;
//! - `read_uid_map` reads fields and lines, not spacing: the text and its lines' fields
//!   joined by one space, blank lines dropped, read the same. It reads `Unwritten` exactly
//!   where no line holds a field, and `Malformed` exactly where some line is not three fields
//!   of ASCII digits within `u32` (checked here by a parse of its own), quoting those lines
//!   joined by `, `; `Identity` is the one extent `0 0 4294967295`, and any extents it reads,
//!   written back one to a line, read to themselves;
//! - the observer concludes nothing but `container`, and concludes it exactly when a positive
//!   marker is there: a runtime marker file, a cgroup naming `docker`, `libpod`, `containerd`
//!   or `lxc`, a non-blank `/run/systemd/container`, a non-empty first `container=` word, or a
//!   uid map that reads `Unwritten` or as extents other than the identity. Silence, an
//!   absence, a refusal and a malformed map settle nothing. A barren set of reads is the one
//!   sentence that says so; an engine is a cgroup word the cgroup carries;
//! - the observation is a sentence for a report and a terminal: every character in it prints
//!   as itself (nothing `char::escape_debug` escapes, controls, format and separator
//!   characters among them, is left raw), whatever the files held;
//! - a kernel's spelling decides its byte order whatever chard's own build is
//!   (`kernel_byte_order_as` under either order), chard's own spelling decides chard's build's
//!   order, and `runs_natively` says `true` only for an order it was given that is the
//!   kernel's.
//!
//! The seeds under `seeds/env_reads/` are the shapes `env.rs`'s unit tests and
//! `tests/platform_reads.rs` write, and the maps its documentation quotes, which name no
//! host.

#![no_main]

use chard::elf::ByteOrder;
use chard::env::{
    ExecutionMode, FileRead, NativeMachine, PlatformReads, UidMap, kernel_byte_order,
    kernel_byte_order_as, observe_execution_mode, read_uid_map, runs_natively,
};
use libfuzzer_sys::fuzz_target;

const FIELD: char = '\u{1e}';
const NONE: &str = "\u{18}";
const ABSENT: &str = "\u{15}";
const REFUSED: &str = "\u{6}";
/// The refusal's words, as `env::read_file` spells a permission error: chard's own text.
const REFUSAL: &str = "permission denied, os error 13";
const CGROUP_WORDS: [&str; 4] = ["docker", "libpod", "containerd", "lxc"];
const BARREN: &str = "no instrument on this platform settles the execution mode";
const ARTIFACTS: [&str; 10] = [
    "x86_64",
    "i386",
    "aarch64",
    "arm",
    "riscv",
    "ppc64",
    "ppc",
    "s390",
    "mips",
    "loongarch",
];

fn text_field(field: Option<&str>) -> Option<String> {
    field.filter(|f| *f != NONE).map(str::to_owned)
}

fn file_field(field: Option<&str>) -> Option<FileRead> {
    match field? {
        NONE => None,
        ABSENT => Some(FileRead::Absent),
        REFUSED => Some(FileRead::Unreadable(REFUSAL.to_owned())),
        content => Some(FileRead::Content(content.to_owned())),
    }
}

fn reads_of(fields: &[&str]) -> PlatformReads {
    let at = |i: usize| fields.get(i).copied();
    PlatformReads {
        uid_map: text_field(at(0)),
        systemd_container: file_field(at(1)),
        pid1_environ: file_field(at(2)),
        pid1_cgroup: text_field(at(3)),
        pid1_comm: text_field(at(4)),
        kernel_machine: text_field(at(5)),
        container_marker: match at(6) {
            Some("podman") => Some("podman marker /run/.containerenv"),
            Some("docker") => Some("docker marker /.dockerenv"),
            _ => None,
        },
        os_release: text_field(at(7)),
        cpuinfo: text_field(at(8)),
        kernel_release: text_field(at(9)),
        system_version: None,
    }
}

/// The text's lines as fields joined by one space, blank lines dropped.
fn normalized(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|l| !l.is_empty())
        .collect()
}

/// A uid map field as the kernel writes one: ASCII digits whose value fits `u32`.
fn is_number(field: &str) -> bool {
    if field.is_empty() || !field.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let significant = field.trim_start_matches('0');
    significant.is_empty()
        || (significant.len() <= 10
            && significant
                .parse::<u64>()
                .is_ok_and(|v| v <= u64::from(u32::MAX)))
}

fn check_uid_map(text: &str) -> UidMap {
    let read = read_uid_map(text);
    assert_eq!(read_uid_map(text), read, "a second reading differs");
    let lines = normalized(text);
    assert_eq!(
        read_uid_map(&lines.join("\n")),
        read,
        "the map with its spacing normalized reads otherwise"
    );
    let well_formed = lines.iter().all(|l| {
        let fields: Vec<&str> = l.split(' ').collect();
        fields.len() == 3 && fields.iter().all(|f| is_number(f))
    });
    match &read {
        UidMap::Unwritten => assert!(lines.is_empty(), "{lines:?} read as unwritten"),
        UidMap::Malformed(quoted) => {
            assert!(
                !well_formed,
                "{lines:?} is three numbers to a line and read as malformed"
            );
            assert_eq!(*quoted, lines.join(", "), "the malformed map's quotation");
        }
        UidMap::Identity => {
            assert!(well_formed, "{lines:?} read as the identity");
            assert_eq!(
                lines.len(),
                1,
                "{lines:?}: more than one extent read as the identity"
            );
        }
        UidMap::Mapped(extents) => {
            assert!(
                well_formed && !lines.is_empty(),
                "{lines:?} read as extents"
            );
            assert_eq!(extents.len(), lines.len(), "an extent per line");
            let written: Vec<String> = extents.iter().map(ToString::to_string).collect();
            assert_eq!(
                read_uid_map(&written.join("\n")),
                read,
                "the extents written back read otherwise"
            );
            assert_ne!(
                written,
                ["0 0 4294967295"],
                "the identity read as a mapping"
            );
        }
    }
    read
}

/// Whether some marker the observer counts as positive is there, by the rules its
/// documentation states.
fn positive(reads: &PlatformReads) -> bool {
    let cgroup = reads
        .pid1_cgroup
        .as_deref()
        .is_some_and(|c| CGROUP_WORDS.iter().any(|w| c.contains(w)));
    let systemd =
        matches!(&reads.systemd_container, Some(FileRead::Content(t)) if !t.trim().is_empty());
    let word = match &reads.pid1_environ {
        Some(FileRead::Content(environ)) => environ
            .split('\0')
            .find_map(|e| e.strip_prefix("container="))
            .is_some_and(|v| !v.is_empty()),
        _ => false,
    };
    let userns = reads
        .uid_map
        .as_deref()
        .is_some_and(|m| matches!(read_uid_map(m), UidMap::Unwritten | UidMap::Mapped(_)));
    reads.container_marker.is_some() || cgroup || systemd || word || userns
}

fn barren(reads: &PlatformReads) -> bool {
    reads.os_release.is_none()
        && reads.cpuinfo.is_none()
        && reads.kernel_release.is_none()
        && reads.pid1_comm.is_none()
        && reads.uid_map.is_none()
        && reads.pid1_cgroup.is_none()
        && reads.container_marker.is_none()
        && reads.systemd_container.is_none()
        && reads.pid1_environ.is_none()
}

fn check_observation(reads: &PlatformReads) {
    let read = observe_execution_mode(reads);
    assert_eq!(
        observe_execution_mode(reads),
        read,
        "a second reading differs"
    );
    let (mode, engine, observation) = &read;
    assert!(
        matches!(mode, None | Some(ExecutionMode::Container)),
        "the observer concluded {mode:?}"
    );
    if barren(reads) {
        assert_eq!(
            read,
            (None, None, BARREN.to_owned()),
            "a barren set of reads"
        );
        return;
    }
    assert_eq!(
        mode.is_some(),
        positive(reads),
        "the observer concluded {mode:?} where a positive marker is there: {}; {observation}",
        positive(reads)
    );
    if let Some(engine) = engine {
        assert!(
            CGROUP_WORDS.contains(&engine.as_str()),
            "the engine {engine:?}"
        );
        assert!(
            reads
                .pid1_cgroup
                .as_deref()
                .is_some_and(|c| c.contains(engine.as_str())),
            "the engine {engine:?} is no word of the cgroup"
        );
    }
    // Every character prints as itself: none is one `char::escape_debug` escapes, but the
    // quotes, which print as themselves, and the backslash, which every escape writes. That
    // an escape reads apart from a planted backslash is `quoted`'s unit test.
    assert!(
        observation
            .chars()
            .all(|c| matches!(c, '\\' | '\'' | '"') || c.escape_debug().nth(1).is_none()),
        "the observation holds a character that does not print as itself: {observation:?}"
    );
}

fn check_spelling(spelling: &str) {
    let read = NativeMachine::read(spelling);
    let little = kernel_byte_order_as(read, ByteOrder::LittleEndian);
    assert_eq!(
        kernel_byte_order_as(read, ByteOrder::BigEndian),
        little,
        "the kernel's word {spelling:?} reads by chard's own build"
    );
    assert_eq!(kernel_byte_order(read), little, "{spelling:?}");
    if spelling == "mips" || spelling == "mips64" {
        assert_eq!(little, None, "{spelling:?} names no order");
    }
    for own in [ByteOrder::LittleEndian, ByteOrder::BigEndian] {
        assert_eq!(
            kernel_byte_order_as(NativeMachine::chards_own(spelling), own),
            Some(own),
            "chard's own {spelling:?}"
        );
    }
    let family = chard::toolchain::machine_family(spelling);
    for artifact in ARTIFACTS.iter().copied().chain(family) {
        for class in [32u8, 64] {
            for order in [
                None,
                Some(ByteOrder::LittleEndian),
                Some(ByteOrder::BigEndian),
            ] {
                let runs = runs_natively(read, artifact, class, order);
                assert_eq!(runs_natively(read, artifact, class, order), runs);
                if runs == Some(true) {
                    assert!(
                        order.is_some() && order == little,
                        "{spelling:?} runs a {artifact} {class}-bit {order:?} artifact, \
                         its own order being {little:?}"
                    );
                }
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let fields: Vec<&str> = text.split(FIELD).collect();
    check_uid_map(&text);
    if let Some(map) = fields.first() {
        check_uid_map(map);
    }
    let reads = reads_of(&fields);
    check_observation(&reads);
    let spelling = reads
        .kernel_machine
        .clone()
        .unwrap_or_else(|| text.lines().next().unwrap_or("").to_owned());
    check_spelling(&spelling);
});
