// SPDX-License-Identifier: BSD-3-Clause

//! The classification `env::read_file` gives real paths, which the marker tests in `env`
//! take as a given: absence from `ENOENT` alone, content from a readable file, and
//! `Unreadable` from everything else, which settles nothing and claims nothing about
//! presence. The two rows that need a refusal need a user the file mode binds; under root
//! they are an arm this binary announces to the ledger rather than passing silently. The
//! classification `env::read_uid_map` gives the maps the kernel writes is held here too: the
//! whole map is identity or it is not, never its first line.
#![cfg(target_os = "linux")]

use std::fs::Permissions;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

use chard::env::{FileRead, UidExtent, UidMap, read_file, read_uid_map};

mod common;

/// Every error but `ENOENT` reads `Unreadable`, whatever it says about the path: a symlink
/// loop, a non-directory in the path, a directory at the path and, as a user the mode binds,
/// a file this user may not read and a parent this user may not search.
#[test]
fn absence_is_enoent_alone_and_content_is_a_readable_file_and_the_rest_is_unreadable() {
    let work = common::Work::new("platform-reads", "read-file");
    let at = |name: &str| work.path(name).to_str().expect("a utf-8 path").to_owned();
    work.write("marker", "systemd-nspawn\n");
    assert_eq!(
        read_file(&at("marker")),
        FileRead::Content("systemd-nspawn\n".to_owned())
    );
    work.write("empty", "");
    assert_eq!(read_file(&at("empty")), FileRead::Content(String::new()));
    assert_eq!(read_file(&at("absent")), FileRead::Absent);
    symlink("nowhere", work.path("dangling")).expect("a symlink");
    assert_eq!(
        read_file(&at("dangling")),
        FileRead::Absent,
        "a symlink to nowhere is absence"
    );
    let unreadable = |name: &str, why: &str| match read_file(&at(name)) {
        FileRead::Unreadable(text) => assert!(text.contains(why), "{name}: {text}"),
        other => panic!("{name} read {other:?}, not Unreadable"),
    };
    symlink("loop", work.path("loop")).expect("a symlink");
    unreadable("loop", "loop");
    unreadable("marker/below", "not a directory");
    std::fs::create_dir(work.path("directory")).expect("a directory");
    unreadable("directory", "is a directory");
    if std::fs::metadata(work.dir()).expect("metadata").uid() == 0 {
        common::capability_gap(
            "read_file refusals",
            "the suite runs as root, which no file mode refuses, so the mode-000 file and \
             mode-000 parent rows were not exercised",
        );
    } else {
        work.write("sealed", "lxc");
        std::fs::set_permissions(work.path("sealed"), Permissions::from_mode(0o000))
            .expect("chmod");
        unreadable("sealed", "permission denied");
        std::fs::create_dir(work.path("vault")).expect("a directory");
        work.write("vault/marker", "lxc");
        std::fs::set_permissions(work.path("vault"), Permissions::from_mode(0o000)).expect("chmod");
        unreadable("vault/marker", "permission denied");
        std::fs::set_permissions(work.path("vault"), Permissions::from_mode(0o700))
            .expect("chmod back, so the scratch can be removed");
    }
}

/// The uid maps `read_uid_map` is held to: each row's text and what it reads.
fn uid_map_rows() -> Vec<(&'static str, &'static str, UidMap)> {
    let mapped = |extents: &[[u32; 3]]| {
        UidMap::Mapped(
            extents
                .iter()
                .map(|&[inside, outside, count]| UidExtent {
                    inside,
                    outside,
                    count,
                })
                .collect(),
        )
    };
    vec![
        ("the identity map", "0 0 4294967295", UidMap::Identity),
        (
            "the identity map as the kernel pads it",
            "         0          0 4294967295\n",
            UidMap::Identity,
        ),
        ("a one-id map", "1000 1000 1", mapped(&[[1000, 1000, 1]])),
        (
            "a one-id map as the kernel pads it",
            "      1000       1000          1\n",
            mapped(&[[1000, 1000, 1]]),
        ),
        ("a bubblewrap cage", "0 1000 1", mapped(&[[0, 1000, 1]])),
        (
            "a multi-extent map whose first extent maps an id to itself",
            "1000 1000 1\n0 524288 1000\n",
            mapped(&[[1000, 1000, 1], [0, 524_288, 1000]]),
        ),
        (
            "rootless podman's two extents",
            "         0       1000          1\n         1     524288      65536\n",
            mapped(&[[0, 1000, 1], [1, 524_288, 65536]]),
        ),
        (
            "the identity map with an extent after it",
            "0 0 4294967295\n0 524288 1\n",
            mapped(&[[0, 0, u32::MAX], [0, 524_288, 1]]),
        ),
        (
            "rootless podman's keep-id",
            "         0          1       1000\n      1000          0          1\n      1001       1001      64536\n",
            mapped(&[[0, 1, 1000], [1000, 0, 1], [1001, 1001, 64536]]),
        ),
        ("no extent written", "", UidMap::Unwritten),
        ("blank lines alone", "\n  \n", UidMap::Unwritten),
        (
            "a line of two fields",
            "0 0",
            UidMap::Malformed("0 0".to_owned()),
        ),
        (
            "a count past u32",
            "0 0 4294967296\n",
            UidMap::Malformed("0 0 4294967296".to_owned()),
        ),
        (
            "a word",
            "garbage\n",
            UidMap::Malformed("garbage".to_owned()),
        ),
        (
            "a sign, which u32's parse would take",
            "+0 +0 4294967295\n",
            UidMap::Malformed("+0 +0 4294967295".to_owned()),
        ),
        (
            "leading zeros, digits all the same",
            "00 0 04294967295\n",
            UidMap::Identity,
        ),
        (
            "a good extent and then a bad line",
            "0 0 1\ngarbage\n",
            UidMap::Malformed("0 0 1, garbage".to_owned()),
        ),
        (
            "a bad line and then a good extent",
            "garbage\n0 0 1\n",
            UidMap::Malformed("garbage, 0 0 1".to_owned()),
        ),
        (
            "eleven digits",
            "0 0 99999999999\n",
            UidMap::Malformed("0 0 99999999999".to_owned()),
        ),
        (
            "four fields",
            "0 0 1 1\n",
            UidMap::Malformed("0 0 1 1".to_owned()),
        ),
        (
            "carriage returns, form feeds and vertical tabs as whitespace",
            "0\x0b1000\x0c1\r\n1 524288 65536\r\n",
            mapped(&[[0, 1000, 1], [1, 524_288, 65536]]),
        ),
    ]
}

/// Only the whole map `0 0 4294967295`, as the kernel pads it or whitespace normalised, is
/// identity. A one-id map (`unshare -U --map-user=1000`) maps one id to itself and is a
/// user namespace, as is a map of several extents whose first maps an id to itself, and
/// one with no extent written; a line that is not three numbers of ASCII digits within
/// `u32` is malformed. This host's own map is read last, and is identity where the suite
/// runs outside a user namespace.
#[test]
fn only_the_whole_identity_map_is_identity() {
    let rows = uid_map_rows();
    for (name, text, reads) in &rows {
        assert_eq!(&read_uid_map(text), reads, "{name}: {text:?}");
    }
    assert_eq!(rows.len(), 21, "every map is a row");
    let own = std::fs::read_to_string("/proc/self/uid_map").expect("/proc/self/uid_map");
    match read_uid_map(&own) {
        UidMap::Identity => {}
        UidMap::Unwritten | UidMap::Mapped(_) | UidMap::Malformed(_) => common::capability_gap(
            "the identity uid map",
            "the suite runs in a user namespace, so this host's own map was not read as identity",
        ),
    }
}
