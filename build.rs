// SPDX-License-Identifier: BSD-3-Clause

//! Embed the VCS revision at build time.
//!
//! It has to be build-time rather than runtime: the guest binary runs inside a VM that
//! has no repository, and asking git there would silently yield nothing on exactly the
//! runs whose provenance matters most.
//!
//! A report identifies its dataset by the pair (`probe_corpus_sha256`,
//! `harness_revision`). The corpus hash covers the declared corpus (probe sources,
//! control flags, gates) and the decoders: it folds in `run.decoders_sha256`, a
//! fingerprint over the macro and elf-static predicates and the source of
//! `src/predicate/`, `src/decode/` and `src/elf.rs` (`probe::decoders_sha256`), so a
//! decoder change moves it. The revision covers the rest of the code that interprets the
//! corpus, which the hash cannot reach: which code decoder a check names, the control
//! triple, the gating. A change there moves verdicts without moving the corpus hash, so
//! without this field half the identity would be missing.
//!
//! Four sources, asked in this order, and the first that answers wins: `CHARD_REVISION`;
//! git, where the manifest directory is a repository's top; [`revision::ARCHIVE_FILE`],
//! which `git archive` fills in; and [`CARGO_VCS_INFO`], which `cargo package` writes. A
//! tree none of them answers for builds as `(revision unknown)`. Which one answered is
//! published beside the revision (`CHARD_REVISION_SOURCE`, `run.harness_revision_source`),
//! since an asserted revision is the builder's word and the other three are read from the
//! tree: a modified tree built with `CHARD_REVISION` set to a clean hash publishes that hash
//! with no `-dirty`, and the source is what says so.
//!
//! The rustflags cargo passed (`CARGO_ENCODED_RUSTFLAGS`, which carries `RUSTFLAGS`,
//! `CARGO_BUILD_RUSTFLAGS` and a config file's `build.rustflags` and `target.*.rustflags`,
//! whichever cargo took) are digested into `CHARD_RUSTFLAGS_SHA256`, published as
//! `run.harness_rustflags_sha256` and in `--version`, since `RUSTFLAGS=-C overflow-checks=on`
//! gave another binary with the same `--version` (measured, the 2026-10-18 audit). The digest,
//! not the flags: a flag can carry a path (`--remap-path-prefix`), and a report names no
//! builder's directory. Not marked: a rustc wrapper (`RUSTC_WRAPPER`, `build.rustc-wrapper`),
//! a profile setting (`CARGO_PROFILE_*`, `[profile]` in a config file) and `cargo rustc`'s
//! trailing arguments, none of which this script marks; the assumption
//! `revision-and-rustflags-name-the-build` (`report::ASSUMPTIONS`) names them.

#[path = "build/revision.rs"]
mod revision;

// The crate's own SHA-256, so the rustflags digest is the one `sha256sum` gives and the build
// script stays without dependencies. Only `sha256_hex` is called here.
#[path = "src/digest.rs"]
#[expect(dead_code, reason = "the build script calls sha256_hex alone")]
mod digest;

use std::path::Path;
use std::process::Command;

/// The file `cargo package` writes into a crate archive made from a git checkout.
const CARGO_VCS_INFO: &str = ".cargo_vcs_info.json";

fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    for path in git_state_paths(&manifest) {
        println!("cargo:rerun-if-changed={path}");
    }
    println!("cargo:rerun-if-env-changed=CHARD_REVISION");
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");

    // `option_env!` reads these where this script emits none, so a value in the build's own
    // environment would reach the binary as though this script had stamped it: a rustflags
    // digest on a build with none, or a source beside no revision. Refused, not overridden.
    for stamped in ["CHARD_REVISION_SOURCE", "CHARD_RUSTFLAGS_SHA256"] {
        println!("cargo:rerun-if-env-changed={stamped}");
        assert!(
            std::env::var_os(stamped).is_none(),
            "{stamped} is set in the build's environment; build.rs alone stamps it, so it is refused"
        );
    }

    // Watching only `.git` is not enough, and fails in the direction that matters:
    // editing a source file without committing leaves the *clean* revision embedded,
    // so a binary that corresponds to no commit claims that it does. Cargo descends
    // into directories, so the paths below cover everything the `-dirty` suffix is meant
    // to detect, and the two revision files beside them.
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=probes");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build");
    println!("cargo:rerun-if-changed={}", revision::ARCHIVE_FILE);

    // Every git call is anchored to the manifest directory. Without `-C`, the answer
    // depends on the caller's working directory, which is not ours to assume.
    // Watched only where it exists: cargo reruns a build script on every build while a path
    // it watches is missing, and this one is missing everywhere but in a crate archive. That
    // spares a clone the rerun; a tree with no `.git` reruns anyway, since `.git/HEAD` above
    // is missing there.
    if Path::new(&manifest).join(CARGO_VCS_INFO).is_file() {
        println!("cargo:rerun-if-changed={CARGO_VCS_INFO}");
    }

    // Empty rustflags are none: cargo sets the variable for every build script. The bytes are
    // digested as they are, so flags that are not UTF-8 are marked too, not read as none.
    let rustflags = std::env::var_os("CARGO_ENCODED_RUSTFLAGS")
        .filter(|flags| !flags.is_empty())
        .map(|flags| digest::sha256_hex(flags.as_encoded_bytes()));
    if let Some(digest) = &rustflags {
        println!("cargo:rustc-env=CHARD_RUSTFLAGS_SHA256={digest}");
    }

    let found = asserted().or_else(|| {
        let (found, source) = from_git(&manifest)
            .map(|r| (r, revision::Source::Git))
            .or_else(|| from_archive_file(&manifest).map(|r| (r, revision::Source::Archive)))
            .or_else(|| from_cargo_vcs_info(&manifest).map(|r| (r, revision::Source::CargoVcs)))?;
        let revision::Revision { short, dirty } = found;
        let suffix = if dirty { "-dirty" } else { "" };
        Some((format!("{short}{suffix}"), source))
    });
    // No source names a commit: the field is absent, which is honest.
    if let Some((revision, source)) = &found {
        println!("cargo:rustc-env=CHARD_REVISION={revision}");
        println!("cargo:rustc-env=CHARD_REVISION_SOURCE={}", source.as_str());
    }
    // `--version` carries the revision too. Without it the only way to ask a built
    // binary which code it contains is to run a measurement and read the report, so a
    // sweep driver wanting to name the binary it is about to use would reach for the
    // repository's HEAD instead, which is a different thing whenever the binary was
    // built before a later commit.
    let words = revision::version_words(
        found.as_ref().map(|(r, s)| (r.as_str(), *s)),
        rustflags.as_deref(),
    );
    println!(
        "cargo:rustc-env=CHARD_VERSION={} ({words})",
        env!("CARGO_PKG_VERSION")
    );
}

/// `CHARD_REVISION`, which wins over the tree's own sources so a release built from an
/// exported tree can still state its provenance, and is published as `asserted` for that
/// reason. A value [`revision::asserted_env`] refuses fails the build.
fn asserted() -> Option<(String, revision::Source)> {
    let value = std::env::var_os("CHARD_REVISION");
    match revision::asserted_env(value.as_deref()) {
        Ok(label) => label.map(|label| (label.to_owned(), revision::Source::Asserted)),
        Err(why) => panic!("CHARD_REVISION is refused: {why}"),
    }
}

/// HEAD of the repository whose top is the manifest directory, `dirty` where tracked files
/// differ from it.
fn from_git(manifest: &str) -> Option<revision::Revision> {
    let git = |args: &[&str]| {
        Command::new("git")
            .args(["-C", manifest])
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
    };

    // git discovery ascends, so a chard tree unpacked inside *someone else's*
    // repository (vendored into a monorepo, or extracted under `third_party/`)
    // would otherwise answer with that repository's HEAD. The field is half of a
    // report's dataset identity, so a revision belonging to unrelated source is worse
    // than no revision: it is wrong in the direction that looks right. Only trust the
    // answer when the repository root is this crate; elsewhere the files below answer.
    let toplevel = git(&["rev-parse", "--show-toplevel"])?;
    let same_repo = std::fs::canonicalize(toplevel.trim())
        .ok()
        .zip(std::fs::canonicalize(manifest).ok())
        .is_some_and(|(top, here)| top == here);
    if !same_repo {
        return None;
    }

    let rev = git(&["rev-parse", "--short=12", "HEAD"])?;
    let rev = rev.trim();
    if rev.is_empty() {
        return None;
    }

    // A dirty tree means the binary does not correspond to any committed revision, and
    // a bare hash would claim it does. Saying so is the whole point of the field.
    // A status git could not give names no clean tree, so it reads as dirty: `git` is a tree
    // source, which joins as the commit itself.
    let dirty =
        git(&["status", "--porcelain", "--untracked-files=no"]).is_none_or(|o| !o.is_empty());
    Some(revision::Revision {
        short: rev.to_owned(),
        dirty,
    })
}

/// The commit `git archive` wrote into [`revision::ARCHIVE_FILE`]. The unfilled placeholder
/// names none; a file holding anything else is refused with a warning and names none.
fn from_archive_file(manifest: &str) -> Option<revision::Revision> {
    let text = std::fs::read_to_string(Path::new(manifest).join(revision::ARCHIVE_FILE)).ok()?;
    revision::from_archive_file(&text).unwrap_or_else(|why| {
        println!(
            "cargo:warning={} is not read as a revision: {why}",
            revision::ARCHIVE_FILE
        );
        None
    })
}

/// The commit `cargo package` wrote into [`CARGO_VCS_INFO`], refused with a warning where the
/// file does not name one as cargo writes it.
fn from_cargo_vcs_info(manifest: &str) -> Option<revision::Revision> {
    let text = std::fs::read_to_string(Path::new(manifest).join(CARGO_VCS_INFO)).ok()?;
    revision::from_cargo_vcs_info(&text)
        .map_err(|why| println!("cargo:warning={CARGO_VCS_INFO} is not read as a revision: {why}"))
        .ok()
}

/// The files git changes when HEAD, the branch it names or the index moves, for cargo to watch.
///
/// `.git/HEAD` and `.git/index` are right in a plain checkout and missing in a linked
/// worktree, whose `.git` is a file naming its git directory elsewhere: cargo finds the paths
/// missing and reruns this script, and rebuilds the crate, on every cargo invocation in every
/// worktree. git names the real files (`rev-parse --git-path`, relative to the
/// manifest directory or absolute, as cargo reads a watched path). Where git does not
/// answer, or answers for a repository whose top is not this crate (see [`from_git`]), the
/// literal paths are watched, and a tree with no `.git` reruns on every build.
///
/// Beside HEAD and the index, the file holding the branch HEAD names and `packed-refs`, each
/// only where it exists (a watched path that is missing reruns every build): a commit that
/// leaves the index alone (`--allow-empty`) or a ref moved by hand changes only those, and
/// the embedded revision would otherwise stay the old one.
/// Not watched: a branch held only in `packed-refs` gains a loose ref file when it moves, and that
/// file was not there to watch at the last build; so after `git pack-refs`, a commit that
/// leaves the index alone keeps the old revision until the next build that reruns this. Watching
/// all of `refs/heads` instead would rebuild every worktree whenever any branch moved.
fn git_state_paths(manifest: &str) -> Vec<String> {
    let ask = |what: &str| -> Option<String> {
        let out = Command::new("git")
            .args([
                "-C",
                manifest,
                "rev-parse",
                "--show-toplevel",
                "--git-path",
                what,
            ])
            .output()
            .ok()
            .filter(|o| o.status.success())?;
        let text = String::from_utf8(out.stdout).ok()?;
        let mut lines = text.lines();
        let (top, path) = (lines.next()?, lines.next()?);
        let ours = std::fs::canonicalize(top)
            .ok()
            .zip(std::fs::canonicalize(manifest).ok())
            .is_some_and(|(top, here)| top == here);
        (ours && !path.is_empty()).then(|| path.to_owned())
    };
    let mut paths = vec![
        ask("HEAD").unwrap_or_else(|| ".git/HEAD".to_owned()),
        ask("index").unwrap_or_else(|| ".git/index".to_owned()),
    ];
    let branch = Command::new("git")
        .args(["-C", manifest, "symbolic-ref", "-q", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok());
    for what in branch.iter().map(|b| b.trim()).chain(["packed-refs"]) {
        if let Some(path) = ask(what).filter(|p| Path::new(manifest).join(p).is_file()) {
            paths.push(path);
        }
    }
    paths
}
