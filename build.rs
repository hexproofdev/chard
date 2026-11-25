// SPDX-License-Identifier: BSD-3-Clause

//! Embed the VCS revision at build time.

#[path = "build/revision.rs"]
mod revision;

// The crate's own SHA-256, so the rustflags digest is the one `sha256sum` gives and the build
// script stays without dependencies.
#[path = "src/digest.rs"]
#[expect(dead_code, reason = "the build script calls sha256_hex alone")]
mod digest;

// The register of the files `run.decoders_sha256` reads, and the strip it reads them by, so
// the binary carries their digest rather than several megabytes of their text.
#[path = "src/fingerprint.rs"]
#[expect(
    dead_code,
    reason = "the build script reads DECODER_SOURCES and the strip alone"
)]
mod fingerprint;

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
    // digest on a build with none, or a source beside no revision.
    for stamped in [
        "CHARD_REVISION_SOURCE",
        "CHARD_RUSTFLAGS_SHA256",
        "CHARD_DECODER_SOURCES_SHA256",
    ] {
        println!("cargo:rerun-if-env-changed={stamped}");
        assert!(
            std::env::var_os(stamped).is_none(),
            "{stamped} is set in the build's environment; build.rs alone stamps it, so it is refused"
        );
    }

    // Watching only `.git` is not enough, and fails in the direction that matters:
    // editing a source file without committing leaves the *clean* revision embedded,
    // so a binary that corresponds to no commit claims that it does.
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=probes");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build");
    println!("cargo:rerun-if-changed={}", revision::ARCHIVE_FILE);

    // Every git call is anchored to the manifest directory.
    if Path::new(&manifest).join(CARGO_VCS_INFO).is_file() {
        println!("cargo:rerun-if-changed={CARGO_VCS_INFO}");
    }

    // Empty rustflags are none: cargo sets the variable for every build script.
    let rustflags = std::env::var_os("CARGO_ENCODED_RUSTFLAGS")
        .filter(|flags| !flags.is_empty())
        .map(|flags| digest::sha256_hex(flags.as_encoded_bytes()));
    if let Some(digest) = &rustflags {
        println!("cargo:rustc-env=CHARD_RUSTFLAGS_SHA256={digest}");
    }

    println!(
        "cargo:rustc-env=CHARD_DECODER_SOURCES_SHA256={}",
        decoder_sources_sha256(&manifest)
    );

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
    // `--version` carries the revision too.
    let words = revision::version_words(
        found.as_ref().map(|(r, s)| (r.as_str(), *s)),
        rustflags.as_deref(),
    );
    println!(
        "cargo:rustc-env=CHARD_VERSION={} ({words})",
        env!("CARGO_PKG_VERSION")
    );
}

/// The digest of [`fingerprint::sources_canonical`] over every file of
/// [`fingerprint::DECODER_SOURCES`] as it is on disk, which `probe::decoder_sources_sha256`
/// publishes and `run.decoders_sha256` folds in. Cargo reruns this script when anything under
/// `src` changes (watched above), so the stamp follows the source. A listed file that cannot
/// be read fails the build: a digest over fewer files than the register names would be a
/// fingerprint blind to the missing one.
#[expect(
    clippy::panic,
    reason = "a build script fails the build by panicking: cargo stops and prints the message, \
              which names the file, and no binary is made with a digest over fewer files"
)]
fn decoder_sources_sha256(manifest: &str) -> String {
    let texts: Vec<(&str, String)> = fingerprint::DECODER_SOURCES
        .iter()
        .map(|path| {
            let text = std::fs::read_to_string(Path::new(manifest).join(path))
                .unwrap_or_else(|why| panic!("reading {path} for the decoder fingerprint: {why}"));
            (*path, text)
        })
        .collect();
    let canonical =
        fingerprint::sources_canonical(texts.iter().map(|(path, text)| (*path, text.as_str())));
    digest::sha256_hex(canonical.as_bytes())
}

/// `CHARD_REVISION`, which wins over the tree's own sources so a release built from an
/// exported tree can still state its provenance, and is published as `asserted` for that
/// reason. A value [`revision::asserted_env`] refuses fails the build.
#[expect(
    clippy::panic,
    reason = "a build script fails the build by panicking: cargo stops and prints the refusal, \
              and no binary is made claiming a revision the check refused"
)]
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
    // would otherwise answer with that repository's HEAD.
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
    // a bare hash would claim it does.
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
