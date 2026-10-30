// SPDX-License-Identifier: BSD-3-Clause

//! Regression tests for ELF facts, pinned against a real compiler.
//!
//! Every test here exists because chard got the answer wrong once, in the same
//! way each time: it reported a hardening feature as absent when the feature was
//! present. That failure mode is silent and indistinguishable from a genuine
//! "this distro does not enable it", which makes it the one class of bug this
//! project cannot ship. Unit tests over synthetic buffers would not have caught
//! any of the three, each needed a real toolchain's output.
//!
//! ## Skips must be loud
//!
//! These tests need a real compiler, and a test that quietly returns when one is
//! missing lets `ok. 6 passed` mean "nothing was checked": the testing analogue of
//! the false `off` the whole project exists to prevent. So a missing toolchain is a
//! FAILURE by default. Set `CHARD_ALLOW_TEST_SKIP=1` to downgrade it to a skip for
//! the genuinely-unable case (a cross-build host, a sandbox with no compiler); the
//! variable's presence is then the record that coverage was reduced.
//!
//! Skips for a *capability* the toolchain lacks (an unsupported flag) remain
//! permitted and are announced on stderr, because those are properties of the
//! compiler rather than of the environment.
//!
//! ## The host that emits no ELF
//!
//! `build_and_read` models two outcomes: the toolchain refused the flag (a skip), or the
//! link succeeded and chard's reader failed (a panic, because that is the regression this
//! file exists to catch). A host whose `cc` emits Mach-O is neither. It links fine and the
//! reader is right to refuse, since there is no ELF there, so it would arrive as the panic,
//! blaming the reader for the host.
//!
//! That is [`emits_elf`], checked per test rather than over the file. A `#![cfg]` on the
//! module is wrong for the same reason `std::process::exit(0)` is wrong in `common`: it makes
//! the binary report `ok. 0 passed`, a green line over
//! nothing, which is the failure mode the section above calls out by name. Announcing
//! seven times that seven tests did not apply is noisier, and true.

use std::path::{Path, PathBuf};
use std::process::Command;

mod common;

use chard::elf;

const PROBE_SOURCE: &str = "int chard_test_probe(void) { return 0; }\n\
                            int main(void) { return chard_test_probe(); }\n";

const LIBRARY_SOURCE: &str = "int chard_test_probe(void) { return 0; }\n";

/// Locate a C compiler, failing the test if there is none.
///
/// Returns `None` only when the operator has explicitly allowed skips, so the
/// default outcome of "no compiler on this machine" is red rather than green.
fn cc() -> Option<PathBuf> {
    for name in ["cc", "gcc", "clang"] {
        if let Ok(path) = chard::toolchain::resolve_driver(name) {
            return Some(path);
        }
    }
    assert!(
        std::env::var_os("CHARD_ALLOW_TEST_SKIP").is_some(),
        "no C compiler found on PATH, so this test verified nothing. These tests each \
         exist because chard once published a wrong hardening verdict, and a green \
         suite that checked nothing is exactly the failure mode they guard against. \
         Install a compiler, or set CHARD_ALLOW_TEST_SKIP=1 to accept reduced coverage \
         deliberately."
    );
    common::capability_gap(
        "whole test",
        "no C compiler, and CHARD_ALLOW_TEST_SKIP is set",
    );
    None
}

/// Build `source` with `flags`, returning the extracted facts, or `None` when the
/// toolchain refused: a compiler that cannot honor a flag is a skip, not a
/// failure, because these tests are about chard's reading of the output.
///
/// What is *not* a skip: the link succeeding and `elf::facts_for` then failing. Returned as
/// `None` through `.ok()`, a regression in chard's own ELF reader, the exact subject of every
/// test in this file, would arrive as "the toolchain lacks a capability" and the test would
/// return green. Two outcomes with opposite meanings would share one channel, so the reader
/// failure panics with the parse error.
fn build_and_read(
    driver: &Path,
    source: &Path,
    out: &Path,
    flags: &[&str],
) -> Option<elf::ElfFacts> {
    let status = Command::new(driver)
        .args(flags)
        .arg("-o")
        .arg(out)
        .arg(source)
        .status()
        .ok()?;
    if !status.success() {
        return None;
    }
    match elf::facts_for(out) {
        Ok(facts) => Some(facts),
        Err(e) => panic!(
            "{} linked {} with {flags:?}, and chard could not read the result: {e}.\n\
             This is a failure of the reader these tests exist to pin, not a toolchain \
             that lacks a capability.",
            driver.display(),
            out.display(),
        ),
    }
}

/// Does this host's `cc` emit the object format every test here reads?
///
/// Separate from [`cc`], which answers "is there a compiler". Both must hold, and they
/// fail differently: no compiler is an environment the operator can fix, where a Mach-O
/// host is one where the question does not arise. The tests stay compiled either way, so a
/// change that breaks them is still caught by `cargo test` on a Mac.
fn emits_elf(verifies: &str) -> bool {
    if common::ELF_HOST {
        return true;
    }
    common::capability_gap(
        verifies,
        "this host's cc emits Mach-O, so there is no ELF for the reader to be right about",
    );
    false
}

fn is_x86_64() -> bool {
    std::env::consts::ARCH == "x86_64"
}

/// The off-by-four in GNU note padding.
///
/// `readelf -n` reports "x86 feature: IBT, SHSTK" for any `-fcf-protection=full`
/// build, but chard reported neither, because it padded `namesz` up to the note
/// alignment independently instead of aligning the absolute descriptor offset.
/// Both control arms then read the same, so the bug looked like "CET is off here".
#[test]
fn cet_markings_are_read_from_the_gnu_property_note() {
    if !emits_elf("that CET markings are read from the GNU property note") {
        return;
    }
    if !is_x86_64() {
        common::capability_gap(
            "cet note reading",
            "CET properties are x86-specific and this host is not x86_64",
        );
        return;
    }
    let Some(driver) = cc() else {
        common::capability_gap("whole test", "no C compiler on PATH");
        return;
    };
    let ws = common::Work::new("elf", "cet");
    let source = ws.write("probe.c", PROBE_SOURCE);

    let Some(enabled) = build_and_read(
        &driver,
        &source,
        &ws.path("cet-full"),
        &["-fcf-protection=full"],
    ) else {
        common::capability_gap(
            "positive arm",
            "toolchain does not support -fcf-protection=full",
        );
        return;
    };
    assert!(
        enabled.x86_ibt,
        "IBT must be seen with -fcf-protection=full; properties were {:?}",
        enabled.gnu_property_types
    );
    assert!(
        enabled.x86_shstk,
        "SHSTK must be seen with -fcf-protection=full; properties were {:?}",
        enabled.gnu_property_types
    );

    // The negative arm matters as much as the positive one: a detector stuck on
    // "present" would pass the assertions above and still be useless.
    let Some(disabled) = build_and_read(
        &driver,
        &source,
        &ws.path("cet-none"),
        &["-fcf-protection=none"],
    ) else {
        common::capability_gap("negative arm", "-fcf-protection=none unsupported");
        return;
    };
    assert!(
        !disabled.x86_ibt,
        "IBT must be absent with -fcf-protection=none"
    );
    assert!(
        !disabled.x86_shstk,
        "SHSTK must be absent with -fcf-protection=none"
    );
}

/// `DF_1_NOOPEN` is `0x40`. chard had `0x4`, which is `DF_1_GROUP`.
///
/// Also pins the discovery that made the wrong constant hard to notice: the flag
/// only takes effect on a shared object. On an executable the linker accepts it,
/// emits `DT_FLAGS_1`, and leaves the bit clear, so measuring it on an
/// executable yields "off" whatever the constant says.
#[test]
fn nodlopen_sets_df_1_noopen_on_a_shared_object() {
    if !emits_elf("that -z nodlopen sets DF_1_NOOPEN on a shared object") {
        return;
    }
    let Some(driver) = cc() else {
        common::capability_gap("whole test", "no C compiler on PATH");
        return;
    };
    let ws = common::Work::new("elf", "nodlopen");
    let source = ws.write("lib.c", LIBRARY_SOURCE);

    let Some(marked) = build_and_read(
        &driver,
        &source,
        &ws.path("libmarked.so"),
        &["-shared", "-fPIC", "-Wl,-z,nodlopen"],
    ) else {
        common::capability_gap(
            "positive arm",
            "cannot link a shared object with -z nodlopen",
        );
        return;
    };
    assert!(
        marked.df_1_noopen,
        "DF_1_NOOPEN (0x40) must be set; DT_FLAGS_1 was {:?}",
        marked
            .dynamic_tags
            .iter()
            .filter(|t| t.starts_with("0x6ffffffb"))
            .collect::<Vec<_>>()
    );

    let Some(plain) = build_and_read(
        &driver,
        &source,
        &ws.path("libplain.so"),
        &["-shared", "-fPIC"],
    ) else {
        common::capability_gap("negative arm", "the toolchain refused the build");
        return;
    };
    assert!(
        !plain.df_1_noopen,
        "DF_1_NOOPEN must be clear without -z nodlopen"
    );
}

/// A shared library is not a static PIE.
///
/// `static_pie` was defined as "`ET_DYN` with no interpreter", which every `.so`
/// satisfies. Any probe that linked a library would have had its `pie` column
/// corrupted.
#[test]
fn a_shared_library_is_classified_as_a_shared_object() {
    if !emits_elf("that a shared library is classified as a shared object") {
        return;
    }
    let Some(driver) = cc() else {
        common::capability_gap("whole test", "no C compiler on PATH");
        return;
    };
    let ws = common::Work::new("elf", "soclass");
    let source = ws.write("lib.c", LIBRARY_SOURCE);
    let Some(facts) = build_and_read(
        &driver,
        &source,
        &ws.path("libclass.so"),
        &["-shared", "-fPIC"],
    ) else {
        common::capability_gap("whole test", "cannot link a shared object");
        return;
    };

    assert_eq!(facts.elf_type, "ET_DYN");
    assert_eq!(
        facts.shared_object,
        Some(true),
        "a .so must be recognized as a shared object"
    );
    assert_eq!(
        facts.static_pie,
        Some(false),
        "a .so must not be reported as a static PIE"
    );
    assert_eq!(
        facts.pie,
        Some(false),
        "a .so is not a position-independent *executable*"
    );
    assert_eq!(facts.statically_linked, Some(false));
}

/// The stack-protector observable, both arms. Guards against a probe whose
/// canary the optimizer removes, which would read as "no stack protector".
#[test]
fn stack_protector_reference_appears_and_disappears_with_the_flag() {
    if !emits_elf("that the stack-protector reference tracks the flag") {
        return;
    }
    let Some(driver) = cc() else {
        common::capability_gap("whole test", "no C compiler on PATH");
        return;
    };
    let ws = common::Work::new("elf", "ssp");
    // A local array whose address escapes: instrumented at every protector level.
    let source = ws.write(
        "canary.c",
        "#include <string.h>\n\
         static void sink(const char *p) { volatile char c = *p; (void)c; }\n\
         int main(int argc, char **argv) {\n\
         char buf[64];\n\
         memset(buf, 0, sizeof buf);\n\
         if (argc > 1) strncpy(buf, argv[1], sizeof buf - 1);\n\
         sink(buf);\n\
         return 0;\n\
         }\n",
    );

    let Some(protected) = build_and_read(
        &driver,
        &source,
        &ws.path("ssp-on"),
        &["-O2", "-fstack-protector-all"],
    ) else {
        common::capability_gap("positive arm", "-fstack-protector-all unsupported");
        return;
    };
    assert!(
        protected.watched_symbols.contains_key("__stack_chk_fail")
            || protected
                .watched_symbols
                .contains_key("__stack_chk_fail_local"),
        "a canary reference must appear under -fstack-protector-all; saw {:?}",
        protected.watched_symbols.keys().collect::<Vec<_>>()
    );
    // An unstripped link carries the reference in `.symtab` as well as `.dynsym`, and
    // `.strtab` spells it `__stack_chk_fail@GLIBC_2.4`. Keyed on the raw spelling, the
    // `.symtab` entry never matched and every fortified binary reported the canary in
    // `.dynsym` alone. The section list says whether there is a `.symtab` to find it in.
    if protected.sections.iter().any(|s| s == ".symtab") {
        let canary = protected
            .watched_symbols
            .get("__stack_chk_fail")
            .or_else(|| protected.watched_symbols.get("__stack_chk_fail_local"))
            .expect("asserted present above");
        assert!(
            canary.tables.iter().any(|t| t == ".symtab"),
            "an unstripped binary must show the canary in .symtab, whatever version \
             suffix .strtab appended; tables were {:?}, versioned spellings {:?}",
            canary.tables,
            canary.versioned
        );
    }

    let Some(unprotected) = build_and_read(
        &driver,
        &source,
        &ws.path("ssp-off"),
        &["-O2", "-fno-stack-protector"],
    ) else {
        common::capability_gap("negative arm", "the toolchain refused the build");
        return;
    };
    assert!(
        !unprotected.watched_symbols.contains_key("__stack_chk_fail")
            && !unprotected
                .watched_symbols
                .contains_key("__stack_chk_fail_local"),
        "no canary reference may remain under -fno-stack-protector"
    );
}

/// RELRO has three states and chard must not collapse them: `-z relro` alone leaves the
/// PLT's GOT writable where the linker places its function slots outside `PT_GNU_RELRO`
/// (GNU ld, gold, lld and mold on Linux, this test's host), which is materially weaker than
/// `-z relro -z now`.
#[test]
fn relro_distinguishes_partial_from_full() {
    if !emits_elf("that RELRO is read as partial or full") {
        return;
    }
    let Some(driver) = cc() else {
        common::capability_gap("whole test", "no C compiler on PATH");
        return;
    };
    let ws = common::Work::new("elf", "relro");
    let source = ws.write("probe.c", PROBE_SOURCE);

    if let Some(full) = build_and_read(
        &driver,
        &source,
        &ws.path("relro-full"),
        &["-Wl,-z,relro", "-Wl,-z,now"],
    ) {
        assert_eq!(full.relro.as_deref(), Some("full"));
        assert_eq!((full.gnu_relro, full.bind_now), (Some(true), Some(true)));
    }

    if let Some(partial) = build_and_read(
        &driver,
        &source,
        &ws.path("relro-partial"),
        &["-Wl,-z,relro", "-Wl,-z,lazy"],
    ) {
        assert_eq!(
            partial.relro.as_deref(),
            Some("partial"),
            "relro without BIND_NOW is partial"
        );
        assert_eq!(
            (partial.gnu_relro, partial.bind_now),
            (Some(true), Some(false))
        );
    }

    if let Some(none) = build_and_read(
        &driver,
        &source,
        &ws.path("relro-none"),
        &["-Wl,-z,norelro"],
    ) {
        assert_eq!(none.relro.as_deref(), Some("none"));
    }
}

/// An executable stack and an absent `PT_GNU_STACK` are different states, and the
/// second one is not evidence of a non-executable stack.
#[test]
fn executable_stack_is_visible_in_the_program_header() {
    if !emits_elf("that an executable stack is visible in the program header") {
        return;
    }
    let Some(driver) = cc() else {
        common::capability_gap("whole test", "no C compiler on PATH");
        return;
    };
    let ws = common::Work::new("elf", "execstack");
    let source = ws.write("probe.c", PROBE_SOURCE);

    if let Some(exec) = build_and_read(&driver, &source, &ws.path("stack-x"), &["-Wl,-z,execstack"])
    {
        assert_eq!(exec.gnu_stack_present, Some(true));
        assert_eq!(
            exec.gnu_stack_executable,
            Some(true),
            "-z execstack must show PF_X on PT_GNU_STACK"
        );
    }

    if let Some(noexec) = build_and_read(
        &driver,
        &source,
        &ws.path("stack-nx"),
        &["-Wl,-z,noexecstack"],
    ) {
        assert_eq!(noexec.gnu_stack_present, Some(true));
        assert_eq!(noexec.gnu_stack_executable, Some(false));
    }
}

/// musl's CRT objects carry no CET property, so the linker's AND-reduction clears
/// IBT/SHSTK for every musl binary, even though `-fcf-protection=full` is accepted
/// and sets `__CET__=3`.
///
/// This is the clearest demonstration available that a requested flag and a marked
/// artifact are different claims, and it is why chard's macro-channel verdict for
/// `-fcf-protection` must never be read as evidence about the binary. The linker
/// itself will say so, but only if asked with `-Wl,-z,cet-report`, which no
/// distribution enables.
#[test]
fn cet_markings_do_not_survive_a_musl_link() {
    if !emits_elf("that CET markings do not survive a musl link") {
        return;
    }
    let Ok(musl) = chard::toolchain::resolve_driver("musl-gcc") else {
        eprintln!("SKIP: musl-gcc not installed; this asserts a cross-libc property");
        return;
    };
    let Some(glibc) = cc() else { return };
    let ws = common::Work::new("elf", "musl-cet");
    let source = ws.write("probe.c", PROBE_SOURCE);

    let Some(with_glibc) = build_and_read(
        &glibc,
        &source,
        &ws.path("cet-glibc"),
        &["-fcf-protection=full"],
    ) else {
        eprintln!("SKIP: toolchain cannot honour -fcf-protection=full");
        return;
    };
    // The control: on glibc the very same flag does produce the markings, so a
    // failure below is about the libc and not about the flag or the reader.
    assert!(
        with_glibc.x86_ibt && with_glibc.x86_shstk,
        "glibc control must carry the markings"
    );

    let Some(with_musl) = build_and_read(
        &musl,
        &source,
        &ws.path("cet-musl"),
        &["-fcf-protection=full"],
    ) else {
        eprintln!("SKIP: musl-gcc could not link the probe");
        return;
    };
    assert!(
        !with_musl.x86_ibt && !with_musl.x86_shstk,
        "musl's unmarked CRT objects must AND the CET property away; if this now \
         passes, Fedora has rebuilt musl with -fcf-protection and the finding is \
         obsolete rather than wrong"
    );
}
