// SPDX-License-Identifier: BSD-3-Clause

//! Regression tests for ELF facts, pinned against a real compiler.

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

use std::path::{Path, PathBuf};
use std::process::Command;

mod common;

use chard::elf;

const PROBE_SOURCE: &str = "int chard_test_probe(void) { return 0; }\n\
                            int main(void) { return chard_test_probe(); }\n";

const LIBRARY_SOURCE: &str = "int chard_test_probe(void) { return 0; }\n";

/// Locate a C compiler, failing the test if there is none.
fn cc() -> Option<PathBuf> {
    for name in ["cc", "gcc", "clang"] {
        if let Ok(path) = chard::toolchain::resolve_driver(name) {
            return Some(path);
        }
    }
    // `refuse` fails the test unless the operator allowed skips.
    common::refuse(
        "no C compiler found on PATH",
        "the ELF note readings these tests hold, each of which guards against a wrong \
         hardening verdict",
    );
    None
}

/// Build `source` with `flags`, returning the extracted facts, or `None` when the
/// toolchain refused: a compiler that cannot honor a flag is a capability gap ([`refused`]
/// records it), not a failure, because these tests are about chard's reading of the output.
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
            "{} linked {} with {flags:?}, and chard could not read the result: {e}",
            driver.display(),
            out.display(),
        ),
    }
}

/// Does this host's `cc` emit the object format every test here reads?
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

/// An arm whose build `build_and_read` refused under FLAGS: a capability gap where DRIVER
/// builds SOURCE with no flags, and a failure where it builds nothing.
fn refused(driver: &Path, source: &Path, out: &Path, arm: &str, flags: &[&str]) {
    assert!(
        build_and_read(driver, source, out, &[]).is_some(),
        "{} builds nothing from {} with {flags:?} or with no flags",
        driver.display(),
        source.display()
    );
    common::capability_gap(arm, &format!("the toolchain refused {}", flags.join(" ")));
}

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
    // `.strtab` spells it `__stack_chk_fail@GLIBC_2.4`.
    if protected.sections.iter().any(|s| s == ".symtab") {
        let canary = protected
            .watched_symbols
            .get("__stack_chk_fail")
            .or_else(|| protected.watched_symbols.get("__stack_chk_fail_local"))
            .expect("asserted present above");
        assert!(
            canary.tables.iter().any(|t| t == ".symtab"),
            "an unstripped binary's canary is not in .symtab: tables {:?}, versioned {:?}",
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

    let plain = ws.path("relro-plain");
    let flags = ["-Wl,-z,relro", "-Wl,-z,now"];
    if let Some(full) = build_and_read(&driver, &source, &ws.path("relro-full"), &flags) {
        assert_eq!(full.relro.as_deref(), Some("full"));
        assert_eq!((full.gnu_relro, full.bind_now), (Some(true), Some(true)));
    } else {
        refused(&driver, &source, &plain, "full RELRO arm", &flags);
    }

    let flags = ["-Wl,-z,relro", "-Wl,-z,lazy"];
    if let Some(partial) = build_and_read(&driver, &source, &ws.path("relro-partial"), &flags) {
        assert_eq!(
            partial.relro.as_deref(),
            Some("partial"),
            "relro without BIND_NOW is partial"
        );
        assert_eq!(
            (partial.gnu_relro, partial.bind_now),
            (Some(true), Some(false))
        );
    } else {
        refused(&driver, &source, &plain, "partial RELRO arm", &flags);
    }

    let flags = ["-Wl,-z,norelro"];
    if let Some(none) = build_and_read(&driver, &source, &ws.path("relro-none"), &flags) {
        assert_eq!(none.relro.as_deref(), Some("none"));
    } else {
        refused(&driver, &source, &plain, "no-RELRO arm", &flags);
    }
}

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

    let plain = ws.path("stack-plain");
    let flags = ["-Wl,-z,execstack"];
    if let Some(exec) = build_and_read(&driver, &source, &ws.path("stack-x"), &flags) {
        assert_eq!(exec.gnu_stack_present, Some(true));
        assert_eq!(
            exec.gnu_stack_executable,
            Some(true),
            "-z execstack must show PF_X on PT_GNU_STACK"
        );
    } else {
        refused(&driver, &source, &plain, "executable-stack arm", &flags);
    }

    let flags = ["-Wl,-z,noexecstack"];
    if let Some(noexec) = build_and_read(&driver, &source, &ws.path("stack-nx"), &flags) {
        assert_eq!(noexec.gnu_stack_present, Some(true));
        assert_eq!(noexec.gnu_stack_executable, Some(false));
    } else {
        refused(&driver, &source, &plain, "non-executable-stack arm", &flags);
    }
}

#[test]
fn cet_markings_do_not_survive_a_musl_link() {
    if !emits_elf("that CET markings do not survive a musl link") {
        return;
    }
    let verifies = "that CET markings do not survive a musl link";
    if !is_x86_64() {
        common::capability_gap(
            verifies,
            "CET properties are x86-specific and this host is not x86_64",
        );
        return;
    }
    let Ok(musl) = chard::toolchain::resolve_driver("musl-gcc") else {
        common::capability_gap(
            verifies,
            "musl-gcc is not installed, and this asserts a cross-libc property",
        );
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
        refused(
            &glibc,
            &source,
            &ws.path("cet-glibc-plain"),
            verifies,
            &["-fcf-protection=full"],
        );
        return;
    };
    // The control: on glibc the very same flag does produce the markings, so a
    // failure below is about the libc and not about the flag or the reader.
    assert!(
        with_glibc.x86_ibt && with_glibc.x86_shstk,
        "glibc control must carry the markings"
    );

    // Not a gap: musl-gcc is installed and the glibc build above honoured the flag, so a
    // link that fails here is a broken musl toolchain or a broken test, and either is a
    // failure rather than an arm the host lacks.
    let with_musl = build_and_read(
        &musl,
        &source,
        &ws.path("cet-musl"),
        &["-fcf-protection=full"],
    )
    .unwrap_or_else(|| {
        panic!(
            "{} is installed and could not link the probe under -fcf-protection=full",
            musl.display()
        )
    });
    assert!(
        !with_musl.x86_ibt && !with_musl.x86_shstk,
        "a musl link under -fcf-protection=full kept a CET marking"
    );
}

/// A unit of assembly the driver preprocesses, defining one function, with the marking
/// that keeps the stack non-executable so the link warns of nothing.
const ASSEMBLY_SOURCE: &str = "\t.text\n\t.globl chard_test_asm\nchard_test_asm:\n\
                               \t.section .note.GNU-stack,\"\",%progbits\n";

#[test]
fn the_run_witness_header_puts_the_runs_nonce_in_every_shape_of_build() {
    if !emits_elf("that the run-witness header's note reaches each shape of build") {
        return;
    }
    let Some(driver) = cc() else {
        common::capability_gap("whole test", "no C compiler on PATH");
        return;
    };
    let ws = common::Work::new("elf", "run-witness");
    let witness = chard::compile::RunWitness::derived_in(["elf-notes"], ws.dir())
        .expect("writing the run-witness header");
    let header = ws.path(chard::compile::RUN_WITNESS_HEADER_NAME);
    let header = header.to_str().expect("a UTF-8 path");
    let nonce = witness.nonce_hex().to_owned();
    let main_source = ws.write("main.c", "int main(void) { return 0; }\n");
    let unit = ws.write("probe.c", PROBE_SOURCE);
    let assembly = ws.write("unit.S", ASSEMBLY_SOURCE);

    let strict = ["-Wall", "-Wextra", "-Werror", "-include", header];
    let with = |more: &[&'static str]| -> Vec<&str> {
        strict.iter().copied().chain(more.iter().copied()).collect()
    };
    // A second unit with no `main` of its own, for the program of two units.
    let second = ws.write("second.c", LIBRARY_SOURCE);
    let unit_arg = second.to_str().expect("a UTF-8 path");
    let assembly_arg = assembly.to_str().expect("a UTF-8 path");
    let two_units: Vec<&str> = strict.iter().copied().chain([unit_arg]).collect();
    let with_assembly: Vec<&str> = strict.iter().copied().chain([assembly_arg]).collect();
    let shapes: [(&str, &Path, Vec<&str>); 8] = [
        ("a C object", &unit, with(&["-c"])),
        ("a linked program", &main_source, with(&[])),
        ("a shared object", &unit, with(&["-shared", "-fPIC"])),
        ("a program of two units", &main_source, two_units),
        (
            "a program with an assembly unit",
            &main_source,
            with_assembly,
        ),
        ("an assembly object", &assembly, with(&["-c"])),
        (
            "a program linked under --gc-sections",
            &main_source,
            with(&[
                "-O2",
                "-ffunction-sections",
                "-fdata-sections",
                "-Wl,--gc-sections",
            ]),
        ),
        (
            "a program built under -undef",
            &main_source,
            with(&["-undef"]),
        ),
    ];
    let mut read = 0usize;
    for (index, (shape, source, flags)) in shapes.iter().enumerate() {
        let out = ws.path(&format!("shape-{index}"));
        // A shape that does not build is a failure, never a gap: each is a build the host's
        // compiler makes without the header, so a failure with it is the header's doing,
        // a diagnostic under `-Werror` among them.
        let facts = build_and_read(&driver, source, &out, flags).unwrap_or_else(|| {
            panic!("the host's compiler did not build {shape} with {flags:?} and the header")
        });
        assert_eq!(
            facts.run_witness.as_slice(),
            std::slice::from_ref(&nonce),
            "{shape} does not carry the run's nonce and nothing else"
        );
        assert_eq!(witness.confirm(&facts), Ok(()), "{shape}");
        assert!(
            facts.sections.iter().any(|s| s == elf::RUN_WITNESS_SECTION),
            "{shape}: {:?}",
            facts.sections
        );
        read += 1;
    }
    assert_eq!(read, shapes.len(), "a shape was not read");

    // The same unit without the header carries no witness, so the readings above are the
    // header's and not something the toolchain writes by itself.
    let plain = build_and_read(&driver, &unit, &ws.path("plain.o"), &["-c"])
        .expect("the host's compiler builds an object");
    assert_eq!(plain.run_witness, Vec::<String>::new());
    assert_eq!(
        witness.confirm(&plain),
        Err(chard::compile::WitnessAbsence::Missing)
    );
}

#[test]
fn the_run_witness_header_builds_as_c89_and_in_a_cxx_unit() {
    if !emits_elf("that the run-witness header builds as C89 and as C++") {
        return;
    }
    let Some(driver) = cc() else {
        common::capability_gap("whole test", "no C compiler on PATH");
        return;
    };
    let ws = common::Work::new("elf", "run-witness-languages");
    let witness = chard::compile::RunWitness::derived_in(["elf-notes-languages"], ws.dir())
        .expect("writing the run-witness header");
    let header = ws.path(chard::compile::RUN_WITNESS_HEADER_NAME);
    let header = header.to_str().expect("a UTF-8 path");
    let nonce = witness.nonce_hex().to_owned();
    let unit = ws.write("probe.c", LIBRARY_SOURCE);

    // C89 under `-pedantic-errors`: the header's file-scope `__asm__` is no diagnostic.
    let strict_c89 = [
        "-std=c89",
        "-pedantic-errors",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-include",
        header,
        "-c",
    ];
    let c89 = build_and_read(&driver, &unit, &ws.path("c89.o"), &strict_c89)
        .expect("the header builds as C89 under -pedantic-errors");
    assert_eq!(c89.run_witness.as_slice(), std::slice::from_ref(&nonce));

    // A C++ unit, where the host has a C++ driver beside its C one.
    match chard::compile::cxx_driver_for(&driver) {
        Some(cxx) => {
            let source = ws.write("unit.cpp", "int chard_test_cxx() { return 0; }\n");
            let flags = ["-Wall", "-Wextra", "-Werror", "-include", header, "-c"];
            let object = build_and_read(&cxx, &source, &ws.path("cxx.o"), &flags)
                .expect("the header builds in a C++ unit");
            assert_eq!(object.run_witness.as_slice(), std::slice::from_ref(&nonce));
        }
        None => common::capability_gap(
            "the run-witness header in a C++ unit",
            "no C++ driver beside the host's C driver",
        ),
    }
}
