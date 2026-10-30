// SPDX-License-Identifier: BSD-3-Clause

//! The compiler-diag detectors: each reads what the compiler or the linker said while
//! building a probe, from the build's exit status and stderr.

use super::common::{excerpt_around, excerpt_at, needle_line, structured_stream};
use crate::compile::BuildRecord;
use crate::probe::{Detection, Evidence, Outcome};

// --- compiler-diag detectors --------------------------------------------------

pub(crate) fn detect_hardened_warning(ev: &Evidence<'_>) -> Detection {
    // The wording, never the `[-Whardened]` tag — see `diag_presence` for the three
    // measured ways keying on an option name goes wrong, the worst being that a
    // compiler which *rejected* the flag still prints its name while saying so.
    //
    // gcc names whichever option was downgraded, and only one downgrade is the one the
    // positive arm makes: "'-fstack-protector-strong' is not enabled by '-fhardened'
    // because it was specified on the command line", from its `-fno-stack-protector`.
    // A toolchain can make another downgrade in both arms. Ubuntu 26.04's gcc 15.2.0
    // defines `_FORTIFY_SOURCE` itself, so the negative arm prints "'_FORTIFY_SOURCE' is
    // not enabled by '-fhardened' because it was specified in '-D' or '-U'", and a needle
    // matching any downgrade read the check `probe-invalid` in every profile. So the
    // needle names the option, and is spelled with both quote characters gcc uses: U+2019
    // under a UTF-8 locale and an ASCII apostrophe under `LC_ALL=C`.
    //
    // A downgrade of another option is not read, and it is not hidden either: an `absent`
    // beside one names its line, so an `off` over a build that did report a downgrade
    // says which, whatever the excerpt kept.
    //
    // The one compiler-diag probe whose canary is not pinned in its source (its controls pass
    // `-Wall`), so a silent build is read against the flags it carried: see [`Canary`].
    let mut detection = diag_presence_with(ev, HARDENED_DOWNGRADE_NEEDLES, Canary::AskedByFlags);
    let unread = ev.build.and_then(|build| {
        let (index, _) = needle_line(&build.stderr, &["is not enabled by"])?;
        build
            .stderr
            .lines()
            .nth(index)
            .map(|line| ev.published(line.trim()))
    });
    if detection.outcome == Outcome::Absent
        && let Some(line) = unread
    {
        detection.observed = format!(
            "{} (another option's downgrade was reported and is not read: {line:?})",
            detection.observed
        );
    }
    detection
}

/// `-Wl,--no-copy-dt-needed-entries`, read from a link that refused.
///
/// The observable is a build failure, which is why this cannot key on the exit status.
/// A non-zero exit means "something went wrong", and a probe whose recipe is broken, a
/// toolchain missing a library, and the flag doing exactly its job all produce one. So
/// the linker's refusal has to name *this probe's own transitive symbol* — the same discipline
/// `diag_severity_of` applies to reading severity from a diagnostic's own line rather
/// than from stderr as a whole.
///
/// `present` therefore requires two things to agree: the link failed, and the linker
/// refused `chard_dt_bfunc`, which is reachable only through `libchard_dt_a.so`'s
/// `DT_NEEDED`, on a line of its own ([`DT_NEEDED_REFUSALS`]). A link that fails for any
/// other reason is `indeterminate`, never `present` and never `absent` — it is a probe that
/// did not pose its question, not an answer about the flag.
///
/// The symbol's name anywhere in stderr is not the refusal. A compiler quotes the probe's
/// source: gcc's `-fdiagnostics-format=sarif-stderr` carries the whole translation unit in
/// `artifacts[].contents.text`, and a plain-text diagnostic on the call line prints that line
/// under its caret. Beside a link that failed for another reason, the first read `present`
/// with the flag absent (measured: gcc 16.1.1, Fedora 44 x86_64, `-O2
/// -fdiagnostics-format=sarif-stderr` with `--ldflags -lchardnosuchlib`). The
/// second is constructed: it reads the same way, and no plain-text warning tried on that
/// host produced it. The refusal is read from one line, and the linker's words and the
/// symbol must be adjacent, so a quoted comment naming both on one line is not the refusal
/// either; `detect_pic_shared_link` reads its own refusal from one line too, a needle naming
/// the symbol with the linker's phrase after it. The probe's sources
/// carry no refusal, which a test holds.
pub(crate) fn detect_no_copy_dt_needed(ev: &Evidence<'_>) -> Detection {
    let Some(build) = ev.build else {
        return Detection::indeterminate("probe not built".to_owned());
    };
    let observed = build_observed(ev, build, DT_NEEDED_REFUSALS);

    if build.succeeded() {
        // The linker followed A's DT_NEEDED into B and resolved the symbol, which is
        // exactly what the flag exists to forbid.
        return Detection::absent(observed);
    }

    // The symbol only the transitive library defines, in the linker's refusal. Matching on
    // the name rather than on "undefined reference" alone, because a missing libc, a bad
    // -L, or a probe whose scaffolding failed to build all produce undefined references
    // too; and on the refusal rather than the name alone, because a compiler quotes the
    // name from the probe's source.
    if needle_line(&build.stderr, DT_NEEDED_REFUSALS).is_some() {
        return Detection::present(None, observed);
    }

    Detection::indeterminate(format!(
        "{observed} (the link failed and no line of its stderr is a linker refusing \
         chard_dt_bfunc in a wording chard reads, so the failure is not read as this check's \
         refusal and the arm poses no question)"
    ))
}

/// The linker's refusal of `chard_dt_bfunc`, the symbol only `libchard_dt_b.so` defines,
/// in each spelling the corpus records (`tests/fixtures/detectors.json`): GNU ld's
/// `undefined reference to symbol 'chard_dt_bfunc'` (Ubuntu 20.04 to Fedora 44) and lld's
/// `undefined symbol: chard_dt_bfunc` (Chimera Linux, clang 22.1.7). The compiler runs under
/// `LC_ALL=C`, so GNU ld quotes in ASCII, and its needle carries the closing quote. lld's
/// line ends at the name, so its needle is a prefix: the probe and its libraries define no
/// other symbol beginning `chard_dt_bfunc`, which a test holds. lld 23.1.0 (macOS, linking
/// aarch64 objects of these sources, 2026-10-23) words the refusal the same way, and
/// words a library B it cannot find through A the same way too, a recipe failure every arm
/// shares and the triple reads `probe-invalid`. A linker whose refusal is worded otherwise
/// (gold and mold are not in the corpus) reads `indeterminate`, the safe side. Named once so
/// the line the detector matches and the line its excerpt centres on are the same line.
pub(crate) const DT_NEEDED_REFUSALS: &[&str] = &[
    "undefined reference to symbol 'chard_dt_bfunc'",
    "undefined symbol: chard_dt_bfunc",
];

/// The exported global `probes/pic_shared_link.c` defines and reads, which a non-PIC
/// reference makes the linker refuse by name.
const PIC_SHARED_SYMBOL: &str = "chard_pic_anchor";

/// The part of the refusal every linker measured writes on the line naming the symbol, after
/// the symbol: GNU ld, lld, mold and gold, on x86_64 (`R_X86_64_PC32`) and aarch64
/// (`R_AARCH64_ADR_PREL_PG_HI21`) alike, so the relocation's name is not matched.
const PIC_SHARED_REFUSAL: &str = "recompile with -fPIC";

/// The linker naming [`PIC_SHARED_SYMBOL`] as the target of the relocation it refuses, in
/// each spelling measured for `-O2 -fPIE -shared probes/pic_shared_link.c` in a Fedora 44
/// x86_64 image (gcc 16.2.1 and clang 22.1.8, `LC_ALL=C`): GNU ld 2.46.1 and mold 2.40.4
/// write ``against symbol `chard_pic_anchor'``, LLD 22.1.8 `against symbol
/// 'chard_pic_anchor'`, and gold 1.16 `against 'chard_pic_anchor'`. GNU ld on aarch64 words
/// it as on x86_64 (`tests/fixtures/detectors.json`), and GNU ld 2.24 and 2.26 (Ubuntu 14.04
/// and 16.04 x86_64) write ``against `chard_pic_anchor'``. Those are every wording naming the
/// symbol beside the phrase in the fleet reports kept from the sweeps of 2026-10 (x86_64 and
/// aarch64): replayed through this detector and the one before it, those reports' rows of
/// this check read the same under both (quoted from the witness record, not re-derived here).
/// The compiler runs under `LC_ALL=C`, so GNU ld quotes in ASCII. A linker whose refusal is
/// worded otherwise reads `indeterminate`, the safe side; an LLD that wrote the symbol
/// unquoted would be one, and none is in the recorded reports.
///
/// The symbol's name anywhere on a line beside [`PIC_SHARED_REFUSAL`] is not the refusal.
/// The probe's own comment quotes `recompile with -fPIC` two lines below one naming
/// `chard_pic_anchor`, and gcc's
/// `-fdiagnostics-format=sarif-stderr` carries the translation unit as one JSON string in
/// `artifacts[].contents.text`, so the document's line holds both. Beside a link that failed
/// for another reason that line reads `absent` and the check `off` to a reader that takes the
/// name anywhere: measured with gcc 16.1.1, Fedora 44 x86_64,
/// `--profile explicit --flags "-O2 -fPIC -fdiagnostics-format=sarif-stderr" --ldflags
/// -lchardnosuchlib`, where the same flags without the SARIF format read
/// `probe-invalid`. The comment spells the name in backticks, which no needle here
/// matches; the probe's sources carry no refusal, which a test holds.
/// Each needle names [`PIC_SHARED_SYMBOL`], which a test holds.
const PIC_SHARED_REFUSALS: &[&str] = &[
    "against symbol `chard_pic_anchor'",
    "against `chard_pic_anchor'",
    "against symbol 'chard_pic_anchor'",
    "against 'chard_pic_anchor'",
];

/// The line of `stderr` that is the linker refusing the probe's reference for want of
/// -fPIC: one of [`PIC_SHARED_REFUSALS`], and [`PIC_SHARED_REFUSAL`] after it on the same
/// line. Returns the line's index, counted as `str::lines` counts, so the verdict and the
/// excerpt ([`excerpt_at`]) rest on one line by construction.
fn pic_refusal_line(stderr: &str) -> Option<usize> {
    stderr.lines().position(|line| {
        PIC_SHARED_REFUSALS.iter().any(|symbol| {
            line.split_once(symbol)
                .is_some_and(|(_, after)| after.contains(PIC_SHARED_REFUSAL))
        })
    })
}

/// `-fPIC`, read from whether code compiled under the flags links `-shared`.
///
/// `present` is a link that succeeded and wrote its output. `absent` is a link the linker
/// refused on a line naming the probe's own symbol in the linker's words and
/// [`PIC_SHARED_REFUSAL`] after it ([`pic_refusal_line`]): the linker saying, about this
/// probe's reference, that the code is not position-independent in the sense a shared
/// object needs. That line is the one the published excerpt centres on. The discipline is
/// `detect_no_copy_dt_needed`'s: a failed link is `absent` only when it failed for this
/// reason, and a link that failed
/// for any other (a rejected flag, a missing library, a refusal naming some other symbol)
/// poses no question and is `indeterminate`.
///
/// A link that succeeds without -fPIC is the reverse error, and the check names the
/// measured ways it happens (`-Wl,-Bsymbolic`, gcc's LTO under lld, the large code
/// model, clang's LTO). Those are not read here; the check's regime-matched arm builds the
/// profile with `-fPIE` after it, and a link that still succeeds there withholds the
/// verdict. A link permitted text relocations is read here twice: from its line and its
/// stderr, by [`text_relocations_permitted`], and from the shared object it wrote, whose
/// `DT_TEXTREL` (or `DF_TEXTREL`) records that some of its code was linked by text
/// relocation whatever the line said. A link that succeeded is `present` only where the
/// object's dynamic section was read and carries neither; one whose object or dynamic
/// section was not read is `indeterminate`.
///
/// Which build's code a verdict describes: the code the measured command line generated
/// and linked. Under clang's `-flto` that is the code the link generated from bitcode, at
/// the position-independence the link chose, and not the code the profile's compile flags
/// describe: `-O2` reads `off` and `-O2 -flto` links with no `-fPIC` anywhere (measured
/// 2026-10-09, Fedora 44 x86_64, clang 22.1.8, GNU ld 2.46.1). The regime arm cannot see
/// that, since `-fPIE` after `-flto` is refused where the measured build is not, and this
/// function sees only the link's outcome. The rule `lto-codegen-at-link`
/// (`report::lto_codegen_limitation`) withholds such an `on` from the driver's `-###`
/// words, a configuration file's `-flto` included, and leaves `off` standing, since a
/// link that was refused under LTO refused the code that was generated. gcc is not asked:
/// its LTO link generates code at the position-independence the compile recorded (the
/// register entry `gcc-lto-link-keeps-recorded-pic`), so a refusal and a success mean what
/// they do without `-flto`.
pub(crate) fn detect_pic_shared_link(ev: &Evidence<'_>) -> Detection {
    let Some(build) = ev.build else {
        return Detection::indeterminate("probe not built".to_owned());
    };
    let refusal = pic_refusal_line(&build.stderr);
    let observed = build_observed_at(ev, build, refusal, PIC_SHARED_REFUSALS);

    if build.succeeded() {
        if build.artifact_sha256.is_none() {
            return Detection::indeterminate(format!(
                "{observed} (the link exited 0 and wrote no shared object, so nothing was \
                 linked)"
            ));
        }
        // Text relocations are the one way non-PIC code is linked into a shared object
        // whole, and the link succeeds over them. `-z notext` permits them under every
        // linker measured, and GNU ld's textrel check can be configured to warn rather
        // than refuse. Measured 2026-10-02: `-O2 -fno-pic -mcmodel=large -Wl,-z,notext`
        // links with DT_TEXTREL under GNU ld 2.46.1, lld 22.1.8 and mold on Fedora 44
        // x86_64 and under gcc 16.2.1 with GNU ld on aarch64. A trailing `-fPIE` is refused
        // under lld, so the regime arm does not withhold that case there; this does.
        if let Some(why) = text_relocations_permitted(build) {
            return Detection::indeterminate(format!(
                "{observed} (the link succeeded {why}, so it does not show the code is \
                 position-independent)"
            ));
        }
        // What the link wrote, whatever its line said. A `-z notext` a specs or
        // configuration file adds is not in the argv, and under lld 22.1.8 `-O2 -fno-pic
        // -mcmodel=large` then links `-shared` with exit 0 and no linker diagnostic (the
        // probe's own canary warning aside) while the
        // regime arm's large-model `-fPIE` is refused (measured 2026-10-08 and 2026-10-11 in
        // the Fedora 44 x86_64 image, gcc 16.2.1 with a specs file and clang 22.1.8 with a
        // configuration file). The object carries `DT_TEXTREL` there. The tag over-reports
        // in one direction: LLD 22.1.8 sets it on every `-z notext` link, and `-O2 -fPIC`
        // under a hidden one carries it with no relocation in a read-only segment (readelf,
        // the same image), so that link withholds where its code is position-independent,
        // and where the toolchain's own default carries the flag the `-fPIC` arm withholds
        // too. Under-reporting is the registered assumption: a text relocation into
        // read-only code is tagged. A link that makes the code writable (`-Wl,-N`) takes
        // non-PIC code untagged, and the regime arm is what withholds it. The check
        // declares the dynamic table, so a cut one withholds before this is read.
        // `textrel` is false for an object with no dynamic section as for one whose
        // section carries no tag, so a link with none is read as one not read.
        let Some(elf) = ev.elf.filter(|elf| elf.has_dynamic) else {
            return Detection::indeterminate(format!(
                "{observed} (the dynamic section of the shared object the link wrote was not \
                 read, so whether it carries DT_TEXTREL is unknown)"
            ));
        };
        if elf.textrel {
            return Detection::indeterminate(format!(
                "{observed} (the linked shared object carries DT_TEXTREL, which a linker sets \
                 where it linked code by text relocation into read-only code and LLD sets on \
                 every -z notext link, so the link does not show the code is \
                 position-independent)"
            ));
        }
        return Detection::present(None, observed);
    }

    if refusal.is_some() {
        return Detection::absent(observed);
    }

    Detection::indeterminate(format!(
        "{observed} (the link failed and no line of its stderr is a linker refusing a \
         reference to {PIC_SHARED_SYMBOL} for want of -fPIC in a wording chard reads, so the \
         failure is not read as this check's refusal and the arm poses no question)"
    ))
}

/// Why a successful link may have taken non-PIC code by text relocation, if it may have.
///
/// Read from what the link line asked and from what the linker said. The link line is read
/// as the linker's own options, never as text: the arguments the driver hands the linker
/// (each `-Wl,` argument split on commas, the argument after each `-Xlinker`, the driver's
/// own `-z keyword`) are flattened into one token stream, and `-z notext` is `-z` followed
/// by `notext` there, or the joined `-znotext`; `textoff`, its synonym under GNU ld and
/// mold, is read the same way. The output, source and workdir paths in the
/// same argv are absolute and host-chosen, so a substring match over them made the verdict
/// depend on a directory's name (a workdir named `wd-notext-dir` withheld every link;
/// seen 2026-10-02). What the linker said is read only from a line holding one
/// of [`TEXT_RELOCATION_WARNINGS`], the linker's own warning, and never from a looser phrase:
/// a compiler quotes the probe's source into its stderr (gcc's
/// `-fdiagnostics-format=sarif-stderr` carries it as one JSON string), and the source's
/// comment says "text relocation", which read a successful `-O2 -fPIC` link as one the
/// linker had reported. The argv is the build's, so a `-z
/// notext` a specs or configuration file adds is not seen here; [`detect_pic_shared_link`]
/// reads the linked object's `DT_TEXTREL` for that, and that a linker sets the tag where
/// it writes a text relocation is the registered assumption
/// `pic-link-hides-no-text-relocation`.
fn text_relocations_permitted(build: &BuildRecord) -> Option<&'static str> {
    if link_line_permits_text_relocations(&build.argv) {
        return Some(
            "under a link line that permits text relocations (`-z notext` or `-z textoff`)",
        );
    }
    let reported = build.stderr.lines().any(|line| {
        TEXT_RELOCATION_WARNINGS
            .iter()
            .any(|warning| line.contains(warning))
    });
    if reported {
        return Some("with the linker reporting text relocations");
    }
    None
}

/// The warnings a linker writes where it linked a shared object by text relocation and its
/// textrel check warns rather than refuses (`--warn-textrel`, `--warn-shared-textrel`, or GNU
/// ld configured `--enable-textrel-check=warning`, which no image here carries, so that one
/// is not measured), each in the linker's own words, case included. Measured with `-O2
/// -fno-pic -mcmodel=large -Wl,-z,notext -Wl,--warn-shared-textrel -shared` over the probe
/// on x86_64: GNU ld 2.38 (Ubuntu 22.04), 2.42 (Ubuntu 24.04), 2.45.1 (Alpine) and 2.46.1
/// (Fedora 44) write `warning: creating DT_TEXTREL in a shared object`, and 2.46.1 writes it
/// under `-Wl,--warn-textrel` alone too, linking where it refuses without; gold 1.16
/// (binutils 2.38, 2.42 and 2.46.1) writes `warning: shared library text segment is not
/// shareable`; mold 2.40.4 (Fedora 44), under `-Wl,--warn-textrel` with or without `-z
/// notext`, writes `warning: creating a DT_TEXTREL in an output file`, after a line naming
/// the relocation in a read-only section, which is not read. GNU ld 2.30's (AlmaLinux 8)
/// `warning: creating a DT_TEXTREL in a shared object.` is read from its libbfd's strings,
/// not from a link: the image has no compiler. GNU ld 2.31 to 2.37 are not measured: a
/// release among them is read by a needle if it writes one of the two spellings, and through
/// the tag otherwise, as an unlisted wording is. Each needle keeps the `warning: ` the
/// linker writes before it, which a test holds. LLD 22.1.8 refuses
/// `--warn-textrel` as an unknown argument and writes no warning under `-z notext`, so a link
/// under it is read through the object's `DT_TEXTREL`. The probe's source, raw and as a JSON
/// string, holds none of these, which a test holds.
const TEXT_RELOCATION_WARNINGS: [&str; 3] = [
    "warning: creating DT_TEXTREL in ",
    "warning: creating a DT_TEXTREL in ",
    "warning: shared library text segment is not shareable",
];

/// Whether the options the driver passes to the linker include `-z notext` or `-z textoff`.
///
/// Only arguments addressed to the linker are tokens; every other argv element, paths
/// included, is skipped whole. See [`text_relocations_permitted`].
///
/// `--for-linker <arg>` and `--for-linker=<arg>`, the driver's other spellings of
/// `-Xlinker`, are read as it is, and so is each abbreviation gcc takes for the two-token
/// one (`--for-l`), through the one classifier, which also steps past clang's
/// `-Xarch_<arch>` to the applied word (clang forwards `-Xarch_x86_64 -Wl,-znotext` to the
/// link). A reader that skipped the joined form whole, and read the
/// separate one only where its argument began with `-z`, missed `--for-linker=-znotext` and
/// `--for-linker -z --for-linker notext`: measured on Fedora 44 x86_64 (gcc 16.1.1, clang
/// 22.1.8), `-O2 -fno-pic -mcmodel=large` with either read `pic-shared-link`'s measured link
/// `present`, and only the regime arm, which linked too, withheld the cell.
fn link_line_permits_text_relocations(argv: &[String]) -> bool {
    let mut tokens: Vec<&str> = Vec::new();
    let mut i = 0;
    while let Some(arg) = argv.get(i) {
        let next = argv.get(i.saturating_add(1)).map(String::as_str);
        // Each word as the driver reads it (`--for-l` and `--for-linker` are `-Xlinker`;
        // `toolchain::read`), the pair passed over where another word takes the next
        // (`-o -znotext` names an output file).
        let reading = crate::toolchain::read(arg, next);
        let word = &*reading.word;
        if let Some(list) = arg.strip_prefix("-Wl,") {
            tokens.extend(list.split(','));
        } else if let Some(value) = arg.strip_prefix("--for-linker=") {
            tokens.push(value);
        } else if word == "-Xlinker" {
            tokens.extend(next.filter(|_| reading.span() == 2));
        } else if word == "-z" {
            tokens.push("-z");
            tokens.extend(next);
            i = i.saturating_add(2);
            continue;
        } else if word.starts_with("-z") {
            tokens.push(arg);
        }
        i = i.saturating_add(reading.own_words_span());
    }
    PERMITS_TEXT_RELOCATIONS.iter().any(|keyword| {
        tokens
            .iter()
            .any(|token| token.strip_prefix("-z") == Some(keyword))
            || tokens
                .windows(2)
                .any(|pair| matches!(pair, [z, value] if *z == "-z" && value == keyword))
    })
}

/// The `-z` keywords that permit text relocations: `notext`, and `textoff`, which GNU ld
/// and mold accept as its synonym. Measured 2026-10-02 on Fedora 44
/// x86_64 (gcc 16.2.1, clang 22.1.8): `-O2 -fno-pic -mcmodel=large -Wl,-z,textoff` links
/// under GNU ld 2.46.1 and mold and reads `probe-invalid`, the regime arm linking too, and
/// GNU ld 2.38 (Ubuntu 22.04) and 2.45.1 (Alpine) link it as well. lld 22.1.8 warns
/// `unknown -z value: textoff`, ignores it and refuses the link, a true `off`.
const PERMITS_TEXT_RELOCATIONS: [&str; 2] = ["notext", "textoff"];

/// Marker the diagnostic-channel canary raises when warnings are being reported.
pub(crate) const DIAG_CANARY: &str = "chard_canary_unused";

/// Reads *severity*, not the presence of text: both control arms emit the same
/// wording and differ only in whether it is an error. Verified identical on gcc
/// ("format not a string literal and no format arguments") and clang ("format string
/// is not a string literal"), which share the substring matched here.
///
/// The canary handles a case the control triple cannot. Controls are profile-free,
/// so a measured build carrying `-w` or `-fdiagnostics-format=sarif-file` has a
/// silent stderr that is indistinguishable from "the flag is off" — the detector
/// would report absent for a build whose diagnostics were never listened to. If
/// neither the primary wording nor the canary warning appears, the channel itself is
/// suspect and the verdict is withheld.
///
/// Order matters: the primary observable is checked first, so a genuine error is
/// still reported even on a build that suppresses ordinary warnings.
/// The severity the compiler gave *this* diagnostic, read from the line carrying it.
///
/// Shared reader for the compiler-diagnostic channel.
///
/// Every Table 1 check answers the same two questions — did the diagnostic appear,
/// and was anything listening — so they share one implementation and one rule about
/// what may be matched.
///
/// **Match the diagnostic's wording, never its option name.** The bracketed
/// `[-Wfoo]` tag looks like the obvious key and is wrong three separate ways, each
/// measured rather than supposed:
///
///   - `-Werror` rewrites it. gcc turns `[-Wsign-compare]` into
///     `[-Werror=sign-compare]` and clang into `[-Werror,-Wsign-compare]`.
///   - `-fno-diagnostics-show-option` removes it outright.
///   - Worst, a compiler that has *rejected* the flag prints its name while
///     saying so. `clang -Wimplicit-fallthrough=5` — a spelling the Linux kernel
///     and several distributions really pass — emits "unknown warning option
///     '-Wimplicit-fallthrough=5'; did you mean '-Wimplicit-fallthrough'?" and no
///     fall-through diagnostic at all. Keying on the option name scores that as
///     the flag being *on* when the compiler ignored it.
///
/// So `needles` carries the message texts, gcc's and clang's both, and a hit on any
/// of them counts. The needles must also avoid quote characters, since gcc quotes
/// with U+2018/U+2019 under a UTF-8 locale and ASCII apostrophes under `LC_ALL=C`,
/// and must not appear in the probe's own filename — `grep trampoline` matched
/// `probes/trampolines.c` in every arm during development.
///
/// Attribution is the whole point, and a wrong rule would manufacture hardening. Asking
/// whether the needle appeared *and* whether stderr contained `error:` anywhere is two
/// independent questions, so any unrelated failure in the same build would promote a
/// warning to `present`:
///
/// ```text
/// $ clang -O2 -Wno-error=int-conversion -lnosuchlib -o out int_conversion.c
/// int_conversion.c:57:10: warning: incompatible integer to pointer conversion ...
/// clang: error: linker command failed with exit code 1
/// ```
///
/// Needle present, `error:` present, and the check would report `-Werror=int-conversion`
/// **on** for a command line that never mentioned it. That is not hypothetical: a
/// profile carrying `-static` fails exactly this way on a box with no static libc, and
/// clang emits `-Wreturn-type` by default, so the sibling return-type check would have
/// read `on` for every failed link.
///
/// Both compilers put `error:` or `warning:` on the same line as the message text, so
/// the line is the unit of attribution. Returns `None` when the needle is absent.
pub(crate) fn diag_severity_of(
    build: &crate::compile::BuildRecord,
    needles: &[&str],
) -> Option<Seen> {
    // The stream is asked about before any line is: in a structured document no line is a
    // diagnostic, so neither the needle nor the severity word on it means anything.
    if structured_stream(&build.stderr) {
        return Some(Seen::Unreadable(Unreadable::StructuredStream));
    }
    let (_, line) = needle_line(&build.stderr, needles)?;
    if line.contains("error:") {
        return Some(Seen::Error);
    }
    if line.contains("warning:") {
        return Some(Seen::Warning);
    }
    // Diagnosed, but with no severity word we recognise. This read as a warning until
    // 2026-10-09, which published a stronger claim than the line supports: a needle on a
    // line that is not a diagnostic (a path header, a quoted source line) read a check `on`
    // at warning strength, and an `error:` further down was never reached.
    Some(Seen::Unreadable(Unreadable::NoSeverityWord))
}

/// What [`diag_severity_of`] read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Seen {
    Error,
    Warning,
    /// The needle was found, or the stream is not text, and the level cannot be read from it.
    Unreadable(Unreadable),
}

/// Why a level could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unreadable {
    /// The build's stderr is a structured diagnostics document: the rule
    /// [`STRUCTURED_STREAM_RULE`].
    StructuredStream,
    /// The matched line carries neither `error:` nor `warning:`.
    NoSeverityWord,
}

/// The rule id a detector names when it withholds a build whose stderr is a structured
/// diagnostics document, and the assumption in `report::ASSUMPTIONS` that bounds it.
pub(crate) const STRUCTURED_STREAM_RULE: &str = "diag-stream-is-text-unless-recognised";

impl Unreadable {
    /// The sentence a detector appends to `observed`.
    fn reason(self) -> String {
        match self {
            Self::StructuredStream => format!(
                "(withheld under {STRUCTURED_STREAM_RULE}: stderr is a structured diagnostics \
                 document, in which a needle on a line and a severity word beside it are not a \
                 diagnostic and its level)"
            ),
            Self::NoSeverityWord => "(withheld: the line carrying the diagnostic names no \
                 severity, so its level cannot be read from it)"
                .to_owned(),
        }
    }
}

impl Seen {
    /// The prose decoder's word for this reading in the structured-diagnostics comparison.
    #[must_use]
    pub(crate) fn word(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Unreadable(_) => "unreadable",
        }
    }
}

/// The needles each prose-decoded compiler-diag check matches, by check id.
///
/// One list per check, named once and used by both the detector and this table, so the
/// structured decoder in [`crate::structured`] asks exactly the question the prose decoder
/// answers. A compiler-diag check absent from here is in [`DIAG_NEEDLES_EXEMPT`] with the
/// reason, and a test holds the two against the corpus.
pub const DIAG_NEEDLES: &[(&str, &[&str])] = &[
    ("hardened-downgrade-warned", HARDENED_DOWNGRADE_NEEDLES),
    (
        "implicit-function-declaration-is-error",
        IMPLICIT_DECLARATION_NEEDLES,
    ),
    ("format-security-is-error", FORMAT_SECURITY_NEEDLES),
    ("warn-all", WARN_ALL_NEEDLES),
    ("warn-extra", WARN_EXTRA_NEEDLES),
    ("format-mismatch-warned", WARN_FORMAT_NEEDLES),
    ("format-nonliteral-warned", FORMAT_NONLITERAL_NEEDLES),
    ("conversion-warns-on-narrowing", CONVERSION_NEEDLES),
    (
        "sign-conversion-warns-on-signedness-change",
        SIGN_CONVERSION_NEEDLES,
    ),
    ("implicit-fallthrough-warned", FALLTHROUGH_NEEDLES),
    ("trampolines-warned", TRAMPOLINE_NEEDLES),
    ("bidi-chars-any", BIDI_NEEDLES),
    ("implicit-int-is-error", IMPLICIT_INT_NEEDLES),
    (
        "incompatible-pointer-types-is-error",
        INCOMPATIBLE_POINTER_NEEDLES,
    ),
    ("int-conversion-is-error", INT_CONVERSION_NEEDLES),
];

/// Compiler-diag checks the structured decoder does not read, and why.
pub const DIAG_NEEDLES_EXEMPT: &[(&str, &str)] = &[
    (
        "no-copy-dt-needed",
        "the observable is the linker refusing to resolve a symbol, which no compiler writes \
         as SARIF: the linker's lines follow the document as text (gcc 15.2.1 and 16.1.1 \
         under -fdiagnostics-format=sarif-stderr)",
    ),
    (
        "pic-shared-link",
        "the observable is the linker refusing a relocation in a shared object, which no \
         compiler writes as SARIF: the linker's lines follow the document as text (gcc \
         16.1.1 under -fdiagnostics-format=sarif-stderr)",
    ),
];

/// The needles a compiler-diag check matches, when it has a list.
#[must_use]
pub fn diag_needles(check: &str) -> Option<&'static [&'static str]> {
    DIAG_NEEDLES
        .iter()
        .find(|(id, _)| *id == check)
        .map(|(_, needles)| *needles)
}

/// The downgrade the positive arm makes, in both of gcc's closing quotes; see
/// [`detect_hardened_warning`].
const HARDENED_DOWNGRADE_NEEDLES: &[&str] = &[
    "-fstack-protector-strong' is not enabled by",
    "-fstack-protector-strong\u{2019} is not enabled by",
];
const WARN_ALL_NEEDLES: &[&str] = &["chard_wall_dead_label"];
const WARN_EXTRA_NEEDLES: &[&str] = &["different sign"];
const WARN_FORMAT_NEEDLES: &[&str] = &["expects argument of type", "format specifies type"];
const FORMAT_NONLITERAL_NEEDLES: &[&str] = &["not a string literal"];
const FORMAT_SECURITY_NEEDLES: &[&str] = &["not a string literal"];
const CONVERSION_NEEDLES: &[&str] = &["may change value", "loses integer precision"];
const SIGN_CONVERSION_NEEDLES: &[&str] = &["change the sign", "changes signedness"];
const FALLTHROUGH_NEEDLES: &[&str] = &["may fall through", "fall-through between switch labels"];
const TRAMPOLINE_NEEDLES: &[&str] = &["trampoline generated for nested function"];
const BIDI_NEEDLES: &[&str] = &["problematic unicode character", "u+202e"];
const IMPLICIT_INT_NEEDLES: &[&str] = &["type defaults to", "type specifier missing"];
const INCOMPATIBLE_POINTER_NEEDLES: &[&str] = &[
    "incompatible pointer type",
    "from incompatible pointer type",
];
const INT_CONVERSION_NEEDLES: &[&str] = &[
    "makes pointer from integer without a cast",
    "integer to pointer conversion",
];

/// What was seen, in the one spelling every compiler-diag detector reports it in.
///
/// Three detectors built this string themselves, identically. It is short enough that the
/// duplication looked harmless, and the truncation length is the reason it is not: the
/// budget is a number a reader compares across cells, and a fourth copy that chose another
/// would make two detectors' `observed` fields incomparable without either one being wrong.
/// The cut itself is [`excerpt_around`]'s: the line carrying one of `needles`, which is
/// the line the detector's verdict rests on, is kept by construction, and the lines
/// around it fill the budget. A stream with no such line is cut to its end.
///
/// The budget is [`DIAG_EXCERPT`] rather than the 160 the runtime strings use, because
/// every compiler-diag probe emits two diagnostics by design: the observable and the
/// canary warning that proves something was listening, each with a source line and a
/// caret line under it. Measured on Apple clang 21 for
/// `implicit-function-declaration-is-error`: the two blocks are about 350 characters
/// without their path prefixes and the trailing count another 35, so a 160-character
/// tail kept the canary and the count and cut the error the check is about. Each block
/// carries the probe's path once, so the budget leaves room for two prefixes of up to
/// about 140 characters. Under a compiler that prints fix-it notes between the two, the
/// lines farthest from the matched diagnostic are what the budget gives up, and the
/// markers say how much on each side. The cut is made in the published stream, with the
/// work directory already relative, so the budget is spent on the same text under every
/// `--workdir`. Cut before that rewrite, a longer work directory would cost lines the
/// published text does not need to lose.
fn build_observed(ev: &Evidence<'_>, build: &BuildRecord, needles: &[&str]) -> String {
    format!(
        "exit={} stderr={:?}",
        build.exit_status,
        excerpt_around(ev, &build.stderr, needles, DIAG_EXCERPT)
    )
}

/// [`build_observed`] around line `hit` of the build's stderr, for a detector whose deciding
/// line is found by a rule of its own ([`pic_refusal_line`]) rather than by one needle.
fn build_observed_at(
    ev: &Evidence<'_>,
    build: &BuildRecord,
    hit: Option<usize>,
    needles: &[&str],
) -> String {
    format!(
        "exit={} stderr={:?}",
        build.exit_status,
        excerpt_at(ev, &build.stderr, hit, needles, DIAG_EXCERPT)
    )
}

/// How much of a compiler's stderr a compiler-diag `observed` string quotes. See
/// [`build_observed`] for the measurement it is sized from.
const DIAG_EXCERPT: usize = 640;

/// How a probe's canary comes to fire: from its own source, or from the build's flags.
///
/// Every compiler-diag probe but one pins `-Wunused-variable` at warning severity with an
/// in-source pragma, so its canary fires under any flags short of ones that suppress or
/// redirect diagnostics. `hardened_downgrade.c` does not: its controls pass `-Wall` instead
/// (`CANARY_WITHOUT_PRAGMA` in `probe.rs`'s tests, which pins that list and binds it to the
/// detectors that pass [`Canary::AskedByFlags`]). Its measured build under `bare` and
/// `bare-optimized` carries no `-Wall`, so the canary stays silent with nothing suppressed,
/// and [`diag_silence`] says the warning was not asked for rather than that the channel was
/// suppressed or redirected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Canary {
    /// The probe's source pins the canary's warning; silence means it was taken away.
    Pinned,
    /// The canary fires only where the build's flags enable `-Wunused-variable`.
    AskedByFlags,
}

/// The options that turn `-Wunused-variable` on, in gcc's and clang's spellings, each also
/// read in its `-Werror=` form, which enables the warning as well as escalating it.
const CANARY_WARNING_ENABLERS: &[&str] =
    &["all", "unused", "unused-variable", "most", "everything"];

/// Whether `argv` shows that the canary's warning was never asked for: no word in it may
/// enable `-Wunused-variable`, may take diagnostics away, or may carry flags the record does
/// not show. Read as a set of words, not in order, so any doubt keeps the other sentence.
///
/// - Enables: one of [`CANARY_WARNING_ENABLERS`] as `-W<name>`, `-Werror=<name>` or gcc's
///   `--warn-<name>`, and gcc's `--all-warnings`; also inside a `-Wp,` list, which the driver
///   hands to the preprocessor and which turns the warning on (gcc 16.1.1 and clang 22.1.8),
///   and after clang's joined `-Xclang=` (clang 22.1.8 warns under `-Xclang=-Wall` and is
///   silent under `-Wall -Xclang=-w`). `-Xclang -Wall` needs no rule: its `-Wall` is a word of
///   its own. A `=<value>` after the name is cut before the name is compared, which can only
///   keep the other sentence (gcc 16.1.1 refuses `-Wunused-variable=1`, and clang 22.1.8
///   ignores it with a warning).
/// - Takes away: `-w`, `--no-warnings`, a `-Wno-` (or `--warn-no-`) of an enabler, and any
///   `-fdiagnostics-format=`, `-fdiagnostics-add-output=` or `-fdiagnostics-set-output=`.
///   A build that carries one is the suppressed or redirected channel, whether or not it
///   also asked.
/// - Unseen: a response file (`@file`), a specs file (`-specs`, `--specs`, joined or as two
///   words) or a configuration file (`--config`), whose words are not in `argv`.
///
/// A configuration or specs file the driver reads on its own is not in `argv` either, nor
/// are flags a driver takes from its environment (clang's `CCC_OVERRIDE_OPTIONS`, which a
/// run's `--env` can set and `profile.compiler_environment` then publishes); the sentence
/// this answers is about the build's recorded flags, and says so.
fn canary_never_asked(argv: &[String]) -> bool {
    fn name(word: &str) -> Option<&str> {
        let rest = word
            .strip_prefix("-Werror=")
            .or_else(|| word.strip_prefix("--warn-"))
            .or_else(|| word.strip_prefix("-W"))?;
        Some(rest.split_once('=').map_or(rest, |(n, _)| n))
    }
    fn enabler(name: Option<&str>) -> bool {
        name.is_some_and(|n| CANARY_WARNING_ENABLERS.contains(&n))
    }
    let words = argv.iter().flat_map(|arg| {
        let arg = arg.strip_prefix("-Xclang=").unwrap_or(arg);
        match arg.strip_prefix("-Wp,") {
            Some(list) => list.split(',').collect::<Vec<_>>(),
            None => vec![arg],
        }
    });
    !words.into_iter().any(|word| {
        let taken_back = word
            .strip_prefix("-Wno-")
            .or_else(|| word.strip_prefix("--warn-no-"));
        word == "--all-warnings"
            || enabler(name(word))
            || matches!(word, "-w" | "--no-warnings")
            || enabler(taken_back)
            || [
                "-fdiagnostics-format=",
                "-fdiagnostics-add-output=",
                "-fdiagnostics-set-output=",
            ]
            .iter()
            .any(|p| word.starts_with(p))
            || word.starts_with('@')
            || ["-specs", "--specs", "--config"]
                .iter()
                .any(|p| word.starts_with(p))
    })
}

/// What silence means, once the needles have not matched.
///
/// Silence is absence only when something was listening. `-w` and
/// `-fdiagnostics-format=sarif-file` empty stderr without countermanding any control flag,
/// so a build carrying neither the observable nor the canary is indeterminate — and a build
/// that failed without the diagnostic is indeterminate for a different reason, because the
/// failure is not attributable to this flag.
///
/// One silence never reaches here: a measured build the driver refused for a flag the
/// profile supplied. It is `build-failed` with the refusal named, withheld by
/// `report::Variant::sufficient_for_measured` before any detector runs, because the
/// sentence below ("suppressed or redirected") was false of it: nothing was suppressed, the
/// profile never came into force.
///
/// The failure is read before the canary, for the same reason. A build that failed and
/// emitted no canary either failed before the compiler proper ran (a driver that could not
/// open its configuration file, or refused a flag chard itself supplied: lines the refusal
/// reader does not count) or failed with the canary suppressed, and in neither case is
/// "suppressed or redirected" the thing a reader can act on; the failure is, and it is
/// certain.
///
/// A build that succeeded silently, for a probe whose canary is [`Canary::AskedByFlags`],
/// is read against its recorded flags: where none of them asks for `-Wunused-variable`,
/// nothing suppressed or redirected the channel, and the sentence says the warning was not
/// asked for. Both sentences withhold the same way; only the reason differs.
///
/// Shared rather than written three times: `diag_presence`, `diag_severity` and
/// `detect_format_security` end the same way, and a defect fixed in one copy of a rule
/// survives in the others. Two copies of a rule are two rules. `what` names the diagnostic
/// the sentence is about.
fn diag_silence(build: &BuildRecord, observed: String, what: &str, canary: Canary) -> Detection {
    if !build.succeeded() {
        return Detection::indeterminate(format!(
            "{observed} (the build failed without the {what}, so the failure is not \
             attributable to this flag)"
        ));
    }
    if !build.diagnostics_contain(DIAG_CANARY) {
        if canary == Canary::AskedByFlags && canary_never_asked(&build.argv) {
            return Detection::indeterminate(format!(
                "{observed} (neither the {what} nor the canary warning was emitted, and the \
                 build's recorded flags never asked for the canary's warning: they carry \
                 neither -Wall nor -Wunused-variable, nor another option that enables it or \
                 takes diagnostics away, and this probe does not pin it in its source, so \
                 silence cannot be read as absence)"
            ));
        }
        return Detection::indeterminate(format!(
            "{observed} (neither the {what} nor the canary warning was emitted, so \
             this build's diagnostic channel is suppressed or redirected and silence \
             cannot be read as absence)"
        ));
    }
    Detection::absent(observed)
}

/// Read a Table 1 warning as presence: did the diagnostic appear at all?
///
/// Silence is only absence when something was listening, which is what the probe's
/// canary establishes. `-w` and `-fdiagnostics-format=sarif-file` empty stderr
/// without countermanding any control flag, so a build with neither the observable
/// nor the canary is reported indeterminate rather than off.
fn diag_presence(ev: &Evidence<'_>, needles: &[&str]) -> Detection {
    diag_presence_with(ev, needles, Canary::Pinned)
}

/// [`diag_presence`] for a probe whose canary comes to fire as `canary` says.
fn diag_presence_with(ev: &Evidence<'_>, needles: &[&str], canary: Canary) -> Detection {
    let Some(build) = ev.build else {
        return Detection::indeterminate("probe not built".to_owned());
    };
    let observed = build_observed(ev, build, needles);

    // Presence is what this channel reports — a profile that additionally escalates
    // the construct to an error is still a profile that diagnoses it — but the level
    // is published alongside, and it must be attributed to *this* diagnostic's own
    // line. Asking whether stderr contains `error:` anywhere makes any unrelated
    // failure in the same build raise the level: a bogus `-l` yields a linker error
    // while the construct is only warned about, and the cell then reads `error`.
    //
    // This is the defect `diag_severity` guards against, in a milder form: presence stays
    // correct and only the level is wrong. It is still the same defect, and it would read
    // as a distribution enforcing something it merely warns about.
    match diag_severity_of(build, needles) {
        Some(Seen::Error) => return Detection::present(Some("error"), observed),
        Some(Seen::Warning) => return Detection::present(Some("warning"), observed),
        Some(Seen::Unreadable(why)) => {
            return Detection::indeterminate(format!("{observed} {}", why.reason()));
        }
        None => {}
    }

    diag_silence(build, observed, "diagnostic", canary)
}

/// Read a Table 1 construct as severity: the same sentence appears either way, and
/// only whether it stops the build differs.
///
/// This is the `-Werror=` shape, shared by the obsolete-C constructs and modelled on
/// [`detect_format_security`]. The observable is tested *before* the canary because
/// `-w` silences the canary while leaving these diagnostics as errors on both
/// compilers — measured — and that build is a true `present`, not an indeterminate.
fn diag_severity(ev: &Evidence<'_>, needles: &[&str]) -> Detection {
    let Some(build) = ev.build else {
        return Detection::indeterminate("probe not built".to_owned());
    };
    let observed = build_observed(ev, build, needles);

    // Severity is read from the diagnostic's own line, never from stderr as a whole:
    // an unrelated failure elsewhere in the build must not promote a warning to an
    // error. See `diag_severity_of`.
    match diag_severity_of(build, needles) {
        Some(Seen::Error) => return Detection::present(Some("error"), observed),
        Some(Seen::Warning) => {
            return Detection::absent(format!("{observed} (diagnosed as a warning only)"));
        }
        Some(Seen::Unreadable(why)) => {
            return Detection::indeterminate(format!("{observed} {}", why.reason()));
        }
        None => {}
    }

    diag_silence(build, observed, "diagnostic", Canary::Pinned)
}

/// gcc: "label 'x' defined but not used". clang: "unused label 'x'". Both quote the
/// identifier, which is what makes one needle serve both.
pub(crate) fn detect_warn_all(ev: &Evidence<'_>) -> Detection {
    diag_presence(ev, WARN_ALL_NEEDLES)
}

pub(crate) fn detect_warn_extra(ev: &Evidence<'_>) -> Detection {
    // gcc "of different signedness", clang "of different signs".
    diag_presence(ev, WARN_EXTRA_NEEDLES)
}

pub(crate) fn detect_warn_format(ev: &Evidence<'_>) -> Detection {
    diag_presence(ev, WARN_FORMAT_NEEDLES)
}

pub(crate) fn detect_warn_format_nonliteral(ev: &Evidence<'_>) -> Detection {
    diag_presence(ev, FORMAT_NONLITERAL_NEEDLES)
}

pub(crate) fn detect_warn_conversion(ev: &Evidence<'_>) -> Detection {
    diag_presence(ev, CONVERSION_NEEDLES)
}

pub(crate) fn detect_warn_sign_conversion(ev: &Evidence<'_>) -> Detection {
    diag_presence(ev, SIGN_CONVERSION_NEEDLES)
}

pub(crate) fn detect_implicit_fallthrough(ev: &Evidence<'_>) -> Detection {
    diag_presence(ev, FALLTHROUGH_NEEDLES)
}

pub(crate) fn detect_trampolines(ev: &Evidence<'_>) -> Detection {
    // Not the bare word "trampoline": it appears in the probe's own path, so it
    // matched in every arm including the negative one.
    diag_presence(ev, TRAMPOLINE_NEEDLES)
}

pub(crate) fn detect_bidi_chars(ev: &Evidence<'_>) -> Detection {
    // Not the option name: clang prints "unknown warning option '-Wbidi-chars=any'"
    // while diagnosing nothing.
    diag_presence(ev, BIDI_NEEDLES)
}

pub(crate) fn detect_implicit_int(ev: &Evidence<'_>) -> Detection {
    diag_severity(ev, IMPLICIT_INT_NEEDLES)
}

pub(crate) fn detect_incompatible_pointer_types(ev: &Evidence<'_>) -> Detection {
    diag_severity(ev, INCOMPATIBLE_POINTER_NEEDLES)
}

pub(crate) fn detect_int_conversion(ev: &Evidence<'_>) -> Detection {
    // Never the bare word "incompatible": clang's -Wint-conversion wording is
    // "incompatible integer to pointer conversion", which would collide with the
    // sibling incompatible-pointer-types check.
    diag_severity(ev, INT_CONVERSION_NEEDLES)
}

pub(crate) fn detect_format_security(ev: &Evidence<'_>) -> Detection {
    const NEEDLES: &[&str] = FORMAT_SECURITY_NEEDLES;
    let Some(build) = ev.build else {
        return Detection::indeterminate("probe not built".to_owned());
    };
    let observed = build_observed(ev, build, NEEDLES);

    // Severity decides — the same sentence appears in both arms — and it is read from
    // the diagnostic's own line. Testing stderr as a whole for `error:` would let any
    // unrelated build failure promote the warning to `present`.
    match diag_severity_of(build, NEEDLES) {
        Some(Seen::Error) => return Detection::present(Some("error"), observed),
        Some(Seen::Warning) => {
            return Detection::absent(format!("{observed} (diagnosed as a warning only)"));
        }
        Some(Seen::Unreadable(why)) => {
            return Detection::indeterminate(format!("{observed} {}", why.reason()));
        }
        None => {}
    }

    diag_silence(build, observed, "format diagnostic", Canary::Pinned)
}

/// Was calling an undeclared function an error, or only a warning?
///
/// Routed through [`diag_severity`] like its three siblings. A reader that takes the needle
/// anywhere in stderr and the severity from `!build.succeeded()` asks two independent
/// questions:
///
/// ```text
/// let mentions = build.diagnostics_contain("implicit declaration");   // whole stderr
/// if !build.succeeded() {                                             // whole build
///     return if mentions { Detection::present(Some("error"), …) }     // <- false `on`
/// ```
///
/// So any unrelated failure in the same build would promote a warning to an error. That is
/// reachable through `--profile explicit --flags "$CFLAGS"`, which the README recommends
/// for closing the gap to a real build: `-static` on an image with no static libc is this
/// tree's own named case, and a targeted `-Werror=unused-variable` escalating the probe's
/// own canary variable is another. It bites the older half of the catalogue, where the
/// diagnostic is a warning by default (Ubuntu 20.04 and
/// 22.04, Debian 11 and 12, Rocky and Alma 8 and 9), while on gcc 14+/clang 16+ the `error`
/// answer would be right for the wrong reason.
///
/// This is the defect `diag_severity_of` exists for, diagnosed at length in this file and held
/// for `detect_int_conversion` by a test named
/// `unrelated_build_failure_does_not_fake_an_error_severity`.
pub(crate) fn detect_implicit_function_declaration(ev: &Evidence<'_>) -> Detection {
    diag_severity(ev, IMPLICIT_DECLARATION_NEEDLES)
}

/// gcc: "implicit declaration of function"; clang 16 and later: "call to undeclared
/// function", with the option name as a third spelling for a compiler that prints only
/// the tag. Named so the unit tests quote the detector's own needles.
///
/// The tag needle carries its `-W`, for the reason `detect_trampolines` gives: a needle
/// short enough to appear in a path matches the compiler's own `<path>: In function ...`
/// header line, which carries no severity word. `diag_severity_of` reads that line as a
/// warning, and a real `error:` two lines below it is never reached. Measured on Fedora
/// 44 gcc 16.1.1 with a work directory named for the check: the positive control arm of
/// `implicit-function-declaration-is-error` read `absent` with `error: implicit
/// declaration of function` in its stderr, and the check read `probe-invalid` where it
/// reads `off` from the same toolchain under a work directory named anything else. A
/// measured arm under such a directory would have read `off` with the diagnostic present,
/// which is the verdict this project cannot publish wrongly.
const IMPLICIT_DECLARATION_NEEDLES: &[&str] = &[
    "implicit declaration",
    "-wimplicit-function-declaration",
    "call to undeclared function",
];

#[cfg(test)]
#[path = "diag_tests.rs"]
mod tests;
