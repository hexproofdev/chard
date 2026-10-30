// SPDX-License-Identifier: BSD-3-Clause

//! What a driver's `-###` listing says a link combines beyond the program's own objects:
//! the program it runs for the link, every input it names by path (the startup objects and
//! archives, whatever their names), the library directories it searches and the system
//! root it hands the linker, and the linkage form (`-pie`, `-shared`, `-static`).
//!
//! The control arms carry the profile's target, runtime, header and linker selection and
//! nothing else of it (`measure::arm_flags`), because a later flag cannot switch off what a gcc
//! `-specs=` file or a clang `--config=` file injects: carried, Fedora's
//! `redhat-hardened-cc1` put its hardening into every negative control. The same two
//! files can also choose the startup objects, through a specs file's `*startfile` or
//! `*endfile` or a configuration file's `--gcc-install-dir=`, and where they do the
//! measured build links objects no arm links, so the triple validates a detector on
//! another link. Neither carrying nor refusing the file serves: refusing it refuses
//! Fedora's own `%build_cflags`. What chard can do is ask the driver, for the measured
//! build's flags and for the arms' selection, which inputs it would hand the linker, and
//! compare. `measure` withholds the checks whose observable the startup objects decide
//! (`report::LINK_INPUT_READINGS`) under `link-inputs-unmatched-by-arms` where the two
//! listings differ, or where either could not be read.
//!
//! The linkage form is normalised, not compared: the arms do not carry `-pie`, `-shared`
//! or `-static` (`toolchain::runtime_selecting_flags` says why), and Fedora's
//! `redhat-hardened-ld` turns a link into a PIE through its `*self_spec`, so the measured
//! link names `Scrt1.o` and `crtbeginS.o` where an arm's names `crt1.o` and `crtbegin.o`.
//! The arms' listing is therefore taken under the measured link's own form
//! ([`LinkageForm::driver_flag`]), and what is compared is which files and directories
//! the driver chose for that form. Equal therefore does not mean that the arms linked
//! these objects: under `redhat-hardened-ld` the measured link names `Scrt1.o` and
//! `crtbeginS.o` and the arms, linked without `-pie`, combine `crt1.o` and `crtbegin.o`.
//! It means the profile chose no startup object the driver would not have chosen for that
//! form on its own, and the gap between one form's objects and another's is the one the
//! arms have without this comparison. Measured on 2026-10-06 on Fedora 44 x86_64 (gcc
//! 16.1.1, clang 22.1.8, glibc 2.43, binutils 2.46.1): under Fedora's `%build_cflags` and
//! `%build_ldflags` the two gcc listings name the same objects, archives and directories
//! once the arms' takes `-pie`, and so do the clang ones under the clang toolchain's
//! `--config=` files; under a specs file whose `*startfile` names a copy of `crtbegin*.o`
//! without the x86 feature note, and under a configuration file holding
//! `--gcc-install-dir=` a copy of the install directory with such objects, they differ in
//! exactly those objects (and, for the second, the install's library directory).
//!
//! Equal means equal after resolution: each path is read through `fs::canonicalize`, so
//! clang's `/usr/bin/../lib/gcc/...` and gcc's `/usr/lib/gcc/...` spellings of one file
//! compare equal, and a path that does not resolve is compared as written. The link
//! program is compared the same way, so a configuration file's `--ld-path=` or a specs
//! `*linker` naming another program differs even where the inputs do not. The listing is
//! taken over an empty C input (`-x c /dev/null`), and the object the compile step writes
//! for it, a temporary file named anew on every run, is recognised as the `-o` of an
//! earlier command of the same listing and left out. The resolution rests on the
//! assumption `driver-listing-names-the-link-inputs` (`report::ASSUMPTIONS`): that the
//! listing names every input the profile can choose for the link. A linker script the link
//! reads (glibc's `libc.so` names `libc_nonshared.a`) is chosen through the library
//! directories, which are compared, and not named itself.
//!
//! The checks that read the clean build are the other way round: their subject is the
//! clean build, so it is that build's link that is held to the measured one, on the link
//! program, the `-L` directories and the system root of the listing and on the program and
//! library lists of the driver's `-print-search-dirs` ([`SearchDirs`]), which name a `-B`
//! prefix gcc's listing does not ([`clean_link_difference`]; the rule is
//! `report::clean_link_limitation`, resting on `driver-answers-name-the-clean-link`).

use std::path::Path;

use crate::compile;

/// The output kind a link line produces, read from the words the driver handed the
/// linker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkageForm {
    /// `-shared`.
    Shared,
    /// `-static` beside `-pie` or `--no-dynamic-linker`: gcc's and clang's `-static-pie`.
    StaticPie,
    /// `-static` alone.
    Static,
    /// `-pie`.
    Pie,
    /// None of them: a position-dependent executable.
    NoPie,
}

impl LinkageForm {
    /// The driver flag that asks for this form, which the arms' listing is taken under.
    #[must_use]
    pub const fn driver_flag(self) -> &'static str {
        match self {
            Self::Shared => "-shared",
            Self::StaticPie => "-static-pie",
            Self::Static => "-static",
            Self::Pie => "-pie",
            Self::NoPie => "-no-pie",
        }
    }

    fn of(words: &[String]) -> Self {
        let has = |w: &str| words.iter().any(|x| x == w);
        if has("-shared") {
            Self::Shared
        } else if has("-static") && (has("-pie") || has("--no-dynamic-linker")) {
            Self::StaticPie
        } else if has("-static") {
            Self::Static
        } else if has("-pie") {
            Self::Pie
        } else {
            Self::NoPie
        }
    }
}

/// What one link line combines beyond the program's own objects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkInputs {
    /// The program the driver runs for the link (`collect2`, `ld`, `ld.lld`), as named.
    pub program: String,
    /// Every input the line names by path, in order: each word that is neither an option
    /// nor the value of one ([`VALUED_OPTIONS`]), whatever its name. These are the startup
    /// objects (`crt1.o`, `Scrt1.o`, `rcrt1.o`, `crti.o`, `crtbegin*.o`, `crtend*.o`,
    /// `crtn.o`, `clang_rt.crtbegin.o`), any archive named whole
    /// (`libclang_rt.builtins.a`), and any other file a specs or configuration file hands
    /// the linker, which ld reads as an input whatever its extension.
    pub objects: Vec<String>,
    /// The `-L` directories, in search order, each once.
    pub library_dirs: Vec<String>,
    /// The `--sysroot=` the line hands the linker, where it hands one.
    pub sysroot: Option<String>,
    pub form: LinkageForm,
}

/// The words of one `-###` command line. clang quotes every word and gcc quotes those
/// holding a character outside its plain set; both escape `"`, `\` and `$` with a
/// backslash inside quotes, so a quoted path holding a space is one word.
pub(crate) fn words(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = line.chars().peekable();
    loop {
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        let Some(&first) = chars.peek() else {
            return out;
        };
        let mut word = String::new();
        if first == '"' {
            chars.next();
            while let Some(c) = chars.next() {
                match c {
                    '"' => break,
                    '\\' => word.extend(chars.next()),
                    other => word.push(other),
                }
            }
        } else {
            while let Some(c) = chars.next_if(|c| !c.is_whitespace()) {
                word.push(c);
            }
        }
        out.push(word);
    }
}

/// Whether a listing line is a command: both drivers indent each by one space before the
/// program, quoted (clang) or not (gcc, which prints its assembler as a bare `as`).
pub(crate) fn is_command(line: &str) -> bool {
    line.strip_prefix(' ')
        .is_some_and(|rest| rest.chars().next().is_some_and(|c| !c.is_whitespace()))
}

/// The linker options gcc's and clang's drivers write as two words, the option and then
/// its value, which is not an input: the output, emulation, loader, plugin, `-z` keyword,
/// `soname`, run paths, entry and undefined symbols. `-L` and `--sysroot` are read beside
/// them, not skipped. `-T` is left out on purpose: a linker script decides what the link
/// combines, so its path is read as an input and a script only one side names differs.
pub const VALUED_OPTIONS: [&str; 14] = [
    "-o",
    "-m",
    "-dynamic-linker",
    "-plugin",
    "-plugin-opt",
    "-z",
    "-soname",
    "-h",
    "-rpath",
    "-rpath-link",
    "-e",
    "-u",
    "-y",
    "-Y",
];

/// The link inputs of a `-###` listing's link line, or `None` where the listing holds
/// none.
///
/// The link line is the last command naming its program by path, quoted or not, which is
/// how `toolchain::link_line` finds it. A word is an input where it does not begin with
/// `-`, is not the value of one of [`VALUED_OPTIONS`], and is not the `-o` of an earlier
/// command, which is the compile step's temporary object for the empty input. Its name is
/// not consulted: ld takes a file named `unmarked`, `x.lo` or `X.O` as an input object as
/// readily as `x.o`, and a reading by suffix let a specs `*startfile` naming one through
/// unseen. The value of an option missing from the list is read as an input, so it
/// compares as one, which errs toward withholding. `-L` is read joined, as both drivers
/// write it, and as two words.
#[must_use]
pub fn parse(listing: &str) -> Option<LinkInputs> {
    let lines: Vec<&str> = listing.lines().filter(|l| is_command(l)).collect();
    let at = lines
        .iter()
        .rposition(|l| l.starts_with(" \"") || l.starts_with(" /"))?;
    let link = words(lines.get(at)?);
    let outputs: Vec<String> = lines
        .get(..at)?
        .iter()
        .flat_map(|l| {
            let w = words(l);
            w.iter()
                .zip(w.iter().skip(1))
                .filter(|(flag, _)| *flag == "-o")
                .map(|(_, value)| value.clone())
                .collect::<Vec<_>>()
        })
        .collect();
    let mut objects = Vec::new();
    let mut library_dirs: Vec<String> = Vec::new();
    let mut sysroot = None;
    let mut rest = link.iter().skip(1);
    while let Some(word) = rest.next() {
        let dir = if word == "-L" {
            rest.next().cloned()
        } else {
            word.strip_prefix("-L").map(str::to_owned)
        };
        if let Some(dir) = dir {
            if !library_dirs.contains(&dir) {
                library_dirs.push(dir);
            }
        } else if word == "--sysroot" {
            sysroot = rest.next().cloned();
        } else if let Some(root) = word.strip_prefix("--sysroot=") {
            sysroot = Some(root.to_owned());
        } else if VALUED_OPTIONS.contains(&word.as_str()) {
            rest.next();
        } else if !word.starts_with('-') && !outputs.contains(word) {
            objects.push(word.clone());
        }
    }
    Some(LinkInputs {
        program: link.first()?.clone(),
        objects,
        library_dirs,
        sysroot,
        form: LinkageForm::of(&link),
    })
}

/// Ask `driver` for its `-###` listing of a link of an empty C input under `flags`, and
/// read it. `Err` carries the sentence saying why it could not be read.
///
/// # Errors
///
/// Errors when the driver cannot be run, exits other than 0 ([`listing`]), or its listing
/// holds no command line.
pub fn query(driver: &Path, flags: &[String]) -> Result<LinkInputs, String> {
    let mut args = flags.to_vec();
    args.extend(
        ["-###", "-x", "c", "/dev/null", "-o", "/dev/null"]
            .iter()
            .map(|s| (*s).to_owned()),
    );
    let stderr = listing(driver, &args, &under(flags), Path::new(""))?;
    parse(&stderr).ok_or_else(|| {
        format!(
            "the driver's -### listing {} held no link line",
            under(flags)
        )
    })
}

/// The flags a query ran under, as the sentences name them: `under -O2 -fPIE`, or `under
/// no flags` where the query ran under none, so a `bare` cell's sentence does not run two
/// spaces together around a word it has nothing to say. For a query handed the whole of
/// a build's flags, as the two input comparisons' are; a query handed a named subset of
/// them says which subset through [`under_named`], since `under no flags` would be read
/// as a claim about the profile.
pub(crate) fn under(flags: &[String]) -> String {
    if flags.is_empty() {
        "under no flags".to_owned()
    } else {
        format!("under {}", flags.join(" "))
    }
}

/// [`under`] for a query that ran under a named subset of a build's flags, `what` naming
/// the subset in the singular: `under the link-selection flag -fuse-ld=lld`, `under the
/// link-selection flags -fuse-ld=lld -B/opt/bin`, or `with no link-selection flag` where
/// the subset is empty. The empty case names the subset rather than saying `no flags`,
/// because the profile may well have flags that are not of this kind: `under no flags` for
/// an `openssf-tldr` profile whose listing the driver rejected would read as a claim about
/// the profile.
pub(crate) fn under_named(flags: &[String], what: &str) -> String {
    match flags {
        [] => format!("with no {what}"),
        [one] => format!("under the {what} {one}"),
        many => format!("under the {what}s {}", many.join(" ")),
    }
}

/// Run `driver` over `args` (a `-###` query: the flags it ran under and the query's own
/// words) and return the listing it printed to stderr, or the sentence saying why it is
/// not one to read. `under` is the phrase naming those flags in the sentence, rendered by
/// the caller through [`under`] or [`under_named`], since only the caller knows whether
/// the flags are a build's whole list or a named part of one. Shared with
/// [`crate::compile_inputs::query`] and `toolchain::read_link_line`, so the three readers
/// read a listing under one rule.
///
/// A driver that exits other than 0 has rejected the command it was asked to list, so the
/// listing describes a build that would not run, and it is not read whatever it holds. The
/// exit status decides and not the wording of a diagnostic, because no wording is common to
/// every driver. In a fleet sweep, clang 3.4 and 3.8 (Ubuntu 14.04 and 16.04) exit 1 on the
/// arms' `-no-pie`, an argument neither knows, and still print a link line, which a reader
/// that ignored the status would compare.
///
/// `workdir` is [`diagnostic_line`]'s, for the driver's words the sentence quotes: the
/// two comparisons hand an empty path, since their sentence becomes a gating's reason and
/// `measure::publish` makes it relative there; the linker detection hands the
/// measurement's, since nothing rewrites `toolchain.linker.detection` after it.
///
/// # Errors
///
/// Errors when the driver cannot be run or exits other than 0; the sentence says how it
/// ended ([`compile::BuildRecord::ended`]) and quotes the driver's diagnostic as
/// [`diagnostic_line`] picks and publishes it, or says `no diagnostic on stderr`.
pub(crate) fn listing(
    driver: &Path,
    args: &[String],
    under: &str,
    workdir: &Path,
) -> Result<String, String> {
    let record = compile::capture(driver, args)
        .map_err(|why| format!("the driver did not answer -### ({why:#})"))?;
    if record.succeeded() {
        return Ok(record.stderr);
    }
    let said = diagnostic_line(&record.stderr, workdir)
        .unwrap_or_else(|| "no diagnostic on stderr".to_owned());
    Err(format!(
        "the driver {} on its -### listing {under} ({said})",
        record.ended()
    ))
}

/// The line of a failed query's stderr the sentence quotes, ready for publication: the first line
/// holding `error:`, the word with its colon, as gcc, clang, tcc and the linkers all shape a
/// diagnostic (`cc: error: ...`, `cc: fatal error: ...`, `ld.lld: error: ...`). The colon is what
/// keeps a command-line word out: a listing echoes the query's own `-Werror=format` on every
/// command it prints, so without the colon a match on the bare word `error` could quote one of
/// those commands as the diagnostic. Where no line has the shape, `None`, and the sentence says so
/// rather than quoting the first line of stderr, which on a `-###` listing is the driver's version
/// banner or its first command and not what the driver objected to.
///
/// The line passes through [`crate::measure::publish_text`] against `workdir` before the
/// 200-character cut, as `compile::BuildRecord::first_stderr_line` does, so a path under
/// the work directory is made relative, a temporary name is scrubbed, and the budget is
/// spent on what is kept. The sentence lands in `toolchain.linker.detection` as well as in
/// a gating's reason, and this one quote is published there rather than as the driver
/// wrote it. Only the quote is published so: the flags the sentence names are the profile's, and
/// stay spelled as `profile_flags` spells them.
fn diagnostic_line(stderr: &str, workdir: &Path) -> Option<String> {
    stderr
        .lines()
        .map(str::trim)
        .find(|line| line.contains("error:"))
        .map(|line| {
            crate::measure::publish_text(line, workdir)
                .chars()
                .take(200)
                .collect()
        })
}

/// A path as the comparison reads it: resolved, or as written where it does not resolve.
pub(crate) fn resolved(path: &str) -> String {
    std::fs::canonicalize(path).map_or_else(|_| path.to_owned(), |p| p.display().to_string())
}

/// Where the arms' link differs from the measured one, as a sentence naming each side's
/// files, or `None` where they run the same link program over the same inputs,
/// directories and system root once resolved. The forms are not compared: the arms' listing is taken under the
/// measured one's.
#[must_use]
pub fn difference(measured: &LinkInputs, arms: &LinkInputs) -> Option<String> {
    let sides = [
        (
            "link program",
            resolve_all(std::slice::from_ref(&measured.program)),
            resolve_all(std::slice::from_ref(&arms.program)),
        ),
        (
            "inputs",
            resolve_all(&measured.objects),
            resolve_all(&arms.objects),
        ),
        (
            "library directories",
            resolve_all(&measured.library_dirs),
            resolve_all(&arms.library_dirs),
        ),
        (
            "system root",
            resolve_all(measured.sysroot.as_slice()),
            resolve_all(arms.sysroot.as_slice()),
        ),
    ];
    describe_sides(sides, "its", "the arms'")
}

/// Each path of `list` [`resolved`], each once, in order.
fn resolve_all(list: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for path in list.iter().map(|p| resolved(p)) {
        if !out.contains(&path) {
            out.push(path);
        }
    }
    out
}

/// The sentence naming where two sides' resolved lists differ, each list by what it is
/// (`link program`, `inputs`), the first side by `own` (`its`) and the second by `other`
/// (`the arms'`); `None` where every list is equal.
fn describe_sides<const N: usize>(
    sides: [(&str, Vec<String>, Vec<String>); N],
    own: &str,
    other: &str,
) -> Option<String> {
    let mut parts = Vec::new();
    for (what, m, a) in sides {
        if m == a {
            continue;
        }
        let only_m: Vec<&str> = m
            .iter()
            .filter(|p| !a.contains(p))
            .map(String::as_str)
            .collect();
        let only_a: Vec<&str> = a
            .iter()
            .filter(|p| !m.contains(p))
            .map(String::as_str)
            .collect();
        let none = |l: &[&str]| {
            if l.is_empty() {
                "none".to_owned()
            } else {
                l.join(", ")
            }
        };
        parts.push(if only_m.is_empty() && only_a.is_empty() {
            format!("{own} {what} are {other} in another order")
        } else {
            format!(
                "{own} {what} include {} where {other} include {}",
                none(&only_m),
                none(&only_a)
            )
        });
    }
    (!parts.is_empty()).then(|| parts.join("; "))
}

/// The directories a driver searches for the programs it runs and for the files it links,
/// as its `-print-search-dirs` answer names them: the `programs:` and `libraries:` lists,
/// each in order, with the `=` both gcc and clang print before a list left off.
///
/// A `-B` or `--prefix` prefix is the first entry of both lists under gcc and of the first
/// under clang, and it is where gcc's `collect2` finds the `ld` it runs, which gcc's
/// `-###` link line does not name: it names `collect2`. Measured on Fedora 44 x86_64 with
/// gcc 16.1.1 and clang 22.1.8: under `-B<dir>/` gcc's answer begins both lists with
/// `<dir>/<triple>/16/` and `<dir>/`, clang's begins `programs:` with `<dir>/`, and its
/// `-###` link line names `<dir>/ld` where `<dir>` holds one; without the prefix neither
/// list names it. An answer that lacks either list is not read as an empty one, which two
/// such answers would share and so agree on without naming a directory: it is no answer
/// ([`parse_search_dirs`]), and the comparison withholds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchDirs {
    pub programs: Vec<String>,
    pub libraries: Vec<String>,
}

/// The two lists of a `-print-search-dirs` answer ([`SearchDirs`]): each line `programs:`
/// or `libraries:` followed by its entries, separated by `:`, the first line of each key
/// read. `None` where the answer lacks either line: gcc and clang print both, and a list
/// the answer does not hold is no list, which two such answers would agree on without
/// naming a directory.
#[must_use]
pub fn parse_search_dirs(answer: &str) -> Option<SearchDirs> {
    let list = |key: &str| -> Option<Vec<String>> {
        let rest = answer.lines().find_map(|line| line.strip_prefix(key))?;
        let rest = rest.trim_start();
        let rest = rest.strip_prefix('=').unwrap_or(rest);
        Some(
            rest.split(':')
                .filter(|entry| !entry.is_empty())
                .map(str::to_owned)
                .collect(),
        )
    };
    Some(SearchDirs {
        programs: list("programs:")?,
        libraries: list("libraries:")?,
    })
}

/// Ask `driver` for its `-print-search-dirs` answer under `flags`, and read it
/// ([`parse_search_dirs`]). `Err` carries the sentence saying why it could not be read.
///
/// # Errors
///
/// Errors when the driver cannot be run, exits other than 0, prints an answer whose last
/// line is cut off, or prints one lacking either list.
pub fn query_search_dirs(driver: &Path, flags: &[String]) -> Result<SearchDirs, String> {
    let mut args = flags.to_vec();
    args.push("-print-search-dirs".to_owned());
    let record = compile::capture(driver, &args)
        .map_err(|why| format!("the driver did not answer -print-search-dirs ({why:#})"))?;
    if !record.succeeded() {
        let said = diagnostic_line(&record.stderr, Path::new(""))
            .unwrap_or_else(|| "no diagnostic on stderr".to_owned());
        return Err(format!(
            "the driver {} on -print-search-dirs {} ({said})",
            record.ended(),
            under(flags)
        ));
    }
    if record.stdout_unterminated {
        return Err(format!(
            "the driver's -print-search-dirs answer {} ended partway through a line",
            under(flags)
        ));
    }
    parse_search_dirs(&record.stdout).ok_or_else(|| {
        format!(
            "the driver's -print-search-dirs answer {} lacks its programs: or its libraries: \
             list",
            under(flags)
        )
    })
}

/// Where the clean build's link would run another linker program, or search another
/// directory for programs or libraries, than the measured build's, as a sentence naming
/// each side's entries, or `None` where the two agree once resolved.
///
/// `measured` is the measured build's `-###` link line and its `-print-search-dirs` answer;
/// `clean` is the link line of the clean build's flags with the measured line's linker
/// program selection (`toolchain::linker_program_flags`), the line the default-asking
/// check's arms link with, and the clean build's own answer. From each link line the
/// program, the `-L` directories and the system root are compared, and from each answer
/// its two lists: a `-L` directory reaches neither list (gcc 16.1.1 and clang 22.1.8 answer
/// the same lists with and without one, Fedora 44 x86_64), and through a `libc.so` script
/// there a directory chooses what the link reads. The link line is that one rather than the
/// clean build's own because the clean build leaves a program selection off on purpose
/// (`measure::clean_flags`): it links with the driver's default linker, and the measured
/// line's `-fuse-ld=lld` would otherwise differ by design; so where the profile selects a
/// program, the program the clean build itself runs is not compared (the assumption
/// `driver-answers-name-the-clean-link` names it). The search lists are read from the
/// clean build's own answer, since no program selection moves them. The inputs the link
/// lines name by path are not compared: the clean build links the toolchain's own startup
/// objects for its target and runtime, the default the check asks about, and an object the
/// profile names is not its subject.
#[must_use]
pub fn clean_link_difference(
    measured: (&LinkInputs, &SearchDirs),
    clean: (&LinkInputs, &SearchDirs),
) -> Option<String> {
    let ((measured_link, measured_dirs), (clean_link, clean_dirs)) = (measured, clean);
    let sides = [
        (
            "link program",
            resolve_all(std::slice::from_ref(&measured_link.program)),
            resolve_all(std::slice::from_ref(&clean_link.program)),
        ),
        (
            "library directories",
            resolve_all(&measured_link.library_dirs),
            resolve_all(&clean_link.library_dirs),
        ),
        (
            "system root",
            resolve_all(measured_link.sysroot.as_slice()),
            resolve_all(clean_link.sysroot.as_slice()),
        ),
        (
            "program search directories",
            resolve_all(&measured_dirs.programs),
            resolve_all(&clean_dirs.programs),
        ),
        (
            "library search directories",
            resolve_all(&measured_dirs.libraries),
            resolve_all(&clean_dirs.libraries),
        ),
    ];
    describe_sides(sides, "the measured build's", "the clean build's")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The collect2 line of gcc 16.1.1 on Fedora 44 x86_64 (2026-10-06) under
    /// Fedora's `redhat-hardened-ld`, trimmed of its plugin options, after the `as` step
    /// that writes the compile's temporary object.
    const GCC_PIE: &str = " /usr/libexec/gcc/x86_64-redhat-linux/16/cc1 -quiet /dev/null -o /tmp/ccA.s\n \
        as --64 -o /tmp/ccB.o /tmp/ccA.s\nCOMPILER_PATH=/usr/libexec/gcc/\n \
        /usr/libexec/gcc/x86_64-redhat-linux/16/collect2 -plugin /usr/libexec/gcc/x86_64-redhat-linux/16/liblto_plugin.so \
        \"-plugin-opt=-fresolution=/tmp/ccC.res\" --build-id --no-add-needed --eh-frame-hdr \"--hash-style=gnu\" \
        -m elf_x86_64 -dynamic-linker /lib64/ld-linux-x86-64.so.2 -pie -o /dev/null \
        /usr/lib/gcc/x86_64-redhat-linux/16/../../../../lib64/Scrt1.o \
        /usr/lib/gcc/x86_64-redhat-linux/16/../../../../lib64/crti.o \
        /usr/lib/gcc/x86_64-redhat-linux/16/crtbeginS.o -L/usr/lib/gcc/x86_64-redhat-linux/16 \
        -L/usr/lib/gcc/x86_64-redhat-linux/16/../../../../lib64 -L/lib/../lib64 -L/usr/lib/../lib64 -L/lib -L/usr/lib \
        /tmp/ccB.o -lgcc -lgcc_s_asneeded -lc /usr/lib/gcc/x86_64-redhat-linux/16/crtendS.o \
        /usr/lib/gcc/x86_64-redhat-linux/16/../../../../lib64/crtn.o\nCOLLECT_GCC_OPTIONS='-o' '/dev/null'\n";

    /// clang 22.1.8's two lines on the same host under `--config=` a file holding
    /// `--gcc-install-dir=` a directory with a space in its name, and `--rtlib=compiler-rt`.
    const CLANG: &str = "clang version 22.1.8\nConfiguration file: /srv/c.cfg\n \
        \"/usr/bin/clang-22\" \"-cc1\" \"-triple\" \"x86_64-redhat-linux-gnu\" \"-o\" \"/tmp/null-1a2b3c.o\" \"-x\" \"c\" \"/dev/null\"\n \
        \"/usr/bin/ld\" \"--hash-style=gnu\" \"-m\" \"elf_x86_64\" \"-dynamic-linker\" \"/lib64/ld-linux-x86-64.so.2\" \
        \"-o\" \"/dev/null\" \"/lib/../lib64/crt1.o\" \"/lib/../lib64/crti.o\" \"/srv/fake gcc/16/crtbegin.o\" \
        \"-L/srv/fake gcc/16\" \"-L\" \"/usr/lib64\" \"-L/usr/lib64\" \"--sysroot=/srv/root\" \"/tmp/null-1a2b3c.o\" \
        \"/usr/lib/clang/22/lib/x86_64-redhat-linux-gnu/libclang_rt.builtins.a\" \"-lc\" \
        \"/srv/fake gcc/16/crtend.o\" \"/lib/../lib64/crtn.o\"\n";

    /// Each listing's objects, directories, root and form are read whole, with the compile
    /// step's temporary object left out and every quoted path one word. The cases are
    /// counted against the inputs handed in.
    #[test]
    fn a_listing_names_the_startup_objects_directories_and_form_of_its_link() {
        let mut read = 0;
        let gcc = parse(GCC_PIE).expect("the gcc listing has a link line");
        read += 1;
        assert_eq!(
            gcc.objects,
            [
                "/usr/lib/gcc/x86_64-redhat-linux/16/../../../../lib64/Scrt1.o",
                "/usr/lib/gcc/x86_64-redhat-linux/16/../../../../lib64/crti.o",
                "/usr/lib/gcc/x86_64-redhat-linux/16/crtbeginS.o",
                "/usr/lib/gcc/x86_64-redhat-linux/16/crtendS.o",
                "/usr/lib/gcc/x86_64-redhat-linux/16/../../../../lib64/crtn.o",
            ],
            "the temporary /tmp/ccB.o is the as step's -o and is left out"
        );
        assert_eq!(gcc.library_dirs.len(), 6, "{:?}", gcc.library_dirs);
        assert_eq!(gcc.sysroot, None);
        assert_eq!(gcc.form, LinkageForm::Pie);

        let clang = parse(CLANG).expect("the clang listing has a link line");
        read += 1;
        assert_eq!(
            clang.objects,
            [
                "/lib/../lib64/crt1.o",
                "/lib/../lib64/crti.o",
                "/srv/fake gcc/16/crtbegin.o",
                "/usr/lib/clang/22/lib/x86_64-redhat-linux-gnu/libclang_rt.builtins.a",
                "/srv/fake gcc/16/crtend.o",
                "/lib/../lib64/crtn.o",
            ]
        );
        assert_eq!(
            clang.library_dirs,
            ["/srv/fake gcc/16", "/usr/lib64"],
            "joined and two-word -L read alike, each directory once"
        );
        assert_eq!(clang.sysroot.as_deref(), Some("/srv/root"));
        assert_eq!(clang.form, LinkageForm::NoPie);

        for (words, form) in [
            ("-shared -pie", LinkageForm::Shared),
            ("-static -pie --no-dynamic-linker", LinkageForm::StaticPie),
            ("-static", LinkageForm::Static),
            ("-pie", LinkageForm::Pie),
            ("", LinkageForm::NoPie),
        ] {
            let listing = format!(" /usr/bin/ld {words} -o /dev/null /x/crti.o\n");
            assert_eq!(parse(&listing).map(|l| l.form), Some(form), "{words}");
            read += 1;
        }
        assert_eq!(parse("gcc: error: no input files\n"), None);
        read += 1;

        // An input is read by position, not by name: a specs `*startfile` naming a file
        // with no extension, a `.lo`, an upper-case `.O` or a shared object by path hands
        // ld an input as surely as `crtbegin.o` does. Each option's value is not one.
        let odd = [
            "/srv/s.ld",
            "/srv/start/unmarked",
            "/srv/start/x.lo",
            "/srv/start/X.O",
            "/srv/start/libx.so",
        ];
        let listing = format!(
            " /usr/bin/ld -plugin /srv/p.so -m elf_x86_64 -dynamic-linker /lib64/ld.so -z now \
             -soname s -rpath /srv/r -e start -u sym -T {} -lc\n",
            odd.join(" ").replacen(' ', " -o /dev/null ", 1)
        );
        let read_odd = parse(&listing).expect("a link line");
        assert_eq!(
            read_odd.objects, odd,
            "every input and the -T script, and no other option's value"
        );
        assert_eq!(read_odd.program, "/usr/bin/ld");
        read += 1;
        assert_eq!(read, 9, "every listing handed in was read");
    }

    /// Two listings combining the same files through other spellings are equal; one
    /// naming another startup object, directory or root differs, and the sentence names
    /// the file on each side. Counted against the cases handed in.
    #[test]
    fn listings_differ_exactly_where_a_resolved_input_does() {
        let dir = std::env::temp_dir().join(format!("chard-link-inputs-{}", std::process::id()));
        let lib = dir.join("lib");
        std::fs::create_dir_all(&lib).expect("scratch directory");
        let crt = lib.join("crtbeginS.o");
        std::fs::write(&crt, b"").expect("scratch object");
        let other = lib.join("other.o");
        std::fs::write(&other, b"").expect("scratch object");
        let spelled = |p: &Path| p.display().to_string();
        let roundabout = format!("{}/../lib/crtbeginS.o", lib.display());
        let base = LinkInputs {
            program: "/usr/bin/ld".to_owned(),
            objects: vec![spelled(&crt)],
            library_dirs: vec![spelled(&lib)],
            sysroot: None,
            form: LinkageForm::Pie,
        };
        let cases = [
            (
                LinkInputs {
                    program: "/usr/bin/../bin/ld".to_owned(),
                    objects: vec![roundabout.clone()],
                    library_dirs: vec![format!("{}/.", lib.display()), spelled(&lib)],
                    sysroot: None,
                    form: LinkageForm::NoPie,
                },
                None,
            ),
            (
                LinkInputs {
                    program: "/srv/other/ld".to_owned(),
                    ..base.clone()
                },
                Some("/srv/other/ld".to_owned()),
            ),
            (
                LinkInputs {
                    objects: vec![spelled(&other)],
                    ..base.clone()
                },
                Some(spelled(&other)),
            ),
            (
                LinkInputs {
                    library_dirs: vec![spelled(&dir)],
                    ..base.clone()
                },
                Some(spelled(&dir)),
            ),
            (
                LinkInputs {
                    sysroot: Some("/srv/no-such-root".to_owned()),
                    ..base.clone()
                },
                Some("/srv/no-such-root".to_owned()),
            ),
            (
                LinkInputs {
                    objects: vec![spelled(&other), spelled(&crt)],
                    ..base.clone()
                },
                Some(spelled(&other)),
            ),
        ];
        let mut compared = 0;
        for (arms, quoted) in &cases {
            let found = difference(&base, arms);
            match quoted {
                None => assert_eq!(found, None, "{arms:?}"),
                Some(path) => {
                    let sentence = found.unwrap_or_else(|| panic!("no difference: {arms:?}"));
                    assert!(sentence.contains(path.as_str()), "{sentence}");
                }
            }
            compared += 1;
        }
        let reordered = LinkInputs {
            objects: vec![spelled(&other), spelled(&crt)],
            ..base.clone()
        };
        let swapped = LinkInputs {
            objects: vec![spelled(&crt), spelled(&other)],
            ..base.clone()
        };
        assert!(
            difference(&reordered, &swapped).is_some_and(|s| s.contains("another order")),
            "the same files in another order differ"
        );
        compared += 1;
        assert_eq!(compared, cases.len() + 1);
        std::fs::remove_dir_all(&dir).expect("removing the scratch directory");
    }

    /// A driver that prints a listing and exits 1 gives no listing to read, to either
    /// comparison: the shape of clang 3.4 and 3.8 under `-no-pie`, which they reject and
    /// still list (a fleet sweep, Ubuntu 14.04 and 16.04). The same listing under
    /// exit 0 is read by both, so what the refusal turns on is the status and not the text.
    /// Counted against the drivers handed in.
    #[test]
    fn a_driver_that_exits_other_than_0_gives_no_listing_to_read() {
        let dir = std::env::temp_dir().join(format!("chard-listing-status-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch directory");
        let listing = "clang version 3.8.0\n\
            clang: error: unknown argument: '-no-pie'\n \
            \"/usr/bin/clang\" \"-cc1\" \"-triple\" \"x86_64-pc-linux-gnu\" \"-emit-obj\" \
            \"-o\" \"/tmp/null-1a.o\" \"-x\" \"c\" \"/dev/null\"\n \
            \"/usr/bin/ld\" \"-o\" \"/dev/null\" \"/usr/lib/x86_64-linux-gnu/crt1.o\" \
            \"/tmp/null-1a.o\" \"-lc\"\n";
        let flags = vec!["-no-pie".to_owned()];
        let mut fed = 0;
        for status in [0, 1] {
            let driver = compile::test_script(
                &dir.join(format!("exits-{status}")),
                &format!("printf '%s' '{listing}' >&2\nexit {status}"),
            );
            fed += 1;
            let link = query(&driver, &flags);
            let compile = crate::compile_inputs::query(&driver, &flags, "c");
            if status == 0 {
                let link = link.expect("exit 0: the link line is read");
                assert_eq!(link.objects, ["/usr/lib/x86_64-linux-gnu/crt1.o"]);
                compile.expect("exit 0: the compile command is read");
            } else {
                for why in [link.map(|_| ()), compile.map(|_| ())] {
                    let why = why.expect_err("exit 1: no listing is read");
                    // The script's single quotes swallow the diagnostic's own.
                    assert_eq!(
                        why,
                        "the driver exited 1 on its -### listing under -no-pie (clang: error: \
                         unknown argument: -no-pie)"
                    );
                }
            }
        }
        assert_eq!(fed, 2, "a driver exiting 0 and one exiting 1");
        std::fs::remove_dir_all(&dir).expect("removing the scratch directory");
    }

    /// A static link reads as static-pie from `-pie` or from `--no-dynamic-linker`, either
    /// alone, and as static from neither.
    #[test]
    fn a_static_link_reads_as_static_pie_from_either_word() {
        let form = |words: &[&str]| {
            LinkageForm::of(&words.iter().map(|w| (*w).to_owned()).collect::<Vec<_>>())
        };
        assert_eq!(form(&["-static", "-pie"]), LinkageForm::StaticPie);
        assert_eq!(
            form(&["-static", "--no-dynamic-linker"]),
            LinkageForm::StaticPie
        );
        assert_eq!(form(&["-static"]), LinkageForm::Static);
    }

    /// A listing a signal ended is refused in `BuildRecord::ended`'s words, never "exited -1".
    #[test]
    fn a_listing_a_signal_ended_names_the_signal() {
        let dir = std::env::temp_dir().join(format!("chard-listing-signal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch directory");
        let driver = compile::test_script(
            &dir.join("killed"),
            "printf '%s\\n' 'cc: error: gone' >&2\nkill -KILL $$",
        );
        let why = query(&driver, &["-no-pie".to_owned()]).expect_err("no listing is read");
        assert_eq!(
            why,
            "the driver was killed by a signal on its -### listing under -no-pie (cc: error: \
             gone)"
        );
        std::fs::remove_dir_all(&dir).expect("removing the scratch directory");
    }

    /// The two phrases naming a query's flags: `under` for a build's whole list, which says
    /// `no flags` where the list is empty, and `under_named` for a named part of one, which
    /// names the part in the empty case too, since `no flags` there would be read as a
    /// claim about the profile.
    #[test]
    fn the_flags_a_query_ran_under_are_named_for_what_they_are() {
        let none: [String; 0] = [];
        let one = ["-fuse-ld=lld".to_owned()];
        let two = ["-O2".to_owned(), "-fPIE".to_owned()];
        assert_eq!(under(&none), "under no flags");
        assert_eq!(under(&one), "under -fuse-ld=lld");
        assert_eq!(under(&two), "under -O2 -fPIE");
        assert_eq!(
            under_named(&none, "link-selection flag"),
            "with no link-selection flag"
        );
        assert_eq!(
            under_named(&one, "link-selection flag"),
            "under the link-selection flag -fuse-ld=lld"
        );
        assert_eq!(
            under_named(&two, "link-selection flag"),
            "under the link-selection flags -O2 -fPIE"
        );
    }

    /// The line a rejected query's sentence quotes is the first shaped as a diagnostic,
    /// `error:` with its colon, not the first holding the word: a `-###` listing echoes a
    /// `-Werror=` flag on every command, and a match on the bare word could quote a command
    /// as the diagnostic. Where no line has the shape there is no
    /// quote, rather than the banner or the first command. A temporary name is scrubbed
    /// before the 200-character cut.
    #[test]
    fn the_quoted_line_is_a_diagnostic_or_nothing() {
        let listing_with_werror = "clang version 22.1.8\n \
            \"/usr/bin/clang\" \"-cc1\" \"-Werror=format\" \"-o\" \"/tmp/null-1a.o\"\n\
            clang: error: unknown argument: '-no-pie'\n";
        assert_eq!(
            diagnostic_line(listing_with_werror, Path::new("")).as_deref(),
            Some("clang: error: unknown argument: '-no-pie'"),
            "the command carrying -Werror= is not the diagnostic"
        );
        assert_eq!(
            diagnostic_line(
                "cc: fatal error: no input files\ncompilation terminated.\n",
                Path::new("")
            )
            .as_deref(),
            Some("cc: fatal error: no input files")
        );
        assert_eq!(
            diagnostic_line(
                "clang version 22.1.8\n \"/usr/bin/clang\" \"-Werror\"\n",
                Path::new("")
            ),
            None,
            "a listing with no diagnostic quotes nothing"
        );
        assert_eq!(diagnostic_line("", Path::new("")), None);
        let scrubbed = diagnostic_line(
            "ld: error: cannot open /tmp/ccAbC123.o: No such file\n",
            Path::new(""),
        )
        .expect("a diagnostic");
        assert!(
            !scrubbed.contains("ccAbC123"),
            "the temporary name is scrubbed: {scrubbed}"
        );
        assert_eq!(
            diagnostic_line(
                "cc: error: cannot read /tmp/wd/late.rsp\n",
                Path::new("/tmp/wd")
            )
            .as_deref(),
            Some("cc: error: cannot read late.rsp"),
            "a path under the work directory is made relative"
        );
        let long = format!("cc: error: {}", "x".repeat(300));
        assert_eq!(
            diagnostic_line(&long, Path::new("")).map(|l| l.chars().count()),
            Some(200),
            "the quote is cut at 200 characters"
        );
    }

    /// gcc 16.1.1's and clang 22.1.8's `-print-search-dirs` answers on Fedora 44 x86_64 under
    /// `-B/srv/px/`, trimmed, and an answer holding neither list: each list is read in order
    /// without the leading `=`, and an answer without a list reads it empty.
    #[test]
    fn a_search_dirs_answer_names_its_program_and_library_lists() {
        let gcc = "install: /usr/lib/gcc/x86_64-redhat-linux/16/\nprograms: =/srv/px/x86_64-redhat-linux/16/:/srv/px/:/usr/libexec/gcc/x86_64-redhat-linux/16/\nlibraries: =/srv/px/x86_64-redhat-linux/16/:/srv/px/:/usr/lib/gcc/x86_64-redhat-linux/16/:/lib/\n";
        let read = parse_search_dirs(gcc).expect("gcc's answer holds both lists");
        assert_eq!(
            read.programs,
            [
                "/srv/px/x86_64-redhat-linux/16/",
                "/srv/px/",
                "/usr/libexec/gcc/x86_64-redhat-linux/16/"
            ]
        );
        assert_eq!(
            read.libraries,
            [
                "/srv/px/x86_64-redhat-linux/16/",
                "/srv/px/",
                "/usr/lib/gcc/x86_64-redhat-linux/16/",
                "/lib/"
            ]
        );
        let clang = "programs: =/srv/px/:/usr/bin\nlibraries: =/usr/bin/../lib/clang/22\n";
        let read = parse_search_dirs(clang).expect("clang's answer holds both lists");
        assert_eq!(read.programs, ["/srv/px/", "/usr/bin"]);
        assert_eq!(read.libraries, ["/usr/bin/../lib/clang/22"]);
        for lacking in [
            "",
            "programs: =/usr/bin\n",
            "libraries: =/usr/lib\n",
            "install: /srv/cc\ninclude:\n  /usr/include\ncrt:\n  /usr/lib\n",
        ] {
            assert_eq!(parse_search_dirs(lacking), None, "{lacking:?} is no answer");
        }
    }

    /// The clean build's link is held to the measured one on the program, the `-L`
    /// directories and the system root of the link line and on both search lists, each in
    /// order: equal answers agree, the inputs the lines name decide nothing, and each other
    /// field on one side alone, or a list in another order, is named with the side it is on.
    #[test]
    fn the_clean_link_is_held_to_the_measured_program_and_search_directories() {
        let link =
            |program: &str, objects: &[&str], dirs: &[&str], root: Option<&str>| LinkInputs {
                program: program.to_owned(),
                objects: objects.iter().map(|o| (*o).to_owned()).collect(),
                library_dirs: dirs.iter().map(|d| (*d).to_owned()).collect(),
                sysroot: root.map(str::to_owned),
                form: LinkageForm::Pie,
            };
        let lists = |programs: &[&str], libraries: &[&str]| SearchDirs {
            programs: programs.iter().map(|p| (*p).to_owned()).collect(),
            libraries: libraries.iter().map(|l| (*l).to_owned()).collect(),
        };
        let ld = "/srv/nowhere/ld";
        let host_link = link(ld, &["/srv/a.o"], &["/srv/nowhere/lib"], None);
        let host = lists(
            &["/srv/nowhere/bin"],
            &["/srv/nowhere/lib", "/srv/other/lib"],
        );
        let other_objects = link(ld, &["/srv/b.o"], &["/srv/nowhere/lib"], None);
        assert_eq!(
            clean_link_difference((&host_link, &host), (&other_objects, &host)),
            None,
            "the inputs are not compared"
        );
        // Two spellings of one directory agree once resolved: `/usr/..` is `/` on any host
        // that has a `/usr`, and an unresolved comparison reads them apart.
        if std::path::Path::new("/usr").is_dir() {
            let spelled = |root: &str| link(ld, &[], &["/srv/nowhere/lib"], Some(root));
            assert_eq!(
                clean_link_difference((&spelled("/"), &host), (&spelled("/usr/.."), &host)),
                None,
                "a system root is compared resolved"
            );
        }
        let cases: [(LinkInputs, SearchDirs, &str); 6] = [
            (
                link("/srv/px/ld", &[], &["/srv/nowhere/lib"], None),
                host.clone(),
                "the measured build's link program include /srv/nowhere/ld where the clean \
                 build's include /srv/px/ld",
            ),
            (
                link(ld, &[], &["/srv/px", "/srv/nowhere/lib"], None),
                host.clone(),
                "the measured build's library directories include none where the clean \
                 build's include /srv/px",
            ),
            (
                link(ld, &[], &["/srv/nowhere/lib"], Some("/srv/root")),
                host.clone(),
                "the measured build's system root include none where the clean build's \
                 include /srv/root",
            ),
            (
                host_link.clone(),
                lists(
                    &["/srv/px/", "/srv/nowhere/bin"],
                    &["/srv/nowhere/lib", "/srv/other/lib"],
                ),
                "the measured build's program search directories include none where the clean \
                 build's include /srv/px/",
            ),
            (
                host_link.clone(),
                lists(
                    &["/srv/nowhere/bin"],
                    &["/srv/px/", "/srv/nowhere/lib", "/srv/other/lib"],
                ),
                "the measured build's library search directories include none where the clean \
                 build's include /srv/px/",
            ),
            (
                host_link.clone(),
                lists(
                    &["/srv/nowhere/bin"],
                    &["/srv/other/lib", "/srv/nowhere/lib"],
                ),
                "the measured build's library search directories are the clean build's in \
                 another order",
            ),
        ];
        for (clean_link, clean, said) in &cases {
            let found = clean_link_difference((&host_link, &host), (clean_link, clean))
                .unwrap_or_else(|| panic!("{said}: no difference found"));
            assert_eq!(found, *said);
        }
    }
}
