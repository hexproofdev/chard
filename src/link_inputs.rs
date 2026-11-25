// SPDX-License-Identifier: BSD-3-Clause

//! What a driver's `-###` listing says a link combines beyond the program's own objects:
//! the program it runs for the link, every input it names by path (the startup objects and
//! archives, whatever their names), the library directories it searches and the system
//! root it hands the linker, and the linkage form (`-pie`, `-shared`, `-static`).

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::compile;

/// The output kind a link line produces, read from the words the driver handed the
/// linker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
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
    /// Every form, which `listings.*.form` in the report schema is pinned to.
    pub const ALL: [Self; 5] = [
        Self::Shared,
        Self::StaticPie,
        Self::Static,
        Self::Pie,
        Self::NoPie,
    ];

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkInputs {
    /// The program the driver runs for the link (`collect2`, `ld`, `ld.lld`), as named.
    pub program: String,
    /// Every input the line names by path, in order: each word that is neither an option
    /// nor the value of one ([`VALUED_OPTIONS`]), whatever its name: the startup objects,
    /// any archive named whole, and any other file a specs or configuration file hands the
    /// linker.
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
/// Errors when the driver cannot be run, exits other than 0 (`listing`), or its listing
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
/// no flags` where the query ran under none. For a query handed the whole of a build's
/// flags; a query handed a named subset of them says which subset through
/// [`under_named`], since `under no flags` would be read as a claim about the profile.
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
/// the subset is empty, since the profile may have flags of another kind.
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
/// the caller through [`under`] or [`under_named`]. Shared with
/// [`crate::compile_inputs::query`], [`crate::overridden::query`] and
/// `toolchain::read_link_line`, so the four readers read a listing under one rule.
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

/// The line of a failed query's stderr the sentence quotes, ready for publication: the first
/// line holding `error:`, the word with its colon, as gcc, clang, tcc and the linkers all
/// shape a diagnostic (`cc: error: ...`, `ld.lld: error: ...`). The colon keeps out the
/// commands a listing prints, which echo the query's own `-Werror=format`. Where no line has
/// the shape, `None`, rather than the version banner or first command a `-###` listing
/// begins with.
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

/// How a comparison reads the paths a listing names: the two questions it asks of the
/// filesystem, and nothing else of it.
pub trait Resolve {
    /// The path as the comparison reads it: resolved, or as written where it does not
    /// resolve.
    fn resolved(&self, path: &str) -> String;
    /// Whether the path names a directory.
    fn is_dir(&self, path: &str) -> bool;
}

/// What the comparisons of one probe read of the filesystem, each path as the listing wrote
/// it: what it resolved to ([`Resolve::resolved`]), and whether it is a directory
/// ([`Resolve::is_dir`]), for each path the question was asked of.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathAnswers {
    pub resolved: BTreeMap<String, String>,
    pub directories: BTreeMap<String, bool>,
}

/// The host's filesystem, read through `fs::canonicalize` and `Path::is_dir`, each answer
/// kept: [`Host::answers`] is the record a replay reads in its place.
#[derive(Debug, Default)]
pub struct Host {
    answers: RefCell<PathAnswers>,
}

impl Host {
    /// Every answer given, by path.
    #[must_use]
    pub fn answers(self) -> PathAnswers {
        self.answers.into_inner()
    }
}

impl Resolve for Host {
    fn resolved(&self, path: &str) -> String {
        let answer = std::fs::canonicalize(path)
            .map_or_else(|_| path.to_owned(), |p| p.display().to_string());
        self.answers
            .borrow_mut()
            .resolved
            .insert(path.to_owned(), answer.clone());
        answer
    }

    fn is_dir(&self, path: &str) -> bool {
        let answer = Path::new(path).is_dir();
        self.answers
            .borrow_mut()
            .directories
            .insert(path.to_owned(), answer);
        answer
    }
}

/// Where the arms' link differs from the measured one, as a sentence naming each side's
/// files, or `None` where they run the same link program over the same inputs,
/// directories and system root once resolved. The forms are not compared: the arms'
/// listing is taken under the measured one's.
#[must_use]
pub fn difference(measured: &LinkInputs, arms: &LinkInputs, paths: &dyn Resolve) -> Option<String> {
    let resolve_all = |list: &[String]| resolve_all(list, paths);
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

/// Each path of `list` [`Resolve::resolved`], each once, in order.
fn resolve_all(list: &[String], paths: &dyn Resolve) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for path in list.iter().map(|p| paths.resolved(p)) {
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchDirs {
    pub programs: Vec<String>,
    pub libraries: Vec<String>,
}

/// The two lists of a `-print-search-dirs` answer ([`SearchDirs`]): each line `programs:`
/// or `libraries:` followed by its entries, separated by `:`, the first line of each key
/// read. `None` where the answer lacks either line ([`SearchDirs`] says why).
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
            "the driver's -print-search-dirs answer {} lacks its programs",
            under(flags)
        )
    })
}

/// Where the clean build's link would run another linker program, or search another
/// directory for programs or libraries, than the measured build's, as a sentence naming
/// each side's entries, or `None` where the two agree once resolved.
#[must_use]
pub fn clean_link_difference(
    measured: (&LinkInputs, &SearchDirs),
    clean: (&LinkInputs, &SearchDirs),
    paths: &dyn Resolve,
) -> Option<String> {
    let ((measured_link, measured_dirs), (clean_link, clean_dirs)) = (measured, clean);
    let resolve_all = |list: &[String]| resolve_all(list, paths);
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
        // ld an input as surely as `crtbegin.o` does.
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
            let found = difference(&base, arms, &Host::default());
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
            difference(&reordered, &swapped, &Host::default())
                .is_some_and(|s| s.contains("another order")),
            "the same files in another order differ"
        );
        compared += 1;
        assert_eq!(compared, cases.len() + 1);
        std::fs::remove_dir_all(&dir).expect("removing the scratch directory");
    }

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
            clean_link_difference(
                (&host_link, &host),
                (&other_objects, &host),
                &Host::default()
            ),
            None,
            "the inputs are not compared"
        );
        // Two spellings of one directory agree once resolved: `/usr/..` is `/` on any host
        // that has a `/usr`, and an unresolved comparison reads them apart.
        if Path::new("/usr").is_dir() {
            let spelled = |root: &str| link(ld, &[], &["/srv/nowhere/lib"], Some(root));
            assert_eq!(
                clean_link_difference(
                    (&spelled("/"), &host),
                    (&spelled("/usr/.."), &host),
                    &Host::default()
                ),
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
            let found =
                clean_link_difference((&host_link, &host), (clean_link, clean), &Host::default())
                    .unwrap_or_else(|| panic!("{said}: no difference found"));
            assert_eq!(found, *said);
        }
    }
}
