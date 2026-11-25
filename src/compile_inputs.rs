// SPDX-License-Identifier: BSD-3-Clause

//! What a driver's `-###` listing says a compile reads beyond the probe's own source: the
//! compile programs it runs, the header search directories, system root and forced
//! includes it hands them, the macros it defines or undefines, and the defaults it
//! removes.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::link_inputs::{Resolve, is_command, words};
use crate::toolchain::{Hand, read, spelled_alone};

/// The code-model words gcc's `cc1` carries as written, which `report::lto_codegen_limitation`
/// reads for gcc: the last of them is the model the compile asked for. clang's `-cc1` carries none
/// of them, its model resolved into `-mrelocation-model`.
pub const GCC_CODE_MODEL_WORDS: &[&str] = &[
    "-fPIC", "-fpic", "-fPIE", "-fpie", "-fno-PIC", "-fno-pic", "-fno-PIE", "-fno-pie",
];

/// What the compile commands of one listing read beyond the probe's source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompileInputs {
    /// The compile programs (`cc1`, `cc1plus`, clang's own path before `-cc1`), as named,
    /// one per compile command.
    pub programs: Vec<String>,
    /// Every header search directory, system root, resource directory and forced include
    /// the commands carry, in order, as the option and its value ([`HEADER_OPTIONS`]).
    pub headers: Vec<(String, String)>,
    /// Every `-D` and `-U`, in order, joined to its operand.
    pub macros: Vec<String>,
    /// Every word removing a default the compile would otherwise read ([`REMOVALS`]).
    pub removals: Vec<String>,
    /// The target each command compiles for, which decides the architecture's predefined
    /// macros: clang's `-triple` value, and gcc's `-m16`, `-m32`, `-m64` and `-mx32`
    /// words (`TARGET_WORDS`).
    pub targets: Vec<String>,
    /// Every sanitizer word (`-fsanitize`, `-fno-sanitize`, `-fsanitize-trap`,
    /// `-fno-sanitize-trap` and kin), in order, as the compile command receives it: clang's
    /// resolved group lists, gcc's words as written. Not compared by [`difference`], since the
    /// arms carry none; read by `report::sanitizer_group_limitation`.
    pub sanitizers: Vec<String>,
    /// Every word that turns link-time optimization on or off (`-flto`, `-flto=<mode>`,
    /// `-fno-lto`), in order, as the compile command receives it: clang's resolved mode,
    /// gcc's words as written. `-flto-unit` and the `-flto-` tuning options are not among
    /// them. Not compared by [`difference`], since the arms carry none; read by
    /// `report::lto_codegen_limitation`.
    pub lto: Vec<String>,
    /// The code-model words the compile command carries, in order, as the driver resolved
    /// them: clang's `-mrelocation-model <model>` and `-pic-level <n>` with their values
    /// joined by a space, and `-pic-is-pie`; gcc's `cc1` carries its own words as written
    /// ([`GCC_CODE_MODEL_WORDS`]), and a default the driver configured (Ubuntu's PIE) as none.
    /// Not compared by [`difference`]; read by `report::lto_codegen_limitation`.
    pub relocation: Vec<String>,
    /// The exception model the compile command is told to use, in order: clang's
    /// `-exception-model=<model>`, or `-exception-model` and its value kept joined, and the
    /// driver's spellings (`DRIVER_MODEL_WORDS`). Empty under the default model and for gcc.
    /// Not compared by [`difference`]; compared by [`exception_model_difference`] for the
    /// checks `report::EXCEPTION_MODEL_READINGS` names.
    pub exception_models: Vec<String>,
}

/// The driver's exception-model selectors, read on a compile command as well, for a `-cc1`
/// that takes the model in the driver's spelling rather than as `-exception-model=`: a model
/// a listing names in a spelling the reader does not know would read as the default on both
/// sides and compare equal. clang 22.1.8's `-cc1` rejects all four (Fedora 44 x86_64,
/// 2026-10-21), so on it they never stand on a compile line.
const DRIVER_MODEL_WORDS: [&str; 4] = [
    "-fsjlj-exceptions",
    "-fdwarf-exceptions",
    "-fseh-exceptions",
    "-fwasm-exceptions",
];

/// The compile-command options whose value is a header search directory, a system root,
/// the resource directory clang's built-in headers come from, or a file read before the
/// source, spelled as gcc's `cc1` and clang's `-cc1` receive them. Read joined, with or
/// without `=`, and as two words; a word is read by the longest of these it begins with,
/// so `-isystem-after` is not `-isystem` and `-include-pch` is not `-include`.
pub const HEADER_OPTIONS: [&str; 28] = [
    "-I",
    "-F",
    "-isystem",
    "-isystem-after",
    "-idirafter",
    "-iquote",
    "-iprefix",
    "-iwithprefix",
    "-iwithprefixbefore",
    "-iwithsysroot",
    "-isysroot",
    "--sysroot",
    "-imultilib",
    "-imultiarch",
    "-iframework",
    "-iframeworkwithsysroot",
    "-internal-isystem",
    "-internal-externc-isystem",
    "-c-isystem",
    "-cxx-isystem",
    "-objc-isystem",
    "-objcxx-isystem",
    "-stdlib++-isystem",
    "-resource-dir",
    "-ivfsoverlay",
    "-include",
    "-include-pch",
    "-imacros",
];

/// The [`HEADER_OPTIONS`] whose value is a directory searched as it is written, which a
/// compile skips where it is not one: gcc 16.1.1 and clang 22.1.8 print "ignoring
/// nonexistent directory" and leave it out of the `-v -E` search list. [`difference`]
/// leaves such a directory out too, so a `--gcc-install-dir=` copy without the
/// `<triple>/include` directory clang names beside it does not differ there. Measured on
/// 2026-10-07 on Fedora 44 x86_64: under `--config=` such a file, clang 22.1.8's C
/// listing named `-internal-isystem` a missing directory where the arms' named the host's
/// equally missing one, and the two `-v -E` search lists were equal.
const SEARCH_DIRECTORY_OPTIONS: [&str; 14] = [
    "-I",
    "-F",
    "-isystem",
    "-isystem-after",
    "-idirafter",
    "-iquote",
    "-iframework",
    "-internal-isystem",
    "-internal-externc-isystem",
    "-c-isystem",
    "-cxx-isystem",
    "-objc-isystem",
    "-objcxx-isystem",
    "-stdlib++-isystem",
];

/// The compile-command words that remove a default: the standard header directories,
/// clang's built-in and system ones, and every predefined macro (`-undef`).
pub const REMOVALS: [&str; 6] = [
    "-nostdinc",
    "-nostdinc++",
    "-nostdsysteminc",
    "-nostdlibinc",
    "-nobuiltininc",
    "-undef",
];

/// The [`HEADER_OPTIONS`] a compile command spells `option=value`, read as the option and
/// its value. Any other option joined to a `=` keeps it in the value: gcc reads
/// `-isystem=dir` and `-I=dir` as a directory relative to the system root, which is not
/// the absolute `dir`.
const EQUALS_JOINED: [&str; 2] = ["-resource-dir", "--sysroot"];

/// gcc's `cc1` words choosing the target's word size, which its driver hands the compile
/// as written. clang names its target as `-triple`, read beside these.
const TARGET_WORDS: [&str; 4] = ["-m16", "-m32", "-m64", "-mx32"];

/// Whether a listing's command is a compile: gcc's `cc1`, `cc1plus` and kin, named by
/// path, or clang's own path followed by `-cc1`.
pub(crate) fn is_compile(words: &[String]) -> bool {
    let Some(program) = words.first() else {
        return false;
    };
    let named_cc1 = Path::new(program)
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with("cc1"));
    named_cc1 || words.get(1).is_some_and(|w| w == "-cc1")
}

/// The compile inputs of a `-###` listing. `Err` carries the sentence saying why it could
/// not be read.
///
/// # Errors
///
/// Errors where the listing holds no compile command, or an option that takes a value is
/// a command's last word, which is a truncated listing and not an empty value.
pub fn parse(listing: &str) -> Result<CompileInputs, String> {
    let mut read = CompileInputs {
        programs: Vec::new(),
        headers: Vec::new(),
        macros: Vec::new(),
        removals: Vec::new(),
        targets: Vec::new(),
        sanitizers: Vec::new(),
        lto: Vec::new(),
        relocation: Vec::new(),
        exception_models: Vec::new(),
    };
    for line in listing.lines().filter(|l| is_command(l)) {
        let line = words(line);
        if !is_compile(&line) {
            continue;
        }
        let Some((program, options)) = line.split_first() else {
            continue;
        };
        read.programs.push(program.clone());
        let mut rest = options.iter();
        while let Some(word) = rest.next() {
            let mut operand = || {
                rest.next()
                    .cloned()
                    .ok_or_else(|| format!("the compile command {program} ends at {word}"))
            };
            if REMOVALS.contains(&word.as_str()) {
                read.removals.push(word.clone());
            } else if word.starts_with("-fsanitize") || word.starts_with("-fno-sanitize") {
                read.sanitizers.push(word.clone());
            } else if word == "-flto" || word.starts_with("-flto=") || word == "-fno-lto" {
                read.lto.push(word.clone());
            } else if word == "-mrelocation-model" || word == "-pic-level" {
                read.relocation.push(format!("{word} {}", operand()?));
            } else if word == "-pic-is-pie" || GCC_CODE_MODEL_WORDS.contains(&word.as_str()) {
                read.relocation.push(word.clone());
            } else if TARGET_WORDS.contains(&word.as_str()) {
                read.targets.push(word.clone());
            } else if word == "-triple" {
                read.targets.push(format!("-triple {}", operand()?));
            } else if word == "-exception-model" {
                read.exception_models
                    .push(format!("-exception-model={}", operand()?));
            } else if word.starts_with("-exception-model=")
                || DRIVER_MODEL_WORDS.contains(&word.as_str())
            {
                read.exception_models.push(word.clone());
            } else if word == "-D" || word == "-U" {
                read.macros.push(format!("{word}{}", operand()?));
            } else if word.starts_with("-D") || word.starts_with("-U") {
                read.macros.push(word.clone());
            } else if let Some((option, joined)) = HEADER_OPTIONS
                .iter()
                .filter_map(|o| word.strip_prefix(*o).map(|joined| (*o, joined)))
                .max_by_key(|(o, _)| o.len())
            {
                let value = if joined.is_empty() {
                    operand()?
                } else if EQUALS_JOINED.contains(&option) {
                    joined.strip_prefix('=').unwrap_or(joined).to_owned()
                } else {
                    joined.to_owned()
                };
                read.headers.push((option.to_owned(), value));
            }
        }
    }
    if read.programs.is_empty() {
        return Err("the listing held no compile command".to_owned());
    }
    Ok(read)
}

/// Whether `word`, as the driver reads it, is a macro operation joined to its name
/// (`-DNAME=v`, `-UNAME`): the words [`macro_words`] carries alone, and the pieces of a
/// `-Wp,` word it carries whole.
fn joined_macro_op(word: &str) -> bool {
    (word.starts_with("-D") || word.starts_with("-U")) && word.len() > 2
}

/// Whether `word` is the macro reader's own two-token option, `-D` or `-U` ahead of its
/// name, in any of gcc's spellings (`--define-macro`, `--def`, `--undefine-macro`, `--un`;
/// `toolchain::LONG_ALIASES`): the one value-taking pair [`macro_words`] carries, which the
/// `flag_words` fuzz target's value law exempts by this classifier and not by the carrying.
#[must_use]
pub fn is_macro_option(word: &str) -> bool {
    let word = spelled_alone(word);
    word == "-D" || word == "-U"
}

/// The macro a `-D` or `-U` word operates on, as a listing or a control arm spells it
/// joined: `-DNAME=v`, `-DNAME` and `-UNAME` name `NAME`, which ends at the first `=` or
/// `(`. `None` for any other word, a bare `-D` included.
#[must_use]
pub fn macro_name(word: &str) -> Option<&str> {
    let rest = word
        .strip_prefix("-D")
        .or_else(|| word.strip_prefix("-U"))?;
    let name = rest.split(['=', '(']).next().unwrap_or(rest);
    (!name.is_empty()).then_some(name)
}

/// The profile's own `-D` and `-U` words, as written, for the arms' listing: a joined
/// `-DNAME=v` or `-UNAME`, a split `-D NAME`, a `-Wp,` word every comma piece of which is
/// a joined `-D` or `-U`, an `-Xpreprocessor` handing one, and gcc's long spellings of each
/// (`toolchain::LONG_ALIASES`). Anything else that defines a macro (`-Xclang -D`, a `-Wp,`
/// word mixing other options) is not carried, so it differs in the comparison, which errs
/// toward withholding.
#[must_use]
pub fn macro_words(flags: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(flag) = flags.get(i) {
        let one = i.saturating_add(1);
        let reading = read(flag, flags.get(one).map(String::as_str));
        let word = &*reading.word;
        let carried = match reading.hand {
            // `-D NAME`, `--def NAME`: the operation and its name.
            Hand::Value => (word == "-D" || word == "-U") && reading.span() == 2,
            Hand::Driver => {
                joined_macro_op(word)
                    || flag.strip_prefix("-Wp,").is_some_and(|list| {
                        list.split(',')
                            .all(|piece| joined_macro_op(&spelled_alone(piece)))
                    })
            }
            // `-Xpreprocessor -DNAME`: the preprocessor reads the define as the driver would,
            // gcc's long spellings included (`-Xpreprocessor --define-macro=X` and
            // `-Wp,--def,X` define `X` on gcc 16.1.1, measured 2026-10-28 by `-dM -E`; clang's
            // `-cc1` refuses them, and the build fails).
            Hand::Preprocessor => flags
                .get(one)
                .is_some_and(|w| joined_macro_op(&spelled_alone(w))),
            Hand::Tool | Hand::Arch => false,
        };
        let end = i.saturating_add(reading.span());
        if carried && let Some(words) = flags.get(i..end) {
            out.extend(words.iter().cloned());
        }
        i = end;
    }
    out
}

/// The profile's own optimisation words, as written and in order, for the arms' listing:
/// every word the driver reads as its own beginning `-O` (`-O2`, `-Ofast`, and gcc's
/// `--optimize`, `--optimize=N` and their abbreviations, `toolchain::LONG_ALIASES`). A
/// `-Wl,-O1`, a word handed to another tool or applied for one architecture, and a word
/// taken as another option's value (`-L -O0`, `-u -O1`) are not: the list is walked by the
/// one classifier (`toolchain::read`).
#[must_use]
pub fn optimization_words(flags: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(flag) = flags.get(i) {
        let reading = read(flag, flags.get(i.saturating_add(1)).map(String::as_str));
        // A level is one word of the driver's own; a reading that spans two is a hand-on's,
        // a value's or a selection's, and carries nothing here.
        if reading.hand == Hand::Driver && reading.span() == 1 && reading.word.starts_with("-O") {
            out.push(flag.clone());
        }
        i = i.saturating_add(reading.span());
    }
    out
}

/// Ask `driver` for its `-###` listing of a compile of an empty input in `language` (the
/// `-x` word) under `flags`, and read it. `Err` carries the sentence saying why it could
/// not be read.
///
/// # Errors
///
/// Errors when the driver cannot be run, exits other than 0 (`crate::link_inputs::listing`),
/// or its listing holds no compile command.
pub fn query(driver: &Path, flags: &[String], language: &str) -> Result<CompileInputs, String> {
    let mut args = flags.to_vec();
    args.extend(
        [
            "-no-integrated-cpp",
            "-###",
            "-x",
            language,
            "/dev/null",
            "-c",
            "-o",
            "/dev/null",
        ]
        .iter()
        .map(|s| (*s).to_owned()),
    );
    let stderr = crate::link_inputs::listing(
        driver,
        &args,
        &crate::link_inputs::under(flags),
        Path::new(""),
    )?;
    parse(&stderr).map_err(|why| {
        format!(
            "the driver's -### listing {}: {why}",
            crate::link_inputs::under(flags)
        )
    })
}

/// One kind of compile input two listings differ on: the words only the first side has
/// and the words only the second has, both empty where the sides hold the same words in
/// another order or number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Differing {
    /// `compile programs`, `header options`, `macro operations`, `removed defaults` or
    /// `targets`, the five kinds [`difference`] names.
    pub what: &'static str,
    pub only_first: Vec<String>,
    pub only_second: Vec<String>,
}

/// Where two listings differ, by kind, once resolved: the programs by canonical path, the
/// header options with an absolute value by canonical path and with any other as written,
/// an absolute search directory that does not exist left out (`SEARCH_DIRECTORY_OPTIONS`).
/// Empty where they run the same programs for the same targets with the same headers,
/// macro operations and removals, in the same order.
#[must_use]
pub fn differences(
    first: &CompileInputs,
    second: &CompileInputs,
    paths: &dyn Resolve,
) -> Vec<Differing> {
    let resolve =
        |list: &[String]| -> Vec<String> { list.iter().map(|p| paths.resolved(p)).collect() };
    let headers = |inputs: &CompileInputs| -> Vec<String> {
        inputs
            .headers
            .iter()
            .filter(|(option, value)| {
                let path = Path::new(value);
                !SEARCH_DIRECTORY_OPTIONS.contains(&option.as_str())
                    || !path.is_absolute()
                    || paths.is_dir(value)
            })
            .map(|(option, value)| {
                if Path::new(value).is_absolute() {
                    format!("{option} {}", paths.resolved(value))
                } else {
                    format!("{option} {value}")
                }
            })
            .collect()
    };
    let sides = [
        (
            "compile programs",
            resolve(&first.programs),
            resolve(&second.programs),
        ),
        ("header options", headers(first), headers(second)),
        (
            "macro operations",
            first.macros.clone(),
            second.macros.clone(),
        ),
        (
            "removed defaults",
            first.removals.clone(),
            second.removals.clone(),
        ),
        ("targets", first.targets.clone(), second.targets.clone()),
    ];
    let only = |this: &[String], other: &[String]| -> Vec<String> {
        this.iter()
            .filter(|w| !other.contains(w))
            .cloned()
            .collect()
    };
    sides
        .into_iter()
        .filter(|(_, a, b)| a != b)
        .map(|(what, a, b)| Differing {
            what,
            only_first: only(&a, &b),
            only_second: only(&b, &a),
        })
        .collect()
}

/// The sentence naming what each side of `differing` has that the other lacks, one clause
/// per kind joined with `; `, and empty where there is no difference.
#[must_use]
pub fn sentence(differing: &[Differing]) -> String {
    let words = |list: &[String]| -> String {
        if list.is_empty() {
            "none".to_owned()
        } else {
            list.join(", ")
        }
    };
    let clauses: Vec<String> = differing
        .iter()
        .map(|d| {
            if d.only_first.is_empty() && d.only_second.is_empty() {
                format!("its {} are the arms' in another order or number", d.what)
            } else {
                format!(
                    "its {} include {} where the arms' include {}",
                    d.what,
                    words(&d.only_first),
                    words(&d.only_second)
                )
            }
        })
        .collect();
    clauses.join("; ")
}

/// Where the arms' compile differs from the measured one, as the [`sentence`] over
/// [`differences`], or `None` where there is none.
#[must_use]
pub fn difference(
    measured: &CompileInputs,
    arms: &CompileInputs,
    paths: &dyn Resolve,
) -> Option<String> {
    let differing = differences(measured, arms, paths);
    (!differing.is_empty()).then(|| sentence(&differing))
}

/// Where the measured compile's exception model differs from the arms', as a sentence, or
/// `None` where both name the same one (neither naming one is the default model).
#[must_use]
pub fn exception_model_difference(
    measured: &CompileInputs,
    arms: &CompileInputs,
) -> Option<String> {
    (measured.exception_models != arms.exception_models).then(|| {
        // The listing has a line per compile step (the preprocessing one and the compile
        // under `-no-integrated-cpp`), each naming the model; the sentence names it once.
        let named = |list: &[String]| -> String {
            let mut once: Vec<&str> = Vec::new();
            for word in list {
                if !once.contains(&word.as_str()) {
                    once.push(word);
                }
            }
            if once.is_empty() {
                "the default".to_owned()
            } else {
                once.join(", ")
            }
        };
        format!(
            "its exception model is {} where the arms' is {}",
            named(&measured.exception_models),
            named(&arms.exception_models)
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link_inputs::Host;

    #[test]
    fn the_exception_model_is_read_from_the_compile_line_and_compared_alone() {
        let line = |extra: &str| -> String {
            format!(
                "clang version 22.1.8\n \"/usr/bin/clang-22\" \"-cc1\" \"-triple\" \
                 \"armv6kz-unknown-linux-gnueabihf\" \"-emit-obj\" \"-fexceptions\" {extra} \
                 \"-o\" \"x.o\" \"-x\" \"c\" \"/dev/null\"\n"
            )
        };
        let read = |extra: &str| parse(&line(extra)).expect("a compile listing");
        let default = read("");
        let joined = read("\"-exception-model=sjlj\"");
        let split = read("\"-exception-model\" \"sjlj\"");
        let dwarf = read("\"-exception-model=dwarf\" \"-D\" \"_EXTRA\"");
        assert!(
            default.exception_models.is_empty(),
            "a command with no exception-model word reads none: {:?}",
            default.exception_models
        );
        assert_eq!(
            joined.exception_models,
            vec!["-exception-model=sjlj".to_owned()]
        );
        assert_eq!(split.exception_models, joined.exception_models);
        assert_eq!(exception_model_difference(&joined, &split), None);
        assert_eq!(exception_model_difference(&default, &default), None);
        assert_eq!(
            exception_model_difference(&joined, &default).as_deref(),
            Some("its exception model is -exception-model=sjlj where the arms' is the default")
        );
        assert_eq!(
            exception_model_difference(&default, &dwarf).as_deref(),
            Some("its exception model is the default where the arms' is -exception-model=dwarf")
        );
        let near = read(
            "\"-exception-modelx\" \"-fexception-model=sjlj\" \"--exception-model=sjlj\" \
             \"-mllvm\" \"-exception-modelx=sjlj\"",
        );
        assert!(
            near.exception_models.is_empty(),
            "a longer, a prefixed or a doubled-dash word is not the option: {near:?}"
        );
        assert_eq!(
            read("\"-fsjlj-exceptions\"").exception_models,
            vec!["-fsjlj-exceptions".to_owned()],
            "the driver's spelling on a compile line is read as a model"
        );
        let mut twice = joined.clone();
        twice
            .exception_models
            .push("-exception-model=sjlj".to_owned());
        assert_eq!(
            exception_model_difference(&twice, &default).as_deref(),
            Some("its exception model is -exception-model=sjlj where the arms' is the default"),
            "a model each compile step names is named once"
        );
        let mut macro_only = joined.clone();
        macro_only.macros.push("-D_EXTRA".to_owned());
        assert_eq!(exception_model_difference(&joined, &macro_only), None);
        assert!(
            difference(&joined, &default, &Host::default()).is_none(),
            "the header and macro comparison does not read the exception model"
        );
    }

    /// gcc 16.1.1's two `cc1` lines on Fedora 44 x86_64 (2026-10-07) under
    /// `-no-integrated-cpp`, a specs file whose `*cpp` adds `-isystem /srv/inc` and whose
    /// `*cc1` adds `-include /srv/forced.h`, the profile's
    /// `-Wp,-U_FORTIFY_SOURCE,-D_FORTIFY_SOURCE=3` and Fedora's annobin plugin options.
    const GCC: &str = "Using built-in specs.\nCOLLECT_GCC=gcc\n \
        /usr/libexec/gcc/x86_64-redhat-linux/16/cc1 -E -quiet -isystem /srv/inc -U_FORTIFY_SOURCE \
        \"-D_FORTIFY_SOURCE=3\" /dev/null \"-mtune=generic\" -O2 -fPIE -o /tmp/ccA.i\n \
        /usr/libexec/gcc/x86_64-redhat-linux/16/cc1 -fpreprocessed /tmp/ccA.i -include /srv/forced.h -quiet \
        -dumpbase null -O2 -fPIE \"-iplugindir=/usr/lib/gcc/x86_64-redhat-linux/16/plugin\" \
        \"-fplugin=gcc-annobin\" -o /tmp/ccB.s\n as --64 -o /dev/null /tmp/ccB.s\n";

    /// clang 22.1.8's preprocessing `-cc1` line on the same host under `--config=` a file
    /// holding `--gcc-install-dir=` a directory with a space in its name, trimmed.
    const CLANG: &str = "clang version 22.1.8\nConfiguration file: /srv/c.cfg\n \
        \"/usr/bin/clang-22\" \"-cc1\" \"-triple\" \"x86_64-redhat-linux-gnu\" \"-E\" \
        \"-resource-dir\" \"/usr/bin/../lib/clang/22\" \"-internal-isystem\" \"/srv/g cc/16/../../../../include/c++/16\" \
        \"-D\" \"_GLIBCXX_ASSERTIONS\" \"-internal-externc-isystem\" \"/usr/include\" \"-undef\" \
        \"-fdebug-compilation-dir=/srv\" \"-o\" \"/tmp/null-1a.ii\" \"-x\" \"c++\" \"/dev/null\"\n \
        \"/usr/bin/clang-22\" \"-cc1\" \"-emit-obj\" \"-resource-dir=/usr/bin/../lib/clang/22\" \
        \"-o\" \"/dev/null\" \"-x\" \"c++-cpp-output\" \"/tmp/null-1a.ii\"\n";

    #[test]
    fn sanitizer_words_are_kept_in_order_and_not_compared() {
        let listing = concat!(
            " \"/usr/lib/gcc/x86_64-redhat-linux/16/cc1\" \"-quiet\" \"-D\" \"X\"",
            " \"-fsanitize=undefined\" \"-fsanitize-trap=undefined\" \"-fno-sanitize-trap=enum\"",
            " \"-o\" \"/tmp/a.s\" \"/dev/null\"\n"
        );
        let read = parse(listing).expect("a compile command");
        assert_eq!(
            read.sanitizers,
            [
                "-fsanitize=undefined",
                "-fsanitize-trap=undefined",
                "-fno-sanitize-trap=enum"
            ]
        );
        assert_eq!(read.macros, ["-DX"]);
        let bare = CompileInputs {
            sanitizers: Vec::new(),
            lto: Vec::new(),
            relocation: Vec::new(),
            exception_models: Vec::new(),
            ..read.clone()
        };
        assert!(
            difference(&read, &bare, &Host::default()).is_none(),
            "sanitizer words are not compared"
        );
    }

    #[test]
    fn lto_words_are_kept_in_order_and_not_compared() {
        let clang = concat!(
            " \"/usr/bin/clang-22\" \"-cc1\" \"-triple\" \"x86_64-redhat-linux-gnu\"",
            " \"-emit-llvm-bc\" \"-flto=thin\" \"-flto-unit\" \"-o\" \"/dev/null\"",
            " \"-x\" \"c\" \"/dev/null\"\n"
        );
        assert_eq!(parse(clang).expect("a compile command").lto, ["-flto=thin"]);
        let gcc = concat!(
            " \"/usr/lib/gcc/x86_64-redhat-linux/16/cc1\" \"-quiet\" \"-flto\"",
            " \"-flto-partition=none\" \"-fno-lto\" \"-flto=auto\" \"-o\" \"/tmp/a.s\"",
            " \"/dev/null\"\n"
        );
        let read = parse(gcc).expect("a compile command");
        assert_eq!(read.lto, ["-flto", "-fno-lto", "-flto=auto"]);
        let bare = CompileInputs {
            lto: Vec::new(),
            relocation: Vec::new(),
            exception_models: Vec::new(),
            ..read.clone()
        };
        assert!(
            difference(&read, &bare, &Host::default()).is_none(),
            "LTO words are not compared"
        );
        assert!(
            parse(CLANG).expect("a compile command").lto.is_empty(),
            "the clang command carries no LTO word"
        );
    }

    #[test]
    fn relocation_words_are_kept_in_order_and_not_compared() {
        let clang = concat!(
            " \"/usr/bin/clang-22\" \"-cc1\" \"-triple\" \"x86_64-redhat-linux-gnu\"",
            " \"-mrelocation-model\" \"pic\" \"-pic-level\" \"2\" \"-pic-is-pie\"",
            " \"-o\" \"/dev/null\" \"-x\" \"c\" \"/dev/null\"\n"
        );
        let read = parse(clang).expect("a compile command");
        assert_eq!(
            read.relocation,
            ["-mrelocation-model pic", "-pic-level 2", "-pic-is-pie"]
        );
        let bare = CompileInputs {
            relocation: Vec::new(),
            exception_models: Vec::new(),
            ..read.clone()
        };
        assert!(
            difference(&read, &bare, &Host::default()).is_none(),
            "not compared"
        );
        let cut = " \"/usr/bin/clang-22\" \"-cc1\" \"-pic-level\"\n";
        assert!(parse(cut).is_err(), "a level with no value is not read");
        assert!(
            parse(CLANG)
                .expect("a compile command")
                .relocation
                .is_empty(),
            "the clang command carries no relocation word"
        );
    }

    #[test]
    fn gcc_code_model_words_are_kept_and_not_compared() {
        let line = |words: &str| {
            format!(
                " /usr/libexec/gcc/x86_64-redhat-linux/16/cc1 -quiet probe.c -quiet -dumpbase \
                 probe.c -mtune=generic -march=x86-64 -O2 {words} -o /tmp/ccX.s\n"
            )
        };
        for (words, model) in [
            ("-flto -fPIC", &["-fPIC"][..]),
            ("-flto -fPIE", &["-fPIE"][..]),
            ("-flto -fpic", &["-fpic"][..]),
            ("-flto -fno-pie", &["-fno-pie"][..]),
            ("-flto", &[][..]),
        ] {
            let read = parse(&line(words)).expect("a gcc compile command");
            assert_eq!(read.relocation, model, "{words}");
            assert_eq!(read.lto, ["-flto"], "{words}");
            let bare = CompileInputs {
                relocation: Vec::new(),
                ..read.clone()
            };
            assert!(
                difference(&read, &bare, &Host::default()).is_none(),
                "{words}: not compared"
            );
        }
    }

    #[test]
    fn a_listing_names_the_headers_and_macros_of_its_compile_commands() {
        let mut read = 0;
        let gcc = parse(GCC).expect("the gcc listing has compile commands");
        read += 1;
        assert_eq!(gcc.programs.len(), 2, "both cc1 lines and not `as`");
        assert_eq!(
            gcc.headers,
            [
                ("-isystem".to_owned(), "/srv/inc".to_owned()),
                ("-include".to_owned(), "/srv/forced.h".to_owned()),
            ],
            "-iplugindir= is not a header option"
        );
        assert_eq!(gcc.macros, ["-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=3"]);
        assert!(
            gcc.removals.is_empty(),
            "the gcc command removes no word: {:?}",
            gcc.removals
        );
        assert!(gcc.targets.is_empty(), "-mtune= is not a target word");

        let clang = parse(CLANG).expect("the clang listing has compile commands");
        read += 1;
        assert_eq!(clang.programs, ["/usr/bin/clang-22", "/usr/bin/clang-22"]);
        assert_eq!(
            clang.headers,
            [
                ("-resource-dir", "/usr/bin/../lib/clang/22"),
                (
                    "-internal-isystem",
                    "/srv/g cc/16/../../../../include/c++/16"
                ),
                ("-internal-externc-isystem", "/usr/include"),
                ("-resource-dir", "/usr/bin/../lib/clang/22"),
            ]
            .map(|(o, v)| (o.to_owned(), v.to_owned())),
            "two-word and `=`-joined values read alike, a quoted path holding a space whole"
        );
        assert_eq!(clang.macros, ["-D_GLIBCXX_ASSERTIONS"]);
        assert_eq!(clang.removals, ["-undef"]);
        assert_eq!(clang.targets, ["-triple x86_64-redhat-linux-gnu"]);

        // The longest option a word begins with names it, and a joined value is read
        // without the option.
        let odd = parse(
            " /x/cc1 -isystem-after /a -include-pch /b.pch -I/c -iwithprefixbefore/d -DX -U Y \
             -isystem=/e -I=/f --sysroot=/g -m32\n",
        )
        .expect("a compile command");
        read += 1;
        assert_eq!(
            odd.headers,
            [
                ("-isystem-after", "/a"),
                ("-include-pch", "/b.pch"),
                ("-I", "/c"),
                ("-iwithprefixbefore", "/d"),
                ("-isystem", "=/e"),
                ("-I", "=/f"),
                ("--sysroot", "/g"),
            ]
            .map(|(o, v)| (o.to_owned(), v.to_owned()))
        );
        assert_eq!(odd.macros, ["-DX", "-UY"]);
        assert_eq!(odd.targets, ["-m32"]);

        let unread = parse(" as --64 -o /dev/null /tmp/x.s\n /usr/bin/ld -o /dev/null /x/crt1.o\n")
            .expect_err("a listing with no compile command is not read as an empty one");
        assert!(unread.contains("no compile command"), "{unread}");
        read += 1;

        // A command cut off after an option that takes a value is refused, not read as an
        // empty value.
        let truncated = [
            " /x/cc1 -E -isystem\n",
            " /x/cc1 -E -U\n",
            " /x/clang -cc1 -triple\n",
        ];
        for listing in &truncated {
            parse(listing).expect_err("a truncated command");
            read += 1;
        }
        assert_eq!(
            read,
            4 + truncated.len(),
            "every listing handed in was read"
        );
    }

    #[test]
    fn the_profiles_macro_words_are_carried_and_nothing_else() {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let cases: [(&str, &[&str]); 17] = [
            (
                "-O2 -Wp,-U_FORTIFY_SOURCE,-D_FORTIFY_SOURCE=3 -Wp,-D_GLIBCXX_ASSERTIONS -fPIE",
                &[
                    "-Wp,-U_FORTIFY_SOURCE,-D_FORTIFY_SOURCE=3",
                    "-Wp,-D_GLIBCXX_ASSERTIONS",
                ],
            ),
            ("-D X -UY -DZ=1", &["-D", "X", "-UY", "-DZ=1"]),
            (
                "-Xpreprocessor -DX -Xpreprocessor -MD",
                &["-Xpreprocessor", "-DX"],
            ),
            ("-Wp,-DX,-MD,dep", &[]),
            ("-Xclang -DX -Xarch_x86_64 -UY", &[]),
            ("-include /srv/x.h -isystem /srv/i", &[]),
            ("-undef -D", &[]),
            ("-specs=/srv/s --config=/srv/c", &[]),
            // gcc's long spellings and abbreviations, carried as written: `--def X` is
            // `-D X` to gcc, `--define-macro=X=1` is `-DX=1`, `--un` is `-U`
            // (`toolchain::LONG_ALIASES`); `--def=X` is gcc's `-fdef=X`, no macro.
            (
                "--define-macro X --def Y --define-macro=Z=1 --undefine-macro W --un V --def=U",
                &[
                    "--define-macro",
                    "X",
                    "--def",
                    "Y",
                    "--define-macro=Z=1",
                    "--undefine-macro",
                    "W",
                    "--un",
                    "V",
                ],
            ),
            // A `-D` a selection took as its value is the value: a directory named `-DX`
            // after `-L`, a directory named `-D` after `-isystem` and then `X` on its own.
            ("-L -DX -O2", &[]),
            ("-isystem -D X", &[]),
            ("--li -DX --sys -UY", &[]),
            // A `-D` a value-taking option took is that option's value: a symbol, an output.
            ("-u -DX -o -UY", &[]),
            ("--force-link -DX --forc -UY", &[]),
            // A word joined to an alias is no operation: `-std=-DX` and `-m-DX` to gcc.
            ("--std -DX --machine -UY", &[]),
            // `-Xpreprocessor -D X`: the preprocessor is handed a bare `-D`, and `X` is the
            // driver's own word, an input file.
            ("-Xpreprocessor -D X", &[]),
            // Handed to gcc's `cc1`, which reads the long spellings as the driver does:
            // carried as written where every piece is an operation, as `-Wp,-DX` is.
            (
                "-Wp,--define-macro=X -Xpreprocessor --define-macro=Y -Wp,--def,Z",
                &["-Wp,--define-macro=X", "-Xpreprocessor", "--define-macro=Y"],
            ),
        ];
        let mut checked = 0;
        for (flags, carried) in cases {
            assert_eq!(macro_words(&line(flags)), carried, "{flags}");
            checked += 1;
        }
        assert_eq!(checked, cases.len());
    }

    #[test]
    fn the_profiles_optimization_words_are_carried_in_order_and_nothing_else() {
        const HANDED: [&str; 8] = [
            "-Xclang",
            "-Xlinker",
            "--for-linker",
            "--for-l",
            "-Xassembler",
            "-Xopenmp-target",
            "-Xcuda-ptxas",
            "-mllvm",
        ];
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let cases: [(&str, &[&str]); 14] = [
            ("-O2", &["-O2"]),
            ("-O0 -D_FORTIFY_SOURCE=3 -O2", &["-O0", "-O2"]),
            // gcc's long spelling, joined, alone and abbreviated to `--op`, the shortest
            // gcc 16.1.1 takes; `--o=2` and `--o` it refuses, and `--output=x` is `-ox`.
            (
                "-O2 --optimize=1 --optimize --opti --op --o=2 --o -fPIE --output=x",
                &["-O2", "--optimize=1", "--optimize", "--opti", "--op"],
            ),
            (
                "-Ofast -fPIE -Og -Os -Oz -O",
                &["-Ofast", "-Og", "-Os", "-Oz", "-O"],
            ),
            ("-Wl,-O1 -Wa,-O2 -Wp,-O2", &[]),
            ("-Xlinker -O1 -O3 -mllvm -O2", &["-O3"]),
            ("-Xpreprocessor -O2 -Xarch_x86_64 -O1", &[]),
            (
                "-fstack-protector-strong -D_FORTIFY_SOURCE=3 -include /srv/x.h",
                &[],
            ),
            // An `-O` a selection or a value-taking option took is its value: a directory
            // named `-O0`, a prefix named `-O2`, a symbol named `-O1`, a file named `-O3`.
            ("-L -O0 -O2", &["-O2"]),
            ("-B -O2 -u -O1 -MF -O3", &[]),
            ("--li -O0 --pref -O2 --forc -O1", &[]),
            // A word joined to an alias is no level: `-std=-O2` and `-m-O1` to gcc; and
            // `--optimize 2` is `-O` and then the input file `2`.
            ("--std -O2 --machine -O1", &[]),
            ("--optimize 2", &["--optimize"]),
            ("", &[]),
        ];
        let mut checked = 0;
        for (flags, carried) in cases {
            assert_eq!(optimization_words(&line(flags)), carried, "{flags}");
            checked += 1;
        }
        assert_eq!(checked, cases.len());
        // Every word that hands the next one on, not only the two the table names: the
        // word after each is not carried, the one after that is.
        for handed in HANDED {
            let flags = format!("{handed} -O1 -O2");
            assert_eq!(optimization_words(&line(&flags)), ["-O2"], "{flags}");
            checked += 1;
        }
        assert_eq!(checked, cases.len() + HANDED.len());
    }

    #[test]
    fn a_macro_operation_names_its_macro_and_nothing_else_names_one() {
        let cases: [(&str, Option<&str>); 9] = [
            ("-D_FORTIFY_SOURCE=3", Some("_FORTIFY_SOURCE")),
            ("-U_FORTIFY_SOURCE", Some("_FORTIFY_SOURCE")),
            ("-D_GLIBCXX_ASSERTIONS", Some("_GLIBCXX_ASSERTIONS")),
            ("-DF(x)=x", Some("F")),
            ("-D", None),
            ("-U", None),
            ("-O2", None),
            ("-include", None),
            ("_FORTIFY_SOURCE", None),
        ];
        let mut checked = 0;
        for (word, name) in cases {
            assert_eq!(macro_name(word), name, "{word}");
            checked += 1;
        }
        assert_eq!(checked, cases.len());
    }

    #[test]
    fn ubuntus_driver_adds_its_fortify_macro_under_o2_and_the_stand_in_under_o2_matches() {
        const TAIL: &str = "-fasynchronous-unwind-tables -fstack-protector-strong -Wformat \
            -Wformat-security -fstack-clash-protection -fcf-protection \
            \"-fzero-init-padding-bits=all\" \"-Wbidi-chars=any\"";
        let listing = |opt: &str| {
            format!(
                "Using built-in specs.\nCOLLECT_GCC=gcc\n \
                 /usr/libexec/gcc/x86_64-linux-gnu/15/cc1 -E -quiet -imultiarch x86_64-linux-gnu \
                 /tmp/x.c \"-mtune=generic\" \"-march=x86-64\" {opt}{TAIL} -o /tmp/ccX.i\n \
                 /usr/libexec/gcc/x86_64-linux-gnu/15/cc1 -fpreprocessed /tmp/ccX.i -quiet \
                 -dumpbase x.c -dumpbase-ext .c \"-mtune=generic\" \"-march=x86-64\" {opt}{TAIL} \
                 -o /tmp/ccX.s\n as --64 -o /dev/null /tmp/ccX.s\n"
            )
        };
        let measured = parse(&listing("-O2 \"-D_FORTIFY_SOURCE=3\" ")).expect("the -O2 listing");
        let stand_in_with_o2 = parse(&listing("-O2 \"-D_FORTIFY_SOURCE=3\" ")).expect("the same");
        let stand_in_without = parse(&listing("")).expect("the flagless listing");
        assert_eq!(
            measured.macros,
            ["-D_FORTIFY_SOURCE=3", "-D_FORTIFY_SOURCE=3"],
            "the macro is added to both cc1 commands"
        );
        assert!(
            stand_in_without.macros.is_empty(),
            "the stand-in without the macro carries none: {:?}",
            stand_in_without.macros
        );
        assert_eq!(
            difference(&measured, &stand_in_with_o2, &Host::default()),
            None
        );
        assert_eq!(
            differences(&measured, &stand_in_with_o2, &Host::default()),
            []
        );
        assert_eq!(
            differences(&measured, &stand_in_without, &Host::default()),
            [Differing {
                what: "macro operations",
                only_first: vec![
                    "-D_FORTIFY_SOURCE=3".to_owned(),
                    "-D_FORTIFY_SOURCE=3".to_owned()
                ],
                only_second: Vec::new(),
            }]
        );
        assert_eq!(
            difference(&measured, &stand_in_without, &Host::default()).as_deref(),
            Some(
                "its macro operations include -D_FORTIFY_SOURCE=3, -D_FORTIFY_SOURCE=3 where the \
                 arms' include none"
            )
        );
    }

    /// Other spellings of the same headers and an absolute search directory that does not
    /// exist make no difference; an added directory (absolute, relative to the system root,
    /// or relative), forced include, macro operation, removal, target or program does, and
    /// the sentence names it. Every path the equal case resolves is in the test's scratch
    /// directory, so the case holds on any host.
    #[expect(
        clippy::too_many_lines,
        reason = "one table of header-option shapes, each a literal of every field, read top to bottom"
    )]
    #[test]
    fn listings_differ_exactly_where_a_header_or_macro_does() {
        let dir = std::env::temp_dir().join(format!("chard-compile-inputs-{}", std::process::id()));
        let (system, added, bin) = (dir.join("include"), dir.join("inc"), dir.join("bin"));
        for d in [&system, &added, &bin] {
            std::fs::create_dir_all(d).expect("scratch directory");
        }
        let program = bin.join("cc1");
        std::fs::write(&program, "").expect("a scratch compile program");
        let spelled = |p: &Path| p.display().to_string();
        let header = |o: &str, v: String| (o.to_owned(), v);
        let base = CompileInputs {
            programs: vec![spelled(&program)],
            headers: vec![header("-internal-isystem", spelled(&system))],
            macros: vec!["-D_FORTIFY_SOURCE=3".to_owned()],
            removals: Vec::new(),
            targets: vec!["-triple x86_64-redhat-linux-gnu".to_owned()],
            sanitizers: Vec::new(),
            lto: Vec::new(),
            relocation: Vec::new(),
            exception_models: Vec::new(),
        };
        let missing = spelled(&dir.join("no-such-include"));
        let under_root = format!("={}", spelled(&added));
        // The base with one header option ahead of its own.
        let ahead = |option: &str, value: &str| CompileInputs {
            headers: vec![
                header(option, value.to_owned()),
                header("-internal-isystem", spelled(&system)),
            ],
            ..base.clone()
        };
        let cases = [
            (
                CompileInputs {
                    programs: vec![format!("{}/../bin/cc1", bin.display())],
                    headers: vec![
                        header(
                            "-internal-isystem",
                            format!("{}/../include", system.display()),
                        ),
                        header("-internal-isystem", missing.clone()),
                    ],
                    ..base.clone()
                },
                None,
            ),
            (
                CompileInputs {
                    programs: vec!["/srv/other/cc1".to_owned()],
                    ..base.clone()
                },
                Some("/srv/other/cc1".to_owned()),
            ),
            (
                ahead("-isystem", &spelled(&added)),
                Some(format!("-isystem {}", spelled(&added))),
            ),
            (
                ahead("-include", &missing),
                Some(format!("-include {missing}")),
            ),
            (
                CompileInputs {
                    macros: vec![
                        "-D_FORTIFY_SOURCE=3".to_owned(),
                        "-D_FORTIFY_SOURCE=0".to_owned(),
                    ],
                    ..base.clone()
                },
                Some("-D_FORTIFY_SOURCE=0".to_owned()),
            ),
            (
                CompileInputs {
                    removals: vec!["-undef".to_owned()],
                    ..base.clone()
                },
                Some("-undef".to_owned()),
            ),
            (
                ahead("-isystem", &under_root),
                Some(format!("-isystem {under_root}")),
            ),
            (
                ahead("-isystem", "no-such-relative-include"),
                Some("-isystem no-such-relative-include".to_owned()),
            ),
            (
                CompileInputs {
                    targets: vec!["-triple i686-redhat-linux-gnu".to_owned()],
                    sanitizers: Vec::new(),
                    lto: Vec::new(),
                    relocation: Vec::new(),
                    exception_models: Vec::new(),
                    ..base.clone()
                },
                Some("-triple i686-redhat-linux-gnu".to_owned()),
            ),
            (
                CompileInputs {
                    macros: vec![
                        "-D_FORTIFY_SOURCE=3".to_owned(),
                        "-D_FORTIFY_SOURCE=3".to_owned(),
                    ],
                    ..base.clone()
                },
                Some("another order or number".to_owned()),
            ),
        ];
        assert_eq!(compared(&cases, &base), cases.len());
        std::fs::remove_dir_all(&dir).expect("removing the scratch directory");
    }

    /// Compare each case against `base`: `None` must find no difference, and `Some` a
    /// sentence quoting the text. Returns the number compared.
    fn compared(cases: &[(CompileInputs, Option<String>)], base: &CompileInputs) -> usize {
        let mut compared = 0;
        for (measured, quoted) in cases {
            let found = difference(measured, base, &Host::default());
            match quoted {
                None => assert_eq!(found, None, "{measured:?}"),
                Some(text) => {
                    let sentence = found.unwrap_or_else(|| panic!("no difference: {measured:?}"));
                    assert!(sentence.contains(text.as_str()), "{sentence}");
                }
            }
            compared += 1;
        }
        compared
    }

    /// A `-Wp,` piece that is `-D` or `-U` alone names no macro, so the word is not
    /// carried; one that names its macro is.
    #[test]
    fn a_preprocessor_piece_naming_no_macro_is_not_carried() {
        assert!(
            macro_words(&["-Wp,-D".to_owned()]).is_empty(),
            "-Wp,-D names no macro, so the word is not carried"
        );
        assert!(
            macro_words(&["-Wp,-U".to_owned()]).is_empty(),
            "-Wp,-U names no macro, so the word is not carried"
        );
        assert_eq!(macro_words(&["-Wp,-DX".to_owned()]), ["-Wp,-DX"]);
    }
}
