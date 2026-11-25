// SPDX-License-Identifier: BSD-3-Clause

//! Whether the compile command the driver lists under a control arm's flags sets the arm's
//! option otherwise than the arm's flag does, which is the one thing a withheld triple can be
//! told about why its control was no control.

use std::path::Path;

use serde::Serialize;

/// The two words of a finding: the arm's flag, and the word the driver's compile command
/// sets the same option with instead. Published as `controls.<arm>.overridden`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Overridden {
    /// The arm's own flag, as `flags` spells it.
    pub flag: String,
    /// The word of the compile command that sets the same option otherwise: a later word of
    /// the command, as written (a `-D` or `-U` joined to its operand), or clang's
    /// `-stack-protector N`.
    pub by: String,
}

/// What asking the driver for an arm's compile command gave, as the arm publishes it: the
/// finding under `overridden`, or under `overridden_unread` the sentence saying why the
/// command could not be read. One value and two keys, so an arm cannot publish both. An arm
/// nothing was asked about, and one whose command was read and showed nothing, publishes
/// neither.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Listed {
    Overridden(Overridden),
    OverriddenUnread(String),
}

impl Listed {
    /// The finding, where the command was read and made one.
    #[must_use]
    pub fn found(&self) -> Option<&Overridden> {
        match self {
            Self::Overridden(found) => Some(found),
            Self::OverriddenUnread(_) => None,
        }
    }
}

/// The `-f` names read as one option though they are spelled as four.
const STACK_PROTECTOR: [&str; 4] = [
    "stack-protector",
    "stack-protector-strong",
    "stack-protector-all",
    "stack-protector-explicit",
];

/// The `-f` options [`option_of`] declines, by the whole name after `-f` or `-fno-`: the
/// code-model words, which the drivers resolve among themselves and `compile_inputs` reads,
/// `-flto`, read there too, and `-fhardened`, which stands for other options and is no
/// setting of one. The sanitizer words are declined beside these by their prefix
/// ([`UNREAD_F_FAMILY`]).
const UNREAD_F: [&str; 6] = ["PIC", "PIE", "pic", "pie", "lto", "hardened"];

/// The one family declined by prefix: `-fsanitize=`, `-fsanitize-trap=`,
/// `-fsanitize-recover=` and their kin each add to a list and replace nothing.
const UNREAD_F_FAMILY: &str = "sanitize";

/// The option `word` sets, where this module reads it: `None` for every word it does not.
#[must_use]
pub fn option_of(word: &str) -> Option<String> {
    if let Some(name) = crate::compile_inputs::macro_name(word) {
        return Some(format!("macro {name}"));
    }
    let body = word.strip_prefix("-f")?;
    let body = body.strip_prefix("no-").unwrap_or(body);
    let name = body.split_once('=').map_or(body, |(name, _)| name);
    if name.is_empty() || UNREAD_F.contains(&name) || name.starts_with(UNREAD_F_FAMILY) {
        return None;
    }
    if STACK_PROTECTOR.contains(&name) {
        return Some("-fstack-protector".to_owned());
    }
    Some(format!("-f{name}"))
}

/// The level clang's `-cc1` names for a stack-protector word of the driver's: none, the
/// arrays of [`crate::probe`]'s `ssp-buffer-size`, strong, all. `None` for a word that is
/// not one of the four.
#[must_use]
pub fn clang_protector_level(word: &str) -> Option<u8> {
    match word {
        "-fno-stack-protector" => Some(0),
        "-fstack-protector" => Some(1),
        "-fstack-protector-strong" => Some(2),
        "-fstack-protector-all" => Some(3),
        _ => None,
    }
}

/// The level a `by` word of the clang shape names: `-stack-protector N`, for the four levels
/// [`clang_protector_level`] knows, each spelled one way. `None` for any other word, a
/// number clang does not name (`4`) or another spelling of one it does (`02`) among them.
fn named_level(by: &str) -> Option<u8> {
    (0..=3).find(|level| by == format!("-stack-protector {level}"))
}

/// The words of the listing's compile command, with a `-D` or `-U` joined to the operand
/// the command carries as its next word, and whether the command is clang's `-cc1`.
///
/// # Errors
///
/// Errors, with the sentence saying so, where the listing holds no compile command, holds
/// more than one (the arm's build runs one, and a listing naming several is not one this
/// module reads), or its command ends at a `-D` or `-U` with no operand.
fn compile_command(listing: &str) -> Result<(Vec<String>, bool), String> {
    let mut commands = listing
        .lines()
        .filter(|line| crate::link_inputs::is_command(line))
        .map(crate::link_inputs::words)
        .filter(|words| crate::compile_inputs::is_compile(words));
    let Some(command) = commands.next() else {
        return Err("the listing held no compile command".to_owned());
    };
    if commands.next().is_some() {
        return Err("the listing held more than one compile command".to_owned());
    }
    let clang = command.get(1).is_some_and(|word| word == "-cc1");
    let mut joined = Vec::with_capacity(command.len());
    let mut rest = command.into_iter();
    while let Some(word) = rest.next() {
        if word == "-D" || word == "-U" {
            match rest.next() {
                Some(operand) => joined.push(format!("{word}{operand}")),
                None => {
                    return Err(format!(
                        "the compile command ends at {word}, with no value after it"
                    ));
                }
            }
        } else {
            joined.push(word);
        }
    }
    Ok((joined, clang))
}

/// What the compile command of `listing` shows of an arm whose own flags are `control`:
/// the first of the arm's settings, in the arm's order, the command sets otherwise, and
/// `None` where it sets none of them otherwise.
///
/// # Errors
///
/// Errors where the listing is not one compile command (`compile_command`), and where
/// clang's `-stack-protector` is followed by a word that is no level beside an arm that sets
/// the protector.
pub fn read(listing: &str, control: &[&str]) -> Result<Option<Overridden>, String> {
    let (command, clang) = compile_command(listing)?;
    let mut seen = Vec::new();
    for word in control {
        let Some(option) = option_of(word) else {
            continue;
        };
        if seen.contains(&option) {
            continue;
        }
        seen.push(option.clone());
        let Some(setting) = control
            .iter()
            .rev()
            .find(|w| option_of(w).as_ref() == Some(&option))
        else {
            continue;
        };
        // Where the command holds the arm's setting, a last word that differs stands after
        // it, the setting being itself a word of the option.
        if let Some(last) = command
            .iter()
            .rev()
            .find(|w| option_of(w).as_ref() == Some(&option))
            && last != setting
            && (command.iter().any(|w| w == setting) || (clang && option.starts_with("-f")))
        {
            return Ok(Some(Overridden {
                flag: (*setting).to_owned(),
                by: last.clone(),
            }));
        }
        if clang
            && let Some(asked) = clang_protector_level(setting)
            && let Some((_, level)) = command
                .iter()
                .zip(command.iter().skip(1))
                .rfind(|(word, _)| *word == "-stack-protector")
        {
            let by = format!("-stack-protector {level}");
            let Some(resolved) = named_level(&by) else {
                return Err(format!("the compile command names {by}, which is no level"));
            };
            if resolved != asked {
                return Ok(Some(Overridden {
                    flag: (*setting).to_owned(),
                    by,
                }));
            }
        }
    }
    Ok(None)
}

/// Ask `driver` for the compile command it would run for an arm built with `flags`, whose
/// own flags are `control`, over an empty input of `language`, and [`read`] it.
#[must_use]
pub fn query(driver: &Path, flags: &[String], control: &[&str], language: &str) -> Option<Listed> {
    if !control.iter().any(|word| option_of(word).is_some()) {
        return None;
    }
    let mut args = flags.to_vec();
    args.extend(
        ["-###", "-x", language, "/dev/null", "-c", "-o", "/dev/null"]
            .iter()
            .map(|s| (*s).to_owned()),
    );
    let under = crate::link_inputs::under(flags);
    let read =
        crate::link_inputs::listing(driver, &args, &under, Path::new("")).and_then(|listing| {
            read(&listing, control)
                .map_err(|why| format!("the driver's -### listing {under}: {why}"))
        });
    match read {
        Ok(found) => found.map(Listed::Overridden),
        Err(why) => Some(Listed::OverriddenUnread(why)),
    }
}

/// Whether a published finding is one [`read`] could have made of an arm built with `flags`:
/// `flag` is the arm's last word of an option this module reads, and `by` is another setting
/// of that option, as a word of it or as one of the four levels clang names for the
/// protector. The consistency rule `verdict-unearned-by-controls` holds every published
/// finding to this, so a finding naming a flag the arm never carried, a flag the arm itself
/// set again, or a word of another option, contradicts the report it is in. It does not hold
/// `by` to the listing, which is not published: [`query`] says how to list it again.
#[must_use]
pub fn stands(found: &Overridden, flags: &[String]) -> bool {
    let Some(option) = option_of(&found.flag) else {
        return false;
    };
    let setting = flags
        .iter()
        .rev()
        .find(|w| option_of(w).as_ref() == Some(&option));
    if setting != Some(&found.flag) || found.by == found.flag {
        return false;
    }
    let another_word = option_of(&found.by).as_ref() == Some(&option);
    let another_level = clang_protector_level(&found.flag)
        .zip(named_level(&found.by))
        .is_some_and(|(asked, resolved)| asked != resolved);
    another_word || another_level
}

#[cfg(test)]
mod tests {
    use super::*;

    /// gcc's `cc1` command for an arm under a specs file whose `*self_spec: +` appends, as
    /// measured (the module note has the frame), cut to the words that matter and two that
    /// do not.
    const GCC_UNDER_SPEC: &str = "Using built-in specs.\n\
        Reading specs from /etc/over.spec\n\
        COLLECT_GCC_OPTIONS='-U' '_FORTIFY_SOURCE' '-D' '_FORTIFY_SOURCE=0' '-O2' \
        '-fno-stack-protector' '-fstack-protector-strong' '-fcf-protection=full'\n \
        /usr/libexec/gcc/x86_64-redhat-linux/16/cc1 -quiet -U _FORTIFY_SOURCE -D \
        \"_FORTIFY_SOURCE=0\" \"-D_FORTIFY_SOURCE=3\" /dev/null -quiet -dumpbase null \
        \"-mtune=generic\" -O2 -fno-stack-protector \"-fcf-protection=none\" \
        -fstack-protector-strong \"-fcf-protection=full\" -o /tmp/ccke226B.s\n";

    /// clang's `-cc1` command for `-fstack-protector --param ssp-buffer-size=8` at `level`,
    /// as Alpine's clang 23.1.2 (2) and Fedora's 22.1.8 (1) wrote it, cut likewise.
    fn clang_at(level: &str) -> String {
        format!(
            "clang version 23.1.2\nConfiguration file: /etc/clang23/x86_64-alpine-linux-musl.cfg\n \
             \"/usr/lib/llvm23/bin/clang-23\" \"-cc1\" \"-triple\" \"x86_64-alpine-linux-musl\" \
             \"-emit-obj\" \"-fstack-clash-protection\" \"-stack-protector\" \"{level}\" \
             \"-stack-protector-buffer-size\" \"8\" \"-D\" \"_FORTIFY_SOURCE=0\" \"-o\" \
             \"/dev/null\" \"-x\" \"c\" \"/dev/null\"\n"
        )
    }

    fn of(flag: &str, by: &str) -> Overridden {
        Overridden {
            flag: flag.to_owned(),
            by: by.to_owned(),
        }
    }

    #[test]
    fn a_finding_is_the_arms_word_and_the_one_set_after_it() {
        let alpine = clang_at("2");
        let fedora = clang_at("1");
        let level_three = clang_at("3");
        let cases: [(&str, &[&str], Option<Overridden>); 19] = [
            // A later word of the same option, gcc.
            (
                GCC_UNDER_SPEC,
                &["-fno-stack-protector"],
                Some(of("-fno-stack-protector", "-fstack-protector-strong")),
            ),
            (
                GCC_UNDER_SPEC,
                &["-fcf-protection=none"],
                Some(of("-fcf-protection=none", "-fcf-protection=full")),
            ),
            // The arm's setting is its last word of the option, and a `-D` carried as two
            // words is the arm's joined one.
            (
                GCC_UNDER_SPEC,
                &["-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0", "-O2"],
                Some(of("-D_FORTIFY_SOURCE=0", "-D_FORTIFY_SOURCE=3")),
            ),
            // The first of the arm's settings the command sets otherwise, in the arm's order.
            (
                GCC_UNDER_SPEC,
                &["-O2", "-fcf-protection=none", "-fno-stack-protector"],
                Some(of("-fcf-protection=none", "-fcf-protection=full")),
            ),
            // The command's last word of the option is the arm's own: nothing set after it.
            (GCC_UNDER_SPEC, &["-fstack-protector-strong"], None),
            (GCC_UNDER_SPEC, &["-fcf-protection=full"], None),
            // A word the command does not carry shows nothing, whatever else it carries.
            (GCC_UNDER_SPEC, &["-fno-stack-clash-protection"], None),
            // Words this module does not read are not findings: the level, a machine word.
            (GCC_UNDER_SPEC, &["-O0", "-mtune=native"], None),
            // clang's resolved level against the arm's word.
            (
                &alpine,
                &["-fstack-protector", "--param", "ssp-buffer-size=8"],
                Some(of("-fstack-protector", "-stack-protector 2")),
            ),
            (
                &fedora,
                &["-fstack-protector", "--param", "ssp-buffer-size=8"],
                None,
            ),
            (&alpine, &["-fstack-protector-strong"], None),
            // The all spelling is level 3: a lower one is a finding, as a higher one is for
            // strong.
            (
                &alpine,
                &["-fstack-protector-all"],
                Some(of("-fstack-protector-all", "-stack-protector 2")),
            ),
            (&level_three, &["-fstack-protector-all"], None),
            (
                &level_three,
                &["-fstack-protector-strong"],
                Some(of("-fstack-protector-strong", "-stack-protector 3")),
            ),
            (
                &alpine,
                &["-fno-stack-protector"],
                Some(of("-fno-stack-protector", "-stack-protector 2")),
            ),
            // clang's resolved word: another setting of the arm's option and not the arm's
            // word.
            (
                &alpine,
                &["-fno-stack-clash-protection"],
                Some(of(
                    "-fno-stack-clash-protection",
                    "-fstack-clash-protection",
                )),
            ),
            (&alpine, &["-fstack-clash-protection"], None),
            (&alpine, &["-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=3"], None),
            (GCC_UNDER_SPEC, &["-fcf-protection=branch"], None),
        ];
        let mut made = 0;
        for (listing, control, expected) in &cases {
            let read = read(listing, control).expect("one compile command");
            assert_eq!(&read, expected, "{control:?}");
            // A finding stands beside an arm ending in the control's words, as
            // `measure::arm_flags` builds every arm.
            if let Some(found) = &read {
                let arm: Vec<String> = control.iter().map(|w| (*w).to_owned()).collect();
                assert!(stands(found, &arm), "{found:?} beside {control:?}");
            }
            made += usize::from(read.is_some());
        }
        assert_eq!(made, 9, "nine of the nineteen rows are findings");
    }

    #[test]
    fn a_listing_that_is_not_one_compile_command_is_unread() {
        let control: &[&str] = &["-fno-stack-protector"];
        assert!(
            matches!(read(GCC_UNDER_SPEC, control), Ok(Some(_))),
            "the control row"
        );
        let command = GCC_UNDER_SPEC
            .lines()
            .find(|line| line.contains("cc1"))
            .expect("the command line");
        let none = GCC_UNDER_SPEC.replace(command, " /usr/bin/as --64 -o /dev/null x.s");
        let two = format!("{GCC_UNDER_SPEC}{command}\n");
        let cut = format!("{} -D\n", command.trim_end());
        for (listing, says) in [
            (none, "held no compile command"),
            (two, "more than one compile command"),
            (cut, "ends at -D"),
        ] {
            let why = read(&listing, control).expect_err(says);
            assert!(why.contains(says), "{why}");
        }
    }

    #[test]
    fn a_word_of_another_option_and_a_link_word_are_no_finding() {
        let listing = |appended: &str| {
            format!(
                "Reading specs from /etc/innocuous.spec\n \
                 /usr/libexec/gcc/x86_64-redhat-linux/16/cc1 -quiet /dev/null -O2 \
                 -fno-stack-clash-protection \"-fcf-protection=none\" {appended} -o /tmp/cc.s\n \
                 /usr/libexec/gcc/x86_64-redhat-linux/16/collect2 -z ibt -z relro \
                 -fcf-protection=full -fstack-clash-protection -o a.out\n"
            )
        };
        let arm: &[&str] = &["-O2", "-fno-stack-clash-protection", "-fcf-protection=none"];
        assert_eq!(read(&listing("-fhardened -Wno-hardened"), arm), Ok(None));
        assert_eq!(
            read(&listing("-fhardened -fstack-clash-protection"), arm),
            Ok(Some(of(
                "-fno-stack-clash-protection",
                "-fstack-clash-protection"
            ))),
            "the control row: the same listing with the arm's option set after it"
        );
    }

    #[test]
    fn every_control_word_is_classed() {
        let declined_f = |word: &str| {
            word.strip_prefix("-f").is_some_and(|body| {
                let body = body.strip_prefix("no-").unwrap_or(body);
                let name = body.split_once('=').map_or(body, |(name, _)| name);
                UNREAD_F.contains(&name) || name.starts_with(UNREAD_F_FAMILY)
            })
        };
        let declined = |word: &str, arm: &[&str]| {
            if let Some(handed) = word.strip_prefix("-Wp,") {
                return handed.split(',').all(|piece| {
                    option_of(piece).is_some_and(|macro_set| {
                        arm.iter()
                            .any(|other| option_of(other).as_ref() == Some(&macro_set))
                    })
                });
            }
            word.starts_with("-O")
                || word.starts_with("-Wl,")
                || (word.starts_with("-W") && !word.contains(','))
                || word.starts_with("-m")
                || word == "--param"
                || word.starts_with("ssp-buffer-size=")
                || word == "-pie"
                || word == "-no-pie"
                || declined_f(word)
        };
        let (mut read, mut left) = (0, 0);
        for probe in crate::probe::CORPUS {
            for check in probe.checks {
                let by_arch = crate::probe::ARCH_CONTROLS
                    .iter()
                    .filter(|row| row.check == check.id)
                    .map(|row| row.positive);
                for arm in [check.positive, check.negative].into_iter().chain(by_arch) {
                    for word in arm {
                        match (option_of(word), declined(word, arm)) {
                            (Some(_), false) => read += 1,
                            (None, true) => left += 1,
                            (Some(option), true) => {
                                panic!("{word} of {} is read as {option} and declined", check.id)
                            }
                            (None, false) => panic!(
                                "{word} of {} is neither read as an option's setting nor a \
                                 kind the module note declines",
                                check.id
                            ),
                        }
                    }
                }
            }
        }
        assert!(
            read > 0 && left > 0,
            "both kinds are in the corpus: {read} read, {left} left"
        );
        // The rule the `-Wp,` clause holds, shown on an arm the corpus does not have.
        assert!(declined("-Wp,-U_X", &["-U_X", "-Wp,-U_X"]));
        assert!(!declined("-Wp,-D_X=0", &["-O2", "-Wp,-D_X=0"]));
        assert!(!declined("-Wp,-MD,x.d", &["-U_X", "-Wp,-MD,x.d"]));
    }

    #[test]
    fn an_option_is_named_whatever_its_setting() {
        let same = [
            ("-fno-stack-protector", "-fstack-protector-all"),
            ("-fstack-protector", "-fstack-protector-strong"),
            ("-fstack-protector", "-fstack-protector-explicit"),
            ("-fno-strict-aliasing", "-fstrict-aliasing"),
            (
                "-ftrivial-auto-var-init=zero",
                "-ftrivial-auto-var-init=pattern",
            ),
            ("-fstrict-flex-arrays", "-fstrict-flex-arrays=3"),
            ("-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=3"),
        ];
        for (a, b) in same {
            assert!(option_of(a).is_some(), "{a}");
            assert_eq!(option_of(a), option_of(b), "{a} {b}");
        }
        let apart = [
            ("-fstack-protector", "-fstack-clash-protection"),
            ("-fstack-protector", "-fstack-protector-guard=tls"),
            ("-fstack-protector", "-fstack-protectorfoo"),
            ("-D_FORTIFY_SOURCE=3", "-D_GLIBCXX_ASSERTIONS"),
        ];
        for (a, b) in apart {
            assert!(option_of(a).is_some() && option_of(b).is_some(), "{a} {b}");
            assert_ne!(option_of(a), option_of(b), "{a} {b}");
        }
        // Read, though each begins like a declined name.
        for word in [
            "-fpicture",
            "-fpiece=1",
            "-fno-ltoish",
            "-fhardened-usercopy",
        ] {
            assert!(option_of(word).is_some(), "{word}");
        }
        for word in [
            "-fsanitize=undefined",
            "-fno-sanitize-trap=all",
            "-fsanitize-recover=all",
            "-fPIC",
            "-fpic",
            "-fPIE",
            "-fpie",
            "-fno-PIC",
            "-fno-PIE",
            "-fno-pie",
            "-flto",
            "-fno-lto",
            "-fno-pic",
            "-flto=thin",
            "-fhardened",
            "-f",
            "-fno-",
            "-O2",
            "-Wformat",
            "-mbranch-protection=none",
            "-D",
            "-Wp,-U_GLIBCXX_ASSERTIONS",
        ] {
            assert_eq!(option_of(word), None, "{word}");
        }
    }

    #[test]
    fn a_finding_stands_only_beside_its_arms_setting() {
        let flags = |words: &[&str]| words.iter().map(|w| (*w).to_owned()).collect::<Vec<_>>();
        let arm = flags(&["-m32", "-fno-stack-protector"]);
        let fortify = flags(&["-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0", "-O2"]);
        let all = flags(&["-fstack-protector-all"]);
        let cases = [
            (
                &arm,
                of("-fno-stack-protector", "-fstack-protector-strong"),
                true,
            ),
            (&arm, of("-fno-stack-protector", "-stack-protector 2"), true),
            // Each of the three levels clang names, against the word that asks for it.
            (&arm, of("-fno-stack-protector", "-stack-protector 3"), true),
            (
                &all,
                of("-fstack-protector-all", "-stack-protector 2"),
                true,
            ),
            (
                &all,
                of("-fstack-protector-all", "-stack-protector 3"),
                false,
            ),
            (
                &fortify,
                of("-D_FORTIFY_SOURCE=0", "-D_FORTIFY_SOURCE=3"),
                true,
            ),
            // The level the arm's own word asks for is no other setting.
            (
                &arm,
                of("-fno-stack-protector", "-stack-protector 0"),
                false,
            ),
            (
                &arm,
                of("-fno-stack-protector", "-fno-stack-protector"),
                false,
            ),
            (
                &arm,
                of("-fno-stack-protector", "-fcf-protection=full"),
                false,
            ),
            // A level clang does not name, and another spelling of one it does.
            (
                &arm,
                of("-fno-stack-protector", "-stack-protector strong"),
                false,
            ),
            (
                &arm,
                of("-fno-stack-protector", "-stack-protector 4"),
                false,
            ),
            (
                &arm,
                of("-fno-stack-protector", "-stack-protector 02"),
                false,
            ),
            (
                &arm,
                of("-fno-stack-protector", "-stack-protector +2"),
                false,
            ),
            // A flag the arm never carried.
            (
                &arm,
                of("-fcf-protection=none", "-fcf-protection=full"),
                false,
            ),
            // A flag the arm carried and then set again itself: the arm's setting is its
            // last word of the option, and a record naming an earlier one is no finding.
            (
                &fortify,
                of("-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0"),
                false,
            ),
            (
                &fortify,
                of("-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=3"),
                false,
            ),
            // A word this module reads as no option, both ways.
            (&arm, of("-m32", "-m64"), false),
            (&fortify, of("-O2", "-O0"), false),
        ];
        let mut stood = 0;
        for (flags, finding, expected) in cases {
            assert_eq!(stands(&finding, flags), expected, "{finding:?}");
            stood += usize::from(expected);
        }
        assert_eq!(stood, 5, "five of the eighteen rows stand");
    }

    #[test]
    fn a_protector_level_that_is_no_level_is_unread() {
        for level in ["strong", "4", "02"] {
            let listing = clang_at(level);
            let why = read(&listing, &["-fno-stack-protector"]).expect_err(level);
            assert!(why.contains(&format!("-stack-protector {level}")), "{why}");
            assert_eq!(
                read(&listing, &["-fstack-clash-protection"]),
                Ok(None),
                "{level}"
            );
        }
        assert_eq!(read(&clang_at("0"), &["-fno-stack-protector"]), Ok(None));
    }
}
