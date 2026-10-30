// SPDX-License-Identifier: BSD-3-Clause

//! chard CLI.
//!
//! `chard measure` builds every probe three times per check — bare, positive
//! control, negative control — and emits one schema-conforming report. What every
//! command writes where, and what each exit status means, is [`CONTRACT`], the one
//! statement of it, which `DESIGN.md` carries word for word.
//!
//! The driver's contract with itself: it counts the checks it was handed and
//! compares that against what it emitted, because a check that was never run
//! cannot report its own absence. That count lands in `coverage`, and
//! `--fail-on-missing` turns an incomplete sweep into a distinct exit code so a
//! caller never mistakes a partial column for a full one.

// The same lint wall as `lib.rs`. It was missing here, which left the driver —
// where the control triple is actually wired together, and where a panic would
// abort a sweep mid-flight — as the one module outside the no-panic guarantee the
// project claims.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::as_conversions,
        clippy::cast_lossless,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::unused_result_ok,
        clippy::let_underscore_must_use,
        clippy::map_err_ignore,
        clippy::allow_attributes_without_reason,
    )
)]
// Not under `cfg_attr(not(test))`: a `println!` in the binary is a panic on a closed pipe
// in any build. Output goes through `write_stdout`; `lib.rs` denies the same for the modules.
#![deny(clippy::print_stdout)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

use chard::compile;
use chard::composite;
use chard::dataset;
use chard::detect;
use chard::elf;
use chard::env as environment;
use chard::error::{self, ConfigError, HarnessPath, UserError};
use chard::matrix;
use chard::measure::{self, Conditions, Driver};
use chard::probe::{self, Probe};
use chard::report::{
    self, Coverage, Diagnostic, Observation, Profile, Report, RunMeta, Severity, Verdict,
};
use chard::table;
use chard::toolchain;

/// The contract every command keeps with its caller: what makes a command, what goes to
/// stdout and stderr, each exit status, the error envelope and the schema policy. It is
/// stated here once, printed by `chard --help`, and `DESIGN.md` ("The command-line
/// contract") carries the same words, which `the_contract_is_stated_once` holds; the
/// module docs of `error.rs` and `detect.rs` and the README point here rather than
/// restating it.
const CONTRACT: &str = "A command is one operation that reads reports, binaries or nothing \
     and writes one document: `measure` builds the probes with a compiler and writes a report; \
     `table` and `matrix` read reports, and `digest` reads one and writes the block that \
     report leads with; `detect` reads a report or another of chard's \
     documents (`--evidence`) or one binary (`--artifact`); `elf` reads binaries; `probes` \
     reads nothing and lists what `measure` builds. Setup and tooling, building chard and \
     running its gates among them, are flags or Makefile targets, not commands. A command \
     writes its document to stdout, or to the file `-o` names (`-o -` is stdout); `measure` \
     writes its report to `chard-<cc>-<profile>.json` in the current directory unless `-o` \
     names another file or `-`. The document is JSON except `table`'s rendering and `probes \
     --format text`, which are text for people (as are `--help` and `--version`); progress \
     and notes go to stderr, prefixed `chard: `, and a usage error's own text goes there \
     unprefixed. `measure` ends every run that exits 0, 1, 2 or 3, a refused one too, with one \
     line there naming its exit status, the file it wrote or kept, the report's counts and \
     what to run next; a panic (exit 101) ends on a line saying so, and a killed run on none. \
     Exit 0: the document is \
     written, and from `detect` every reading it replayed agrees. Exit 1: a gate tripped and \
     the document is written: from `measure --fail-on-missing`, a check did not settle; from \
     `detect`, a reading disagrees with its replay. Exit 2: chard refused the invocation or \
     failed, a usage error among them, and a `--execution` that what chard observed \
     contradicts, whose report is kept as for exit 3 and not published. stdout then carries an error envelope in place of the \
     document, `{\"chard_schema\", \"error\": {\"code\", \"operation\", \"message\", \
     \"hint\"}}`, whose `code` names whose action comes next: `USER_INPUT` the caller, \
     `PERMISSION` whoever owns the filesystem, `TRANSIENT` a retry, `CONFIGURATION` the \
     invocation's settings, `INTERNAL` a bug report against chard. Exit 3: chard contradicted \
     itself, and only `measure` exits 3: the report it built disagrees with itself and is not \
     published (it is written only to `<file>.contradicted`, beside the file it would have \
     gone to, and under `-o -` nowhere), and stdout carries an `INTERNAL` envelope whose hint \
     names that file or says how to keep one. Every JSON \
     document but `elf`'s carries `chard_schema`, the major version of its own shape; the \
     shapes of a report, a matrix, `detect`'s output and the envelope are in `schema/`, and \
     `digest`'s is the report's `digest`. \
     `elf`'s output is a map from the paths it was given to their facts, with no place for a \
     key beside them. A key chard adds is not a change: a consumer ignores keys it does not \
     know, and the shipped schemas admit them. Removing or renaming a key, changing a \
     value's type or meaning, or adding a value to an enumeration raises `chard_schema`. The \
     rule holds from chard's first publication, where every document is at `1`. `table`, \
     `matrix`, `digest` and `detect` read a report at the `chard_schema` this chard writes \
     and refuse any other with exit 2, and `table`, `matrix` and `digest` refuse a report \
     without its `digest` the same way.";

/// `chard --help`'s description: what chard is, then [`CONTRACT`].
fn long_about() -> String {
    format!(
        "Measure which C/C++ hardening flags a toolchain actually applies.\n\n\
         `measure` builds small probe programs with the compiler you name, reads the \
         artifacts it just built and the probes' own reports, and publishes a verdict per \
         check only where its control triple (the flag forced on, forced off, and as \
         configured) shows the probe can tell the states apart. It reads no distribution's \
         packaging.\n\n{CONTRACT}"
    )
}

#[derive(Parser)]
#[command(
    name = "chard",
    version = env!("CHARD_VERSION"),
    about = "Measure which C/C++ hardening flags a toolchain actually applies",
    long_about = long_about(),
    after_long_help = "Example:\n  chard measure --cc gcc && chard table chard-gcc-bare.json"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// `--format`, on the two commands that print for people as well as for programs: one
/// declaration over each command's own forms, which clap lists with their default.
#[derive(Args)]
struct FormatArg<F: FormatChoice> {
    /// Form.
    ///
    /// How the document is printed; the forms and the default are listed below.
    // A one-word summary keeps `-h`'s line, which clap ends with the default and the forms,
    // within 80 columns. `default_value`, not `default_value_t`: the derive keeps a `_t`
    // default's rendering in
    // a static, which every instantiation of this struct shares, so `table` was given
    // `probes`'s `json`.
    #[arg(long, value_name = "FORM", value_enum, default_value = F::DEFAULT)]
    format: F,
}

/// One command's `--format` forms, and the one it takes by default.
trait FormatChoice: clap::ValueEnum + Clone + Send + Sync + 'static {
    /// The default form's name, as `--format` spells it.
    const DEFAULT: &'static str;
}

/// How `chard probes` prints the corpus.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum ProbeFormat {
    /// The full listing as JSON: controls, decoders, levels, the defects each check bears
    /// on and what it observes.
    Json,
    /// One line per probe and per check, for people.
    Text,
}

impl FormatChoice for ProbeFormat {
    const DEFAULT: &'static str = "json";
}

/// How `chard table` renders its reports.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum TableFormat {
    /// A grid with its notes wrapped at `--width`, for a terminal.
    Text,
    /// A Markdown table, not wrapped.
    Markdown,
}

impl FormatChoice for TableFormat {
    const DEFAULT: &'static str = "text";
}

impl TableFormat {
    /// The form `table::render_reports` renders: matched whole, so a form added here is
    /// one the renderer is made to name.
    fn form(self) -> table::Format {
        match self {
            Self::Text => table::Format::Text,
            Self::Markdown => table::Format::Markdown,
        }
    }
}

/// `--allow-mixed`, on the two commands that set reports side by side.
#[derive(Args)]
struct AllowMixedArg {
    /// Allow reports that are not one dataset.
    ///
    /// Refused by default where the reports differ in their probe set, the chard revision
    /// that read their evidence (with the source that named it and the rustflags chard was
    /// built under), or where they ran (host, container or vm): a table or a
    /// matrix claims its reports are comparable, so a check missing from an older report
    /// would read as a protection the toolchain lacks, and a change in chard as a property
    /// of a toolchain.
    #[arg(long)]
    allow_mixed: bool,
}

/// `--replace-repeated`, on the two commands that set reports side by side, as the choice
/// each renderer takes: one reading of the flag, so `table` and `matrix` cannot read it apart.
fn repeated_of(replace_repeated: bool) -> matrix::Repeated {
    if replace_repeated {
        matrix::Repeated::Replace
    } else {
        matrix::Repeated::Refuse
    }
}

/// `-o`, on every command but `measure`: each writes one document, and this is where.
#[derive(Args)]
struct OutputArg {
    #[arg(long = "output", short = 'o', value_name = "FILE",
          help = "Write the document to this file (`-`: stdout)",
          long_help = output_help("Write the document to this file, not stdout (`-`: stdout)."))]
    path: Option<PathBuf>,
}

impl OutputArg {
    /// The file `-o` names, or `None` for stdout: no `-o`, or `-o -`.
    fn file(&self) -> Option<&Path> {
        self.path.as_deref().and_then(named_file)
    }
}

/// `-o`'s value as a file, or `None` where it is `-`, which names stdout on every command.
fn named_file(path: &Path) -> Option<&Path> {
    (path != Path::new("-")).then_some(path)
}

/// `-o` on `measure`, whose report goes to a file unless `-o -` asks for stdout: a run's
/// report is about a megabyte of JSON, and on stdout a tool that keeps the head of what it
/// captured kept the head of a document and a cut.
#[derive(Args)]
struct ReportArg {
    #[arg(long = "output", short = 'o', value_name = "FILE",
          help = "Report file; default chard-<cc>-<profile>.json",
          long_help = output_help(
              "Write the report to this file (`-`: stdout).\n\nBy default \
               `chard-<cc>-<profile>.json` in the current directory, `<cc>` the last component \
               of `--cc`. The name holds nothing else, so a run under the same compiler name \
               and profile replaces an earlier report there whatever else it changed (its \
               flags, `--probe`, `--env`, `--execution`, or another compiler of that name), \
               as a rerun does; give each run its own `-o` to keep both. The closing line \
               says when an earlier report was replaced."
          ))]
    path: Option<PathBuf>,
}

/// `-o`'s long help: what it writes, then what an earlier file at the path becomes, which is
/// one rule for every command.
fn output_help(what: &str) -> String {
    format!(
        "{what}\n\nAn invocation refused before the earlier file at the path is set aside \
         leaves that file as it was: a usage error; an input that cannot be read or that the \
         command refuses (a file that is not JSON, a check id `detect` does not know); an \
         option `measure` refuses before it builds (`--probe`, `--env`, a profile's flags, \
         `--workdir`); a path no run could write; and a path that is one of the inputs, or \
         beside which chard writes a name that is one. From the set-aside on, a run that \
         fails leaves no earlier document there to be read as this one (it is kept as \
         `<file>.previous`), and one that writes its document removes what was set aside."
    )
}

#[derive(Subcommand)]
enum Command {
    /// Build probes with a compiler, read the result; write a JSON report.
    ///
    /// Each check gets a verdict (`on`, `off`, `partial`), or a reading that says why it
    /// has none (`unsupported`, `not-applicable`, `indeterminate`, `probe-invalid`,
    /// `build-failed`, `run-failed`). The report goes to `chard-<cc>-<profile>.json` in the
    /// current directory, or to `-o` (`-o -`: stdout). The run's last line on stderr names
    /// its exit status, the file it wrote or kept, the report's counts and what to run next.
    ///
    /// Exits 0 when the report is published; 1 under `--fail-on-missing` when a check is not
    /// settled, which without `--execution` includes the checks that depend on kernel policy; 2
    /// when the run cannot be done or the declared `--execution` is contradicted by what chard
    /// observed (the envelope says why); 3 when the report contradicts
    /// itself, a defect in chard: it is not published (it is written to `<file>.contradicted`,
    /// beside the file it would have gone to, and under `-o -` nowhere), and the `INTERNAL`
    /// envelope on stdout names where it is or how to keep it. Each profile flag the toolchain rejects
    /// is named once per tool that refused it, first in `diagnostics` and above `chard table`'s
    /// grid, with the checks it left `build-failed` counted, and the run still exits 0, or 1
    /// under `--fail-on-missing`.
    #[command(after_long_help = "Examples:\n  \
        chard measure --cc gcc && chard table chard-gcc-bare.json\n  \
        chard measure --cc clang --profile explicit \\\n      \
        --flags \"-O2 -D_FORTIFY_SOURCE=3 -fstack-protector-strong\" \\\n      \
        --ldflags \"-Wl,-z,relro,-z,now\" -o clang-flags.json")]
    Measure(Box<MeasureArgs>),
    /// Read nothing; write the probes and their checks, as JSON or text.
    ///
    /// A probe is one program; a check is one question a probe answers, so one probe can
    /// hold several checks. `measure --probe` takes probe ids; `detect` takes a check id.
    #[command(after_long_help = "Example:\n  chard probes --format text")]
    Probes {
        #[command(flatten)]
        format: FormatArg<ProbeFormat>,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Read reports; write them as a table for people, a column each.
    #[command(
        after_long_help = "Example:\n  chard table gcc-bare.json clang-bare.json --width \"${COLUMNS:-80}\""
    )]
    Table {
        /// Report files to render.
        #[arg(required = true)]
        reports: Vec<PathBuf>,
        #[command(flatten)]
        format: FormatArg<TableFormat>,
        /// A row per defect class (what is protected), not flag.
        #[arg(long)]
        by_defect: bool,
        #[command(flatten)]
        allow_mixed: AllowMixedArg,
        /// Keep a repeated configuration's later report, whole.
        ///
        /// Refused by default where two reports agree on every axis a column keys on: a
        /// table column holds one report. With this flag the later report on the command
        /// line replaces the earlier's column, nothing of the earlier kept, and the table's
        /// notes name both reports, every flag whose verdict or polarity differs between
        /// them, a differing `kernel.ownership`, and every flag that left the column with the
        /// earlier or joined it with the later; with `--by-defect`, every defect class drawn
        /// differently, and every class that left or joined.
        #[arg(long)]
        replace_repeated: bool,
        /// Wrap a text table's notes (default 80; 0: no wrap).
        ///
        /// The legend, levels, flags, withheld reasons and notes are wrapped; the grid is as
        /// wide as its columns, and `markdown` is not wrapped. chard does not read the
        /// terminal's width: pass `--width "${COLUMNS:-80}"` to fit it.
        #[arg(long, value_name = "COLS", default_value_t = table::DEFAULT_WIDTH, hide_default_value = true)]
        width: usize,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Read reports; write them cross-tabulated by configuration, as JSON.
    ///
    /// A distribution is only one of the things a result depends on: the compiler version,
    /// the C library and the flag profile can each explain it. The matrix keys every report
    /// on all of them and, for each check, names which axes account for its results, or
    /// says that none does alone.
    #[command(after_long_help = "Example:\n  chard matrix reports/*.json")]
    Matrix {
        /// Report files to tabulate.
        #[arg(required = true)]
        reports: Vec<PathBuf>,
        #[command(flatten)]
        allow_mixed: AllowMixedArg,
        /// Keep a repeated configuration's later report, whole.
        ///
        /// Refused by default where two reports agree on every axis the matrix keys on: a
        /// matrix cell holds one report. With this flag the later report on the command line
        /// replaces the earlier's cell, nothing of the earlier kept, and the matrix's warnings
        /// name both reports, every flag whose verdict or polarity differs between them, a
        /// differing `kernel.ownership`, and every flag that left the cell with the earlier or
        /// joined it with the later.
        #[arg(long)]
        replace_repeated: bool,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Read one report; write its digest alone, as JSON.
    ///
    /// The digest is the report's first key: the consistency status, coverage with its earned
    /// limitations apart from its instrument withholdings, one row per check (verdict, level,
    /// polarity, channel, gating rule), every reason a check is not a measurement, and the
    /// toolchain, profile, execution mode and revision measured, without the controls, facts
    /// and decoders that make up most of the report. It is derived from the report's own
    /// fields. Its `consistency` is the report's `consistency.status`, the word `measure` wrote
    /// after applying every consistency rule; reading the report, chard re-runs only the rules
    /// that need nothing outside the file. Exit 2 refuses what `table` refuses: a report whose
    /// `chard_schema` is not the one this chard reads, one with no digest, one that
    /// contradicts itself, and one whose digest is not the one its fields give.
    #[command(after_long_help = "Example:\n  chard digest chard-gcc-bare.json")]
    Digest {
        /// Report file to read.
        report: PathBuf,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Read binaries; write the ELF facts chard decides from, as JSON.
    ///
    /// These are the facts the artifact checks decide from (program headers, dynamic
    /// tags, property notes, symbols); no verdict is formed.
    #[command(after_long_help = "Example:\n  chard elf /usr/bin/ls")]
    Elf {
        /// Binaries to inspect.
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Read a chard document or a binary; write a replay or detection.
    ///
    /// With a report (`--evidence report.json`), each reading of the check that can be
    /// decided again from the report's own facts is, and compared with what the report
    /// states, each verdict with its control triple. The counts are printed: `expected`
    /// equals `replayed` plus `not_replayable`. A report with no reading of the check is
    /// refused. Exit 0 when all agree, 1 on a disagreement (a tripped gate: the replay is
    /// written, and each disagreement in it is an entry with `agrees: false`, a
    /// `decoder.digest_agrees: false` or a `reading-absent` entry), 2 on input that cannot be
    /// used.
    ///
    /// With one `facts` entry, a `chard elf` output or `--artifact`, the decoder runs once
    /// and prints a detection. That is not a verdict: no control triple ran.
    ///
    /// The argument is a check id, as `chard probes --format text` lists it, not a probe id.
    #[command(after_long_help = "Examples:\n  \
        chard detect relro --evidence report.json\n  \
        chard detect cet-marked --artifact ./a.out")]
    Detect {
        /// A check id (not a probe id), from `chard probes --format text`.
        check: String,
        /// A report, a `facts` entry, a fixture or `elf` output.
        #[arg(long, value_name = "FILE")]
        evidence: Option<PathBuf>,
        /// An ELF object to read, with its `.chard.report`.
        #[arg(long, value_name = "FILE")]
        artifact: Option<PathBuf>,
        /// With a report, re-check one reading only.
        ///
        /// `measured`, `positive`, `negative` or `regime`.
        #[arg(long)]
        arm: Option<String>,
        #[command(flatten)]
        output: OutputArg,
    },
}

#[derive(Parser)]
struct MeasureArgs {
    /// C compiler driver to measure.
    #[arg(long, default_value = "cc")]
    cc: String,

    /// Profile: bare (default), or see --help.
    ///
    /// `bare` measures the compiler's own defaults. `bare-optimized` adds only -O2, which
    /// `_FORTIFY_SOURCE` needs to exist. `openssf-tldr` builds with the flags the OpenSSF
    /// compiler options guide recommends: a near positive control, on which most checks
    /// read `on` and some read `off` by the guide's own choices. `explicit` builds with the
    /// lists you give in `--flags`, `--cxxflags` and `--ldflags`: a distribution's own build
    /// flags are measured this way.
    // chard does not query rpm, dpkg-buildflags, abuild, makepkg or portageq: a runtime
    // query describes only the image it runs in, and each distribution's spelling of its
    // flag list belongs to whatever assembles the list.
    #[arg(long, default_value = "bare", hide_default_value = true, hide_possible_values = true, value_parser = ["bare", "bare-optimized", "openssf-tldr", "explicit"])]
    profile: String,

    /// C flags for --profile explicit.
    ///
    /// Split on whitespace. Refused beside any other profile, as are `--cxxflags` and
    /// `--ldflags`. Also refused, in any of the three lists:
    ///
    /// - a response file (`@file`, or `@` inside `-Wl,`, `-Wp,` or `-Wa,`), which chard
    ///   cannot read into;
    ///
    /// - a relative path given to `-B`, `-L`, `-I`, `--sysroot` and their kin, read as the
    ///   driver or the tool a word is handed to reads it (write it absolute), and a path
    ///   option handed to a tool with no path in the same word or the pair after it;
    ///
    /// - a flag that removes the startup objects, the default libraries or the default
    ///   headers (`-nostartfiles`, `-nostdlib`, `-nostdinc` and their kin);
    ///
    /// - a pair the two drivers read differently, an option one of gcc and clang takes a
    ///   value for and the other reads as a flag of its own (clang's `-isystem-after` and
    ///   `-dependency-file`, gcc's `-Tbss` and their kin), followed by a word that selects
    ///   something or takes a word of its own;
    ///
    /// - a flag that can select x32, 16-bit or aarch64 ILP32 code, targets chard does not
    ///   measure (`-mx32`, `-m16`, `-mabi=ilp32`, a triple with an x32, `code16` or
    ///   `gnu_ilp32` environment or an `arm64_32` architecture, `-arch arm64_32`, or GNU as's
    ///   `--x32` handed to the assembler), wherever it stands, even where a later flag overrides it: remove it.
    // `allow_hyphen_values`: every realistic value starts with `-`, which clap would
    // otherwise reject as an unknown option.
    #[arg(long, allow_hyphen_values = true)]
    flags: Option<String>,

    /// C++ flags for --profile explicit.
    ///
    /// Without them the C++ probes are built with `--flags`. Distributions set the C++
    /// hardening macros (`_GLIBCXX_ASSERTIONS`, `_LIBCPP_HARDENING_MODE`) in CXXFLAGS, so
    /// pass that list here, or the C++ checks measure a build without them.
    // Building the C++ probes with CFLAGS asks a question whose answer is `off` wherever the
    // two differ, which is where the C++ hardening lives (`report::Profile::cxxflags`).
    #[arg(long, allow_hyphen_values = true)]
    cxxflags: Option<String>,

    /// Link flags for --profile explicit.
    ///
    /// Added to every probe's link, and kept apart so the report records `-Wl,-z,relro` and
    /// its kin as the build's LDFLAGS, not folded into its CFLAGS.
    #[arg(long, allow_hyphen_values = true)]
    ldflags: Option<String>,

    /// A variable for the toolchain (repeatable).
    ///
    /// The compiler runs with only `PATH`, `LC_ALL=C` and `TERM=dumb` set, under any
    /// profile, so a toolchain configured through its environment (a Nix cc-wrapper's
    /// `NIX_HARDENING_ENABLE` and its `NIX_CC_WRAPPER_TARGET_HOST_<triple>=1`) is measured
    /// as configured only when each variable it reads is given here. Each pair reaches every
    /// compiler run, never a probe's own run, and is published in the report
    /// (`profile.compiler_environment`), so none should be a secret. `PATH`, `LC_ALL` and
    /// `TERM` are refused, as are a name given twice, a name that is not a portable variable
    /// name, and a value holding a relative path, read as in `--flags` (write it absolute).
    #[arg(long = "env", value_name = "NAME=VALUE", allow_hyphen_values = true)]
    env: Vec<String>,

    /// Work directory, kept as evidence.
    ///
    /// Sources, artifacts and captured output are kept here and not cleaned up (default
    /// `chard-work`). One run at a time: a second run in a directory a live run holds is
    /// refused.
    #[arg(
        long,
        value_name = "DIR",
        default_value = "chard-work",
        hide_default_value = true
    )]
    workdir: PathBuf,

    /// Put the full macro dump in the report.
    #[arg(long)]
    emit_macros: bool,

    /// Where chard runs: `host`, `container`, `vm`.
    ///
    /// Detected as far as chard can: a container runtime's marker file, a cgroup path naming docker, libpod,
    /// containerd or lxc, systemd's `/run/systemd/container`, a `container=` word on PID 1 (read as root or
    /// PID 1's user) or a user namespace reads `container`; no
    /// instrument reads `host` or `vm`, so without the flag the mode is `host` by default and whose kernel it is
    /// stays unsettled. The checks that depend on kernel policy are reported `indeterminate` under `container` and
    /// under that default; where chard observed no container, `--execution host` or `vm` publishes them, and inside
    /// a container it recognises an asserted `host` or `vm` is refused as a contradicted assertion.
    #[arg(long, value_name = "WHERE", hide_possible_values = true, value_parser = ["host", "container", "vm"])]
    execution: Option<String>,

    /// The image this run is in, as recorded.
    #[arg(long)]
    image: Option<String>,

    /// A JSON file saying where the image came from.
    ///
    /// Written by whatever fetched and verified the image. Without it, a container or vm
    /// run records `image_attestation: unattested`, and a host run, which has no image,
    /// records `not-applicable` and refuses one. chard cannot verify the attestation from
    /// inside the image: it records it and says so. One whose digest was compared with a
    /// fetched manifest and did not match is refused; one whose manifest could not be
    /// fetched is recorded as unattested. An `installed_disk` record in it is published too.
    // The harness writes this object as `provenance` in its session file; an
    // `installed_disk` record is `env::InstalledDisk`, hashed into `run.inputs_sha256`.
    #[arg(long, value_name = "FILE")]
    image_attestation: Option<PathBuf>,

    /// Run only these probes, by probe id.
    ///
    /// Repeatable. Probe ids are listed by `chard probes --format text`. A probe id names a
    /// program, which may hold several checks; `detect` takes a check id instead. The
    /// report's `coverage` then counts only the selected checks (`checks_expected` below
    /// `corpus_checks_total`), so it is never mistaken for a full run.
    #[arg(long = "probe", value_name = "PROBE")]
    probes: Vec<String>,

    /// Seconds a probe may run.
    ///
    /// At least 1; a probe still running then is stopped.
    // `0` is refused: it kills a probe still running at the first look (`run::execute`), so
    // a run under it measures how fast each probe exits rather than what it reports.
    #[arg(long, value_name = "SECS", default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..))]
    timeout: u64,

    /// Exit 1 unless every check settled.
    ///
    /// A check settles on a verdict (`on`, `off`, `partial`), or on `unsupported` or
    /// `not-applicable` where the run established that the toolchain or the host has no
    /// such mechanism. Any other reading, and an `unsupported` that rests on a limit of
    /// chard's own, fails it, and each check that fails it is named on stderr with the
    /// reason the report records, the lines ending on the exit status and the remedy where
    /// chard knows one. Without
    /// `--execution`, the checks that depend on kernel policy (`noexecstack-enforced`,
    /// `shadow-stack-enforced`) are withheld, since nothing chard reads tells a system that
    /// owns its kernel from a container chard has no instrument for, and so fail it.
    /// `--execution host` or `vm` lets them be measured on a target that has them; a kernel
    /// with no shadow-stack interface settles `shadow-stack-enforced` as `unsupported`,
    /// while a platform or a CPU chard's run was handed that cannot answer them leaves them
    /// unsettled even then. The gate
    /// counts the whole corpus, so a run narrowed by `--probe` always fails it. This says
    /// whether the run was complete, not whether the build is hardened. A list of the
    /// `off` verdicts is not a hardening gate either: for a `weaken` check `off` is the
    /// protected state, and a `partial` or withheld verdict is neither `on` nor `off`.
    /// Which checks a build must have is the reader's decision.
    #[arg(long)]
    fail_on_missing: bool,

    /// Also compare SARIF with the text reading.
    ///
    /// Each compiler-diagnostic build's SARIF output is read and compared with the text
    /// reading, arm by arm, at the cost of one extra build per arm. The verdicts are the
    /// text reading's either way; disagreements are published as diagnostics and counted in
    /// `structured_diagnostics`.
    #[arg(long)]
    structured_diagnostics: bool,

    /// Blank what varies between runs.
    ///
    /// The start time and every duration are zeroed; the values of `--workdir`, `-o` and
    /// `--image-attestation` in the recorded invocation become `<normalized>`; and the
    /// readings inside a probe's output that move from run to run (stack-clash-guard-page's
    /// `SCPRT dist=`) become `<volatile>`. Two normalized reports of the same measurement
    /// then compare byte for byte. The schema marks each such field `x-volatile` and lists
    /// each reading under `x-volatile-readings`.
    // The lists are `report::VOLATILE_FIELDS`, `report::VOLATILE_READINGS` and
    // `report::INVOCATION_PATH_OPTIONS`.
    #[arg(long)]
    normalize: bool,

    #[command(flatten)]
    output: ReportArg,
}

impl MeasureArgs {
    /// The file the report goes to, or `None` for stdout: `-o`'s file, nothing for `-o -`,
    /// and by default [`default_report_name`].
    ///
    /// # Errors
    ///
    /// [`UserError`], when `--cc` has no last component to name the report from.
    fn report_file(&self) -> Result<Option<PathBuf>> {
        match self.output.path.as_deref() {
            Some(path) => Ok(named_file(path).map(Path::to_path_buf)),
            None => default_report_name(&self.cc, &self.profile).map(Some),
        }
    }
}

/// `chard-<cc>-<profile>.json`, relative, so in the current directory: named from the two
/// inputs that most decide what a report says and nothing of the host, so a rerun of one
/// measurement replaces its own earlier report (set aside as `-o`'s is) and a run of another
/// compiler or profile beside it does not. `<cc>` is the last component of `--cc`, so
/// `/usr/bin/gcc-14` names `chard-gcc-14-bare.json`.
///
/// # Errors
///
/// [`UserError`], for a `--cc` with no last component (`/`, `..`, a path ending in `..`).
fn default_report_name(cc: &str, profile: &str) -> Result<PathBuf> {
    let Some(base) = Path::new(cc).file_name() else {
        return Err(UserError::with_hint(
            format!("--cc {cc} has no file name to name the report from"),
            "give --cc the compiler's name or path, or name the report with -o",
        )
        .into());
    };
    let mut name = std::ffi::OsString::from("chard-");
    name.push(base);
    name.push(format!("-{profile}.json"));
    Ok(PathBuf::from(name))
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(refusal) => return refuse_usage(&refusal),
    };
    let operation = match &cli.command {
        Command::Measure(_) => "measure",
        Command::Matrix { .. } => "matrix",
        Command::Digest { .. } => "digest",
        Command::Table { .. } => "table",
        Command::Probes { .. } => "probes",
        Command::Elf { .. } => "elf",
        Command::Detect { .. } => "detect",
    };
    match dispatch(cli) {
        Ok(code) => code,
        Err(err) => error::emit(operation, &err),
    }
}

/// A command line clap refuses, through the envelope as every other refusal is: clap's own
/// text (the error, a tip, the usage line) goes to stderr, and stdout carries a
/// `USER_INPUT` envelope naming the command, exit 2. Left to `Cli::parse`, it would exit
/// 2 with stdout empty, the one refusal in which a caller reading stdout would find nothing.
/// `--help` and `--version` reach here as clap's "errors" too, and print to stdout with
/// exit 0.
fn refuse_usage(refusal: &clap::Error) -> ExitCode {
    use clap::error::ErrorKind;
    // clap's text quotes the command line, and clap built without `color` passes a quoted
    // escape through as given, so the text is scrubbed before it reaches either stream or
    // the envelope.
    let rendered = table::scrub_lines(&refusal.to_string());
    let write = |stream: &mut dyn std::io::Write| {
        stream
            .write_all(rendered.as_bytes())
            .and_then(|()| stream.flush())
    };
    // Where it goes is clap's choice by kind: stdout for help and version, stderr for the
    // rest. A closed or full stream has nowhere left to report to.
    if refusal.use_stderr() {
        error::best_effort(write(&mut std::io::stderr()));
    } else {
        error::best_effort(write(&mut std::io::stdout()));
    }
    let message = match refusal.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
            return ExitCode::from(error::EXIT_OK);
        }
        // clap's message here is the whole help, printed above.
        ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => match invoked_command() {
            Some(command) => format!("`chard {command}` takes a command"),
            None => "chard takes a command".to_owned(),
        },
        _ => {
            // clap's first block, up to its first blank line: the error and what it names
            // (the arguments missing, the values allowed); a tip and the usage line follow.
            let block = rendered
                .lines()
                .take_while(|line| !line.trim().is_empty())
                .map(str::trim)
                .collect::<Vec<_>>()
                .join(" ");
            match block.strip_prefix("error: ").unwrap_or(&block) {
                "" => "the command line was refused".to_owned(),
                message => message.to_owned(),
            }
        }
    };
    let command = invoked_command();
    let hint = match &command {
        Some(command) => format!("see `chard {command} --help` for what it takes"),
        None => "see `chard --help` for the commands".to_owned(),
    };
    let code = error::emit(
        command.as_deref().unwrap_or("chard"),
        &UserError::with_hint(message, hint).into(),
    );
    // `measure` closes every run with its line, one clap refused among them.
    if command.as_deref() == Some("measure") {
        error::note(&failed_line(error::EXIT_FAILURE, &Ending::default()));
    }
    code
}

/// The command the arguments name, where they name one: the first argument after the
/// program name. The top level takes no option but `--help` and `--version`, which never
/// reach here, so a refusal with anything before the command is the top level's own.
fn invoked_command() -> Option<String> {
    use clap::CommandFactory;
    let first = std::env::args_os().nth(1)?;
    let first = first.to_str()?;
    Cli::command()
        .get_subcommands()
        .find(|c| c.get_name() == first)
        .map(|c| c.get_name().to_owned())
}

fn dispatch(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Measure(args) => Ok(measure_command(&args)),
        Command::Table {
            reports,
            format,
            by_defect,
            allow_mixed,
            replace_repeated,
            width,
            output,
        } => {
            // The inputs are read and parsed first: a path that is missing, unreadable or
            // named as unpublished is the invocation's error and leaves an earlier table at
            // `-o` untouched. Then, as `measure` does and for the same reason, the earlier
            // table is set aside before the set is judged, so a refused set (reports of two
            // datasets, a report that contradicts itself) leaves no earlier table at `-o`
            // to be read as this one.
            let inputs = dataset::read_reports(&reports)?;
            let destination = set_aside_output(output.file(), &paths_of(&reports))?;
            let rendered = table::render_reports(
                &inputs,
                format.format.form(),
                by_defect,
                allow_mixed.allow_mixed,
                repeated_of(replace_repeated),
                width,
            )?;
            deliver(destination.as_ref(), &rendered, "table")?;
            Ok(ExitCode::from(error::EXIT_OK))
        }
        Command::Matrix {
            reports,
            allow_mixed,
            replace_repeated,
            output,
        } => {
            // As for `table`: the inputs first, then the set-aside, then the judgement.
            let inputs = dataset::read_reports(&reports)?;
            let destination = set_aside_output(output.file(), &paths_of(&reports))?;
            let m = matrix::build_from_reports(
                &inputs,
                allow_mixed.allow_mixed,
                repeated_of(replace_repeated),
            )?;
            let rendered = serde_json::to_string_pretty(&m).context("serializing the matrix")?;
            deliver(destination.as_ref(), &format!("{rendered}\n"), "matrix")?;
            Ok(ExitCode::from(error::EXIT_OK))
        }
        Command::Digest { report, output } => {
            // As for `table`: the input first, then the set-aside, then the judgement, which
            // holds the digest to the report's own fields (`report::reread_contradictions`).
            let input = dataset::read_report(&report)?;
            let destination = set_aside_output(output.file(), &[report.as_path()])?;
            let digest = report::digest::of_read(&input)?;
            deliver(destination.as_ref(), &json_document(digest)?, "digest")?;
            Ok(ExitCode::from(error::EXIT_OK))
        }
        Command::Probes { format, output } => {
            let destination = set_aside_output(output.file(), &[])?;
            let rendered = match format.format {
                ProbeFormat::Text => corpus_text(),
                ProbeFormat::Json => json_document(&corpus_listing())?,
            };
            deliver(destination.as_ref(), &rendered, "probe listing")?;
            Ok(ExitCode::from(error::EXIT_OK))
        }
        Command::Elf { paths, output } => {
            let mut out = BTreeMap::new();
            for path in &paths {
                // `ElfError` names the path itself, and `error::classify` reads its
                // variant, so no context is layered over it.
                let facts = elf::facts_for(path)?;
                out.insert(path.display().to_string(), facts);
            }
            // As for `table`: the inputs first, then the set-aside.
            let destination = set_aside_output(output.file(), &paths_of(&paths))?;
            deliver(destination.as_ref(), &json_document(&out)?, "ELF facts")?;
            Ok(ExitCode::from(error::EXIT_OK))
        }
        Command::Detect {
            check,
            evidence,
            artifact,
            arm,
            output,
        } => detect_command(
            &check,
            evidence.as_deref(),
            artifact.as_deref(),
            arm.as_deref(),
            output.file(),
        ),
    }
}

/// `chard detect`: `detect` carries the mechanism; this checks the invocation and maps
/// agreement onto the exit code.
fn detect_command(
    check: &str,
    evidence: Option<&Path>,
    artifact: Option<&Path>,
    arm: Option<&str>,
    output: Option<&Path>,
) -> Result<ExitCode> {
    let check = detect::check_by_id(check)?;
    let arm = arm.map(detect::ArmSel::parse).transpose()?;
    let decoded = match (evidence, artifact) {
        (Some(path), None) => detect::decode_file(path, check, arm)?,
        (None, Some(path)) => {
            if arm.is_some() {
                return Err(UserError::with_hint(
                    "--arm selects among a report's readings, and --artifact reads one object",
                    "drop --arm, or pass a report with --evidence",
                )
                .into());
            }
            detect::Output::Detected(detect::decode_artifact(path, check)?)
        }
        (Some(_), Some(_)) | (None, None) => {
            return Err(UserError::with_hint(
                "detect takes exactly one of --evidence and --artifact",
                "pass a report, store entry, record or `chard elf` output with --evidence, \
                 or an ELF object with --artifact",
            )
            .into());
        }
    };
    // As for `table`: the inputs first, then the set-aside.
    let inputs: Vec<&Path> = evidence.into_iter().chain(artifact).collect();
    let destination = set_aside_output(output, &inputs)?;
    deliver(destination.as_ref(), &json_document(&decoded)?, "detection")?;
    Ok(ExitCode::from(if decoded.agrees() {
        error::EXIT_OK
    } else {
        error::EXIT_GATE
    }))
}

/// [`report::set_aside`] on a command's `-o`, with the path in the error's context: where
/// the output goes, classified once for every write after it. An output the run could
/// never publish to is refused first ([`refuse_unpublishable_output`]), so the refusal
/// leaves an earlier output where it is.
fn set_aside_output(
    output: Option<&Path>,
    inputs: &[&Path],
) -> Result<Option<report::Destination>> {
    output
        .map(|path| {
            refuse_output_naming_an_input(path, inputs)?;
            refuse_unpublishable_output(path)?;
            report::set_aside(path)
                .with_context(|| format!("setting aside the earlier {}", path.display()))
        })
        .transpose()
}

/// An `-o` that is one of the command's own `inputs`, or a name chard writes beside `-o`
/// that is one, is refused: the input has been read, and the set-aside, the cleanup of
/// temporary names and the publication would replace or remove it, so `chard elf ./a.out
/// -o ./a.out` removed the binary, `chard table r.json -o r.json` the report, and `chard elf
/// a.out.previous -o a.out` the binary the set-aside renamed `a.out` over. `-o` itself is
/// compared by device and inode, so a second spelling of the input, a hard link to it or a
/// symbolic link to it is refused as the input is (regular files only: a stream such as
/// `/dev/stdout` can share a terminal's inode and is no file to lose). The names beside it
/// are compared as directory entries, since a rename or a removal acts on the entry. An
/// input is one of them when its own entry, or the entry at the end of a link it is, is in
/// the directory of the file a publication writes ([`report::published_path`], the end of
/// a link at `-o`) and is that file's name followed by [`report::SET_ASIDE_SUFFIX`] or
/// [`report::QUARANTINE_SUFFIX`], or by [`report::PARTIAL_SUFFIX`] and anything after it.
///
/// # Errors
///
/// [`UserError`], when a name chard writes is one of the inputs.
fn refuse_output_naming_an_input(output: &Path, inputs: &[&Path]) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let same_file = |a: &Path, b: &Path| {
        std::fs::metadata(a).is_ok_and(|a| {
            std::fs::metadata(b).is_ok_and(|b| {
                a.is_file() && b.is_file() && a.dev() == b.dev() && a.ino() == b.ino()
            })
        })
    };
    // A path's directory, resolved, and its own name: the entry a rename or a removal
    // acts on. `None` where either cannot be had, which names no entry an input could be.
    let entry = |path: &Path| {
        let directory = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        match (std::fs::canonicalize(directory), path.file_name()) {
            (Ok(directory), Some(name)) => Some((directory, name.to_os_string())),
            _ => None,
        }
    };
    // A failure to classify `-o` is `refuse_unpublishable_output`'s, which runs next.
    let beside = match report::published_path(output) {
        Ok(Some(published)) => entry(&published),
        _ => None,
    };
    for input in inputs {
        if same_file(output, input) {
            return Err(UserError::with_hint(
                format!(
                    "the output {} is the input {}, which writing it would replace",
                    output.display(),
                    input.display()
                ),
                "give -o a path that is not one of the inputs",
            )
            .into());
        }
        let Some((directory, name)) = &beside else {
            continue;
        };
        let name = name.as_encoded_bytes();
        // The input's own entry, and the entry at the end of a link it is, since a rename
        // or a removal of that one loses what the link reads.
        let mut entries = vec![entry(input)];
        if let Ok(resolved) = std::fs::canonicalize(input) {
            entries.push(entry(&resolved));
        }
        let written = entries
            .into_iter()
            .flatten()
            .any(|(input_directory, input_name)| {
                input_directory == *directory
                    && input_name
                        .as_encoded_bytes()
                        .strip_prefix(name)
                        .is_some_and(|rest| {
                            rest == report::SET_ASIDE_SUFFIX.as_bytes()
                                || rest == report::QUARANTINE_SUFFIX.as_bytes()
                                || rest.starts_with(report::PARTIAL_SUFFIX.as_bytes())
                        })
            });
        if written {
            return Err(UserError::with_hint(
                format!(
                    "the input {} is a name chard replaces or removes when it writes {}",
                    input.display(),
                    output.display()
                ),
                "rename the input, or give -o a path whose names beside it are not an input",
            )
            .into());
        }
    }
    Ok(())
}

/// [`report::refuse_unpublishable`] on `-o`, as the refusal that names what to change.
///
/// Each shape has its own hint, because the one the io table gives a missing path names
/// scripts and interpreters, which an output has neither of.
/// An output neither route can write is `PERMISSION`, as an unwritable `--workdir` is, with
/// a hint for the kind that refused it: a permission, or a read-only filesystem. A path
/// whose shape is wrong (a directory in it missing or a regular file, a name ending in a
/// slash) is `USER_INPUT` with a hint about the path; any other io error, a full
/// filesystem or a name too long even in place, is classified by its kind as before.
///
/// # Errors
///
/// The refusal, when the output is unusable.
fn refuse_unpublishable_output(path: &Path) -> Result<()> {
    use std::io::ErrorKind as Kind;
    let refusal = match report::refuse_unpublishable(path) {
        Ok(()) => return Ok(()),
        Err(refusal) => refusal,
    };
    let message = format!("the output {} cannot be written: {refusal}", path.display());
    Err(match refusal {
        report::Unpublishable::NoDirectory { directory } => UserError::with_hint(
            message,
            format!(
                "create {} first, or give -o a path in a directory that exists",
                directory.display()
            ),
        )
        .into(),
        report::Unpublishable::Directory => UserError::with_hint(
            message,
            "-o names the file to write; give a file name inside the directory",
        )
        .into(),
        report::Unpublishable::BrokenLink(_) => UserError::with_hint(
            message,
            "point the link at a file in a directory that exists, or give -o another path",
        )
        .into(),
        report::Unpublishable::Unwritable { in_place, .. } => error::PermissionError {
            message,
            hint: if in_place.kind() == Kind::ReadOnlyFilesystem {
                "the filesystem holding it is read-only; give -o a path on a writable one"
            } else {
                "give -o a path in a directory this user can create files in"
            }
            .to_owned(),
        }
        .into(),
        report::Unpublishable::SiblingName { .. } | report::Unpublishable::SiblingLength { .. } => {
            UserError::with_hint(
                message,
                "give -o a shorter file name: chard writes names beside the output that are \
             longer than it",
            )
            .into()
        }
        report::Unpublishable::Io(source)
            if matches!(
                source.kind(),
                Kind::NotFound | Kind::NotADirectory | Kind::IsADirectory
            ) =>
        {
            UserError::with_hint(
                message,
                "-o names a file: check that each directory in its path exists and is a \
                 directory, and that it does not end in a slash",
            )
            .into()
        }
        report::Unpublishable::Io(source) => anyhow::Error::new(source)
            .context(format!("the output {} cannot be written", path.display())),
    })
}

/// `paths` as the slice [`set_aside_output`] takes its inputs in.
fn paths_of(paths: &[PathBuf]) -> Vec<&Path> {
    paths.iter().map(PathBuf::as_path).collect()
}

/// [`report::discard_set_aside`], with the path in the error's context.
fn discard_set_aside(destination: &report::Destination) -> Result<()> {
    report::discard_set_aside(destination)
        .with_context(|| format!("removing the earlier {destination} set aside before this run"))
}

/// `value` as the JSON document a command writes: pretty, with a closing newline.
fn json_document<T: serde::Serialize>(value: &T) -> Result<String> {
    let rendered = serde_json::to_string_pretty(value).context("serializing output")?;
    Ok(format!("{rendered}\n"))
}

/// Write a command's `document` where it goes: to `-o`, which [`set_aside_output`] has
/// classified and cleared, naming `what` was written on stderr; or to stdout.
fn deliver(destination: Option<&report::Destination>, document: &str, what: &str) -> Result<()> {
    match destination {
        Some(destination) => {
            destination
                .write(document.as_bytes())
                .with_context(|| format!("writing {destination}"))?;
            discard_set_aside(destination)?;
            error::note(&format!("{what} written to {destination}"));
            Ok(())
        }
        None => write_stdout(document),
    }
}

/// Write `text` to stdout and flush it: the one way a subcommand's output reaches stdout,
/// held by the `print_stdout` lint above.
///
/// A reader that closed the pipe (`chard probes | head -1`) has left, and the command
/// keeps the exit status its own work earned. Rust ignores `SIGPIPE`, so where a C
/// program would be killed the write returns `EPIPE`, and `println!` turned that into a
/// panic and exit 101. Every subcommand writes its output last, so nothing is skipped
/// by returning here. Any other write error (`ENOSPC` on `> /dev/full`) is the
/// invocation's failure, since the output did not reach a reader that asked for it.
/// The probes chard runs are untouched: `std::process::Command` restores the default
/// `SIGPIPE` disposition in every child it spawns.
fn write_stdout(text: &str) -> Result<()> {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        written => written.context("writing to stdout"),
    }
}

/// Split a caller-supplied flag string on whitespace.
///
/// Whitespace only: chard does not implement shell quoting, so a flag containing a
/// literal space cannot be passed here. Splitting is what `--flags` has always done and
/// the two new arguments match it rather than inventing a second convention.
fn split_flags(text: &str) -> Vec<String> {
    text.split_whitespace().map(ToOwned::to_owned).collect()
}

/// A check's level vocabulary as `chard probes` publishes it: the words
/// `observations[].level` may carry for this check, whether they are graded, and on a
/// graded check the scale's kind and the ask. `probe::Levels` carries the mechanism.
fn levels_listing(levels: probe::Levels) -> serde_json::Value {
    let mut listing = serde_json::Map::new();
    listing.insert("kind".to_owned(), serde_json::json!(levels.kind()));
    listing.insert("words".to_owned(), serde_json::json!(levels.words()));
    if let Some(grade) = levels.grade() {
        // The words the check may publish on no rung of the scale, graded against nothing
        // (`probe::Grade::ungraded`); listed only where there are any.
        if !grade.ungraded.is_empty() {
            listing.insert("ungraded".to_owned(), serde_json::json!(grade.ungraded));
        }
        listing.insert("scale".to_owned(), serde_json::json!(grade.scale.kind()));
        listing.insert(
            "recommended".to_owned(),
            serde_json::json!(grade.recommended),
        );
    }
    serde_json::Value::Object(listing)
}

/// A check's decoder as `chard probes` publishes it: its kind, the predicate language
/// where it is a predicate, and the digest `probe::Decoder::sha256` takes.
fn decoder_listing(decoder: &probe::Decoder) -> serde_json::Value {
    let mut listing = serde_json::Map::new();
    listing.insert("kind".to_owned(), serde_json::json!(decoder.kind()));
    if decoder.predicate().is_some() {
        listing.insert(
            "language".to_owned(),
            serde_json::json!(chard::predicate::LANGUAGE),
        );
    }
    listing.insert("sha256".to_owned(), serde_json::json!(decoder.sha256()));
    // `probe::RunBasis`: whether a reading taken under user-mode emulation is withheld.
    if let probe::Decoder::Runtime { basis, .. } = decoder {
        listing.insert("run_basis".to_owned(), serde_json::json!(basis.as_str()));
    }
    serde_json::Value::Object(listing)
}

/// The corpus for a person: each probe's id, language and title, then one line per check
/// with its id and the flag it asks about, so the two id namespaces sit side by side (a
/// probe id for `measure --probe`, a check id for `detect`). The counts close it.
fn corpus_text() -> String {
    // Each column as wide as its longest entry, so a long id shifts no other column.
    let probe_w = probe::CORPUS
        .iter()
        .map(|p| p.id.len())
        .fold("probe (measure --probe)".len(), usize::max);
    let check_w = probe::CORPUS
        .iter()
        .flat_map(|p| p.checks)
        .map(|c| c.id.len())
        .fold("check (detect)".len(), usize::max);
    let mut lines = vec![format!(
        "{:<probe_w$}  {:<check_w$}  flag",
        "probe (measure --probe)", "check (detect)"
    )];
    let mut checks = 0_usize;
    for p in probe::CORPUS {
        let lang = match p.lang {
            probe::Lang::C => "C",
            probe::Lang::Cxx => "C++",
        };
        lines.push(format!("{:<probe_w$}  {lang}: {}", p.id, p.title));
        for c in p.checks {
            checks = checks.saturating_add(1);
            lines.push(format!("{:<probe_w$}  {:<check_w$}  {}", "", c.id, c.flag));
        }
    }
    lines.push(String::new());
    lines.push(format!("{} probes, {checks} checks", probe::CORPUS.len()));
    lines.join("\n") + "\n"
}

fn corpus_listing() -> serde_json::Value {
    let probes: Vec<serde_json::Value> = probe::CORPUS
        .iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id,
                "title": p.title,
                "language": p.lang,
                "source": p.source_name,
                // `probe::Probe::run_environment`: what this probe's runs receive beside
                // `run::PROBE_ENVIRONMENT`, empty for every probe but one.
                "run_environment": p
                    .run_environment
                    .iter()
                    .map(|(name, value)| (*name, *value))
                    .collect::<std::collections::BTreeMap<_, _>>(),
                "checks": p.checks.iter().map(|c| serde_json::json!({
                    "id": c.id,
                    "flag": c.flag,
                    "channel": c.channel(),
                    "decoder": decoder_listing(&c.decoder),
                    "polarity": c.polarity,
                    "observable": c.observable,
                    "defects": c.defects,
                    "observes": c.observes,
                    "recommended_level": c.recommended_level(),
                    "levels": levels_listing(c.levels),
                    "positive_control": c.positive,
                    // `probe::ArchControl`: the list the positive arm uses on these
                    // architectures in place of `positive_control`.
                    "positive_control_by_arch": probe::ARCH_CONTROLS
                        .iter()
                        .filter(|row| row.check == c.id)
                        .map(|row| (row.arch, row.positive))
                        .collect::<std::collections::BTreeMap<_, _>>(),
                    "negative_control": c.negative,
                    "needs_vm": c.gate.needs_vm,
                    "arch": c.gate.arch,
                    "libc_unsupported": c.gate.libc_unsupported,
                    "reads": c.reads().iter().map(|t| t.as_str()).collect::<Vec<_>>(),
                    "notes": c.notes,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    serde_json::json!({
        "chard_schema": probe::LISTING_SCHEMA_VERSION,
        "corpus_sha256": probe::corpus_sha256(),
        "decoders_sha256": probe::decoders_sha256(),
        "total_checks": probe::total_checks(),
        "probes": probes,
    })
}

/// The C probes' and the C++ probes' link lines: the lists `measure::variant_flags` hands
/// the two builds, with nothing appended, so the linker is detected under exactly the
/// flags the artifacts were linked with.
fn link_lines(profile: &Profile) -> (Vec<String>, Vec<String>) {
    (
        measure::variant_flags(profile, probe::Lang::C, &[]),
        measure::variant_flags(profile, probe::Lang::Cxx, &[]),
    )
}

/// Hold `toolchain.linker` to the `.comment` of every linked artifact the run built.
///
/// `measure::artifact_comments` says which artifacts are fed, under which label, and
/// which are named and left out, given the selection each side's link line made. When
/// the profile's C++ link selected its own linker, the C++ probes' artifacts are held to
/// `linker.cxx` and every other artifact to `linker`; otherwise all of them are held to
/// the one linker. A `disagrees` is published beside the banner with an error diagnostic
/// and an `artifact-only` with a warning; `DESIGN.md`, "The binary testifies about
/// itself", says why the first is a finding about the environment and the second a gap in
/// chard's own reading.
fn cross_check_linker(
    toolchain: &mut toolchain::Toolchain,
    observations: &[Observation],
    facts: &report::FactStore,
    ctx: &Conditions<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let selections = measure::LinkSelections {
        c: &toolchain.detected.linker.profile_flags,
        cxx: toolchain
            .detected
            .linker
            .cxx
            .as_deref()
            .map(|cxx| cxx.profile_flags.as_slice()),
    };
    let (c_witnesses, cxx_witnesses) =
        measure::artifact_comments(observations, facts, ctx.profile_is_clean, selections);
    let linker = &mut toolchain.detected.linker;
    linker.artifact = Some(toolchain::artifact_agreement(
        &linker.kind,
        linker.version.as_deref(),
        &c_witnesses,
    ));
    if let Some(cxx) = linker.cxx.as_mut() {
        cxx.artifact = Some(toolchain::artifact_agreement(
            &cxx.kind,
            cxx.version.as_deref(),
            &cxx_witnesses,
        ));
    }
    let published = [
        ("toolchain.linker", linker.artifact.as_ref()),
        (
            "toolchain.linker.cxx",
            linker.cxx.as_ref().and_then(|c| c.artifact.as_ref()),
        ),
    ];
    for (context, agreement) in published {
        let Some(a) = agreement else { continue };
        let (severity, message) = match a.agreement {
            toolchain::Agreement::Disagrees => (
                Severity::Error,
                format!(
                    "the artifacts this run linked contradict the linker the report names \
                     under {context}, or one another: {}. The banner stands as published \
                     and {context}.artifact says what the artifacts said",
                    a.evidence
                ),
            ),
            toolchain::Agreement::ArtifactOnly => (
                Severity::Warning,
                format!(
                    "the linker under {context} is known from its artifacts alone: {}. \
                     {context}.kind stays unknown, since no banner chard read established \
                     one, \
                     and {context}.artifact.signature carries the line the artifacts wrote",
                    a.evidence
                ),
            ),
            _ => continue,
        };
        diagnostics.push(Diagnostic {
            severity,
            message,
            context: Some(context.to_owned()),
            rejection: None,
        });
    }
}

/// Hold the architecture the arch gate read to the `e_machine` of every ELF artifact
/// the run built and to the architecture macros of the driver's intrinsic macro dump,
/// flagless, under the profile's C flags, and through the C++ driver under its C++ flags
/// where those differ, and withhold the verdicts that premise decided where any witness
/// contradicts it.
///
/// `toolchain::target_agreement` derives the agreements and
/// `report::withhold_on_contradicted_target` the withholding; `DESIGN.md`, "The
/// binary testifies about itself", says why a contradicted premise withholds rather than
/// re-gates. `report::target_witness_diagnostics` says what is published: an error naming
/// every witness that spoke against the premise, a warning for an `unmapped` witness that
/// flipped a gate, and a warning of its own for a dump the artifacts overruled, which
/// contradicts nothing.
fn cross_check_target(
    toolchain: &mut toolchain::Toolchain,
    observations: &mut [Observation],
    facts: &report::FactStore,
    target_arch: &str,
    source: toolchain::ArchSource,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let artifacts = report::artifact_machines(observations, facts);
    let target = toolchain::target_agreement(
        target_arch,
        source,
        &artifacts,
        &toolchain.detected.arch_macros,
        toolchain.detected.profile_macros.as_ref(),
    )
    .with_intrinsic_abi(toolchain.detected.arch_abi)
    .with_cxx_dump(toolchain.detected.profile_macros_cxx.as_ref(), &artifacts);
    let withheld = report::withhold_on_contradicted_target(observations, &target);
    diagnostics.extend(report::target_witness_diagnostics(&target, &withheld));
    toolchain.detected.target = Some(target);
}

/// The profile resolved under `target_arch`, the architecture the gate reads, where `posed`
/// was resolved under `default_arch`, the driver's default target, before the dump under its
/// flags could say which target they select.
///
/// `openssf-tldr` picks its flags by architecture and selects no target; `explicit` selects
/// whatever its flags say and does not depend on architecture. So no profile chard ships can
/// resolve to different flags under the two, and one that did would have been dumped and
/// linked under flags the published profile does not carry: that is refused as an unusable
/// invocation rather than measured.
///
/// # Errors
///
/// [`resolve_profile`]'s, and the refusal above.
fn settle_profile(
    args: &MeasureArgs,
    posed: Profile,
    default_arch: &str,
    target_arch: &str,
    config_files: &[String],
) -> Result<Profile> {
    if target_arch == default_arch {
        return Ok(posed);
    }
    let settled = resolve_profile(args, target_arch, config_files)?;
    if link_lines(&settled) != link_lines(&posed) {
        return Err(ConfigError(format!(
            "the profile {} resolves to different flags under {target_arch}, the target its \
             flags select, than under {default_arch}, the driver's default, under which its \
             target was read; a profile whose target selection depends on the architecture it \
             selects has no single target to measure",
            posed.id
        ))
        .into());
    }
    Ok(settled)
}

/// The gate-vocabulary architectures the driver's intrinsic macro dumps name, taken before any
/// build: the flagless dump's, and the dump's under the profile's C flags where it completed
/// ([`toolchain::ProfileDump::completed`]: not where it exited 0 with its output cut off).
/// Each is read through [`toolchain::ARCH_MACROS`] where the dump defined exactly one of them;
/// a dump that defined none or several names nothing here.
fn witnessed_archs(detected: &toolchain::Detected) -> Vec<&'static str> {
    let one = |defined: &[String]| -> Option<&'static str> {
        let mut named = toolchain::ARCH_MACROS
            .iter()
            .filter(|(name, _)| defined.iter().any(|d| d == name));
        match (named.next(), named.next()) {
            (Some((_, machine)), None) => Some(toolchain::gate_arch_of_machine(machine)),
            _ => None,
        }
    };
    let flagless = one(&detected.arch_macros);
    let profile = detected
        .profile_macros
        .as_ref()
        .filter(|dump| dump.completed())
        .and_then(|dump| one(&dump.defined));
    flagless.into_iter().chain(profile).collect()
}

/// Refuse a profile whose flags depend on an architecture the driver's own macro dumps
/// contradict.
///
/// `openssf-tldr` is resolved under the architecture the arch gate reads, which is
/// `-dumpmachine`'s unless the profile's flags select a target. A driver can build for
/// another without saying so there: gcc under `-m32` prints its own x86_64 triple while its
/// dump defines `__i386__`, so the profile carried the guide's x86_64 row onto i386 builds and
/// the CET checks read that row's request under the guide's name. The dumps are taken before
/// any probe is built (after the driver's `-###` query) and name the machine the driver
/// compiles for. Where one names an architecture
/// the profile resolves to other flags under, the invocation has no single architecture for
/// the profile to be chosen by, and it is refused as [`settle_profile`] refuses a
/// target-dependent one, rather than measured under either list. A profile that does not
/// depend on architecture (`bare`, `bare-optimized`, `explicit`) is never refused here; the
/// contradiction it meets is published and withheld on by `cross_check_target`.
///
/// # Errors
///
/// [`resolve_profile`]'s, and the refusal above.
fn refuse_on_witnessed_arch(
    args: &MeasureArgs,
    profile: Profile,
    target_arch: &str,
    witnessed: &[&str],
    config_files: &[String],
) -> Result<Profile> {
    for arch in witnessed.iter().filter(|arch| **arch != target_arch) {
        let other = resolve_profile(args, arch, config_files)?;
        if link_lines(&other) != link_lines(&profile) {
            return Err(ConfigError(format!(
                "the profile {} resolves to different flags under {arch}, the architecture the \
                 driver's intrinsic macro dump names, than under {target_arch}, the one the arch \
                 gate read; a profile chosen by architecture has no single architecture to be \
                 chosen by here, so it is measured under neither. A driver that builds for \
                 another target than its -dumpmachine names (gcc under -m32 prints its own \
                 triple) can be measured under --profile explicit with the flags for the target \
                 it builds",
                profile.id
            ))
            .into());
        }
    }
    Ok(profile)
}

/// The refusal of `--profile explicit` without `--flags`, checked in [`measure`] before the
/// earlier output is set aside and again where the profile is resolved, from one string.
const EXPLICIT_NEEDS_FLAGS: &str = "--profile explicit requires --flags";

/// The refusal of `--flags`, `--cxxflags` or `--ldflags` beside a built-in profile, checked
/// in [`measure`] before the earlier output is set aside and again where the profile is
/// resolved.
///
/// A built-in profile reads none of the three, so a list beside one would be applied to no
/// build and named nowhere in the report: `chard measure --profile bare --flags -O2` would
/// publish a measurement of the compiler's defaults, which reads as a measurement of `-O2`
/// to whoever asked for one. An empty list is refused too, since it is still written beside
/// a profile that does not read it.
fn refuse_flags_beside_a_builtin_profile(args: &MeasureArgs) -> Result<()> {
    if args.profile == "explicit" {
        return Ok(());
    }
    let given: Vec<&str> = [
        ("--flags", &args.flags),
        ("--cxxflags", &args.cxxflags),
        ("--ldflags", &args.ldflags),
    ]
    .into_iter()
    .filter_map(|(name, value)| value.as_ref().map(|_| name))
    .collect();
    if given.is_empty() {
        return Ok(());
    }
    let given = match given.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} and {last}", rest.join(", ")),
        _ => given.join(""),
    };
    Err(ConfigError(format!(
        "--profile {p} reads none of {given}; only --profile explicit does: use --profile \
         explicit, or drop {given} to measure {p}",
        p = args.profile,
    ))
    .into())
}

/// `profile` with a note where the driver's `-v` was refused (`toolchain::answered`): chard
/// then read no configuration file, which does not say the driver loads none, so a `bare`
/// column's `flags_source: none` and every other profile's results may carry what such a
/// file supplies. The note sits where `config_files`' own note would, beside `flags_source`.
fn with_unread_config(mut profile: Profile, failures: &[toolchain::QueryFailure]) -> Profile {
    if failures
        .iter()
        .any(|f| f.context == toolchain::CONFIG_FILES_FIELD)
    {
        let unread = format!(
            "chard read nothing from the driver's `{}` (the toolchain.config_files diagnostic \
             says how it ended), so it read no configuration file from it, which does not say \
             the driver loads none: these results may include whatever such a file supplies",
            toolchain::VERBOSE_QUERY
        );
        profile.toolchain_note = Some(match profile.toolchain_note.take() {
            Some(note) => format!("{note}; {unread}"),
            None => unread,
        });
    }
    profile
}

/// Resolve `--profile` into flags, recording how they were obtained.
///
/// `config_files` is what the driver said it loaded, from `toolchain.config_files`. It
/// decides what a `bare` column is a measurement of: with no file, the compiler's
/// compiled-in defaults, and `flags_source: none` says so; with one, those defaults plus
/// whatever the file supplies, which chard does not read, and `driver-config-file` says
/// that instead. `bare-optimized` keeps `chard-enabling-condition`, since that value
/// attributes the one flag chard passed, and its note names the file; the diagnostic
/// `measure` raises names it for every profile.
fn resolve_profile(args: &MeasureArgs, arch: &str, config_files: &[String]) -> Result<Profile> {
    let config_note = || {
        (!config_files.is_empty()).then(|| {
            format!(
                "the driver loaded a configuration file it applies to every invocation \
                 ({}), so these defaults are the compiler's compiled-in ones plus whatever \
                 that file supplies; chard does not read the file",
                config_files.join(", ")
            )
        })
    };
    refuse_flags_beside_a_builtin_profile(args)?;
    match args.profile.as_str() {
        "bare" => Ok(Profile {
            id: "bare".to_owned(),
            flags_source: if config_files.is_empty() {
                report::flags_source::NONE.to_owned()
            } else {
                report::flags_source::DRIVER_CONFIG.to_owned()
            },
            cflags: Vec::new(),
            cxxflags: Vec::new(),
            ldflags: Vec::new(),
            toolchain_note: config_note(),
            compiler_environment: compile::CompilerEnvironment::of_this_run(),
        }),
        // The compiler's own defaults, measured under the one condition several of
        // them require in order to exist at all.
        //
        // `bare` answers a real question — what does `cc file.c` give you — and it
        // is the right question for a CI script that compiles exactly that way. But
        // it cannot answer whether the *compiler* ships a hardening default,
        // because fortify does not instantiate without optimization: glibc's
        // <features.h> gates `__USE_FORTIFY_LEVEL` on `__OPTIMIZE__`, and a vendor
        // patch that injects `-D_FORTIFY_SOURCE` may condition it the same way. A
        // `--` in the bare column is therefore ambiguous between "the compiler sets
        // nothing" and "the compiler sets it only when optimizing", which are
        // different facts about the distribution — `compiler-default` versus
        // `compiler-default-gated` in the attribution taxonomy.
        //
        // Measured on Ubuntu 24.04, bare gcc-13 reported no fortify while its
        // packages reported level 3. That is consistent with both readings, so
        // LP#2012440's claim that the level lives in gcc-13 rather than in dpkg
        // could not be settled from the two profiles that existed.
        //
        // `-O2` is deliberately the only flag. It is not a hardening flag and it
        // grants nothing on its own, so anything observed here beyond what `-O2`
        // enables is the compiler's own choice. `-O2` rather than `-O1` because it
        // is what packaging uses and what the fortify levels are tuned against.
        // The `optimization-enabled` check necessarily reads `on` in this profile:
        // that cell is the profile's own flag rather than a finding, and
        // `flags_source` says so.
        "bare-optimized" => Ok(Profile {
            id: "bare-optimized".to_owned(),
            flags_source: report::flags_source::ENABLING_CONDITION.to_owned(),
            cflags: vec!["-O2".to_owned()],
            cxxflags: Vec::new(),
            ldflags: Vec::new(),
            toolchain_note: Some(match config_note() {
                Some(config) => format!(
                    "the compiler's own defaults with optimization enabled and nothing \
                     else; -O2 is the precondition for fortify to instantiate, not a \
                     hardening flag. {config}"
                ),
                None => "the compiler's own defaults with optimization enabled and nothing \
                         else; -O2 is the precondition for fortify to instantiate, not a \
                         hardening flag"
                    .to_owned(),
            }),
            compiler_environment: compile::CompilerEnvironment::of_this_run(),
        }),
        report::OPENSSF_TLDR_ID => Ok(Profile {
            id: report::OPENSSF_TLDR_ID.to_owned(),
            flags_source: report::flags_source::OPENSSF_GUIDE.to_owned(),
            cflags: report::openssf_tldr_cflags(arch),
            cxxflags: Vec::new(),
            ldflags: Vec::new(),
            toolchain_note: None,
            compiler_environment: compile::CompilerEnvironment::of_this_run(),
        }),
        "explicit" => {
            let (cflags, cxxflags, ldflags) = explicit_lists(args)?;
            // The id carries a digest of the three lists, because `profile.id` is a
            // column join key and two explicit lists are two columns. Every `--flags`
            // run was `explicit:cli` before, so a hardened list and a bare one joined as
            // one column measured twice. See `report::explicit_profile_id`.
            Ok(Profile {
                id: report::explicit_profile_id(&cflags, &cxxflags, &ldflags),
                flags_source: report::flags_source::USER.to_owned(),
                cflags,
                cxxflags,
                ldflags,
                toolchain_note: None,
                compiler_environment: compile::CompilerEnvironment::of_this_run(),
            })
        }
        other => Err(ConfigError(format!("unknown profile: {other}")).into()),
    }
}

/// The three lists of an explicit profile, read from `--flags`, `--cxxflags` and
/// `--ldflags` and refused where chard cannot read them ([`refuse_unreadable_flags`]).
///
/// One reader for both of its callers: `measure` calls it before the set-aside and the
/// toolchain interrogation, so a list it refuses touches nothing, and [`resolve_profile`]
/// builds the
/// profile from what it returns. None of the refusals depends on the toolchain.
///
/// An absent `--cxxflags` stays empty rather than being filled from `--flags`:
/// `measure::variant_flags` reads empty as "same as cflags", and the report should say the
/// caller supplied one set, not claim they supplied two that happen to match.
///
/// # Errors
///
/// A [`ConfigError`] for `--profile explicit` without `--flags`, or for a list
/// [`refuse_unreadable_flags`] refuses.
fn explicit_lists(args: &MeasureArgs) -> Result<(Vec<String>, Vec<String>, Vec<String>)> {
    let flags = args
        .flags
        .as_deref()
        .ok_or_else(|| ConfigError(EXPLICIT_NEEDS_FLAGS.to_owned()))?;
    let cflags = split_flags(flags);
    let cxxflags = args
        .cxxflags
        .as_deref()
        .map(split_flags)
        .unwrap_or_default();
    let ldflags = args.ldflags.as_deref().map(split_flags).unwrap_or_default();
    refuse_unreadable_flags(&[
        ("--flags", &cflags),
        ("--cxxflags", &cxxflags),
        ("--ldflags", &ldflags),
    ])?;
    Ok((cflags, cxxflags, ldflags))
}

/// Each relative path argument of `lists`, by list, as [`refuse_unreadable_flags`] names it:
/// as written and in its list, with gcc's reading of clang's own option or the pair a handed
/// path option lacks where the argument was read so ([`compile::relative_path_readings`]).
fn relative_path_refusals(lists: &[(&str, &Vec<String>)]) -> Vec<String> {
    lists
        .iter()
        .flat_map(|(name, list)| {
            compile::relative_path_readings(list)
                .into_iter()
                .map(move |found| {
                    let arg = found.argument;
                    match found.reading.note() {
                        Some(note) => format!("{arg:?} in {name}, {note}"),
                        None => format!("{arg:?} in {name}"),
                    }
                })
        })
        .collect()
}

/// Refuse an explicit profile's flag lists where chard cannot read what they hand the
/// driver: a response file first, since a relative `@file` is first of all a file chard
/// cannot read into ([`compile::response_file_arguments`] says why), then a flag that
/// selects x32, 16-bit or aarch64 ILP32 code, which chard does not measure
/// ([`toolchain::unsupported_target_flags`] says which), then a flag that
/// removes part of the runtime and leaves its replacement unnamed
/// ([`toolchain::runtime_removing_flags`] says why), then a flag holding U+001F, which
/// `report::flags_sha256` joins a list's flags with, then a pair the two drivers read
/// differently, clang's `-isystem-after` or `-include-pch` alone before a word a selection
/// reader takes ([`toolchain::driver_divided_pairs`] says why the arms can match one
/// reading and not the other), then a relative path ([`compile::relative_path_readings`]
/// says why one names two directories in a run). Called before any of the lists reaches a
/// driver.
///
/// # Errors
///
/// A [`ConfigError`] naming each refused argument and the list it came from.
fn refuse_unreadable_flags(lists: &[(&str, &Vec<String>)]) -> Result<()> {
    let named = |read: fn(&[String]) -> Vec<String>| -> Vec<String> {
        lists
            .iter()
            .flat_map(|(name, list)| {
                read(list)
                    .into_iter()
                    .map(move |arg| format!("{arg:?} in {name}"))
            })
            .collect()
    };
    let response_files = named(compile::response_file_arguments);
    if !response_files.is_empty() {
        return Err(ConfigError(format!(
            "a response file hands the build flags chard cannot see, and chard reads the \
             profile's flags to build each control arm for the same target and linker, so a \
             flag inside one would reach the measured build and no control; write its flags \
             out on the command line: {}",
            response_files.join(", ")
        ))
        .into());
    }
    let unsupported = named(toolchain::unsupported_target_flags);
    if !unsupported.is_empty() {
        return Err(ConfigError(format!(
            "chard does not measure x32, 16-bit or aarch64 ILP32 targets, and a flag that can \
             select x32, 16-bit or ILP32 code is refused wherever it stands, a later flag that \
             overrides it included; remove it: {}",
            unsupported.join(", ")
        ))
        .into());
    }
    let removals = named(toolchain::runtime_removing_flags);
    if !removals.is_empty() {
        return Err(ConfigError(format!(
            "a flag that removes the startup objects, the default libraries or the default \
             headers leaves the build to a replacement the profile does not name, so chard \
             can build its control arms neither with the removal nor without it; name the \
             installation instead (--sysroot, --gcc-install-dir, -B, -stdlib++-isystem): {}",
            removals.join(", ")
        ))
        .into());
    }
    // `report::flags_sha256` joins a list's flags with U+001F, so a flag holding one hashes as
    // the two flags either side of it, and the explicit profile id with it.
    let separators = named(|list| {
        list.iter()
            .filter(|flag| flag.contains('\u{1f}'))
            .cloned()
            .collect()
    });
    if !separators.is_empty() {
        return Err(ConfigError(format!(
            "a flag holding the unit separator (U+001F) cannot be told from two flags in the \
             profile's flags hash and id, which join each list's flags with it; remove it: {}",
            separators.join(", ")
        ))
        .into());
    }
    // Before the relative-path refusal, which refuses `-isystem-after` for gcc's reading,
    // `-isystem` joined to the relative `-after`, and would name the less specific cause.
    let divided = named(toolchain::driver_divided_pairs);
    if !divided.is_empty() {
        return Err(ConfigError(format!(
            "one of gcc and clang reads this option followed by a word as the option and its \
             value, and the other reads the word after it as a flag of its own (for example \
             clang's -isystem-after and -dependency-file, gcc's -Tbss and --entry, and gcc's \
             abbreviations of --include-prefix and kin; the list is in chard's source, \
             toolchain::driver_divided_pairs), so where that word selects a target, system \
             root, runtime, header or linker, or itself takes a word, chard can build its \
             control arms to match one driver's reading and not the other's; put another \
             word between the two or spell an abbreviation whole, and for clang's \
             -isystem-after and -include-pch, which gcc reads joined to their value or not as \
             -isystem or -include joined to a relative path, name a directory with -idirafter, \
             which both drivers read, or leave the option out: {}",
            divided.join(", ")
        ))
        .into());
    }
    let relative = relative_path_refusals(lists);
    if !relative.is_empty() {
        return Err(ConfigError(format!(
            "a relative path in an explicit profile names one directory to the probe builds, \
             which run in the work directory, and another to the toolchain interrogation, which \
             runs where chard was started, and chard reads each word as the tool it is handed to \
             reads it, refusing what it cannot read so; give each path as an absolute path, or \
             do as its note says: {}",
            relative.join(", ")
        ))
        .into());
    }
    Ok(())
}

/// Resolve `--probe` ids into the probes to run, and the truncation a narrowed run
/// records.
///
/// A repeated id is refused rather than deduplicated. The selection is the coverage
/// denominator, and an invocation naming one probe twice is asking for a denominator
/// that counts one thing twice: honouring it counted the probe's checks twice against
/// two identical observations and published `all_checks_attempted` over the doubled
/// pair, with `defect_coverage.from_checks` listing one check id twice as though a
/// second measurement had corroborated the first. Deduplicating silently would change
/// what the caller typed into what they meant, and the two readings of a repeated id
/// (once, or twice) both differ from the invocation. A duplicated `--probe` is a
/// scripted loop that appended one id twice, and the loop is what needs fixing.
///
/// Unknown ids are refused for the same reason they always were: a selection that
/// names nothing measures nothing and must not look like a run.
///
/// # Errors
///
/// A [`UserError`] naming the first unknown or repeated id.
fn select_probes(requested: &[String]) -> Result<(Vec<&'static Probe>, Vec<String>)> {
    if requested.is_empty() {
        return Ok((probe::CORPUS.iter().collect(), Vec::new()));
    }
    let mut chosen: Vec<&'static Probe> = Vec::new();
    for id in requested {
        let found = probe::find(id).ok_or_else(|| {
            UserError::with_hint(
                format!("unknown probe id: {id}"),
                "list them with `chard probes --format text`",
            )
        })?;
        if chosen.iter().any(|p| p.id == found.id) {
            return Err(UserError::with_hint(
                format!("probe id given more than once: {id}"),
                "pass each --probe once; the selection is a set, and a repeated id would \
                 count one probe's checks twice in the coverage denominator",
            )
            .into());
        }
        chosen.push(found);
    }
    // A filtered run is recorded as a truncation so a partial report is never
    // rendered as a complete column.
    let truncations = vec![format!(
        "run restricted to {} of {} probes via --probe",
        chosen.len(),
        probe::CORPUS.len()
    )];
    Ok((chosen, truncations))
}

/// Read an image attestation from `path`, if one was supplied.
///
/// Malformed input is an error rather than a silent `unattested`. The two are different
/// claims — "nothing was offered" against "something was offered and could not be read" —
/// and collapsing them would let a typo in a harness invocation downgrade a verified image
/// to an unverified one without saying so. That is the failure mode this whole feature
/// exists to close, so it must not be reintroduced by the reader.
///
/// # Errors
///
/// When the file cannot be read, or does not deserialise into the fetcher's own
/// attestation shape.
fn read_image_attestation(path: Option<&Path>) -> Result<Option<environment::Attestation>> {
    let Some(path) = path else {
        return Ok(None);
    };
    // The io error keeps its kind, so `error::classify` reads it as it does for every other
    // reader of an operator-named file (an unreadable one is `PERMISSION` there, as it is
    // for `table`); only bytes that are not UTF-8 are this function's to refuse.
    // Refused from the metadata first, as `detect --evidence` and `table` refuse it: a
    // character device such as `/dev/zero` would be read without bound, and the allocation
    // failure that ends that read is chard's own (`INTERNAL`), not the caller's.
    let reading = || format!("reading the image attestation {}", path.display());
    let kind = std::fs::metadata(path).with_context(reading)?.file_type();
    if !(kind.is_file() || std::os::unix::fs::FileTypeExt::is_fifo(&kind)) {
        return Err(error::UserError::new(format!(
            "{} is not an image attestation chard can read: it is {}",
            path.display(),
            error::file_type_name(kind)
        ))
        .into());
    }
    let bytes = std::fs::read(path).with_context(reading)?;
    let text = String::from_utf8(bytes).map_err(|e| {
        error::UserError::new(format!(
            "reading the image attestation {}: {e}",
            path.display()
        ))
    })?;
    // Parsed by the library rather than here, so the refinement has a test: `from_json`
    // refuses a digest that is not hex of the length its own `digest_kind` implies.
    let attestation = environment::Attestation::from_json(&text).map_err(|e| {
        error::UserError::with_hint(
            format!("parsing the image attestation {}: {e}", path.display()),
            "the file must be the fetcher's provenance object: verdict, url, served_by, \
                 manifest_url, digest_kind, digest, digest_matched, signature, and \
                 optionally installed_disk {sha256, installed_at, installed_from_digest}. \
                 The harness writes exactly this as `provenance` in its session file.",
        )
    })?;
    Ok(Some(attestation))
}

#[allow(
    clippy::too_many_lines,
    reason = "one invocation, read top to bottom: the work directory, the selection, the \
              toolchain and then its environment, the profile, the sweep over the \
              library's loop, the derived layer, and publication. Each step is read \
              through the one before it, and that order is the provenance a report rests \
              on; one function keeps it auditable in one place. The control triple itself \
              lives in `measure::run_check`."
)]
fn measure(args: &MeasureArgs, ending: &mut Ending) -> Result<Closed> {
    let started_at = SystemTime::now();
    let started_utc = report::iso8601_utc(started_at);
    let wall = std::time::Instant::now();

    // The invocation's own arguments first, before anything on disk is touched: a run
    // refused here measured nothing and is not a run, so it leaves the earlier report at
    // `-o` and the work directory as they were. With the set-aside first, a mistyped
    // `--probe` would move a good report to `<output>.previous` while measuring nothing.
    // The selection is settled before the compiler is
    // touched, so an invocation that names a probe twice or names one that does not exist
    // is refused at the door rather than after a toolchain interrogation it was never
    // going to use.
    let (selected, truncations) = select_probes(&args.probes)?;
    let attestation = read_image_attestation(args.image_attestation.as_deref())?;
    if args.profile == "explicit" {
        explicit_lists(args)?;
    }
    refuse_flags_beside_a_builtin_profile(args)?;
    // The compiler environment's `--env` pairs, refused or fixed before any toolchain runs.
    // The first toolchain invocation reads them, and `compile::RunEnvironment` makes a set
    // after that read an error, so no run is measured under one environment in its early
    // invocations and another in its later ones.
    compile::add_to_compiler_environment(compile::compiler_environment_additions(&args.env)?)?;
    // A work directory that exists and is not a directory is the invocation's error too,
    // and `create_dir_all` would refuse it after the set-aside.
    if std::fs::metadata(&args.workdir).is_ok_and(|m| !m.is_dir()) {
        return Err(UserError::with_hint(
            format!(
                "the work directory {} exists and is not a directory",
                args.workdir.display()
            ),
            "pass --workdir a directory, or a path where one can be made",
        )
        .into());
    }

    // Then, so no exit this run can take from here on leaves an earlier report at the
    // requested path to be read as this run's; `report::set_aside` says why it is moved,
    // not deleted.
    let report_file = args.report_file()?;
    // Whether this run sets an earlier report aside, read before it does: the closing line
    // says it replaced one, or where it is kept, only where there was one. A metadata error
    // reads as none: `set_aside_output` reads the same metadata next and refuses the run on
    // it, so the run closes as refused before the set-aside and this is never read.
    let earlier = report_file
        .as_deref()
        .and_then(|path| report::published_path(path).ok().flatten())
        .is_some_and(|path| path.is_file());
    let destination = set_aside_output(
        report_file.as_deref(),
        &args
            .image_attestation
            .as_deref()
            .into_iter()
            .collect::<Vec<_>>(),
    )?;
    ending.target = destination.clone().map_or(Target::Stdout, Target::File);
    ending.earlier = earlier;

    std::fs::create_dir_all(&args.workdir)
        .with_context(|| format!("creating work directory {}", args.workdir.display()))?;
    ending.workdir = Some(args.workdir.clone());
    // Absolutize once, here, so nothing downstream has to care whether the
    // operator passed a relative path. Probe binaries are executed with their cwd
    // set to the work directory, and a relative artifact path would then resolve
    // against the wrong base.
    let workdir = std::path::absolute(&args.workdir)
        .with_context(|| format!("resolving {}", args.workdir.display()))?;
    // One run to a work directory, held until this function returns: two runs sharing one
    // overwrite each other's artifacts, and `measure::claim_workdir` says what that
    // published and how another run's claim is judged.
    let claim = measure::claim_workdir(&workdir)?;

    let distro = environment::detect_distro();
    error::note(&format!(
        "measuring {} on {} {}",
        args.cc, distro.id, distro.version_id
    ));

    let mut detected = toolchain::detect(&args.cc, &workdir, args.emit_macros)?;
    let execution = args.execution.as_deref().map(|mode| match mode {
        "container" => environment::ExecutionMode::Container,
        "vm" => environment::ExecutionMode::Vm,
        _ => environment::ExecutionMode::Host,
    });
    let env = environment::detect(
        detected.headers_dump(),
        execution,
        args.image.clone(),
        attestation,
    )
    .map_err(|refusal| match refusal {
        environment::AttestationRefusal::DigestMismatch(a) => error::ConfigError(format!(
            "refusing to measure: the image was fetched but did not match the publisher's \
             manifest.\n  \
             image     {}\n  \
             manifest  {}\n  \
             digest    {} {}\n\
             A report from these bytes would attach a distribution's name to an artifact \
             known not to be that distribution's. Re-fetch the image, or measure with no \
             --image-attestation and accept a report marked `unattested`.",
            a.url(),
            a.manifest_url(),
            a.digest_kind(),
            a.digest(),
        )),
        // The invocation contradicts itself rather than the specimen being wrong: an
        // attestation describes an image, and this run booted none. Recording it as
        // `attested` is what happened before, which published a report claiming its image
        // had been established while naming no image at all.
        environment::AttestationRefusal::NoImageToAttest => error::ConfigError(
            "refusing to measure: --image-attestation was given for a run that booted no \
             image. Pass --execution vm or --execution container for the environment the \
             attestation describes, or drop the attestation to measure this system."
                .to_owned(),
        ),
    })?;
    // The toolchain's own target, not the arch chard's own binary was compiled for —
    // they coincide for a native build, and only for one, so the two must not be read
    // as interchangeable. See `Detected::target_arch`'s doc comment for what reading the
    // wrong one costs. That is the driver's default target, which the profile is
    // first resolved under; where the profile's flags select another, the gate reads the
    // one they select (`toolchain::gate_target`), and the profile is resolved again under it.
    let default_arch = detected
        .target_arch()
        .unwrap_or_else(|| env.kernel.arch.clone());
    let posed = resolve_profile(args, &default_arch, &detected.config_files)?;
    // The two link lines a linker selection in the profile reaches the artifacts through;
    // `Detected::link_with` says why this is a second step and why there are two.
    let (c_link, cxx_link) = link_lines(&posed);
    detected.link_with(&c_link, &cxx_link, &workdir);
    // The target the profile's own flags select, which `-dumpmachine` and the flagless
    // dump cannot see; `toolchain::ProfileMacroWitness` says why. The C++ list is dumped
    // only where it differs, and `Detected::dump_with` says why.
    detected.dump_with(&c_link, &cxx_link, &workdir)?;
    let (target_arch, arch_source) = toolchain::gate_target(
        detected.target_triple.as_deref(),
        detected.profile_macros.as_ref(),
        &env.kernel.arch,
    );
    let profile = settle_profile(
        args,
        posed,
        &default_arch,
        &target_arch,
        &detected.config_files,
    )?;
    let profile = refuse_on_witnessed_arch(
        args,
        profile,
        &target_arch,
        &witnessed_archs(&detected),
        &detected.config_files,
    )?;
    let profile = with_unread_config(profile, &detected.query_failures);
    // The join key is composed here, once, from halves the environment owns. The
    // environment could only be read through the toolchain's own macro dump, which is
    // why the published struct is made after it rather than by `toolchain::detect`;
    // `Detected::qualified` is its only constructor, so no report carries an unqualified
    // key. The tags are `env::Libc::tag` and `env::Distro::tag`.
    let mut toolchain = detected.qualified(&env.libc.tag(), &env.distro.tag());
    error::note(&format!(
        "{} / {} {} / kernel {}",
        toolchain.id(),
        env.libc.impl_name,
        env.libc.version.clone().unwrap_or_else(|| "?".to_owned()),
        env.kernel.release
    ));
    let mut diagnostics: Vec<Diagnostic> = Vec::new();
    // Every profile is measured through the file, so every report says so. The `bare`
    // profile additionally names the mechanism in `flags_source`, since that is the field
    // a reader of a bare column consults; the others already name where their flags came
    // from, and a file on top of them is what this diagnostic records.
    if !toolchain.detected.config_files.is_empty() {
        diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            message: format!(
                "the driver loaded {} configuration file(s) it applies to every invocation: \
                 {}. Whatever they supply is in every build measured here, and chard does \
                 not read them; a bare column measured through this driver is the \
                 compiler's defaults plus that file, which profile.flags_source names",
                toolchain.detected.config_files.len(),
                toolchain.detected.config_files.join(", ")
            ),
            context: Some("toolchain.config_files".to_owned()),
            rejection: None,
        });
    }
    // A driver query whose output was refused (`toolchain::QueryFailure`): the field it
    // fills is absent or empty, and this says why.
    for failure in &toolchain.detected.query_failures {
        diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            message: failure.message.clone(),
            context: Some(failure.context.to_owned()),
            rejection: None,
        });
    }

    // The denominator for coverage: the check ids the selection names, as a set,
    // computed before any work happens so a crash mid-sweep cannot quietly shrink it.
    // A set of identities rather than a count, because `report::coverage` reconciles
    // what came back against what was handed in by name: a count-only comparison is
    // satisfied by any list of the right length, including one that measured a check
    // twice and another not at all.
    let checks_expected: BTreeSet<String> = selected
        .iter()
        .flat_map(|p| p.checks)
        .map(|c| c.id.to_owned())
        .collect();

    // Sources are written once; every variant compiles the same bytes. Both paths are
    // chard's own, under the directory it just created, and tagged so: a failure here is
    // never the caller's typo, and `error::classify` reads the tag before the io kind.
    let header = workdir.join(probe::SELFREPORT_HEADER_NAME);
    std::fs::write(&header, probe::SELFREPORT_HEADER)
        .with_context(|| HarnessPath(header.clone()))
        .context("writing the self-report header")?;
    for probe in &selected {
        if !probe.source.is_empty() {
            let source = workdir.join(probe.source_name);
            std::fs::write(&source, probe.source)
                .with_context(|| HarnessPath(source.clone()))
                .with_context(|| format!("writing probe source {}", probe.source_name))?;
        }
    }

    let ctx = Conditions {
        env: &env,
        profile: &profile,
        toolchain_kind: toolchain.detected.kind,
        target_arch: &target_arch,
        profile_is_clean: Conditions::profile_is_clean(&profile),
    };

    // The gate's flag, decided once. A toolchain with no structured form chard has measured
    // is said so rather than compared against nothing.
    let structured_format = args
        .structured_diagnostics
        .then(|| chard::structured::format_flag(toolchain.detected.kind))
        .flatten();
    if args.structured_diagnostics && structured_format.is_none() {
        diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            message: format!(
                "--structured-diagnostics: no structured diagnostic format is known for a \
                 `{}` toolchain, so nothing was compared",
                toolchain.detected.kind.as_str()
            ),
            context: None,
            rejection: None,
        });
    }

    // Measurement borrows the detected half alone: nothing in the loop reads the join
    // key, which is what lets `tests/measurement_loop.rs` drive it without one.
    let driver = Driver {
        toolchain: &toolchain.detected,
        workdir: &workdir,
        timeout: Duration::from_secs(args.timeout),
        structured: structured_format,
    };

    let mut observations: Vec<Observation> = Vec::new();
    let mut facts = report::FactStore::default();
    let mut fact_conflicts: Vec<report::Conflict> = Vec::new();

    for probe in &selected {
        error::note(&format!("probe {}", probe.id));
        let outcome = measure::run_probe(&driver, probe, &ctx);
        observations.extend(outcome.observations);
        diagnostics.extend(outcome.diagnostics);
        // One store for the run. Two probes offering different facts under one digest is
        // chard disagreeing with itself about one sequence of bytes: said so here, and a
        // contradiction in the consistency pass, which refuses the report.
        for conflict in facts.merge(outcome.facts) {
            diagnostics.push(Diagnostic {
                severity: Severity::Error,
                message: conflict.sentence(),
                context: Some(probe.id.to_owned()),
                rejection: None,
            });
            fact_conflicts.push(*conflict);
        }
    }
    // Arms' facts as changes against an observation's own build, where that is smaller
    // and exact; the observations' own entries stay whole for every reader below.
    facts.compact_arms(
        &observations
            .iter()
            .filter_map(|o| o.build.as_ref()?.artifact_sha256.clone())
            .collect(),
    );

    // The artifacts' testimony against the banner, now that every artifact this run will
    // link has been linked.
    cross_check_linker(
        &mut toolchain,
        &observations,
        &facts,
        &ctx,
        &mut diagnostics,
    );
    // The artifacts' testimony against the architecture the arch gate read before any
    // build, which can withhold verdicts, so before anything is derived from them.
    cross_check_target(
        &mut toolchain,
        &mut observations,
        &facts,
        &target_arch,
        arch_source,
        &mut diagnostics,
    );
    // The built thing's testimony against the macro channel, over the settled verdicts:
    // a macro reading of a code-generation observable whose elf-static or runtime twin
    // read the opposite presence is withheld (`report::MACRO_TWINS`; DESIGN.md, "Four
    // observation channels"). After the target rule, so a twin it withheld decides
    // nothing, and before anything is derived from the verdicts.
    let contradicted = report::withhold_contradicted_macros(&mut observations);
    diagnostics.extend(contradicted.diagnostics());

    // The ratchet is derived before the rollup, because a non-monotone reading means
    // a probe is faulty and its rungs must not reach the matrix as measurements;
    // `report::withhold_inconsistent_rungs` moves them, says why, and derives the ratchet
    // again so the summary agrees with the observations it summarises.
    let (ratchet, withheld) = report::withhold_inconsistent_rungs(&mut observations, &facts);
    diagnostics.extend(withheld);
    let defect_coverage = report::defect_coverage(&observations);
    let corroboration = report::corroboration(&observations, &|check_id| {
        probe::CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .find(|c| c.id == check_id)
            .and_then(|c| c.corroborates)
    });
    let structured_diagnostics = args.structured_diagnostics.then(|| {
        for (check, message) in chard::structured::Summary::findings(&observations) {
            diagnostics.push(Diagnostic {
                severity: Severity::Warning,
                message,
                context: Some(check),
                rejection: None,
            });
        }
        chard::structured::Summary::over(structured_format, &observations)
    });
    for group in corroboration.values() {
        if !group.agree {
            diagnostics.push(Diagnostic {
                severity: Severity::Error,
                message: group.note.clone(),
                context: Some(group.protection.clone()),
                rejection: None,
            });
        }
    }
    // The artifact's SafeStack reading against the flags that asked for it, or did not.
    diagnostics.extend(report::safestack_cross_check(&observations, &profile));

    let coverage: Coverage = report::coverage(
        &observations,
        &checks_expected,
        probe::total_checks(),
        &profile,
        truncations,
    );

    if !coverage.all_checks_attempted {
        // Against the corpus total, which is what the flag tests.
        //
        // This printed `checks_attempted` against `checks_expected` while
        // `all_checks_attempted` compares `attempted` to `corpus_checks_total`, so a
        // filtered run reported "coverage incomplete: 1 of 1 checks produced an
        // observation" — a warning whose own numbers say nothing is missing. Both
        // denominators are real and they answer different questions: `checks_expected`
        // is how many this invocation asked for, `corpus_checks_total` how many exist.
        // A message must quote the one its condition used.
        diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            message: format!(
                "coverage incomplete: {} of the corpus's {} checks produced an \
                 observation ({} were asked for by this invocation)",
                coverage.checks_attempted, coverage.corpus_checks_total, coverage.checks_expected
            ),
            context: None,
            rejection: None,
        });
    }
    let invalid = observations
        .iter()
        .filter(|o| o.verdict == Verdict::ProbeInvalid)
        .count();
    if invalid > 0 {
        diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            message: format!(
                "{invalid} check(s) had non-discriminating controls and were reported \
                 probe-invalid rather than off"
            ),
            context: None,
            rejection: None,
        });
    }

    // Reduced over the observations above, not measured. `-fhardened` is an umbrella,
    // so what matters is whether its constituents are in force — a toolchain can be
    // effectively hardened without the option existing, and can pass the option while
    // downgrading a constituent underneath it.
    // `cfi-effective` after `fhardened-effective`, and appended rather than inserted: a
    // consumer reading `composites[0]` keeps reading the umbrella it always read.
    let composites = vec![
        composite::fhardened(
            &observations,
            &target_arch,
            &toolchain.detected.fhardened_fortify,
            &env.libc,
            toolchain.detected.target_triple.as_deref(),
            &facts,
        ),
        composite::cfi(&observations, &target_arch, &env.libc, &facts),
    ];
    // Each profile flag the toolchain rejected, once per tool and flag, counted over the
    // final verdicts and put first: forty cells naming one refused flag read as forty
    // problems where there is one, and a reader of `diagnostics` meets it before them.
    diagnostics.splice(
        0..0,
        report::profile_flag_rejections(&observations, &profile),
    );

    let report = Report {
        // Made by `report::publish`, after the consistency pass.
        digest: None,
        chard_schema: report::SCHEMA_VERSION.to_owned(),
        run: RunMeta {
            // Both filled below, from the assembled report: each is a digest of fields the
            // report carries, and `report::inputs_of` is the one reader of the inputs,
            // shared with the consistency rule that recomputes both.
            id: String::new(),
            inputs_sha256: String::new(),
            started_utc,
            duration_ms: wall.elapsed().as_millis(),
            harness_version: report::HARNESS_VERSION.to_owned(),
            harness_revision: report::HARNESS_REVISION.map(ToOwned::to_owned),
            harness_revision_source: report::HARNESS_REVISION_SOURCE.map(ToOwned::to_owned),
            harness_rustflags_sha256: report::HARNESS_RUSTFLAGS_SHA256.map(ToOwned::to_owned),
            probe_corpus_sha256: probe::corpus_sha256(),
            decoders_sha256: probe::decoders_sha256(),
            invocation: report::recorded_invocation(std::env::args_os()),
            deadlines: report::Deadlines::new(Duration::from_secs(args.timeout)),
        },
        environment: env,
        toolchain,
        profile,
        decoders: report::decoders_of(&observations),
        observations,
        facts,
        fortify_ratchet: ratchet,
        corroboration,
        structured_diagnostics,
        defect_coverage,
        composites,
        coverage,
        evidence_filters: report::evidence_filters(),
        consistency: report::Consistency::default(),
        diagnostics,
        fact_conflicts,
    };

    // Check the derived layer against the observations it was computed from, before
    // anything is written. The rollups — the ratchet, defect coverage, the composites —
    // are the numbers most likely to be read and the only part of the report nothing
    // else validates: a control triple validates one check and
    // `corroboration` compares channels within a protection. A contradiction
    // here means the report disagrees with itself, which is a fault in chard rather
    // than a finding about the toolchain, so it is said loudly and recorded in the
    // document that carries it.
    let mut report = report;
    // Derived from the measurement rather than the clock, after the observations are
    // final: the ratchet downgrade above moves verdicts, and an id computed earlier would
    // name a set of cells the report does not carry. The inputs first, since the id
    // digests them.
    report.run.inputs_sha256 = report::inputs_of(&report).sha256();
    report.run.id = report::run_id(&report.run.inputs_sha256, &report.observations);
    // Before the consistency pass, so what is published is what was checked. Nothing
    // derived is among the volatile fields, so the pass sees the same claims either way.
    if args.normalize {
        report::normalize(&mut report);
    }
    // A run whose claim was removed under it may have shared the directory, and refuses
    // rather than publish; `WorkdirClaim::confirm` says why.
    claim.confirm()?;
    ending.counts = Some(Counts::of(&report.coverage));
    // A self-contradicting report is never written where a consumer would find it; see
    // `report::publish` for why it is still written, beside the requested path.
    match report::publish(&mut report, destination.as_ref()).context("publishing the report")? {
        report::Publication::Refused {
            contradictions,
            quarantine,
            cause: report::RefusalCause::Defect,
        } => {
            return Ok(Closed::Contradicted {
                contradictions,
                quarantine,
            });
        }
        report::Publication::Refused {
            quarantine,
            cause: report::RefusalCause::DeclaredExecution,
            ..
        } => {
            return Ok(Closed::DeclarationContradicted {
                execution: Box::new(report.environment.execution.clone()),
                quarantine,
            });
        }
        report::Publication::Rendered(rendered) => write_stdout(&format!("{rendered}\n"))?,
        report::Publication::Written => {}
    }

    // Both halves, deliberately. Gating on `all_checks_attempted` alone would pass a run
    // where every check was handed in and nine of them earned no verdict, which is the
    // shape of an incomplete measurement that looks complete. The gate is
    // `all_verdicts_published` and not a count of triples that discriminated, which a
    // withheld `indeterminate` satisfies and an earned `unsupported` does not: both the
    // wrong way round for a completeness gate. `report::Standing` is the rule, and the
    // field is false exactly when `coverage.withholding.instrument_withholdings` is not
    // empty or a check went unattempted; the field's own doc records why a limitation
    // passes it.
    let complete = report.coverage.all_verdicts_published;
    if args.fail_on_missing && !complete {
        return Ok(Closed::GateFailed {
            unsettled: name_the_shortfalls(&report),
        });
    }
    Ok(Closed::Published)
}

/// The lines a failed `--fail-on-missing` leaves on stderr, after the report: a count, then
/// one line per check that failed it, in `report::shortfalls`'s order, then the exit status
/// and the remedies chard knows; returns how many checks it named.
///
/// The exit status alone said only that the gate failed, and the reason was a reading of
/// `coverage` and every verdict. `gate_lines` builds the lines from the report alone, so
/// the unit tests below hold each of them.
fn name_the_shortfalls(report: &Report) -> usize {
    let corpus = probe::CORPUS.iter().flat_map(|p| p.checks).map(|c| c.id);
    let shortfalls = report::shortfalls(&report.observations, corpus);
    for line in gate_lines(&report.coverage, &shortfalls) {
        error::note(&line);
    }
    shortfalls.len()
}

/// The count line, the shortfalls, and where none is named the line that says so.
///
/// A run narrowed by `--probe` fails the gate for each corpus check it did not select,
/// because the gate counts the whole corpus (`all_checks_attempted` says why), so the count
/// line says how many the run selected.
fn gate_lines(coverage: &Coverage, shortfalls: &[report::Shortfall]) -> Vec<String> {
    let selected = if coverage.checks_expected == coverage.corpus_checks_total {
        String::new()
    } else {
        format!(
            "; this run selected {} with --probe, and the gate counts the whole corpus",
            coverage.checks_expected
        )
    };
    let are = if shortfalls.len() == 1 { "is" } else { "are" };
    let mut lines = vec![format!(
        "--fail-on-missing: {} of the corpus's {} checks {are} not attempted or not settled\
         {selected}",
        shortfalls.len(),
        coverage.corpus_checks_total
    )];
    lines.extend(
        shortfalls
            .iter()
            .map(|shortfall| format!("--fail-on-missing: {shortfall}")),
    );
    // The consistency pass refuses a report whose observations do not carry each corpus
    // check once, the one shape where the field is false and no check is short; were one
    // to reach here, the exit still says why.
    if shortfalls.is_empty() {
        lines.push(format!(
            "--fail-on-missing: no check is named, yet coverage.all_verdicts_published is \
             false over {} observations of the corpus's {} checks; report this",
            coverage.checks_attempted, coverage.corpus_checks_total
        ));
    }
    lines.push(format!(
        "--fail-on-missing: exit {}, the report written; {}",
        error::EXIT_GATE,
        remedies(shortfalls)
    ));
    lines
}

/// What a caller can change to settle the gate, for the shortfalls where chard knows: a
/// kernel-policy check withheld because nothing established whose kernel the run's is
/// (`execution-mode-assumed`) or because the run is in a container (`needs-vm`), and a
/// check `--probe` left out. The other reasons are the toolchain's or the instrument's, and
/// each line above says which; no option of the run is claimed to settle them.
fn remedies(shortfalls: &[report::Shortfall]) -> String {
    use report::gating_rule::{EXECUTION_MODE_ASSUMED, NEEDS_VM};
    let count = |rule: &str| {
        shortfalls
            .iter()
            .filter(
                |s| matches!(s, report::Shortfall::Unsettled { rule: Some(id), .. } if *id == rule),
            )
            .count()
    };
    let not_attempted = shortfalls
        .iter()
        .filter(|s| matches!(s, report::Shortfall::NotAttempted { .. }))
        .count();
    let mut remedies = Vec::new();
    let covered = count(EXECUTION_MODE_ASSUMED.id)
        .saturating_add(count(NEEDS_VM.id))
        .saturating_add(not_attempted);
    match count(EXECUTION_MODE_ASSUMED.id) {
        0 => {}
        n => remedies.push(format!(
            "--execution host or --execution vm, where this run owns the kernel it runs on, \
             lifts gating.rule {} from the {n} {} it holds, which the run then attempts \
             instead of withholding",
            EXECUTION_MODE_ASSUMED.id,
            plural(n, "check", "checks")
        )),
    }
    match count(NEEDS_VM.id) {
        0 => {}
        n => remedies.push(format!(
            "the {n} {} under gating.rule {} {} measured only outside a container, on the \
             host or in a vm, with --execution saying which",
            plural(n, "check", "checks"),
            NEEDS_VM.id,
            plural(n, "is", "are")
        )),
    }
    if not_attempted > 0 {
        remedies.push(format!(
            "a run without --probe attempts the {not_attempted} not attempted"
        ));
    }
    match shortfalls.len().saturating_sub(covered) {
        _ if remedies.is_empty() => {
            "no option of this run is known to settle these; each line gives the report's reason"
                .to_owned()
        }
        0 => remedies.join("; "),
        others => format!(
            "{}; no option of this run is known to settle the other {others}",
            remedies.join("; ")
        ),
    }
}

/// `one` where `n` is 1, `many` otherwise.
fn plural<'a>(n: usize, one: &'a str, many: &'a str) -> &'a str {
    if n == 1 { one } else { many }
}

/// How a `measure` run ended: [`measure_command`] makes the exit status from it and writes
/// the line the run closes with from it, so `measure` has no way to exit without that line.
enum Closed {
    /// The report was published.
    Published,
    /// The report was published and `--fail-on-missing` named `unsettled` checks: exit 1.
    GateFailed { unsettled: usize },
    /// The report contradicts itself in `contradictions` places, a defect in chard: exit 3,
    /// kept at `quarantine` where the report went to a file.
    Contradicted {
        contradictions: usize,
        quarantine: Option<PathBuf>,
    },
    /// The declared `--execution` is contradicted by what chard observed: exit 2, the report
    /// kept as for [`Closed::Contradicted`].
    DeclarationContradicted {
        execution: Box<environment::Execution>,
        quarantine: Option<PathBuf>,
    },
    /// Refused or failed: exit 2, with the envelope on stdout.
    Failed(anyhow::Error),
}

/// Where a run's report goes, once the set-aside has decided it.
#[derive(Default)]
enum Target {
    /// Not yet decided: the run was refused before the set-aside, which nothing before it
    /// can have moved an earlier report or built anything.
    #[default]
    Undecided,
    /// `-o -`.
    Stdout,
    File(report::Destination),
}

/// What a `measure` run has left so far, filled in as it goes, for its closing line.
#[derive(Default)]
struct Ending {
    target: Target,
    /// Whether a regular file was at the report's path when the run set it aside: the one
    /// case where an earlier report was replaced, or is kept as `<file>.previous`, by this
    /// run. A `.previous` beside the path is otherwise an older run's.
    earlier: bool,
    /// The work directory as given, once it exists.
    workdir: Option<PathBuf>,
    /// The report's counts, once it is built.
    counts: Option<Counts>,
}

/// A report's verdicts as the closing line counts them: `on`, `partial` and `off` from
/// `coverage.verdict_counts`, then the two halves of `coverage.withholding`, the earned
/// `unsupported` and `not-applicable` answers and the checks withheld, which the consistency
/// pass holds to `verdict_counts`; the five sum to `checks_attempted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Counts {
    attempted: usize,
    on: usize,
    partial: usize,
    off: usize,
    limitations: usize,
    withheld: usize,
}

impl Counts {
    fn of(coverage: &Coverage) -> Self {
        let verdict = |v: Verdict| {
            coverage
                .verdict_counts
                .get(v.as_str())
                .copied()
                .unwrap_or(0)
        };
        Self {
            attempted: coverage.checks_attempted,
            on: verdict(Verdict::On),
            partial: verdict(Verdict::Partial),
            off: verdict(Verdict::Off),
            limitations: coverage.withholding.earned_limitations.count,
            withheld: coverage.withholding.instrument_withholdings.count,
        }
    }
}

impl std::fmt::Display for Counts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {}: {} on, {} partial, {} off, {} unsupported or not-applicable, {} withheld",
            self.attempted,
            plural(self.attempted, "check", "checks"),
            self.on,
            self.partial,
            self.off,
            self.limitations,
            self.withheld
        )
    }
}

/// `measure`, its envelope where it has one, and its closing line on stderr, last: the exit
/// status, the file written or kept, the counts and what to run next. Every exit `measure`
/// takes passes through here, the refusals and the contradictions with the rest, so a caller
/// reading only the tail of stderr learns how the run ended, rather than the last probe's name.
/// A panic on the main thread, which
/// nothing in chard catches, closes with a line of its own ([`close_a_panic`]); a run that
/// is killed closes with none.
fn measure_command(args: &MeasureArgs) -> ExitCode {
    close_a_panic();
    let mut ending = Ending::default();
    let closed = measure(args, &mut ending).unwrap_or_else(Closed::Failed);
    // The status each arm returns, and the number its line names, side by side.
    let (code, status) = match &closed {
        Closed::Published => (ExitCode::from(error::EXIT_OK), error::EXIT_OK),
        Closed::GateFailed { .. } => (ExitCode::from(error::EXIT_GATE), error::EXIT_GATE),
        Closed::Contradicted {
            contradictions,
            quarantine,
        } => (
            error::emit_contradiction(*contradictions, quarantine.as_deref()),
            error::EXIT_CONTRADICTION,
        ),
        Closed::DeclarationContradicted {
            execution,
            quarantine,
        } => (
            error::emit_declaration_contradicted(execution, quarantine.as_deref()),
            error::EXIT_FAILURE,
        ),
        Closed::Failed(err) => (error::emit("measure", err), error::EXIT_FAILURE),
    };
    error::note(&closing_line(&closed, status, &ending));
    code
}

/// The status Rust's runtime exits with after a panic on the main thread.
const PANIC_STATUS: u8 = 101;

/// Install a panic hook that writes `measure`'s closing line after the panic's own message,
/// for a panic on the main thread. chard catches no panic, so one there ends the process
/// with exit 101; a panic on another thread (the pipe readers of `compile::run`) is joined
/// and reported as that run's failure, and closes no run.
fn close_a_panic() {
    let report = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        report(info);
        if std::thread::current().name() == Some("main") {
            error::note(&format!(
                "measure exits {PANIC_STATUS}: chard panicked, a defect in chard, and the run \
                 stopped where the message above says; what it left on disk is unchecked; \
                 next: report this with that message"
            ));
        }
    }));
}

/// The line a `measure` run closes with, from how it ended, the status it exits with and
/// what it left.
fn closing_line(closed: &Closed, status: u8, ending: &Ending) -> String {
    let workdir = workdir_kept(ending);
    let published = |how: &str| {
        let counts = ending
            .counts
            .map(|counts| format!(" ({counts})"))
            .unwrap_or_default();
        match &ending.target {
            Target::File(destination @ report::Destination::File { requested, .. }) => {
                let replacing = if ending.earlier {
                    ", replacing the earlier report there"
                } else {
                    ""
                };
                format!(
                    "measure exits {status}{how}: wrote {destination}{replacing}{counts}\
                     {workdir}; next: chard table {}",
                    command_word(requested)
                )
            }
            Target::File(destination) => format!(
                "measure exits {status}{how}: sent the report to {destination}{counts}\
                 {workdir}; next: chard table on a file holding what it received"
            ),
            Target::Stdout => format!(
                "measure exits {status}{how}: sent the report to stdout{counts}{workdir}; \
                 next: chard table on a file holding what stdout received"
            ),
            // `measure` sets the target before it can publish; were it not set, the line
            // still says only what is known.
            Target::Undecided => {
                format!("measure exits {status}{how}: published the report{counts}{workdir}")
            }
        }
    };
    // A refused report's counts are its own, and the contradiction leaves them unconfirmed.
    let refused_counts = ending
        .counts
        .map(|counts| format!(" (its own counts, unconfirmed: {counts})"))
        .unwrap_or_default();
    match closed {
        Closed::Published => published(""),
        Closed::GateFailed { unsettled } => published(&format!(
            " (--fail-on-missing: {unsettled} {} not attempted or not settled, named above)",
            plural(*unsettled, "check", "checks")
        )),
        Closed::Contradicted {
            contradictions,
            quarantine,
        } => {
            let kept = quarantine.as_ref().map_or_else(
                || {
                    format!(
                        "kept it nowhere{workdir}; next: re-run with -o FILE to keep it as \
                         FILE{}, and attach that to a bug report",
                        report::QUARANTINE_SUFFIX
                    )
                },
                |path| {
                    format!(
                        "kept it as {}{refused_counts}{}{workdir}; next: attach {} to a bug \
                         report",
                        path.display(),
                        earlier_kept(ending),
                        command_word(path)
                    )
                },
            );
            format!(
                "measure exits {status}: the report contradicts itself in {contradictions} {}, \
                 a defect in chard, and was not published; {kept}",
                plural(*contradictions, "place", "places")
            )
        }
        Closed::DeclarationContradicted { quarantine, .. } => {
            let kept = quarantine.as_ref().map_or_else(
                || "kept it nowhere".to_owned(),
                |path| {
                    format!(
                        "kept it as {}{refused_counts}{}",
                        path.display(),
                        earlier_kept(ending)
                    )
                },
            );
            format!(
                "measure exits {status}: the declared --execution is contradicted by what chard \
                 observed, so the report was not published; {kept}{workdir}; next: declare the \
                 mode the run is in, or omit --execution"
            )
        }
        Closed::Failed(_) => failed_line(status, ending),
    }
}

/// `; work directory W kept`, once the run made or found it.
fn workdir_kept(ending: &Ending) -> String {
    ending.workdir.as_ref().map_or_else(String::new, |w| {
        format!("; work directory {} kept", w.display())
    })
}

/// `, and the earlier report is kept as F.previous`, where this run set one aside and it is
/// still there; where the run found none, a `.previous` there is named as an older run's,
/// which may be the only copy of the last good report.
fn earlier_kept(ending: &Ending) -> String {
    let Target::File(destination @ report::Destination::File { .. }) = &ending.target else {
        return String::new();
    };
    let previous = report::sibling(destination.path(), report::SET_ASIDE_SUFFIX);
    match (previous.is_file(), ending.earlier) {
        (true, true) => format!(", and the earlier report is kept as {}", previous.display()),
        (true, false) => format!(", and an older run's {} is beside it", previous.display()),
        (false, _) => String::new(),
    }
}

/// The closing line of a run refused or failed, the envelope written: what it left on disk.
fn failed_line(status: u8, ending: &Ending) -> String {
    let workdir = workdir_kept(ending);
    let left = match &ending.target {
        Target::Undecided => {
            "refused before the run started, so an earlier report is where it was and nothing \
             was built"
                .to_owned()
        }
        Target::Stdout => format!("no whole report is known to have reached stdout{workdir}"),
        Target::File(destination @ report::Destination::Stream(_)) => {
            format!("no whole report is known to have reached {destination}{workdir}")
        }
        // A file there now, not empty, is what this run wrote before it failed: the set-aside
        // moved or emptied an earlier one. Whether it is the whole report (the failure in the
        // cleanup after it) or part of one (a write in place that stopped) is the envelope's
        // to say; the line claims neither.
        Target::File(destination)
            if std::fs::metadata(destination.path()).is_ok_and(|m| m.is_file() && m.len() > 0) =>
        {
            format!(
                "{destination} holds what this run wrote before the failure, which may not be a \
                 whole report{}{workdir}",
                earlier_kept(ending)
            )
        }
        Target::File(destination) => format!(
            "{destination} holds no report from this run{}{workdir}",
            earlier_kept(ending)
        ),
    };
    format!(
        "measure exits {status}: refused or failed, the envelope on stdout says why; {left}; \
         next: the envelope's hint"
    )
}

/// `path` as one word of a command the closing line suggests: a relative path that starts
/// with `-` gets `./`, so the command does not read it as an option, and the rest is
/// [`toolchain::shell_word`]'s.
fn command_word(path: &Path) -> String {
    let text = path.to_string_lossy();
    if text.starts_with('-') {
        toolchain::shell_word(&format!("./{text}"))
    } else {
        toolchain::shell_word(&text)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    /// The probe listing names a graded check's ungraded words where it has any, and no
    /// ungraded key where it has none.
    #[test]
    fn the_levels_listing_names_ungraded_words_only_where_there_are_some() {
        let listed = levels_listing(probe::SSP_LEVELS);
        assert_eq!(
            listed["ungraded"],
            serde_json::json!([probe::SSP_UNSAFE_FRAME])
        );
        assert!(
            levels_listing(probe::FORTIFY_LEVELS)
                .get("ungraded")
                .is_none()
        );
    }

    /// Every subcommand's help is written for a user: `-h` fits one screen (24 lines of 80
    /// columns), `--help` carries an example that clap parses, and no help names a Rust path,
    /// a clap setting or a distribution package query, which chard does not make. The
    /// lists the help writes out in words are held to the code: every verdict word, and
    /// every value the list options accept. Read from clap's rendering of each command, so
    /// a new subcommand or option is held too.
    #[test]
    fn the_help_is_written_for_users() {
        let rendered = rendered_help();
        let names: Vec<&str> = rendered.iter().map(|(n, ..)| n.as_str()).collect();
        assert!(
            names.len() > 1 && names.contains(&"measure") && names.contains(&"detect"),
            "the commands were rendered: {names:?}"
        );
        let mut examples = 0_usize;
        for (name, short, long) in &rendered {
            assert!(
                short.lines().count() <= 24,
                "{name} -h is {} lines",
                short.lines().count()
            );
            for line in short.lines() {
                assert!(
                    line.chars().count() <= 80,
                    "{name} -h has a line over 80 columns: {line}"
                );
            }
            assert!(long.contains("Example"), "{name} --help has no example");
            for word in [
                "::",
                "allow_hyphen",
                "clap",
                "rpm",
                "dpkg",
                "portageq",
                "makepkg",
                "abuild",
            ] {
                assert!(!long.contains(word), "{name} --help names {word:?}");
                assert!(!short.contains(word), "{name} -h names {word:?}");
            }
            // Every example line that starts with `chard` parses as the CLI defines it, so a
            // renamed option leaves no dead example behind.
            let mut joined = String::new();
            for line in long
                .lines()
                .skip_while(|l| !l.starts_with("Example"))
                .skip(1)
            {
                let line = line.trim();
                if let Some(rest) = line.strip_suffix('\\') {
                    joined.push_str(rest);
                    continue;
                }
                joined.push_str(line);
                let command = std::mem::take(&mut joined);
                for one in command.split("&&").map(str::trim) {
                    if !one.starts_with("chard ") {
                        continue;
                    }
                    let words = split_example(one);
                    if let Err(e) = Cli::try_parse_from(&words) {
                        panic!("{name}'s example `{one}` does not parse: {e}");
                    }
                    examples = examples.saturating_add(1);
                }
            }
        }
        assert!(
            examples >= rendered.len(),
            "every command's example parsed: {examples}"
        );
    }

    /// Each command's name and its `-h` and `--help` as clap renders them, `help` aside.
    fn rendered_help() -> Vec<(String, String, String)> {
        use clap::CommandFactory;
        let mut top = Cli::command();
        let mut rendered = vec![(
            "chard".to_owned(),
            top.render_help().to_string(),
            top.render_long_help().to_string(),
        )];
        for sub in top.get_subcommands_mut() {
            if sub.get_name() == "help" {
                continue;
            }
            let name = sub.get_name().to_owned();
            let short = sub.render_help().to_string();
            let long = sub.render_long_help().to_string();
            rendered.push((name, short, long));
        }
        rendered
    }

    /// The lists the help writes out in words are the code's: every verdict word, the two id
    /// kinds where they are taken, and every value the list options accept.
    #[test]
    fn the_help_names_what_the_code_accepts_and_publishes() {
        use clap::CommandFactory;
        let rendered = rendered_help();
        let long_of = |n: &str| {
            &rendered
                .iter()
                .find(|(name, ..)| name == n)
                .expect("rendered")
                .2
        };
        let top_long = &rendered[0].2;
        assert!(
            !top_long.contains("always JSON"),
            "chard --help says stdout is always JSON"
        );
        let measure = long_of("measure");
        assert!(
            measure.contains("probe id") && long_of("detect").contains("check id"),
            "the two id kinds are named where they are taken"
        );
        // The checks `--fail-on-missing`'s paragraph and the README say a run without
        // `--execution` fails on are the ones that declare `needs_vm`, no fewer and no more.
        let fail_on_missing = MeasureArgs::command()
            .get_arguments()
            .find(|a| a.get_id() == "fail_on_missing")
            .and_then(|a| a.get_long_help())
            .expect("--fail-on-missing has a long help")
            .to_string();
        let readme = include_str!("../README.md")
            .split("\n\n")
            .find(|p| p.contains("Without `--execution`"))
            .expect("the README's --fail-on-missing paragraph");
        let mut needs_vm = 0;
        for check in probe::CORPUS.iter().flat_map(|p| p.checks) {
            let named = format!("`{}`", check.id);
            assert_eq!(
                fail_on_missing.contains(&named),
                check.gate.needs_vm,
                "--fail-on-missing's help and {}'s needs_vm disagree",
                check.id
            );
            if check.gate.needs_vm {
                needs_vm += 1;
                assert!(
                    readme.contains(&named),
                    "README.md's --fail-on-missing paragraph does not name {}",
                    check.id
                );
            }
        }
        assert!(
            needs_vm > 0,
            "no check declares needs_vm, so the help names nothing real"
        );
        // `stack-clash-guard-page`'s notes say why it needs no kernel-ownership gate.
        let stack_clash = probe::CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .find(|c| c.id == "stack-clash-guard-page")
            .expect("stack-clash-guard-page");
        assert!(
            !stack_clash.gate.needs_vm && stack_clash.notes.contains("kernel-ownership gate"),
            "stack-clash-guard-page's notes and its needs_vm disagree"
        );
        for verdict in report::Verdict::ALL {
            assert!(
                measure.contains(&format!("`{}`", verdict.as_str())),
                "measure --help does not name the verdict {}",
                verdict.as_str()
            );
        }
        for (command, option) in [
            ("measure", "profile"),
            ("measure", "execution"),
            ("table", "format"),
            ("probes", "format"),
        ] {
            let cmd = if command == "measure" {
                MeasureArgs::command()
            } else {
                Cli::command()
                    .find_subcommand(command)
                    .expect("subcommand")
                    .clone()
            };
            let arg = cmd
                .get_arguments()
                .find(|a| a.get_id() == option)
                .expect("the option");
            // An option whose forms clap lists itself (`--format`) is held to clap's own
            // listing, one `- name:` line per form; one that hides them, to the prose.
            for value in arg.get_possible_values() {
                let named = if arg.is_hide_possible_values_set() {
                    format!("`{}`", value.get_name())
                } else {
                    format!("- {}:", value.get_name())
                };
                assert!(
                    long_of(command).contains(&named),
                    "{command} --help does not name `{}` for --{option}",
                    value.get_name()
                );
            }
        }
    }

    /// A pair the two drivers read differently, clang's `-isystem-after` or `-include-pch`
    /// alone, gcc's `-Tbss` or clang's `-dependency-file`, before a word a selection reader
    /// takes, is refused by name and list, from any of the three lists; the joined spelling,
    /// the pair before a word no reader takes and the dangling option of clang's two are
    /// refused for gcc's reading instead, and the pair handed to another tool and a selection
    /// taken as the value of an option that selects nothing (`-u -B<dir>/`) pass
    /// (`toolchain::driver_divided_pairs` says why).
    #[test]
    fn a_pair_the_drivers_read_differently_is_refused_and_named() {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let refused = [
            ("--flags", "-O2 -isystem-after -m32", "-isystem-after -m32"),
            (
                "--cxxflags",
                "-O2 -include-pch -B/srv/px/",
                "-include-pch -B/srv/px/",
            ),
            (
                "--ldflags",
                "-isystem-after -fuse-ld=lld -O2",
                "-isystem-after -fuse-ld=lld",
            ),
            ("--ldflags", "-O2 -Tbss -B/srv/px/", "-Tbss -B/srv/px/"),
            (
                "--flags",
                "-O2 -dependency-file -L/srv/x",
                "-dependency-file -L/srv/x",
            ),
            (
                "--flags",
                "-O2 --include-p -I/srv/i",
                "--include-p -I/srv/i",
            ),
            ("--ldflags", "-O2 -Tbss -u -B/srv/px/", "-Tbss -u"),
        ];
        let mut fed = 0_usize;
        for (list, flags, pair) in refused {
            let words = line(flags);
            let err = refuse_unreadable_flags(&[(list, &words)]).expect_err("refused");
            let text = format!("{err:#}");
            assert!(
                text.contains("one driver's reading and not the other's")
                    && text.contains(&format!("{pair:?} in {list}")),
                "{list} {flags}: {text}"
            );
            fed = fed.saturating_add(1);
        }
        assert_eq!(fed, refused.len(), "every list was fed a pair");
        // The rest is no divided pair: the joined spelling, a value no reader takes, a
        // dangling option. Each is refused all the same, as a relative path, since gcc reads
        // the word as `-isystem` or `-include` joined to a relative path
        // (`compile::relative_path_readings`), and that refusal names gcc's reading, not this
        // cause.
        for (other, gcc) in [
            (
                "-O2 -isystem-after/srv/i -m32",
                "-isystem with the relative path \"-after/srv/i\"",
            ),
            (
                "-O2 -isystem-after /srv/i -m32",
                "-isystem with the relative path \"-after\"",
            ),
            (
                "-O2 -include-pch /srv/p.pch",
                "-include with the relative path \"-pch\"",
            ),
            (
                "-O2 -isystem-after",
                "-isystem with the relative path \"-after\"",
            ),
        ] {
            let words = line(other);
            let err = refuse_unreadable_flags(&[("--flags", &words)]).expect_err("refused");
            let text = format!("{err:#}");
            assert!(
                text.contains("a relative path")
                    && text.contains(&format!("in --flags, which gcc reads as {gcc}"))
                    && !text.contains("one driver's reading"),
                "{other} is read the same under either driver: {text}"
            );
        }
        // The pair handed to another tool is the linker's word, which names no path.
        for passed in ["-O2 -Xlinker -isystem-after -m32", "-O2 -I/srv/i -m32"] {
            let words = line(passed);
            assert!(
                refuse_unreadable_flags(&[("--flags", &words)]).is_ok(),
                "{passed}"
            );
        }
        // A selection as the value of an option that selects nothing passes every refusal:
        // the pair is the option's, and no reader's (`toolchain::selections` says so).
        let mut passed = 0_usize;
        for value in [
            "-O2 -u -B/srv/px/",
            "-O2 -MF -L/srv/x",
            "-O2 -o -I/srv/i",
            "-O2 -D -m32",
            "-O2 -z -fuse-ld=lld",
            "-O2 --asser -B/srv/px/",
            "-O2 --forc -B/srv/px/",
            "-O2 -u -Tbss -m32",
            "-O2 -u -nostdlib",
        ] {
            let words = line(value);
            assert!(
                refuse_unreadable_flags(&[("--flags", &words)]).is_ok(),
                "{value}: the value is the option's and no reader's"
            );
            passed = passed.saturating_add(1);
        }
        assert_eq!(passed, 9, "every value shape was fed");
    }

    /// gcc's long spelling of a path option is that option to every reader: the directory
    /// named `-B/srv/px/` after `--include-directory-after` is `-idirafter`'s relative path,
    /// refused as `-idirafter -B/srv/px/` is, and `--li` and `--pref` are `-L` and `-B`
    /// (`toolchain::LONG_ALIASES`); a value-taking option's long spelling takes its value
    /// unread, as the test above holds. Counted against the shapes fed.
    #[test]
    fn a_long_spelling_of_a_path_option_refuses_its_relative_value_as_the_short_one() {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let relatives = [
            "-O2 --include-directory-after -B/srv/px/",
            "-O2 --li -B/srv/px/",
            "-O2 --pref -I/srv/i",
            "-O2 --include-directory=rel --machine 32",
        ];
        let mut fed = 0_usize;
        for relative in relatives {
            let words = line(relative);
            let err = refuse_unreadable_flags(&[("--flags", &words)]).expect_err("refused");
            let text = format!("{err:#}");
            assert!(
                text.contains("a relative path") && text.contains("in --flags"),
                "{relative}: the value is the path option's relative path: {text}"
            );
            fed = fed.saturating_add(1);
        }
        assert_eq!(fed, relatives.len(), "every shape was fed");
    }

    /// A relative path refusal names how it read each argument: as written, as gcc reads
    /// clang's own `-isystem-after`, and as a path option handed to a tool with no path in the
    /// pair after it (`compile::relative_path_readings`); and three more lines, a path
    /// handed to the preprocessor by the pair after its option, gcc's `-I-` and a linker word
    /// that begins like a driver option, pass.
    #[test]
    fn a_relative_path_refusal_names_how_it_read_each_argument() {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let words =
            line("-O2 -Xpreprocessor -I -Xpreprocessor rel -isystem-after/srv/i -Xlinker -L -O1");
        let err = refuse_unreadable_flags(&[("--ldflags", &words)]).expect_err("refused");
        let text = format!("{err:#}");
        for named in [
            "\"-Xpreprocessor -I -Xpreprocessor rel\" in --ldflags, ",
            "\"-isystem-after/srv/i\" in --ldflags, which gcc reads as -isystem with the relative \
             path \"-after/srv/i\"; name a directory with -idirafter, which both drivers read, or \
             leave the option out, ",
            "\"-Xlinker -L\" in --ldflags, whose path is not handed in the same word or the pair \
             after it, so the tool reads it from a later word or from none; hand the option and \
             its path together",
            "give each path as an absolute path, or do as its note says: ",
        ] {
            assert!(text.contains(named), "{named} is not in: {text}");
        }
        assert!(!text.contains("  "), "a run of spaces: {text}");
        let passed = line("-O2 -Xpreprocessor -I -Xpreprocessor /srv/i -I- -Xlinker -Bsymbolic");
        assert!(refuse_unreadable_flags(&[("--flags", &passed)]).is_ok());
    }

    /// A flag holding U+001F is refused, since `report::flags_sha256` joins a list's flags with it
    /// and the two lists `-O2<U+001F>-fPIE` and `-O2 -fPIE` would hash alike; the second list
    /// itself passes.
    #[test]
    fn a_flag_holding_the_hash_separator_is_refused() {
        let joined = vec!["-O2\u{1f}-fPIE".to_owned()];
        let err = refuse_unreadable_flags(&[("--flags", &joined)]).expect_err("refused");
        assert!(format!("{err:#}").contains("U+001F"), "{err:#}");
        let split = vec!["-O2".to_owned(), "-fPIE".to_owned()];
        assert!(refuse_unreadable_flags(&[("--flags", &split)]).is_ok());
        assert_eq!(
            report::flags_sha256(&joined, &[], &[]),
            report::flags_sha256(&split, &[], &[]),
            "the collision the refusal keeps out"
        );
    }

    /// The CLI's contract is stated once: `chard --help` prints [`CONTRACT`], `DESIGN.md`
    /// carries the same words in its own section, and the README and the module docs point
    /// there rather than restate the exit statuses. Compared word by word, so the copy's line
    /// breaks are its own.
    #[test]
    fn the_contract_is_stated_once() {
        let words = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
        let contract = words(CONTRACT);
        let top_long = &rendered_help()[0].2;
        assert!(
            words(top_long).contains(&contract),
            "chard --help does not print the contract"
        );
        let design = include_str!("../DESIGN.md");
        let section = design
            .split("\n## ")
            .find(|s| s.starts_with("The command-line contract\n"))
            .expect("DESIGN.md has a section \"The command-line contract\"");
        assert!(
            words(section).contains(&contract),
            "DESIGN.md's contract is not CONTRACT's words"
        );
        for (name, text, pointer) in [
            (
                "README.md",
                include_str!("../README.md"),
                "DESIGN.md#the-command-line-contract",
            ),
            (
                "src/error.rs",
                include_str!("error.rs"),
                "\"The command-line contract\"",
            ),
            (
                "src/detect.rs",
                include_str!("detect.rs"),
                "\"The command-line contract\"",
            ),
        ] {
            assert!(
                text.contains(pointer),
                "{name} does not point at the contract"
            );
            assert!(
                !text.contains("clap rejects exits 2"),
                "{name} still says a usage error has no envelope"
            );
        }
    }

    /// The README's quickstart lists the exit statuses in a table, one row each: it names
    /// exactly the statuses the contract does, each row carries the words the contract gives
    /// its status and none another status's, and the panic status the contract names beside
    /// them is the README's too.
    #[test]
    fn the_readme_exit_table_is_the_contracts() {
        let contract_statuses: std::collections::BTreeSet<String> = CONTRACT
            .match_indices("Exit ")
            .filter_map(|(at, _)| {
                let digits: String = CONTRACT
                    .get(at + "Exit ".len()..)?
                    .chars()
                    .take_while(char::is_ascii_digit)
                    .collect();
                (!digits.is_empty()).then_some(digits)
            })
            .collect();
        assert!(
            contract_statuses.len() > 1,
            "the contract names no exit statuses: {contract_statuses:?}"
        );
        let readme = include_str!("../README.md");
        let rows: BTreeMap<String, String> = readme
            .lines()
            .skip_while(|l| *l != "| Status | Meaning |")
            .skip(2)
            .take_while(|l| l.starts_with('|'))
            .map(|line| {
                let cells: Vec<&str> = line.split('|').map(str::trim).collect();
                assert_eq!(
                    cells.len(),
                    4,
                    "a README exit row with the wrong cells: {line}"
                );
                (
                    cells[1].trim_matches('`').to_owned(),
                    cells[2].to_lowercase(),
                )
            })
            .collect();
        assert_eq!(
            rows.keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>(),
            contract_statuses,
            "README.md's exit status table does not name the contract's statuses"
        );
        let meanings = [
            ("0", "every reading it replayed agrees"),
            ("1", "a gate tripped"),
            ("2", "refused the invocation or failed"),
            ("3", ".contradicted"),
        ];
        for (status, words) in meanings {
            assert!(
                CONTRACT.to_lowercase().contains(words),
                "CONTRACT no longer says {words:?}; update this table and README.md's"
            );
            let row = rows.get(status).map_or("", String::as_str);
            assert!(
                row.contains(words),
                "README.md's exit {status} row does not say {words:?}"
            );
            for (other, theirs) in meanings {
                assert!(
                    other == status || !row.contains(theirs),
                    "README.md's exit {status} row says exit {other}'s {theirs:?}"
                );
            }
        }
        assert!(
            CONTRACT.contains(&format!("a panic (exit {PANIC_STATUS})"))
                && readme.contains(&format!("A panic exits {PANIC_STATUS}.")),
            "the contract and README.md do not both name the panic status {PANIC_STATUS}"
        );
    }

    /// `--format` is one declaration over two commands' forms, each with its own default:
    /// a default rendered through a static the derive shares across the declaration's
    /// instantiations once gave `table` `probes`'s `json`. And every command takes `-o`.
    #[test]
    fn each_format_has_its_own_default_and_every_command_takes_dash_o() {
        use clap::CommandFactory;
        let parsed = |args: &[&str]| Cli::try_parse_from(args).map(|cli| cli.command);
        match parsed(&["chard", "table", "r.json"]) {
            Ok(Command::Table { format, .. }) => assert!(format.format == TableFormat::Text),
            _ => panic!("table r.json did not parse as a table"),
        }
        match parsed(&["chard", "table", "--format", "markdown", "r.json"]) {
            Ok(Command::Table { format, .. }) => assert!(format.format == TableFormat::Markdown),
            _ => panic!("table --format markdown did not parse"),
        }
        match parsed(&["chard", "probes"]) {
            Ok(Command::Probes { format, .. }) => assert!(format.format == ProbeFormat::Json),
            _ => panic!("probes did not parse"),
        }
        match parsed(&["chard", "probes", "--format", "text"]) {
            Ok(Command::Probes { format, .. }) => assert!(format.format == ProbeFormat::Text),
            _ => panic!("probes --format text did not parse"),
        }
        assert!(parsed(&["chard", "probes", "--format", "markdown"]).is_err());
        assert!(parsed(&["chard", "table", "--format", "json", "r.json"]).is_err());

        let top = Cli::command();
        let mut commands = 0;
        for sub in top.get_subcommands() {
            commands += 1;
            assert!(
                sub.get_arguments()
                    .any(|a| a.get_short() == Some('o') && a.get_long() == Some("output")),
                "{} takes no -o/--output",
                sub.get_name()
            );
        }
        assert_eq!(commands, 7, "the commands were counted");
    }

    /// An example's words, with double-quoted runs kept as one word and `${NAME:-default}`
    /// read as its default, the way a shell with the variable unset reads the examples the
    /// help prints.
    fn split_example(line: &str) -> Vec<String> {
        let mut line = line.to_owned();
        while let Some(start) = line.find("${") {
            let end = line[start..]
                .find('}')
                .map(|e| start + e)
                .expect("a closed ${");
            let inner = &line[start + 2..end];
            let default = match inner.split_once(":-") {
                Some((_, d)) => d.to_owned(),
                None => String::new(),
            };
            line.replace_range(start..=end, &default);
        }
        let mut words = Vec::new();
        let mut word = String::new();
        let mut quoted = false;
        for ch in line.chars() {
            match ch {
                '"' => quoted = !quoted,
                ' ' if !quoted => {
                    if !word.is_empty() {
                        words.push(std::mem::take(&mut word));
                    }
                }
                _ => word.push(ch),
            }
        }
        if !word.is_empty() {
            words.push(word);
        }
        words
    }

    /// `probes --format text` names every probe and every check once, each check under its
    /// own probe, lines the flag column up, and closes with the counts it printed.
    #[test]
    fn the_text_listing_names_every_probe_and_check_once() {
        let text = corpus_text();
        let lines: Vec<&str> = text.lines().collect();
        let flag_at = lines[0]
            .find("flag")
            .expect("the header names the flag column");
        let mut row = 1_usize;
        let mut checks = 0_usize;
        for p in probe::CORPUS {
            assert_eq!(
                lines[row].split_whitespace().next(),
                Some(p.id),
                "probe {} in order",
                p.id
            );
            assert!(
                !lines[row].starts_with(' '),
                "probe {} heads its own line",
                p.id
            );
            row += 1;
            for c in p.checks {
                let line = lines[row];
                assert!(line.starts_with(' '), "check {} under its probe", c.id);
                assert_eq!(
                    line.split_whitespace().next(),
                    Some(c.id),
                    "check {} under {}",
                    c.id,
                    p.id
                );
                assert_eq!(
                    line.get(flag_at..),
                    Some(c.flag),
                    "check {}'s flag in the flag column",
                    c.id
                );
                row += 1;
                checks += 1;
            }
        }
        assert_eq!(lines[row], "", "a blank line before the counts");
        assert_eq!(
            lines.get(row + 1).copied(),
            Some(format!("{} probes, {checks} checks", probe::CORPUS.len()).as_str()),
            "the listing closes with the counts it printed"
        );
        assert_eq!(lines.len(), row + 2, "nothing after the counts");
    }

    /// The option lists `report::normalized_invocation` reads are the value-taking options of
    /// `measure` as clap defines them, aliases included, both ways. `--cxxflags -openmp` read
    /// as an attached `-o` was the shape this holds off: an option added to the CLI without a
    /// place in one list has its value read as an argument.
    #[test]
    fn the_normalized_invocation_knows_every_option_that_takes_a_value() {
        use clap::CommandFactory;
        use std::collections::BTreeSet;

        let command = MeasureArgs::command();
        let mut defined = BTreeSet::new();
        for arg in command.get_arguments() {
            if !arg.get_action().takes_values() {
                continue;
            }
            assert!(
                arg.get_long().is_some() || arg.get_short().is_some(),
                "`{}` takes a value and has no option name, so normalized_invocation cannot \
                 tell its value from an argument",
                arg.get_id()
            );
            for long in arg
                .get_long()
                .into_iter()
                .chain(arg.get_all_aliases().into_iter().flatten())
            {
                defined.insert(format!("--{long}"));
            }
            for short in arg
                .get_short()
                .into_iter()
                .chain(arg.get_all_short_aliases().into_iter().flatten())
            {
                defined.insert(format!("-{short}"));
            }
        }
        let listed: BTreeSet<String> = report::INVOCATION_PATH_OPTIONS
            .iter()
            .chain(report::INVOCATION_VALUE_OPTIONS.iter())
            .map(|o| (*o).to_owned())
            .collect();
        assert_eq!(
            listed.len(),
            report::INVOCATION_PATH_OPTIONS.len() + report::INVOCATION_VALUE_OPTIONS.len(),
            "an option is in both lists"
        );
        assert!(!defined.is_empty(), "clap defined no value-taking option");
        assert_eq!(
            defined, listed,
            "measure's value-taking option spellings and the two lists in report.rs disagree: \
             a path-valued option belongs in INVOCATION_PATH_OPTIONS, any other in \
             INVOCATION_VALUE_OPTIONS"
        );
    }

    /// The report's default name is the compiler's last component and the profile, with
    /// nothing of the host; `-o -` is stdout; a `--cc` with no last component is refused
    /// rather than named for something else.
    #[test]
    fn the_report_is_named_from_the_compiler_and_the_profile() {
        let file = |args: &[&str]| {
            let mut words = vec!["chard"];
            words.extend(args);
            MeasureArgs::try_parse_from(words)
                .expect("parses")
                .report_file()
        };
        let named = |args: &[&str]| file(args).expect("named").expect("a file");
        assert_eq!(named(&[]), PathBuf::from("chard-cc-bare.json"));
        assert_eq!(
            named(&["--cc", "/usr/bin/gcc-14", "--profile", "openssf-tldr"]),
            PathBuf::from("chard-gcc-14-openssf-tldr.json")
        );
        assert_eq!(
            named(&["--cc", "clang", "-o", "out/r.json"]),
            PathBuf::from("out/r.json")
        );
        assert_eq!(file(&["--cc", "gcc", "-o", "-"]).expect("stdout"), None);
        for cc in ["/", "..", "/usr/.."] {
            let refused = file(&["--cc", cc]).expect_err("no name to make");
            assert!(
                refused.downcast_ref::<UserError>().is_some(),
                "--cc {cc}: {refused:#}"
            );
        }
        assert_eq!(
            command_word(Path::new("chard-gcc-bare.json")),
            "chard-gcc-bare.json"
        );
        assert_eq!(command_word(Path::new("my r's.json")), r"'my r'\''s.json'");
        assert_eq!(command_word(Path::new("-x.json")), "./-x.json");
    }

    /// The closing lines of the two refusals no run reaches end to end short of a defect in
    /// chard or a container chard recognises: each names its status, the file the refused
    /// report is kept in and what to do next, or that it was kept nowhere.
    #[test]
    fn the_closing_line_names_where_a_refused_report_is_kept() {
        let ending = Ending {
            target: Target::File(report::Destination::File {
                requested: PathBuf::from("r.json"),
                path: PathBuf::from("r.json"),
            }),
            earlier: false,
            workdir: Some(PathBuf::from("wd")),
            // Five counts apart, so a field printed in another's place is seen.
            counts: Some(Counts {
                attempted: 15,
                on: 5,
                partial: 1,
                off: 4,
                limitations: 3,
                withheld: 2,
            }),
        };
        let counts = "(its own counts, unconfirmed: 15 checks: 5 on, 1 partial, 4 off, 3 \
                      unsupported or not-applicable, 2 withheld)";
        let contradicted = |quarantine: Option<&str>| {
            closing_line(
                &Closed::Contradicted {
                    contradictions: 2,
                    quarantine: quarantine.map(PathBuf::from),
                },
                error::EXIT_CONTRADICTION,
                &ending,
            )
        };
        assert_eq!(
            contradicted(Some("r.json.contradicted")),
            format!(
                "measure exits 3: the report contradicts itself in 2 places, a defect in \
                 chard, and was not published; kept it as r.json.contradicted {counts}; work \
                 directory wd kept; next: attach r.json.contradicted to a bug report"
            )
        );
        assert_eq!(
            contradicted(None),
            "measure exits 3: the report contradicts itself in 2 places, a defect in chard, \
             and was not published; kept it nowhere; work directory wd kept; next: re-run with \
             -o FILE to keep it as FILE.contradicted, and attach that to a bug report"
        );
        let execution = environment::Execution {
            mode: environment::ExecutionMode::Host,
            engine: None,
            image: None,
            detection: "operator-supplied via --execution".to_owned(),
            mode_evidence: environment::ModeEvidence {
                basis: environment::ModeBasis::AssertedAndContradicted,
                observed: Some(environment::ExecutionMode::Container),
                observation: "fixture".to_owned(),
            },
            image_attestation: environment::ImageAttestation {
                status: environment::AttestationStatus::NotApplicable,
                established_by: "fixture",
                attestation: None,
            },
        };
        assert_eq!(
            closing_line(
                &Closed::DeclarationContradicted {
                    execution: Box::new(execution),
                    quarantine: Some(PathBuf::from("r.json.contradicted")),
                },
                error::EXIT_FAILURE,
                &ending,
            ),
            format!(
                "measure exits 2: the declared --execution is contradicted by what chard \
                 observed, so the report was not published; kept it as r.json.contradicted \
                 {counts}; work directory wd kept; next: declare the mode the run is in, or \
                 omit --execution"
            )
        );
    }

    /// The gate's lines over a whole run and over one narrowed by `--probe`: the count line
    /// names the selection only where there is one, and agrees in number; a line with no
    /// reason recorded says so; the line that says no check was named is written exactly
    /// where none was; and the block ends on the exit status and the remedies chard knows.
    #[test]
    fn the_gate_lines_name_the_selection_only_where_the_run_was_narrowed() {
        let total = probe::total_checks();
        let mut coverage =
            report::coverage(&[], &BTreeSet::new(), total, &profile("bare"), Vec::new());
        let one = [report::Shortfall::Unsettled {
            check: "ssp-level".to_owned(),
            verdict: Verdict::Indeterminate,
            withheld: None,
            rule: None,
            reason: None,
        }];
        coverage.checks_expected = total;
        assert_eq!(
            gate_lines(&coverage, &one),
            [
                format!(
                    "--fail-on-missing: 1 of the corpus's {total} checks is not attempted or \
                     not settled"
                ),
                "--fail-on-missing: ssp-level: indeterminate; the report records no reason \
                 beside it"
                    .to_owned(),
                "--fail-on-missing: exit 1, the report written; no option of this run is \
                 known to settle these; each line gives the report's reason"
                    .to_owned(),
            ]
        );
        coverage.checks_expected = 3;
        let two = [
            report::Shortfall::NotAttempted {
                check: "pie".to_owned(),
            },
            report::Shortfall::NotAttempted {
                check: "relro".to_owned(),
            },
        ];
        let lines = gate_lines(&coverage, &two);
        assert_eq!(
            lines.first().map(String::as_str),
            Some(
                format!(
                    "--fail-on-missing: 2 of the corpus's {total} checks are not attempted or \
                     not settled; this run selected 3 with --probe, and the gate counts the \
                     whole corpus"
                )
                .as_str()
            )
        );
        assert_eq!(lines.len(), 4, "{lines:?}");
        assert_eq!(
            lines.last().map(String::as_str),
            Some(
                "--fail-on-missing: exit 1, the report written; a run without --probe \
                 attempts the 2 not attempted"
            )
        );
        let none = gate_lines(&coverage, &[]);
        assert_eq!(none.len(), 3, "{none:?}");
        assert!(
            none.get(1).is_some_and(|l| l.contains("no check is named")),
            "{none:?}"
        );
        assert!(
            !gate_lines(&coverage, &two)
                .iter()
                .any(|l| l.contains("no check is named")),
            "the fallback is written only where nothing is named"
        );
    }

    /// The remedies for the two kernel-policy rules name the rule they lift and the count
    /// it holds, by the rules' own ids, beside the one for a narrowed run.
    #[test]
    fn the_remedies_name_the_rule_they_lift() {
        use report::gating_rule::{EXECUTION_MODE_ASSUMED, NEEDS_VM};
        let held = |check: &str, rule: &'static str| report::Shortfall::Unsettled {
            check: check.to_owned(),
            verdict: Verdict::Indeterminate,
            withheld: None,
            rule: Some(rule),
            reason: None,
        };
        let shortfalls = [
            held("noexecstack-enforced", EXECUTION_MODE_ASSUMED.id),
            held("shadow-stack-enforced", EXECUTION_MODE_ASSUMED.id),
            held("a", NEEDS_VM.id),
            report::Shortfall::NotAttempted {
                check: "pie".to_owned(),
            },
        ];
        assert_eq!(
            remedies(&shortfalls),
            "--execution host or --execution vm, where this run owns the kernel it runs on, \
             lifts gating.rule execution-mode-assumed from the 2 checks it holds, which the run \
             then attempts instead of withholding; the 1 check under gating.rule needs-vm \
             is measured only outside a container, on the host or in a vm, with --execution \
             saying which; a run without --probe attempts the 1 not attempted"
        );
    }

    /// A run that wrote to its file and then failed says the file holds what it wrote, which
    /// may not be a whole report, and names a `.previous` it did not set aside as an older
    /// run's, not as the earlier report this run kept.
    #[test]
    fn a_failure_after_the_write_names_the_report_it_wrote() {
        let dir = std::env::temp_dir().join(format!("chard-closing-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("r.json");
        std::fs::write(&path, "{}\n").expect("a written report");
        std::fs::write(dir.join("r.json.previous"), "older\n").expect("an older run's file");
        let mut ending = Ending {
            target: Target::File(report::Destination::File {
                requested: path.clone(),
                path: path.clone(),
            }),
            earlier: false,
            workdir: None,
            counts: None,
        };
        let line = failed_line(error::EXIT_FAILURE, &ending);
        assert_eq!(
            line,
            format!(
                "measure exits 2: refused or failed, the envelope on stdout says why; {} holds \
                 what this run wrote before the failure, which may not be a whole report, and \
                 an older run's {}.previous is beside it; next: the envelope's hint",
                path.display(),
                path.display()
            )
        );
        ending.earlier = true;
        assert!(
            failed_line(error::EXIT_FAILURE, &ending).contains(&format!(
                ", and the earlier report is kept as {}.previous",
                path.display()
            )),
            "a .previous this run set aside is named"
        );
        std::fs::write(&path, "").expect("an emptied report");
        ending.earlier = false;
        assert!(
            failed_line(error::EXIT_FAILURE, &ending).contains(&format!(
                "holds no report from this run, and an older run's {}.previous is beside it;",
                path.display()
            )),
            "an empty file is no report, and an older run's .previous is named as an older run's"
        );
        std::fs::remove_dir_all(&dir).expect("removing the scratch directory");
    }

    fn profile(name: &str) -> Profile {
        let args = MeasureArgs::try_parse_from(["chard", "--profile", name])
            .expect("the CLI must accept this profile name");
        resolve_profile(&args, "x86_64", &[])
            .expect("the profile must resolve without consulting the system")
    }

    /// A refused `-v` is noted on every built-in profile, after any note the profile
    /// already carries, and a refusal of another query notes nothing.
    #[test]
    fn an_unread_configuration_is_noted_on_every_profile() {
        let refused = |context: &'static str| toolchain::QueryFailure {
            context,
            message: String::new(),
        };
        let mut fed = 0;
        for name in ["bare", "bare-optimized", "openssf-tldr"] {
            fed += 1;
            let before = profile(name).toolchain_note;
            let noted =
                with_unread_config(profile(name), &[refused(toolchain::CONFIG_FILES_FIELD)])
                    .toolchain_note
                    .expect("noted");
            assert!(
                noted.contains("so it read no configuration file from it")
                    && noted.contains(toolchain::VERBOSE_QUERY),
                "{name}: {noted}"
            );
            if let Some(before) = before {
                assert!(
                    noted.starts_with(&format!("{before}; ")),
                    "{name} keeps its note: {noted}"
                );
            }
            assert_eq!(
                with_unread_config(profile(name), &[refused(toolchain::TRIPLE_FIELD)])
                    .toolchain_note,
                profile(name).toolchain_note,
                "{name}: a refused triple says nothing about configuration"
            );
        }
        assert!(
            profile("bare-optimized").toolchain_note.is_some(),
            "one profile exercises the join"
        );
        assert_eq!(fed, 3);
    }

    /// `openssf-tldr` as the CLI resolves it: 32-bit x86 gets the block and the executables row
    /// with neither of x86_64's architecture flags, the same list as an architecture the
    /// guide's rows do not name, and x86_64 and aarch64 get their rows. A call site that
    /// aliased x86 to x86_64 would pass the inventory's tests and fail here.
    #[test]
    fn the_cli_resolves_openssf_tldr_by_the_guides_rows_for_each_architecture() {
        let args = MeasureArgs::try_parse_from(["chard", "--profile", "openssf-tldr"])
            .expect("the CLI must accept this profile name");
        let flags = |arch: &str| {
            resolve_profile(&args, arch, &[])
                .expect("openssf-tldr resolves")
                .cflags
        };
        let x86 = flags("x86");
        for word in ["-fcf-protection=full", "-fzero-call-used-regs=used-gpr"] {
            assert!(
                !x86.iter().any(|f| f == word),
                "x86 carries {word}: {x86:?}"
            );
            assert!(
                flags("x86_64").iter().any(|f| f == word),
                "x86_64 lacks {word}"
            );
        }
        assert_eq!(x86, flags("riscv64"), "x86 is an architecture with no row");
        assert!(
            flags("aarch64")
                .iter()
                .any(|f| f == "-mbranch-protection=standard"),
            "aarch64 gets its row"
        );
    }

    /// A profile whose flags depend on an architecture the driver's macro dump names is
    /// refused where the arch gate read another; one that does not depend on architecture,
    /// or a dump that names the gate's own, passes through.
    #[test]
    fn a_profile_chosen_by_an_architecture_the_dump_contradicts_is_refused() {
        let tldr = MeasureArgs::try_parse_from(["chard", "--profile", "openssf-tldr"])
            .expect("the CLI must accept this profile name");
        let posed = resolve_profile(&tldr, "x86_64", &[]).expect("x86_64 resolves");
        let err = refuse_on_witnessed_arch(&tldr, posed.clone(), "x86_64", &["x86"], &[])
            .expect_err("x86_64's row under an i386 dump is refused");
        assert!(
            err.downcast_ref::<ConfigError>().is_some(),
            "the refusal is an unusable invocation, not a harness failure: {err:#}"
        );
        let message = format!("{err:#}");
        assert!(
            message.contains("under x86, the architecture")
                && message.contains("than under x86_64"),
            "the refusal names both architectures: {message}"
        );
        let same = refuse_on_witnessed_arch(&tldr, posed.clone(), "x86_64", &["x86_64"], &[])
            .expect("a dump naming the gate's own architecture passes");
        assert_eq!(link_lines(&same), link_lines(&posed));
        let bare = MeasureArgs::try_parse_from(["chard", "--profile", "bare"])
            .expect("the CLI must accept this profile name");
        let posed = resolve_profile(&bare, "x86_64", &[]).expect("bare resolves");
        refuse_on_witnessed_arch(&bare, posed, "x86_64", &["x86", "aarch64"], &[])
            .expect("a profile that does not depend on architecture is not refused");
    }

    /// A profile whose flags depend on the architecture is refused when the target its
    /// flags select differs from the driver's default it was resolved under.
    ///
    /// No shipped profile both selects a target and depends on architecture, so the
    /// refusal in `settle_profile` is unreachable from the CLI; this drives it directly
    /// with `openssf-tldr`, which picks its flags by architecture, posed under `x86_64`
    /// and settled under `aarch64`. The same pair under one architecture passes through.
    #[test]
    fn a_profile_whose_flags_depend_on_the_selected_target_is_refused() {
        let args = MeasureArgs::try_parse_from(["chard", "--profile", "openssf-tldr"])
            .expect("the CLI must accept this profile name");
        let posed = resolve_profile(&args, "x86_64", &[]).expect("x86_64 resolves");
        let settled = resolve_profile(&args, "aarch64", &[]).expect("aarch64 resolves");
        assert_ne!(
            link_lines(&posed),
            link_lines(&settled),
            "the test's premise: openssf-tldr resolves to different flags per architecture"
        );
        let err = settle_profile(&args, posed.clone(), "x86_64", "aarch64", &[])
            .expect_err("a profile that resolves differently under the selected target is refused");
        assert!(
            err.downcast_ref::<ConfigError>().is_some(),
            "the refusal is an unusable invocation, not a harness failure: {err:#}"
        );
        let same = settle_profile(&args, posed.clone(), "x86_64", "x86_64", &[])
            .expect("an unchanged target keeps the posed profile");
        assert_eq!(link_lines(&same), link_lines(&posed));
    }

    /// `chard probes` lists the tables each check reads, as the check declares them, and
    /// every elf-static check lists at least one.
    ///
    /// `reads` is the declaration the truncation gate intersects, so it is the one field
    /// a reader auditing why a cell went `indeterminate` under `artifact-unreadable` has
    /// to see in the corpus listing; a listing that omitted it left the declaration
    /// visible only in the source.
    #[test]
    fn the_corpus_listing_carries_what_each_check_reads() {
        let listing = corpus_listing();
        let mut elf_static = 0usize;
        let mut listed = 0usize;
        for probe in listing["probes"].as_array().expect("probes is a list") {
            for check in probe["checks"].as_array().expect("checks is a list") {
                listed += 1;
                let reads = check["reads"].as_array().expect("reads is a list");
                if check["channel"] == serde_json::json!(probe::Channel::ElfStatic) {
                    elf_static += 1;
                    assert!(
                        !reads.is_empty(),
                        "{}: an elf-static check lists the tables it reads",
                        check["id"]
                    );
                }
                let declared = probe::CORPUS
                    .iter()
                    .flat_map(|p| p.checks.iter())
                    .find(|c| check["id"].as_str() == Some(c.id))
                    .map(|c| serde_json::json!(c.reads()))
                    .expect("every listed check is in the corpus");
                assert_eq!(
                    serde_json::Value::Array(reads.clone()),
                    declared,
                    "{}: the listing carries the check's own declaration",
                    check["id"]
                );
            }
        }
        assert_eq!(listed, probe::total_checks(), "every check was listed");
        assert!(
            elf_static > 0,
            "no elf-static check was listed, so nothing was held"
        );
    }

    /// `bare-optimized` must carry `-O2` and nothing else.
    ///
    /// The profile's entire evidentiary value rests on this. It exists to remove
    /// one confound — that fortify cannot instantiate without optimization — so
    /// that hardening observed under it is attributable to the *compiler*. A single
    /// additional flag would make it a second `openssf-tldr`: a measurement of
    /// chard's own opinions rather than the distribution's.
    #[test]
    fn bare_optimized_adds_only_the_enabling_condition() {
        let p = profile("bare-optimized");
        assert_eq!(p.cflags, vec!["-O2".to_owned()]);
        assert!(
            p.ldflags.is_empty(),
            "the profile must not touch the link step"
        );
    }

    /// It must differ from `bare` by exactly that one flag, or the two columns are
    /// not comparable and the gated-default question cannot be read off them.
    #[test]
    fn bare_optimized_differs_from_bare_only_by_optimization() {
        let bare = profile("bare");
        let opt = profile("bare-optimized");
        assert!(bare.cflags.is_empty());
        let added: Vec<_> = opt
            .cflags
            .iter()
            .filter(|f| !bare.cflags.contains(f))
            .collect();
        assert_eq!(added, vec![&"-O2".to_owned()]);
    }

    /// The flags must be attributable to chard rather than to the distribution.
    ///
    /// `bare` reports `flags_source: "none"`, and if `bare-optimized` did too, a
    /// reader — or `attribute` — would credit `-O2` to the compiler's own defaults
    /// The explicit profile carries all three flag sets the caller can supply.
    ///
    /// `cxxflags` and `ldflags` existed on `Profile` and in the schema with no way to
    /// reach them: every production construction site set them empty, which made
    /// `measure::variant_flags`' C++ branch unreachable outside its own unit test. The
    /// consequence was a measurement chard could not take — `_GLIBCXX_ASSERTIONS` and
    /// `_LIBCPP_HARDENING_MODE` are set in CXXFLAGS and nowhere else by every
    /// distribution measured that sets them, so the C++ checks were being asked about a
    /// CFLAGS that never carried them.
    /// A relative path in any of the three lists is refused, by name and list, before the
    /// driver is run; an absolute one, a sysroot-relative one and a searched name are not.
    /// `compile::relative_path_arguments` says why.
    #[test]
    fn explicit_refuses_a_relative_path_and_names_it() {
        let refused = |flags: &str, cxx: &str, ld: &str| {
            let args = MeasureArgs::try_parse_from([
                "chard",
                "--profile",
                "explicit",
                "--flags",
                flags,
                "--cxxflags",
                cxx,
                "--ldflags",
                ld,
            ])
            .expect("the CLI accepts the lists");
            resolve_profile(&args, "x86_64", &[])
                .err()
                .map(|err| err.to_string())
        };
        let err = refused("-O2 -Bmy-linker-dir", "-isystem inc", "-Wl,-L,lib")
            .expect("a relative -B is refused");
        for named in [
            "\"-Bmy-linker-dir\" in --flags",
            "\"-isystem inc\" in --cxxflags",
            "\"-Wl,-L,lib\" in --ldflags",
        ] {
            assert!(err.contains(named), "{named} missing from: {err}");
        }
        assert_eq!(
            refused(
                "-O2 -B/opt/ld -I=/inc -fuse-ld=lld",
                "--sysroot=/sr",
                "-Wl,-z,now"
            ),
            None
        );
    }

    /// A flag that removes the startup objects, the default libraries or the default
    /// headers is refused from any of the three lists, by name and list, as
    /// `CONFIGURATION`, before the driver is run; a selection and a linker's own
    /// `-nostdlib` are not. `toolchain::runtime_removing_flags` says why.
    #[test]
    fn explicit_refuses_a_runtime_removal_and_names_it() {
        let refused = |flags: &str, cxx: &str, ld: &str| {
            let args = MeasureArgs::try_parse_from([
                "chard",
                "--profile",
                "explicit",
                "--flags",
                flags,
                "--cxxflags",
                cxx,
                "--ldflags",
                ld,
            ])
            .expect("the CLI accepts the lists");
            resolve_profile(&args, "x86_64", &[]).err()
        };
        let err = refused(
            "-O2 -nostartfiles -nostdinc",
            "-O2 -nostdinc++ -stdlib++-isystem /opt/v1",
            "-nodefaultlibs --no-standard-libraries",
        )
        .expect("a removal is refused");
        assert!(
            err.downcast_ref::<ConfigError>().is_some(),
            "the refusal is the profile's to fix: {err:#}"
        );
        let text = err.to_string();
        let named = [
            "\"-nostartfiles\" in --flags",
            "\"-nostdinc\" in --flags",
            "\"-nostdinc++\" in --cxxflags",
            "\"-nodefaultlibs\" in --ldflags",
            "\"--no-standard-libraries\" in --ldflags",
        ];
        for one in named {
            assert!(text.contains(one), "{one} missing from: {text}");
        }
        assert_eq!(
            text.matches(" in --").count(),
            named.len(),
            "each removal fed is named once, and nothing else: {text}"
        );
        assert!(
            refused(
                "-O2 -B/opt/tc --gcc-install-dir=/opt/g",
                "-stdlib++-isystem /opt/v1",
                "-Xlinker -nostdlib -static-libgcc"
            )
            .is_none(),
            "a selection and a word handed to the linker are not removals"
        );
        let err = refused(
            "-O2 -Wp,-D_X,-nostdinc --no-standard-i",
            "-Xpreprocessor -nostdinc++",
            "-Xarch_x86_64 -nostartfiles",
        )
        .expect("a removal passed through is refused");
        assert!(
            err.downcast_ref::<ConfigError>().is_some(),
            "the refusal is the profile's to fix: {err:#}"
        );
        let text = err.to_string();
        let named = [
            "\"-Wp,-D_X,-nostdinc\" in --flags",
            "\"--no-standard-i\" in --flags",
            "\"-Xpreprocessor\" in --cxxflags",
            "\"-nostdinc++\" in --cxxflags",
            "\"-Xarch_x86_64\" in --ldflags",
            "\"-nostartfiles\" in --ldflags",
        ];
        for one in named {
            assert!(text.contains(one), "{one} missing from: {text}");
        }
        assert_eq!(
            text.matches(" in --").count(),
            named.len(),
            "each pass-through removal fed is named once, and nothing else: {text}"
        );
    }

    /// A flag selecting x32, 16-bit or aarch64 ILP32 code is refused from any of the three
    /// lists, by name
    /// and list, as `CONFIGURATION`, with the sentence saying chard does not measure that
    /// target; `-m32` and an x86_64 triple are not. `toolchain::unsupported_target_flags`
    /// says which spellings and why. The refusal comes after a response file's and before
    /// a removal's.
    #[test]
    fn explicit_refuses_an_x32_sixteen_bit_or_ilp32_target_and_names_it() {
        let refused = |flags: &str, cxx: &str, ld: &str| {
            let args = MeasureArgs::try_parse_from([
                "chard",
                "--profile",
                "explicit",
                "--flags",
                flags,
                "--cxxflags",
                cxx,
                "--ldflags",
                ld,
            ])
            .expect("the CLI accepts the lists");
            resolve_profile(&args, "x86_64", &[]).err()
        };
        let err = refused(
            "-O2 -mx32 --target=x86_64-pc-linux-gnux32",
            "-m16 -target x86_64-linux-gnux32",
            "-Xclang -triple=i386-pc-linux-code16 -mabi=ilp32 --target=aarch64-linux-gnu_ilp32",
        )
        .expect("an x32, 16-bit or ILP32 target is refused");
        assert!(
            err.downcast_ref::<ConfigError>().is_some(),
            "the refusal is the profile's to fix: {err:#}"
        );
        let text = err.to_string();
        assert!(
            text.contains("chard does not measure x32, 16-bit or aarch64 ILP32 targets"),
            "{text}"
        );
        let named = [
            "\"-mx32\" in --flags",
            "\"--target=x86_64-pc-linux-gnux32\" in --flags",
            "\"-m16\" in --cxxflags",
            "\"-target\" in --cxxflags",
            "\"x86_64-linux-gnux32\" in --cxxflags",
            "\"-Xclang\" in --ldflags",
            "\"-triple=i386-pc-linux-code16\" in --ldflags",
            "\"-mabi=ilp32\" in --ldflags",
            "\"--target=aarch64-linux-gnu_ilp32\" in --ldflags",
        ];
        for one in named {
            assert!(text.contains(one), "{one} missing from: {text}");
        }
        assert_eq!(
            text.matches(" in --").count(),
            named.len(),
            "each selection fed is named once, and nothing else: {text}"
        );
        assert!(
            refused(
                "-O2 -m32",
                "--target=x86_64-linux-gnu --target=aarch64-linux-gnu",
                "-m64 -mabi=lp64"
            )
            .is_none(),
            "i386, x86_64 and LP64 aarch64 are measured"
        );
        let first =
            refused("-O2 @/srv/flags.rsp -mx32", "-O2", "-O2").expect("a response file is refused");
        assert!(
            first.to_string().contains("a response file hands"),
            "the response file is refused before the x32 selection: {first:#}"
        );
        let second =
            refused("-O2 -mx32 -nostdlib", "-O2", "-O2").expect("an x32 selection is refused");
        assert!(
            second.to_string().contains("chard does not measure x32"),
            "the x32 selection is refused before the removal: {second:#}"
        );
    }

    /// A response file in any of the three lists is refused, by name and list, as
    /// `CONFIGURATION`, before the driver is run, whether it is absolute or relative and
    /// whichever tool it is handed to. `compile::response_file_arguments` says why.
    #[test]
    fn explicit_refuses_a_response_file_and_names_it() {
        let refused = |flags: &str, cxx: &str, ld: &str| {
            let args = MeasureArgs::try_parse_from([
                "chard",
                "--profile",
                "explicit",
                "--flags",
                flags,
                "--cxxflags",
                cxx,
                "--ldflags",
                ld,
            ])
            .expect("the CLI accepts the lists");
            resolve_profile(&args, "x86_64", &[]).err()
        };
        let err = refused(
            "-O2 @/opt/m32.rsp",
            "-Xclang @cc1.rsp",
            "-Wl,-z,now,@/opt/ld.rsp",
        )
        .expect("a response file is refused");
        assert!(
            err.downcast_ref::<ConfigError>().is_some(),
            "the refusal is the profile's to fix: {err:#}"
        );
        let text = err.to_string();
        for named in [
            "\"@/opt/m32.rsp\" in --flags",
            "\"@cc1.rsp\" in --cxxflags",
            "\"-Wl,-z,now,@/opt/ld.rsp\" in --ldflags",
        ] {
            assert!(text.contains(named), "{named} missing from: {text}");
        }
        assert!(
            !text.contains("relative path"),
            "a relative @file is refused as a response file: {text}"
        );
    }

    #[test]
    fn explicit_carries_the_cxx_and_linker_flags_it_was_given() {
        let args = MeasureArgs::try_parse_from([
            "chard",
            "--profile",
            "explicit",
            "--flags",
            "-O2 -D_FORTIFY_SOURCE=3",
            "--cxxflags",
            "-O2 -D_GLIBCXX_ASSERTIONS",
            "--ldflags",
            "-Wl,-z,relro -Wl,-z,now",
        ])
        .expect("the CLI must accept all three flag arguments");
        let p =
            resolve_profile(&args, "x86_64", &[]).expect("explicit resolves from its arguments");
        assert_eq!(p.cflags, ["-O2", "-D_FORTIFY_SOURCE=3"]);
        assert_eq!(p.cxxflags, ["-O2", "-D_GLIBCXX_ASSERTIONS"]);
        assert_eq!(p.ldflags, ["-Wl,-z,relro", "-Wl,-z,now"]);
    }

    /// An omitted `--cxxflags` stays empty rather than copying `--flags`.
    ///
    /// Empty is what `measure::variant_flags` reads as "build C++ with the C flags", so
    /// filling it in would produce the same builds and a report claiming the caller
    /// supplied two flag sets that happen to match. The distinction is the difference
    /// between "they gave us one set" and "they told us these are the same".
    #[test]
    fn an_omitted_cxxflags_is_absent_rather_than_a_copy() {
        let args =
            MeasureArgs::try_parse_from(["chard", "--profile", "explicit", "--flags", "-O2"])
                .expect("--flags alone is a valid explicit profile");
        let p =
            resolve_profile(&args, "x86_64", &[]).expect("explicit resolves from --flags alone");
        assert_eq!(p.cflags, ["-O2"]);
        assert!(
            p.cxxflags.is_empty(),
            "an unsupplied cxxflags must stay empty, got {:?}",
            p.cxxflags
        );
        assert!(
            p.ldflags.is_empty(),
            "an unsupplied ldflags must stay empty"
        );
    }

    /// and mis-attribute anything it unlocked.
    #[test]
    fn bare_optimized_declares_who_chose_its_flags() {
        assert_eq!(profile("bare").flags_source, "none");
        let p = profile("bare-optimized");
        assert_eq!(p.flags_source, "chard-enabling-condition");
        assert!(
            p.toolchain_note
                .is_some_and(|n| n.contains("not a hardening flag")),
            "the note must say -O2 grants nothing on its own"
        );
    }

    /// A repeated `--probe` is refused, an unknown one is refused, and a distinct
    /// selection names its own size.
    ///
    /// The doubled selection was accepted: `--probe stack-canary --probe stack-canary`
    /// produced two observations per check, `checks_expected: 2` against one distinct
    /// probe, and `defect_coverage.from_checks` listing `canary-emitted` twice.
    #[test]
    fn a_repeated_probe_id_is_refused_and_a_distinct_selection_is_counted_once() {
        let Err(err) = select_probes(&["stack-canary".to_owned(), "stack-canary".to_owned()])
        else {
            panic!("a repeated id must be refused");
        };
        assert!(
            err.downcast_ref::<UserError>()
                .is_some_and(|u| u.message.contains("more than once")),
            "the refusal must be a user error naming the repetition: {err:#}"
        );

        let Err(unknown) = select_probes(&["no-such-probe".to_owned()]) else {
            panic!("an unknown id must be refused");
        };
        assert!(
            unknown
                .downcast_ref::<UserError>()
                .is_some_and(|u| u.message.contains("no-such-probe"))
        );

        let (chosen, truncations) =
            select_probes(&["stack-canary".to_owned(), "link-defaults".to_owned()])
                .expect("two distinct ids select two probes");
        assert_eq!(chosen.len(), 2);
        assert_eq!(truncations.len(), 1);
        assert!(
            truncations[0].starts_with("run restricted to 2 of "),
            "the truncation names the distinct count: {}",
            truncations[0]
        );

        let (all, none) = select_probes(&[]).expect("no filter selects the corpus");
        assert_eq!(all.len(), probe::CORPUS.len());
        assert!(none.is_empty(), "an unfiltered run records no truncation");
    }

    /// A driver that loaded a configuration file changes what `bare` measures, and the
    /// profile says so where a reader of a bare column looks.
    ///
    /// `none` is reserved for compiled-in defaults. A clang auto-loading
    /// `<triple>.cfg` was published under it, with the file named only in
    /// `toolchain.config_files`, so a distribution putting a hardening flag in that file
    /// would have had it credited to the compiler. `bare-optimized` keeps the value
    /// that attributes the `-O2` chard passed, and names the file in its note instead.
    #[test]
    fn a_driver_configuration_file_is_named_by_the_bare_profile_it_stands_behind() {
        let files = vec!["/some.cfg".to_owned()];
        let resolve = |name: &str| {
            let args = MeasureArgs::try_parse_from(["chard", "--profile", name])
                .expect("the CLI must accept this profile name");
            resolve_profile(&args, "x86_64", &files).expect("the profile resolves")
        };

        let bare = resolve("bare");
        assert_eq!(bare.flags_source, report::flags_source::DRIVER_CONFIG);
        assert!(
            bare.toolchain_note
                .as_deref()
                .is_some_and(|n| n.contains("/some.cfg")),
            "the note names the file: {:?}",
            bare.toolchain_note
        );
        assert!(bare.cflags.is_empty(), "no flag was passed");

        let optimized = resolve("bare-optimized");
        assert_eq!(
            optimized.flags_source,
            report::flags_source::ENABLING_CONDITION,
            "the -O2 chard passed keeps its attribution"
        );
        assert!(
            optimized
                .toolchain_note
                .as_deref()
                .is_some_and(|n| n.contains("/some.cfg") && n.contains("not a hardening flag")),
            "both facts reach the note: {:?}",
            optimized.toolchain_note
        );

        // And without a file, nothing changes: `none` still means compiled-in defaults.
        assert_eq!(profile("bare").flags_source, report::flags_source::NONE);
        assert!(profile("bare").toolchain_note.is_none());
    }

    /// Each flag list beside each built-in profile is refused as configuration, naming the
    /// list and `--profile explicit`, both at the door and where the profile resolves; the
    /// same lists under `explicit` resolve.
    #[test]
    fn flags_beside_a_builtin_profile_are_refused_by_name() {
        for profile in ["bare", "bare-optimized", report::OPENSSF_TLDR_ID] {
            for list in ["--flags", "--cxxflags", "--ldflags"] {
                let args =
                    MeasureArgs::try_parse_from(["chard", "--profile", profile, list, "-O2"])
                        .expect("the CLI parses the list");
                for err in [
                    refuse_flags_beside_a_builtin_profile(&args).expect_err("refused at the door"),
                    resolve_profile(&args, "x86_64", &[]).expect_err("refused at resolution"),
                ] {
                    assert!(
                        err.downcast_ref::<ConfigError>().is_some(),
                        "the refusal is an unusable invocation: {err:#}"
                    );
                    let message = err.to_string();
                    assert!(
                        message.contains(&format!("reads none of {list};"))
                            && message.contains("--profile explicit")
                            && message.contains(&format!("--profile {profile} ")),
                        "the refusal names the list, the profile and the way out: {message}"
                    );
                }
            }
        }
        let args = MeasureArgs::try_parse_from([
            "chard",
            "--profile",
            "bare",
            "--flags",
            "",
            "--ldflags",
            "-Wl,-z,now",
        ])
        .expect("the CLI parses an empty list");
        let message = resolve_profile(&args, "x86_64", &[])
            .expect_err("an empty list is still a list the profile would not read")
            .to_string();
        assert!(
            message.contains("reads none of --flags and --ldflags;"),
            "both lists are named: {message}"
        );
        let args = MeasureArgs::try_parse_from([
            "chard",
            "--flags",
            "-O2",
            "--cxxflags",
            "-O2",
            "--ldflags",
            "-Wl,-z,now",
        ])
        .expect("the CLI parses the lists");
        let message = resolve_profile(&args, "x86_64", &[])
            .expect_err("three lists beside the default profile are refused")
            .to_string();
        assert!(
            message.contains("reads none of --flags, --cxxflags and --ldflags;"),
            "the three lists are named as one list: {message}"
        );
        let explicit = MeasureArgs::try_parse_from([
            "chard",
            "--profile",
            "explicit",
            "--flags",
            "-O2",
            "--cxxflags",
            "-O2",
            "--ldflags",
            "-Wl,-z,now",
        ])
        .expect("the CLI parses the lists");
        refuse_flags_beside_a_builtin_profile(&explicit).expect("explicit reads all three");
        resolve_profile(&explicit, "x86_64", &[]).expect("explicit resolves");
    }

    /// `--timeout 0` is refused by the parser; `1` is the least it accepts.
    #[test]
    fn a_zero_timeout_is_refused() {
        let err = MeasureArgs::try_parse_from(["chard", "--timeout", "0"])
            .err()
            .expect("a zero timeout is refused");
        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
        let one = MeasureArgs::try_parse_from(["chard", "--timeout", "1"])
            .expect("a one-second timeout is accepted");
        assert_eq!(one.timeout, 1);
    }

    /// A profile chard cannot resolve must be refused, not silently treated as bare.
    #[test]
    fn an_unknown_profile_is_rejected() {
        let args =
            MeasureArgs::try_parse_from(["chard", "--profile", "bare"]).expect("baseline parse");
        let mut args = args;
        args.profile = "invented".to_owned();
        assert!(resolve_profile(&args, "x86_64", &[]).is_err());
    }
}
