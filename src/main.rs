// SPDX-License-Identifier: BSD-3-Clause

//! chard CLI.

// The driver is held to the same lint wall as the library (`lib.rs`): `Cargo.toml`'s
// generated lint block covers every target of the package, this one included.

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
/// stated here once and printed by `chard --help`.
const CONTRACT: &str = "A command is one operation: it reads reports, binaries or nothing, and \
     writes one document. `measure` builds the probes with a compiler and writes a report. \
     `table` and `matrix` read reports. `digest` reads one report and writes the block that \
     report leads with. `detect` reads a report or another of chard's documents \
     (`--evidence`), or one binary (`--artifact`). `elf` reads binaries. `probes` reads \
     nothing and lists what `measure` builds. Setup and tooling, building chard and running \
     its gates among them, are flags or Makefile targets, not commands.\n\n\
     A command writes its document to stdout, or to the file `-o` names (`-o -` is stdout). \
     `measure` writes its report to `chard-<cc>-<profile>.json` in the current directory \
     unless `-o` names another file or `-`. The document is JSON, except `table`'s rendering \
     and `probes --format text`, which are text for people, as are `--help` and `--version`. \
     Progress and notes go to stderr, prefixed `chard: `. A usage error's own text goes to \
     stderr unprefixed. `measure` ends every run that exits 0, 1, 2, 3 or 4, a refused one \
     too, with one line on stderr. That line names the exit status, the file written or kept, \
     the report's counts and what to run next. After a panic (exit 101) the last line says so, \
     and a killed run has none.\n\n\
     - Exit 0: the document is written. From `detect`, every reading it replayed agrees. From \
     `measure --fail-on-missing`, every check settled or `--allow` excused it, and each \
     excused check is named on stderr and in `coverage.gate.excused`.\n\
     - Exit 1: a gate tripped, and the document is written. From `measure \
     --fail-on-missing`, a check was not attempted or did not settle, `--allow` did not \
     excuse it, and exit 4 does not apply. From `detect`, a reading disagrees with its \
     replay.\n\
     - Exit 4: from `measure --fail-on-missing`, a gate tripped as for exit 1, and every \
     shortfall is a machine limit or a target limit, at least one a machine limit. A caller \
     asking whether the gate passed tests for 0. A machine limit is a check held by one of \
     the gating rules `cpu-lacks-shadow-stack`, `machine-lacks-bti`, `machine-lacks-pac` or \
     `cpu-shows-no-fpac`. The kernel and CPU the run had cannot answer it, and no change of \
     toolchain or profile helps. A target limit is a check held by `no-check-on-target` or \
     `arch-outside-table`: chard does not read it on this target architecture. A rerun on a \
     machine whose kernel and CPU give every feature the machine limits name still exits 1 \
     while a target limit that `--allow` does not excuse stands. Target limits alone exit 1, \
     or 0 where `--allow no-check-on-target` excuses every one. `arch-outside-table` and the \
     machine limits have no allowance, so no allowance moves exit 4. The document is written \
     as for exit 1.\n\
     - Exit 2: chard refused the invocation or failed. A usage error exits 2. So does a \
     `--execution` that what chard observed contradicts, and its report is kept as for exit \
     3, not published. stdout carries an error envelope in place of the document, \
     `{\"chard_schema\", \"error\": {\"code\", \"operation\", \"message\", \"hint\"}}`. Its \
     `code` names whose action comes next: `USER_INPUT` the caller, `PERMISSION` whoever owns \
     the filesystem, `TRANSIENT` a retry, `CONFIGURATION` the invocation's settings, \
     `INTERNAL` a bug report against chard.\n\
     - Exit 3: chard contradicted itself, and only `measure` exits 3. The report it built \
     disagrees with itself and is not published. It is written only to `<file>.contradicted`, \
     beside the file it would have gone to, and under `-o -` nowhere. stdout carries an \
     `INTERNAL` envelope whose hint names that file or says how to keep one.\n\n\
     Every JSON document but `elf`'s carries `chard_schema`, the major version of its own \
     shape. The shapes of a report, a matrix, `detect`'s output and the envelope are in \
     `schema/`, and `digest`'s is the report's `digest`. `elf`'s output is a map from the \
     paths it was given to their facts, with no place for a key beside them. A key chard adds \
     is not a change: a consumer ignores keys it does not know, and the shipped schemas admit \
     them. An enumeration is closed or open. A closed one holds values a consumer decides on, \
     such as a verdict, an error code or a defect status, and adding a value to it raises \
     `chard_schema`. An open one names things chard has, such as gating rules or linker \
     kinds. The schemas spell an open one `anyOf` of the values known and any string. A value \
     may be added to it within a version, and a consumer reads a value it does not know as \
     one it cannot interpret. Removing or renaming a key or a value, in either kind, or \
     changing a value's type or meaning, raises `chard_schema`. The rule holds from chard's \
     first publication, 0.1.0, where every document was at `1`. A report and a matrix are at \
     `2`, and `detect`'s output, the probe listing and the error envelope at `1`. `table`, \
     `matrix`, `digest` and `detect` read a report at the `chard_schema` this chard writes and \
     refuse any other with exit 2. The refusal of a report at `1` whose `run.decoders_sha256` \
     is 0.1.0's names chard 0.1.0. `table`, `matrix` and `digest` refuse a report without its \
     `digest` the same way.";

/// `chard --help`'s description: what chard is, then [`CONTRACT`].
fn long_about() -> String {
    format!(
        "Measure which C/C++ hardening flags a toolchain actually applies.\n\n\
         `measure` builds small probe programs with the compiler you name. It reads the \
         artifacts it just built and the probes' own reports. It publishes a verdict for a \
         check only where the check's control triple (the flag forced on, forced off, and as \
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
    // A one-word summary keeps `-h`'s line, which clap ends with the default and the forms,
    // within 80 columns.
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
               of `--cc`. The name holds nothing else. A run under the same compiler name and \
               profile replaces an earlier report there, whatever else changed: its flags, \
               `--probe`, `--env`, `--execution`, or another compiler of that name. Give each \
               run its own `-o` to keep both. The closing line says when an earlier report was \
               replaced."
          ))]
    path: Option<PathBuf>,
}

/// `-o`'s long help: what it writes, then what an earlier file at the path becomes, which is
/// one rule for every command.
fn output_help(what: &str) -> String {
    format!(
        "{what}\n\nAn invocation refused before the earlier file at the path is set aside \
         leaves that file as it was. These are refused that early:\n\n\
         - a usage error;\n\
         - an input that cannot be read or that the command refuses (a file that is not \
         JSON, a check id `detect` does not know);\n\
         - an option `measure` refuses before it builds (`--probe`, `--env`, a profile's \
         flags, `--workdir`);\n\
         - a path no run could write;\n\
         - a path that is one of the inputs, or beside which chard writes a name that is \
         one.\n\n\
         Once the earlier file is set aside, it is kept as `<file>.previous`. A run that \
         fails then leaves no earlier document at the path to be read as this one. A run \
         that writes its document removes what was set aside."
    )
}

#[derive(Subcommand)]
enum Command {
    /// Build probes with a compiler, read the result; write a JSON report.
    #[command(after_long_help = "Examples:\n  \
        chard measure --cc gcc && chard table chard-gcc-bare.json\n  \
        chard measure --cc clang --profile explicit \\\n      \
        --flags \"-O2 -D_FORTIFY_SOURCE=3 -fstack-protector-strong\" \\\n      \
        --ldflags \"-Wl,-z,relro,-z,now\" -o clang-flags.json")]
    Measure(Box<MeasureArgs>),
    /// Read nothing; write the probes and their checks, as JSON or text.
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
        #[arg(long)]
        replace_repeated: bool,
        /// Wrap a text table's notes (default 80; 0: no wrap).
        #[arg(long, value_name = "COLS", default_value_t = table::DEFAULT_WIDTH, hide_default_value = true)]
        width: usize,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Read reports; write them cross-tabulated by configuration, as JSON.
    #[command(after_long_help = "Example:\n  chard matrix reports/*.json")]
    Matrix {
        /// Report files to tabulate.
        #[arg(required = true)]
        reports: Vec<PathBuf>,
        #[command(flatten)]
        allow_mixed: AllowMixedArg,
        /// Keep a repeated configuration's later report, whole.
        #[arg(long)]
        replace_repeated: bool,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Read one report; write its digest alone, as JSON.
    #[command(after_long_help = "Example:\n  chard digest chard-gcc-bare.json")]
    Digest {
        /// Report file to read.
        report: PathBuf,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Read binaries; write the ELF facts chard decides from, as JSON.
    #[command(after_long_help = "Example:\n  chard elf /usr/bin/ls")]
    Elf {
        /// Binaries to inspect.
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Read a chard document or a binary; write a replay or detection.
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
    // chard does not query rpm, dpkg-buildflags, abuild, makepkg or portageq: a runtime
    // query describes only the image it runs in, and each distribution's spelling of its
    // flag list belongs to whatever assembles the list.
    #[arg(long, default_value = "bare", hide_default_value = true, hide_possible_values = true, value_parser = ["bare", "bare-optimized", "openssf-tldr", "explicit"])]
    profile: String,

    /// C flags for --profile explicit.
    // `allow_hyphen_values`: every realistic value starts with `-`, which clap would
    // otherwise reject as an unknown option.
    #[arg(long, allow_hyphen_values = true)]
    flags: Option<String>,

    /// C++ flags for --profile explicit.
    // Building the C++ probes with CFLAGS asks a question whose answer is `off` wherever the
    // two differ, which is where the C++ hardening lives (`report::Profile::cxxflags`).
    #[arg(long, allow_hyphen_values = true)]
    cxxflags: Option<String>,

    /// Link flags for --profile explicit.
    #[arg(long, allow_hyphen_values = true)]
    ldflags: Option<String>,

    /// A variable for the toolchain (repeatable).
    #[arg(long = "env", value_name = "NAME=VALUE", allow_hyphen_values = true)]
    env: Vec<String>,

    /// Work directory, kept as evidence.
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
    #[arg(long, value_name = "WHERE", hide_possible_values = true, value_parser = ["host", "container", "vm"])]
    execution: Option<String>,

    /// The image this run is in, as recorded.
    #[arg(long)]
    image: Option<String>,

    /// A JSON file saying where the image came from.
    // The harness writes this object as `provenance` in its session file; an
    // `installed_disk` record is `env::InstalledDisk`, hashed into `run.inputs_sha256`.
    #[arg(long, value_name = "FILE")]
    image_attestation: Option<PathBuf>,

    /// Run only these probes, by probe id.
    #[arg(long = "probe", value_name = "PROBE")]
    probes: Vec<String>,

    /// Seconds a probe may run.
    // `0` is refused: it kills a probe still running at the first look (`run::execute`), so
    // a run under it measures how fast each probe exits rather than what it reports.
    #[arg(long, value_name = "SECS", default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..))]
    timeout: u64,

    /// Exit 1 or 4 on a check unsettled and unexcused.
    #[arg(long)]
    fail_on_missing: bool,

    /// Excuse one gating rule's checks from the gate.
    #[arg(long, value_name = "RULE", requires = "fail_on_missing")]
    allow: Vec<report::Allowance>,

    /// Also compare SARIF with the text reading.
    #[arg(long)]
    structured_diagnostics: bool,

    /// Blank what varies between runs.
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
            "give --cc the compiler's name or path",
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
/// `USER_INPUT` envelope naming the command, exit 2, where `Cli::parse` would leave stdout
/// empty. `--help` and `--version` reach here as clap's "errors" too, and print to stdout
/// with exit 0.
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
    // rest.
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
            // The inputs are read and parsed first, so a bad path leaves an earlier table at
            // `-o` untouched; then, as `measure` does, the earlier table is set aside before
            // the set is judged, so a refused set leaves no earlier table at `-o` to be read
            // as this one.
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
                "pass a report, store entry, record or `chard elf` output with --evidence, or an ELF object with --artifact",
            )
            .into());
        }
    };
    // As for `table`: the inputs first, then the set-aside.
    let inputs: Vec<&Path> = evidence.into_iter().chain(artifact).collect();
    let destination = set_aside_output(output, &inputs)?;
    deliver(destination.as_ref(), &json_document(&decoded)?, "detection")?;
    // A gate replay the report could not take is said where a pipeline's log shows it, and
    // not only inside the document: the exit status reads such a gate as agreeing.
    if let detect::Output::Replay(replay) = &decoded {
        let unpublished = replay
            .gates
            .iter()
            .filter(|g| g.outcome == detect::GateOutcome::ListingsUnpublished)
            .count();
        if unpublished > 0 {
            error::note(&format!(
                "{unpublished} of {} gate(s) of {} were not replayed",
                replay.gates.len(),
                replay.check
            ));
        }
    }
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
/// temporary names and the publication would replace or remove it. `-o` itself is compared
/// by device and inode, so a second spelling of the input, a hard link to it or a symbolic
/// link to it is refused as the input is (regular files only: a stream such as
/// `/dev/stdout` can share a terminal's inode and is no file to lose). The names beside it
/// (the file a publication writes, [`report::published_path`], followed by
/// [`report::SET_ASIDE_SUFFIX`] or [`report::QUARANTINE_SUFFIX`], or by
/// [`report::PARTIAL_SUFFIX`] and anything after it) are compared as directory entries, the
/// input's own and the one at the end of a link it is, since a rename or a removal acts on
/// the entry.
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
    // acts on.
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
                    "the output {} is the input {}",
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
        report::Unpublishable::Directory => {
            UserError::with_hint(message, "-o names the file to write").into()
        }
        report::Unpublishable::BrokenLink(_) => UserError::with_hint(
            message,
            "point the link at a file in a directory that exists",
        )
        .into(),
        report::Unpublishable::Unwritable { in_place, .. } => error::PermissionError {
            message,
            hint: if in_place.kind() == Kind::ReadOnlyFilesystem {
                "the filesystem holding it is read-only"
            } else {
                "give -o a path in a directory this user can create files in"
            }
            .to_owned(),
        }
        .into(),
        report::Unpublishable::SiblingName { .. } | report::Unpublishable::SiblingLength { .. } => {
            UserError::with_hint(message, "give -o a shorter file name").into()
        }
        report::Unpublishable::Io(source)
            if matches!(
                source.kind(),
                Kind::NotFound | Kind::NotADirectory | Kind::IsADirectory
            ) =>
        {
            UserError::with_hint(
                message,
                "-o names a file: check that each directory in its path exists and is a directory",
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
/// held by the `print_stdout` lint, which `Cargo.toml`'s lint block denies.
fn write_stdout(text: &str) -> Result<()> {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        written => written.context("writing to stdout"),
    }
}

/// Split a caller-supplied flag string on whitespace.
fn split_flags(text: &str) -> Vec<String> {
    text.split_whitespace().map(ToOwned::to_owned).collect()
}

/// A check's level vocabulary as `chard probes` publishes it: the words
/// `observations[].level` may carry for this check, whether they are graded, and on a
/// graded check the scale's kind and the ask.
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
                    .collect::<BTreeMap<_, _>>(),
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
                        .collect::<BTreeMap<_, _>>(),
                    // `probe::PositiveInput`: the files the positive arm links after the probe's
                    // source, which no other build is handed.
                    "positive_inputs": c
                        .positive_inputs()
                        .iter()
                        .map(|input| input.source_name)
                        .collect::<Vec<_>>(),
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

/// The run's warnings about the compiler lines the rule could not hold: the relocatable
/// objects the run's checks read that show no compiler, and the linked artifacts that name
/// another compiler and not the report's.
fn compiler_line_warnings(
    toolchain: &toolchain::Toolchain,
    observations: &[Observation],
    facts: &report::FactStore,
) -> Vec<Diagnostic> {
    let (kind, version) = (toolchain.detected.kind, toolchain.detected.version.as_str());
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let (mut unshown, mut linked): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    let mut read = 0usize;
    for o in observations {
        let Some(sha) = o.build.as_ref().and_then(|b| b.artifact_sha256.as_deref()) else {
            continue;
        };
        let Some(elf) = facts.measured_elf_of(o) else {
            continue;
        };
        if !seen.insert(sha) {
            continue;
        }
        let short: String = sha.chars().take(16).collect();
        if elf.elf_type == measure::RELOCATABLE {
            read = read.saturating_add(1);
            if let toolchain::ObjectCompiler::NotShown(why) =
                toolchain::object_compiler(&elf.comment, elf.comment_truncation(), kind, version)
            {
                unshown.push(format!("{} sha256:{short} {why}", o.probe));
            }
            continue;
        }
        let assembly = probe::find(&o.probe).is_some_and(|p| {
            Path::new(p.source_name)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("s"))
        });
        if assembly || elf.comment_truncation().is_some() {
            continue;
        }
        if let Some(lines) = toolchain::linked_without_own_line(&elf.comment, kind, version) {
            linked.push(format!(
                "{} sha256:{short} (`{}`)",
                o.probe,
                lines.join("`, `")
            ));
        }
    }
    let named = match kind {
        toolchain::Kind::Other => "any compiler, since toolchain.kind is other".to_owned(),
        _ => format!("{} {version}", kind.as_str()),
    };
    let mut warnings = Vec::new();
    if !unshown.is_empty() {
        warnings.push(Diagnostic {
            severity: Severity::Warning,
            message: format!(
                "{} of the {read} relocatable object(s) the run's measured builds left were not \
                 held to {named}, and their readings are published as measured. \
                 artifact-compiled-by-another-compiler withholds an object only where its \
                 `.comment` names another compiler. Each object, with the reason: {}",
                unshown.len(),
                unshown.join("; ")
            ),
            context: Some("toolchain".to_owned()),
            rejection: None,
        });
    }
    if !linked.is_empty() {
        warnings.push(Diagnostic {
            severity: Severity::Warning,
            message: format!(
                "{} linked artifact(s) of the run's measured builds name a compiler in \
                 `.comment`, and none names {named}. Their readings are published as measured, \
                 since a linked artifact is not held to a compiler line: its startup objects \
                 add lines of their own. A compile forwarded to another compiler leaves this \
                 shape, and so does a unit compiled under -fno-ident or -Qn. Each artifact, \
                 with its lines: {}",
                linked.len(),
                linked.join("; ")
            ),
            context: Some("toolchain".to_owned()),
            rejection: None,
        });
    }
    warnings
}

/// Hold `toolchain.linker` to the `.comment` of every linked artifact the run built.
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
            "the profile {} resolves to different flags under {target_arch}, the target its flags select, than under {default_arch}, the driver's default",
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
                "the profile {} resolves to different flags under {arch}, the architecture the driver's intrinsic macro dump names, than under {target_arch}, the one the arch gate read",
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
/// file supplies.
fn with_unread_config(mut profile: Profile, failures: &[toolchain::QueryFailure]) -> Profile {
    if failures
        .iter()
        .any(|f| f.context == toolchain::CONFIG_FILES_FIELD)
    {
        let unread = format!(
            "chard read nothing from the driver's `{}`",
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
fn resolve_profile(args: &MeasureArgs, arch: &str, config_files: &[String]) -> Result<Profile> {
    let config_note = || {
        (!config_files.is_empty()).then(|| {
            format!(
                "the driver loaded a configuration file it applies to every invocation ({})",
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
                None => "the compiler's own defaults with optimization enabled and nothing else"
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
            // column join key and two explicit lists are two columns.
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

/// Each relative path argument and input file of `lists`, as [`refusals`] names it, with the
/// reading's note where it has one, such as gcc's reading of clang's own option, the pair a
/// handed path option lacks, or what an input file is opened against
/// ([`compile::relative_path_readings`]).
fn relative_path_refusals(lists: &[(&str, &Vec<String>)]) -> Vec<String> {
    refusals(lists, |words| {
        compile::relative_path_readings(words)
            .into_iter()
            .map(|found| (found.argument, found.reading.note()))
            .collect()
    })
}

/// The lines the driver is handed that join two of `lists`, each with the name a refusal gives
/// it and the two lists it joins: `--flags` then `--ldflags`, which every C build is handed, and
/// `--cxxflags` then `--ldflags`, which a C++ build is handed where `--cxxflags` is given. Each
/// line is [`measure::profile_flags_for`]'s, the function the builds take theirs from. A line of
/// one list, where the other is empty, is that list's own, and not returned.
fn joined_lines<'a>(lists: &[(&str, &'a Vec<String>)]) -> Vec<JoinedLine<'a>> {
    let list = |name: &str| {
        lists
            .iter()
            .find(|(n, _)| *n == name)
            .map_or(&[][..], |(_, l)| l.as_slice())
    };
    let (cflags, cxxflags, ldflags) = (list("--flags"), list("--cxxflags"), list("--ldflags"));
    [
        (probe::Lang::C, cflags, "--flags"),
        (probe::Lang::Cxx, cxxflags, "--cxxflags"),
    ]
    .into_iter()
    .filter(|(_, base, _)| !base.is_empty() && !ldflags.is_empty())
    .map(|(lang, base, name)| JoinedLine {
        name: format!("{name} followed by --ldflags, the one line the driver is handed"),
        parts: [base, ldflags],
        line: measure::profile_flags_for((cflags, cxxflags, ldflags), lang),
    })
    .collect()
}

/// One line [`joined_lines`] returns.
struct JoinedLine<'a> {
    /// The name a refusal gives the line.
    name: String,
    /// The two lists it joins, in their order on it.
    parts: [&'a [String]; 2],
    /// The line, as the builds take it.
    line: Vec<String>,
}

/// What `read` finds in `lists`, as [`refuse_unreadable_flags`] names it: as written and in its
/// list, with its note where it has one. Each list is read on its own, and then each line the
/// driver is handed joined from two of them ([`joined_lines`]); a reading the joined line gives
/// that neither list gives on its own is named in the joined line. The driver reads the joined
/// line, so a word at the end of one list takes the first word of the next as its value: under
/// `--flags "-O2 -Xassembler" --ldflags "--x32"`, read a list at a time, neither list selects
/// x32, while the driver is handed `-Xassembler --x32` (clang 22.1.8 on Fedora 44 x86_64,
/// measured 2026-11-15 UTC; the two words in one list are refused). A reading one list gives
/// is named in that list rather than again in the joined line.
fn refusals(
    lists: &[(&str, &Vec<String>)],
    read: impl Fn(&[String]) -> Vec<(String, Option<String>)>,
) -> Vec<String> {
    let entry = |(arg, note): &(String, Option<String>), name: &str| match note {
        Some(note) => format!("{arg:?} in {name}, {note}"),
        None => format!("{arg:?} in {name}"),
    };
    let mut found: Vec<String> = lists
        .iter()
        .flat_map(|(name, list)| {
            read(list)
                .iter()
                .map(|reading| entry(reading, name))
                .collect::<Vec<_>>()
        })
        .collect();
    for JoinedLine { name, parts, line } in joined_lines(lists) {
        let mut apart: Vec<(String, Option<String>)> =
            parts.iter().flat_map(|part| read(part)).collect();
        for reading in read(&line) {
            if let Some(at) = apart.iter().position(|seen| *seen == reading) {
                apart.swap_remove(at);
                continue;
            }
            let named = entry(&reading, &name);
            if !found.contains(&named) {
                found.push(named);
            }
        }
    }
    found
}

/// Refuse an explicit profile's flag lists where chard cannot read what they hand the
/// driver: a response file first, since a relative `@file` is first of all a file chard
/// cannot read into ([`compile::response_file_arguments`]), then a flag that selects x32,
/// 16-bit or aarch64 ILP32 code ([`toolchain::unsupported_target_flags`]), a flag that
/// removes part of the runtime and leaves its replacement unnamed
/// ([`toolchain::runtime_removing_flags`]), a flag holding U+001F, which
/// `report::flags_sha256` joins a list's flags with, a pair the two drivers read differently
/// ([`toolchain::driver_divided_pairs`]), and a relative path or an input file named by one
/// ([`compile::relative_path_readings`]). Each reader reads every list on its own and then
/// the lines the driver is handed joined from them ([`refusals`] says why both). Called
/// before any of the lists reaches a driver.
///
/// # Errors
///
/// A [`ConfigError`] naming each refused argument and the list it came from.
fn refuse_unreadable_flags(lists: &[(&str, &Vec<String>)]) -> Result<()> {
    let named = |read: fn(&[String]) -> Vec<String>| -> Vec<String> {
        refusals(lists, |words| {
            read(words).into_iter().map(|arg| (arg, None)).collect()
        })
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
            "a relative path in an explicit profile names what the toolchain opens in the \
             directory it runs in: the probe builds run in the work directory, which holds what \
             chard and any earlier run wrote there, and the toolchain interrogation runs where \
             chard was started. chard reads each word as the tool it is handed to reads it, \
             refusing what it cannot read so; give each path as an absolute path, or do as its \
             note says: {}",
            relative.join(", ")
        ))
        .into());
    }
    Ok(())
}

/// Resolve `--probe` ids into the probes to run, and the truncation a narrowed run
/// records.
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
                "pass each --probe once; the selection is a set",
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
/// # Errors
///
/// When the file cannot be read, or does not deserialise into the fetcher's own
/// attestation shape.
fn read_image_attestation(path: Option<&Path>) -> Result<Option<environment::Attestation>> {
    let Some(path) = path else {
        return Ok(None);
    };
    // The io error keeps its kind, so `error::classify` reads it as it does for every other
    // reader of an operator-named file; only bytes that are not UTF-8 are this function's to
    // refuse.
    let reading = || format!("reading the image attestation {}", path.display());
    let kind = std::fs::metadata(path).with_context(reading)?.file_type();
    if !(kind.is_file() || std::os::unix::fs::FileTypeExt::is_fifo(&kind)) {
        return Err(UserError::new(format!(
            "{} is not an image attestation chard can read: it is {}",
            path.display(),
            error::file_type_name(kind)
        ))
        .into());
    }
    let bytes = std::fs::read(path).with_context(reading)?;
    let text = String::from_utf8(bytes).map_err(|e| {
        UserError::new(format!(
            "reading the image attestation {}: {e}",
            path.display()
        ))
    })?;
    // Parsed by the library rather than here, so the refinement has a test: `from_json`
    // refuses a digest that is not hex of the length its own `digest_kind` implies.
    let attestation = environment::Attestation::from_json(&text).map_err(|e| {
        UserError::with_hint(
            format!("parsing the image attestation {}: {e}", path.display()),
            "the file must be the fetcher's provenance object: verdict, url, served_by, manifest_url, digest_kind, digest, digest_matched, signature, and optionally installed_disk {sha256, installed_at, installed_from_digest}.",
        )
    })?;
    Ok(Some(attestation))
}

#[expect(clippy::too_many_lines, reason = "one invocation, read top to bottom.")]
fn measure(args: &MeasureArgs, ending: &mut Ending) -> Result<Closed> {
    let started_at = SystemTime::now();
    let started_utc = report::iso8601_utc(started_at);
    let wall = std::time::Instant::now();

    // The invocation's own arguments first, before anything on disk is touched: a run
    // refused here measured nothing and is not a run, so it leaves the earlier report at
    // `-o` and the work directory as they were.
    let (selected, truncations) = select_probes(&args.probes)?;
    let attestation = read_image_attestation(args.image_attestation.as_deref())?;
    if args.profile == "explicit" {
        explicit_lists(args)?;
    }
    refuse_flags_beside_a_builtin_profile(args)?;
    // The compiler environment's `--env` pairs, refused or fixed before any toolchain runs:
    // `compile::RunEnvironment` makes a set after the first read an error, so no run is
    // measured under one environment early and another later.
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
    // says it replaced one, or where it is kept, only where there was one.
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
    // Absolutized once: probe binaries run with their cwd set to the work directory, where a
    // relative artifact path would resolve against the wrong base.
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
        environment::AttestationRefusal::DigestMismatch(a) => ConfigError(format!(
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
        // attestation describes an image, and this run booted none.
        environment::AttestationRefusal::NoImageToAttest => ConfigError(
            "refusing to measure: --image-attestation was given for a run that booted no image. Pass --execution vm or --execution container, or drop the attestation."
                .to_owned(),
        ),
    })?;
    // The toolchain's own target, not the arch chard's own binary was compiled for: they
    // coincide only for a native build.
    let default_arch = detected
        .target_arch()
        .unwrap_or_else(|| env.kernel.arch.clone());
    let posed = resolve_profile(args, &default_arch, &detected.config_files)?;
    // The two link lines a linker selection in the profile reaches the artifacts through;
    // `Detected::link_with` says why this is a second step and why there are two.
    let (c_link, cxx_link) = link_lines(&posed);
    detected.link_with(&c_link, &cxx_link, &workdir);
    // The target the profile's own flags select, which `-dumpmachine` and the flagless
    // dump cannot see; `toolchain::ProfileMacroWitness` says why.
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
    // The join key is composed here, once, from halves the environment owns, which could only
    // be read through the toolchain's own macro dump; `Detected::qualified` is its only
    // constructor, so no report carries an unqualified key.
    let mut toolchain = detected.qualified(&env.libc.tag(), &env.distro.tag());
    error::note(&format!(
        "{} / {} {} / kernel {}",
        toolchain.id(),
        env.libc.impl_name,
        env.libc.version.clone().unwrap_or_else(|| "?".to_owned()),
        env.kernel.release
    ));
    let mut diagnostics: Vec<Diagnostic> = Vec::new();
    // Every profile is measured through the file, so every report says so; the `bare`
    // profile also names it in `flags_source`, the field a reader of a bare column consults.
    if !toolchain.detected.config_files.is_empty() {
        diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            message: format!(
                "the driver loaded {} configuration file(s) it applies to every invocation: {}",
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
    // The banner held to the dump `kind` and `version` are read from: a program that
    // answers `--version` as one compiler and the macro dump as another is named here,
    // with both fields published as read (`toolchain::banner_disagreement`).
    if let Some(message) = toolchain
        .detected
        .version_raw
        .as_deref()
        .and_then(|banner| {
            toolchain::banner_disagreement(
                banner,
                toolchain.detected.kind,
                &toolchain.detected.version,
            )
        })
    {
        diagnostics.push(Diagnostic {
            severity: Severity::Error,
            message,
            context: Some(toolchain::VERSION_RAW_FIELD.to_owned()),
            rejection: None,
        });
    }

    // The denominator for coverage: the check ids the selection names, as a set,
    // computed before any work happens so a crash mid-sweep cannot quietly shrink it.
    let checks_expected: BTreeSet<String> = selected
        .iter()
        .flat_map(|p| p.checks)
        .map(|c| c.id.to_owned())
        .collect();

    // Sources are written once; every variant compiles the same bytes.
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

    // The run's witness: 128 bits of this run's own, or, under `--normalize`, derived from
    // what the run was asked, so the artifacts and their digests are byte-identical too.
    let witness = if env.distro.is_macos() {
        // Mach-O artifacts, which the ELF reader does not read: no header, no witness.
        None
    } else if args.normalize {
        let asked = compile::WitnessQuestion {
            cflags: &profile.cflags,
            cxxflags: &profile.cxxflags,
            ldflags: &profile.ldflags,
            env: profile.compiler_environment.added().collect(),
            driver: &toolchain.detected.driver,
            version_raw: toolchain.detected.version_raw.as_deref(),
            target_triple: toolchain.detected.target_triple.as_deref(),
            probe_corpus_sha256: &probe::corpus_sha256(),
        };
        Some(compile::RunWitness::derived_in(asked.lines(), &workdir)?)
    } else {
        Some(
            compile::RunWitness::random_in(&workdir)
                .context("drawing the run's witness; `--normalize` needs no random device")?,
        )
    };

    let ctx = Conditions {
        env: &env,
        profile: &profile,
        toolchain_kind: toolchain.detected.kind,
        target_arch: &target_arch,
        profile_is_clean: Conditions::profile_is_clean(&profile),
    };

    // The gate's flag, decided once.
    let structured_format = args
        .structured_diagnostics
        .then(|| chard::structured::format_flag(toolchain.detected.kind))
        .flatten();
    if args.structured_diagnostics && structured_format.is_none() {
        diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            message: format!(
                "--structured-diagnostics: no structured diagnostic format is known for a `{}` toolchain",
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
        witness: witness.as_ref(),
    };

    let mut observations: Vec<Observation> = Vec::new();
    let mut facts = report::FactStore::default();
    let mut listings = BTreeMap::new();
    let mut fact_conflicts: Vec<report::Conflict> = Vec::new();

    for probe in &selected {
        error::note(&format!("probe {}", probe.id));
        let outcome = measure::run_probe(&driver, probe, &ctx);
        observations.extend(outcome.observations);
        if let Some(record) = outcome.listings {
            listings.insert(probe.id.to_owned(), record);
        }
        diagnostics.extend(outcome.diagnostics);
        // One store for the run.
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
    // The compiler lines the rule could not hold, named: the objects that showed no
    // compiler, and the linked artifacts that name another compiler and not the report's.
    diagnostics.extend(compiler_line_warnings(&toolchain, &observations, &facts));
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
    // read the opposite presence is withheld (`report::MACRO_TWINS`).
    let contradicted = report::withhold_contradicted_macros(&mut observations);
    diagnostics.extend(contradicted.diagnostics());
    // Where no twin of such a reading is a measurement in this run, the input clause holds
    // it as it holds a macro check with no twin (`measure::withhold_where_no_twin_measured`).
    diagnostics.extend(measure::withhold_where_no_twin_measured(
        &mut observations,
        &profile,
    ));

    // The ratchet is derived before the rollup, because a non-monotone reading means
    // a probe is faulty and its rungs must not reach the matrix as measurements.
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

    let mut coverage: Coverage = report::coverage(
        &observations,
        &checks_expected,
        probe::total_checks(),
        &profile,
        truncations,
    );
    // The gate's record, over the final observations, so the report says what the gate below
    // excused before anything reads the exit status.
    coverage.gate = args
        .fail_on_missing
        .then(|| report::Gate::of(&observations, args.allow.iter().copied().collect()));

    if !coverage.all_checks_attempted {
        // The message quotes what the flag tests: the corpus total, and the two id lists
        // where either names anything.
        diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            message: format!(
                "coverage incomplete: {} of the corpus's {} checks produced an \
                 observation ({} were asked for by this invocation){}",
                coverage.checks_attempted,
                coverage.corpus_checks_total,
                coverage.checks_expected,
                id_shortfall(&coverage.checks_missing, &coverage.checks_unexpected)
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

    // Reduced over the observations above, not measured: what matters for an umbrella is
    // whether its constituents are in force.
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
            artifact_witness: witness.as_ref().map(report::ArtifactWitness::of),
        },
        environment: env,
        toolchain,
        profile,
        decoders: report::decoders_of(&observations),
        observations,
        facts,
        listings,
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

    // Check the derived layer against the observations it was computed from, before anything
    // is written: the rollups (the ratchet, defect coverage, the composites) are the numbers
    // most likely to be read and the only part of the report nothing else validates.
    let mut report = report;
    // Derived from the measurement rather than the clock, after the observations are
    // final: the ratchet downgrade above moves verdicts, and an id computed earlier would
    // name a set of cells the report does not carry.
    report.run.inputs_sha256 = report::inputs_of(&report).sha256();
    report.run.id = report::run_id(&report.run.inputs_sha256, &report.observations);
    // Before the consistency pass, so what is published is what was checked.
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

    // Both halves, deliberately: gating on `all_checks_attempted` alone would pass a run where
    // every check was handed in and some earned no verdict, an incomplete measurement that
    // looks complete.
    let Some(record) = report.coverage.gate.as_ref() else {
        return Ok(Closed::Published);
    };
    let complete = report.coverage.all_verdicts_published;
    if complete && record.allowed.is_empty() {
        return Ok(Closed::Published);
    }
    let corpus = probe::CORPUS.iter().flat_map(|p| p.checks).map(|c| c.id);
    let shortfalls = report::shortfalls(&report.observations, corpus);
    let (closed, lines) = gate(&report.coverage, record, &shortfalls);
    for line in lines {
        error::note(&line);
    }
    Ok(closed)
}

/// Whether the gate failed on machine limits: every shortfall is an unsettled check a gating
/// rule of [`MACHINE_LIMITS`] or of [`TARGET_LIMITS`] holds, and at least one is a machine
/// limit. Target limits are allowed beside a machine limit because every architecture the
/// mechanism table has a column for leaves some check unread there. Target limits alone, a
/// check not attempted, a held check with no rule, a rule of any other kind and an empty list
/// are not machine-limited: the gate fails with no named shortfall only on a report that
/// contradicts itself, a defect in chard.
fn machine_limited(shortfalls: &[report::Shortfall]) -> bool {
    // Both rule sets publish `indeterminate`, since their premise is a limit of the instrument,
    // and the consistency pass refuses either rule beside another verdict.
    let rule = |shortfall: &report::Shortfall| match shortfall {
        report::Shortfall::Unsettled {
            rule: Some(id),
            verdict: Verdict::Indeterminate,
            ..
        } => Some(*id),
        _ => None,
    };
    let machine = |id: &str| MACHINE_LIMITS.iter().any(|(machine, _)| *machine == id);
    shortfalls.iter().filter_map(rule).any(machine)
        && shortfalls.iter().all(|shortfall| {
            rule(shortfall).is_some_and(|id| machine(id) || TARGET_LIMITS.contains(&id))
        })
}

/// How `--fail-on-missing` ends and the lines it leaves on stderr, after the report, under the
/// allowances `record` carries: the shortfalls an allowance excuses are set apart, and the gate
/// passes exactly when none is left and the report agrees that nothing else is short. The
/// status the last line names is the ending's own ([`Closed::status`]), so the unit tests hold
/// the ending and its lines to one value.
fn gate(
    coverage: &Coverage,
    record: &report::Gate,
    shortfalls: &[report::Shortfall],
) -> (Closed, Vec<String>) {
    let (excused, unsettled): (Vec<&report::Shortfall>, Vec<&report::Shortfall>) = shortfalls
        .iter()
        .partition(|shortfall| record.excuses(shortfall).is_some());
    let passed = unsettled.is_empty() && gate_accounts_for(coverage, excused.len());
    let closed = if passed {
        Closed::GatePassed {
            excused: excused.len(),
        }
    } else {
        Closed::GateFailed {
            unsettled: unsettled.len(),
            excused: excused.len(),
            machine_limited: machine_limited(shortfalls),
        }
    };
    let mut lines = if passed {
        Vec::new()
    } else {
        gate_shortfall_lines(coverage, &unsettled)
    };
    lines.extend(excused_lines(record, &excused));
    let status = closed.status();
    let tail = if passed {
        match excused.len() {
            0 => "every check settled".to_owned(),
            n => format!("every check settled but the {n} excused"),
        }
    } else {
        remedies(&unsettled)
    };
    lines.push(format!(
        "--fail-on-missing: exit {status}, the report written; {tail}"
    ));
    (closed, lines)
}

/// Whether the report's own account of what it lacks is exactly the `excused` checks: the run
/// complete (`all_verdicts_published`), or every corpus check attempted once, no id missing or
/// unexpected, and as many checks withheld as the allowances excused. A report incomplete
/// with no shortfall named disagrees with itself, and is never a pass, whatever was allowed.
fn gate_accounts_for(coverage: &Coverage, excused: usize) -> bool {
    coverage.all_verdicts_published
        || (excused > 0
            && coverage.all_checks_attempted
            && coverage.checks_missing.is_empty()
            && coverage.checks_unexpected.is_empty()
            && coverage.withholding.instrument_withholdings.count == excused)
}

/// The count line, the shortfalls, and where none is named the line that says so.
fn gate_shortfall_lines(coverage: &Coverage, shortfalls: &[&report::Shortfall]) -> Vec<String> {
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
    lines
}

/// One line per excused check, naming the allowance with the reason the report records, then
/// one per allowance that excused nothing, which a reader would otherwise take for one that
/// was not given.
fn excused_lines(record: &report::Gate, excused: &[&report::Shortfall]) -> Vec<String> {
    let mut lines: Vec<String> = excused
        .iter()
        .filter_map(|shortfall| {
            record.excuses(shortfall).map(|allowance| {
                format!(
                    "--fail-on-missing: excused by --allow {}: {shortfall}",
                    allowance.as_str()
                )
            })
        })
        .collect();
    lines.extend(
        record
            .allowed
            .iter()
            .filter(|allowance| !excused.iter().any(|s| allowance.excuses(s)))
            .map(|allowance| {
                format!(
                    "--fail-on-missing: --allow {} excused no check",
                    allowance.as_str()
                )
            }),
    );
    lines
}

/// What a caller can change to settle the gate, for the shortfalls where chard knows: a
/// kernel-policy check withheld because nothing established whose kernel the run's is
/// (`execution-mode-assumed`) or because the run is in a container (`needs-vm`), a check
/// `--probe` left out, and a check the machine the run was handed cannot answer
/// (`MACHINE_LIMITS`). A check chard does not read on the target (`TARGET_LIMITS`) is named as
/// one no run on that target settles. No option of the run is claimed to settle the other
/// reasons, the toolchain's or the instrument's.
fn remedies(shortfalls: &[&report::Shortfall]) -> String {
    use report::gating_rule::{EXECUTION_MODE_ASSUMED, NEEDS_VM};
    let count = |rule: &str| {
        shortfalls
            .iter()
            .filter(
                |s| matches!(s, report::Shortfall::Unsettled { rule: Some(id), .. } if *id == rule),
            )
            .count()
    };
    // A machine or target limit counts only beside `indeterminate`, the shape
    // [`machine_limited`] and `report::Allowance::excuses` read, so the remedy that names
    // another machine or `--allow` names no check either would leave held.
    let held = |rule: &str| {
        shortfalls
            .iter()
            .filter(|s| {
                matches!(s, report::Shortfall::Unsettled {
                    rule: Some(id),
                    verdict: Verdict::Indeterminate,
                    ..
                } if *id == rule)
            })
            .count()
    };
    let not_attempted = shortfalls
        .iter()
        .filter(|s| matches!(s, report::Shortfall::NotAttempted { .. }))
        .count();
    let mut remedies = Vec::new();
    let covered = count(EXECUTION_MODE_ASSUMED.id)
        .saturating_add(count(NEEDS_VM.id))
        .saturating_add(not_attempted)
        .saturating_add(MACHINE_LIMITS.iter().map(|(rule, _)| held(rule)).sum())
        .saturating_add(TARGET_LIMITS.iter().map(|rule| held(rule)).sum());
    match count(EXECUTION_MODE_ASSUMED.id) {
        0 => {}
        n => remedies.push(format!(
            "--execution host or --execution vm, where this run owns the kernel it runs on, lifts gating.rule {} from the {n} {} it holds",
            EXECUTION_MODE_ASSUMED.id,
            plural(n, "check", "checks")
        )),
    }
    match count(NEEDS_VM.id) {
        0 => {}
        n => remedies.push(format!(
            "the {n} {} under gating.rule {} {} measured only outside a container, with --execution saying which",
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
    let machine: Vec<(&str, usize)> = MACHINE_LIMITS
        .iter()
        .map(|(rule, _)| (*rule, held(rule)))
        .filter(|(_, n)| *n > 0)
        .collect();
    if !machine.is_empty() {
        let n: usize = machine.iter().map(|(_, n)| n).sum();
        let needs: Vec<&str> = MACHINE_LIMITS
            .iter()
            .filter(|(rule, _)| machine.iter().any(|(m, _)| m == rule))
            .map(|(_, needs)| *needs)
            .collect();
        let rules: Vec<&str> = machine.iter().map(|(rule, _)| *rule).collect();
        remedies.push(format!(
            "the {n} {} under gating.rule {} {} settled only by a run where the kernel and CPU give the feature (another machine, kernel configuration or VM CPU model): {}",
            plural(n, "check", "checks"),
            rules.join(", "),
            plural(n, "is", "are"),
            needs.join("; ")
        ));
    }
    let target: Vec<(&str, usize)> = TARGET_LIMITS
        .iter()
        .map(|rule| (*rule, held(rule)))
        .filter(|(_, n)| *n > 0)
        .collect();
    if !target.is_empty() {
        remedies.push(target_limit_remedy(&target, !machine.is_empty()));
    }
    match shortfalls.len().saturating_sub(covered) {
        _ if remedies.is_empty() => "no option of this run is known to settle these".to_owned(),
        0 => remedies.join("; "),
        others => format!(
            "{}; no option of this run is known to settle the other {others}",
            remedies.join("; ")
        ),
    }
}

/// The gating rules that withhold a check because the machine the run was handed cannot answer
/// it, each with the machine that can: every `MachineWitness` rule of the instrument class,
/// held by `the_machine_limits_are_the_machine_rules_of_the_instrument_class`. No option of a
/// run moves one; a run where the kernel and CPU give the feature does.
const MACHINE_LIMITS: &[(&str, &str)] = &[
    (
        report::gating_rule::CPU_LACKS_SHADOW_STACK.id,
        "a CPU that enumerates CET shadow stack in CPUID leaf 7",
    ),
    (
        report::gating_rule::MACHINE_LACKS_BTI.id,
        "a machine whose /proc/cpuinfo lists `bti`",
    ),
    (
        report::gating_rule::MACHINE_LACKS_PAC.id,
        "a machine whose /proc/cpuinfo lists `paca`",
    ),
    (
        report::gating_rule::CPU_SHOWS_NO_FPAC.id,
        "a CPU with FEAT_FPAC",
    ),
];

/// The remedy clauses for the shortfalls under [`TARGET_LIMITS`] rules, one per rule with its
/// count: no run on the target settles them. Where a machine limit stands beside them
/// (`beside_machine`), the rerun the machine remedy names leaves these, so its gate still
/// fails with exit 1.
fn target_limit_remedy(target: &[(&str, usize)], beside_machine: bool) -> String {
    let allowance = |rule: &str| {
        report::Allowance::ALL
            .into_iter()
            .find(|allowance| allowance.as_str() == rule)
    };
    target
        .iter()
        .map(|&(rule, n)| {
            let (them, stand) = (
                plural(n, "it", "them"),
                plural(n, "it stands", "they stand"),
            );
            let rerun = if beside_machine {
                format!(
                    ", and the run where the kernel and CPU give every feature named still exits \
                     1 while {stand}"
                )
            } else {
                String::new()
            };
            let excuse = match allowance(rule) {
                Some(allowance) => format!(
                    "; --allow {} excuses {them}, and the report then lists {them} in \
                     coverage.gate.excused",
                    allowance.as_str()
                ),
                None => format!("; no --allow excuses {them}"),
            };
            format!(
                "the {n} {} under gating.rule {rule} {} not read on this target architecture, so \
                 no run on it settles {them}{rerun}{excuse}",
                plural(n, "check", "checks"),
                plural(n, "is", "are"),
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// The gating rules that withhold a check because chard reads nothing of it on the target:
/// every applicability rule of the instrument class with target-architecture evidence, held
/// by `the_target_limits_are_the_target_rules_of_the_instrument_class`. No machine of the
/// target is their remedy, so they stand beside a machine limit in [`machine_limited`]
/// without making exit 4 alone.
const TARGET_LIMITS: &[&str] = &[
    report::gating_rule::NO_CHECK_ON_TARGET.id,
    report::gating_rule::ARCH_OUTSIDE_TABLE.id,
];

/// What the closing line says of a gate that passed under `--allow` or failed, after the exit
/// status; nothing for any other ending.
fn gate_how(closed: &Closed) -> String {
    match closed {
        Closed::GatePassed { excused: 0 } => {
            " (--fail-on-missing: passed, --allow excused no check)".to_owned()
        }
        Closed::GatePassed { excused } => format!(
            " (--fail-on-missing: passed, {excused} {} excused by --allow and still withheld, \
             named above)",
            plural(*excused, "check", "checks"),
        ),
        Closed::GateFailed {
            unsettled,
            excused,
            machine_limited: true,
        } => format!(
            " (--fail-on-missing: {unsettled} {} not settled, each a machine limit or a check \
             unread on this target{}, named above)",
            plural(*unsettled, "check", "checks"),
            excused_clause(*excused),
        ),
        Closed::GateFailed {
            unsettled, excused, ..
        } => format!(
            " (--fail-on-missing: {unsettled} {} not attempted or not settled{}, named above)",
            plural(*unsettled, "check", "checks"),
            excused_clause(*excused),
        ),
        _ => String::new(),
    }
}

/// The closing line's count of the checks `--allow` excused beside a failed gate, where there
/// are any.
fn excused_clause(excused: usize) -> String {
    match excused {
        0 => String::new(),
        n => format!(", and {n} excused by --allow"),
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
    /// The report was published and `--fail-on-missing` passed, `excused` checks excused by
    /// `--allow`: exit 0. A gate that passed with no allowance is [`Closed::Published`].
    GatePassed { excused: usize },
    /// The report was published and `--fail-on-missing` named `unsettled` checks beside
    /// `excused` ones: exit 1, or exit 4 where `machine_limited` ([`machine_limited`] holds).
    GateFailed {
        unsettled: usize,
        excused: usize,
        machine_limited: bool,
    },
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

impl Closed {
    /// The exit status this ending makes, which [`measure_command`] exits with and the
    /// closing line and [`gate`]'s last line name. `tests/exit_statuses.rs` holds the
    /// emitters of the three endings with an envelope to these constants.
    const fn status(&self) -> u8 {
        match self {
            Self::Published | Self::GatePassed { .. } => error::EXIT_OK,
            Self::GateFailed {
                machine_limited: true,
                ..
            } => error::EXIT_MACHINE_LIMIT,
            Self::GateFailed { .. } => error::EXIT_GATE,
            Self::Contradicted { .. } => error::EXIT_CONTRADICTION,
            Self::DeclarationContradicted { .. } | Self::Failed(_) => error::EXIT_FAILURE,
        }
    }
}

/// Where a run's report goes, once the set-aside has decided it.
#[derive(Default)]
enum Target {
    /// Not yet decided: the run was refused before the set-aside, so it moved no earlier
    /// report and built nothing.
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
/// takes passes through here, so a caller reading only the tail of stderr learns how the run
/// ended. A panic on the main thread closes with a line of its own ([`close_a_panic`]); a run
/// that is killed closes with none.
fn measure_command(args: &MeasureArgs) -> ExitCode {
    close_a_panic();
    let mut ending = Ending::default();
    let closed = measure(args, &mut ending).unwrap_or_else(Closed::Failed);
    // The status is the ending's own, `Closed::status`; an ending with an envelope makes its
    // code from the emitter that writes it, which returns that same status
    // (`tests/exit_statuses.rs` holds both).
    let code = match &closed {
        Closed::Published | Closed::GatePassed { .. } | Closed::GateFailed { .. } => {
            ExitCode::from(closed.status())
        }
        Closed::Contradicted {
            contradictions,
            quarantine,
        } => error::emit_contradiction(*contradictions, quarantine.as_deref()),
        Closed::DeclarationContradicted {
            execution,
            quarantine,
        } => error::emit_declaration_contradicted(execution, quarantine.as_deref()),
        Closed::Failed(err) => error::emit("measure", err),
    };
    error::note(&closing_line(&closed, closed.status(), &ending));
    code
}

/// The status Rust's runtime exits with after a panic on the main thread.
const PANIC_STATUS: u8 = 101;

/// Install a panic hook that writes `measure`'s closing line after the panic's own message,
/// for a panic on the main thread, which ends the process with exit 101; a panic on another
/// thread (the pipe readers of `compile::run`) is joined and reported as that run's failure.
fn close_a_panic() {
    let report = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        report(info);
        if std::thread::current().name() == Some("main") {
            error::note(&format!(
                "measure exits {PANIC_STATUS}: chard panicked, a defect in chard"
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
                "measure exits {status}{how}: sent the report to {destination}{counts}{workdir}"
            ),
            Target::Stdout => {
                format!("measure exits {status}{how}: sent the report to stdout{counts}{workdir}")
            }
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
        Closed::GatePassed { .. } | Closed::GateFailed { .. } => published(&gate_how(closed)),
        Closed::Contradicted {
            contradictions,
            quarantine,
        } => {
            let kept = quarantine.as_ref().map_or_else(
                || {
                    format!(
                        "kept it nowhere{workdir}; next: re-run with -o FILE to keep it as FILE{}",
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
                "measure exits {status}: the declared --execution is contradicted by what chard observed, so the report was not published; {kept}{workdir}"
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
        Target::Undecided => "refused before the run started".to_owned(),
        Target::Stdout => format!("no whole report is known to have reached stdout{workdir}"),
        Target::File(destination @ report::Destination::Stream(_)) => {
            format!("no whole report is known to have reached {destination}{workdir}")
        }
        // A file there now, not empty, is what this run wrote before it failed: the set-aside
        // moved or emptied an earlier one.
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
    format!("measure exits {status}: refused or failed, the envelope on stdout says why; {left}")
}

/// `path` as one word of a command the closing line suggests: a relative path that starts
/// with `-` gets `./`, so the command does not read it as an option.
fn command_word(path: &Path) -> String {
    let text = path.to_string_lossy();
    if text.starts_with('-') {
        toolchain::shell_word(&format!("./{text}"))
    } else {
        toolchain::shell_word(&text)
    }
}

/// The ids the coverage warning names beside its counts: the selection's ids no observation
/// carries and the observations' ids the selection never named, which keep
/// `all_checks_attempted` false where the counts alone would agree.
fn id_shortfall(missing: &[String], unexpected: &[String]) -> String {
    let mut out = String::new();
    if !missing.is_empty() {
        out.push_str("; missing: ");
        out.push_str(&missing.join(", "));
    }
    if !unexpected.is_empty() {
        out.push_str("; never asked for: ");
        out.push_str(&unexpected.join(", "));
    }
    out
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn the_coverage_warning_names_the_ids_the_counts_hide() {
        assert_eq!(id_shortfall(&[], &[]), "");
        let ids = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<String>>();
        assert_eq!(
            id_shortfall(&ids(&["b"]), &ids(&["c", "d"])),
            "; missing: b; never asked for: c, d"
        );
        assert_eq!(id_shortfall(&ids(&["b"]), &[]), "; missing: b");
        assert_eq!(id_shortfall(&[], &ids(&["c"])), "; never asked for: c");
    }

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
        // The rest is no divided pair, and each is refused as a relative path instead: gcc
        // reads the word as `-isystem` or `-include` joined to a relative path.
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

    #[test]
    fn a_relative_path_refusal_names_how_it_read_each_argument() {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let words =
            line("-O2 -Xpreprocessor -I -Xpreprocessor rel -isystem-after/srv/i -Xlinker -L -O1");
        let err = refuse_unreadable_flags(&[("--ldflags", &words)]).expect_err("refused");
        let text = format!("{err:#}");
        for named in [
            "\"-Xpreprocessor -I -Xpreprocessor rel\" in --ldflags",
            "\"-isystem-after/srv/i\" in --ldflags",
            "\"-Xlinker -L\" in --ldflags",
        ] {
            assert!(text.contains(named), "{named} is not in: {text}");
        }
        assert!(!text.contains("  "), "a run of spaces: {text}");
        let passed = line("-O2 -Xpreprocessor -I -Xpreprocessor /srv/i -I- -Xlinker -Bsymbolic");
        assert!(refuse_unreadable_flags(&[("--flags", &passed)]).is_ok());
    }

    #[test]
    fn an_input_file_named_by_a_relative_path_is_refused() {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let cases = [
            ("--flags", "foo.c"),
            ("--cxxflags", "./foo.o"),
            ("--ldflags", "libfoo.a"),
        ];
        let mut fed = 0_usize;
        for (list, word) in cases {
            let words = line(&format!("-O2 {word}"));
            let err = refuse_unreadable_flags(&[(list, &words)]).expect_err("refused");
            let text = format!("{err:#}");
            assert!(
                err.downcast_ref::<ConfigError>().is_some()
                    && text.contains(&format!("{word:?} in {list}")),
                "{list} {word}: {text}"
            );
            fed = fed.saturating_add(1);
        }
        assert_eq!(fed, cases.len(), "every list was fed an input");
        for pair in [
            "-Ttext 0x8000",
            "-dumpbase foo.c",
            "-undefined dynamic_lookup",
        ] {
            let err = refuse_unreadable_flags(&[("--ldflags", &line(&format!("-O2 {pair}")))])
                .expect_err("refused");
            let text = format!("{err:#}");
            assert!(
                text.contains(&format!("{pair:?} in --ldflags")),
                "{pair}: {text}"
            );
        }
        let absolute = line("-O2 /srv/src/foo.c /srv/obj/foo.o /srv/lib/libfoo.a");
        for list in ["--flags", "--cxxflags", "--ldflags"] {
            assert!(
                refuse_unreadable_flags(&[(list, &absolute)]).is_ok(),
                "{list}"
            );
        }
    }

    #[test]
    fn no_builtin_profiles_lists_are_refused_as_an_explicit_profiles() {
        use clap::CommandFactory as _;
        let command = MeasureArgs::command();
        let profiles: Vec<String> = command
            .get_arguments()
            .find(|arg| arg.get_id() == "profile")
            .expect("measure takes --profile")
            .get_possible_values()
            .iter()
            .map(|value| value.get_name().to_owned())
            .filter(|name| name != "explicit")
            .collect();
        assert!(profiles.len() >= 3, "{profiles:?}");
        let arches: BTreeSet<&str> = chard::guide::INVENTORY
            .iter()
            .filter_map(|row| match row.carried {
                chard::guide::Carried::Arch(arches) => Some(arches),
                _ => None,
            })
            .flatten()
            .copied()
            .chain(["x86"])
            .collect();
        let mut fed = 0_usize;
        for arch in &arches {
            for name in &profiles {
                let args = MeasureArgs::try_parse_from(["chard", "--profile", name.as_str()])
                    .expect("the CLI parses the profile");
                let profile = resolve_profile(&args, arch, &[]).expect("a built-in profile");
                assert!(
                    refuse_unreadable_flags(&[
                        ("--flags", &profile.cflags),
                        ("--cxxflags", &profile.cxxflags),
                        ("--ldflags", &profile.ldflags),
                    ])
                    .is_ok(),
                    "{name} on {arch}: {:?}",
                    profile.cflags
                );
                fed = fed.saturating_add(1);
            }
        }
        assert!(
            arches.contains("x86_64") && arches.contains("aarch64"),
            "{arches:?}"
        );
        assert_eq!(fed, arches.len() * profiles.len(), "every profile was fed");
    }

    #[test]
    fn a_refusal_reads_the_line_the_driver_is_handed() {
        let line = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let x32 = "chard does not measure x32";
        let refused = [
            ("--flags", "-O2 -Xassembler", "--x32", x32),
            ("--cxxflags", "-O2 -Xassembler", "-x32", x32),
            ("--flags", "-O2 -target", "x86_64-pc-linux-gnux32", x32),
            ("--cxxflags", "-O2 --machine", "x32", x32),
        ];
        let mut fed = 0_usize;
        for (list, head, tail, why) in refused {
            let (head_words, tail_words) = (line(head), line(tail));
            let other = line("-O2");
            let lists: Vec<(&str, &Vec<String>)> = if list == "--flags" {
                vec![("--flags", &head_words), ("--ldflags", &tail_words)]
            } else {
                vec![
                    ("--flags", &other),
                    ("--cxxflags", &head_words),
                    ("--ldflags", &tail_words),
                ]
            };
            let err = refuse_unreadable_flags(&lists).expect_err("refused");
            let text = format!("{err:#}");
            assert!(
                err.downcast_ref::<ConfigError>().is_some()
                    && text.contains(why)
                    && text.contains(&format!(
                        "{tail:?} in {list} followed by --ldflags, the one line the driver is \
                         handed"
                    )),
                "{list} {head:?} --ldflags {tail:?}: {text}"
            );
            fed = fed.saturating_add(1);
        }
        assert_eq!(fed, refused.len(), "every split was fed");
        let (head_words, tail_words) = (line("-O2 -Xassembler"), line("--x32"));
        assert!(
            refuse_unreadable_flags(&[("--flags", &head_words), ("--cxxflags", &tail_words)])
                .is_ok(),
            "--flags and --cxxflags are never handed to one driver as one line"
        );
        let (cflags, ldflags) = (line("-O2 -fPIE"), line("-pie -Wl,-z,now"));
        assert!(refuse_unreadable_flags(&[("--flags", &cflags), ("--ldflags", &ldflags)]).is_ok());
        // A reading one list gives is named in that list and not again in the joined line,
        // which repeats it; a reading only the joined line gives is named there.
        for (cflags, ldflags, named, joined) in [
            ("-O2 -I inc", "-pie", "\"-I inc\" in --flags", false),
            (
                "-O2 -I",
                "inc",
                "\"-I inc\" in --flags followed by --ldflags",
                true,
            ),
            (
                "-O2 -I inc -I",
                "inc",
                "\"-I inc\" in --flags followed by --ldflags",
                true,
            ),
        ] {
            let (cflags, ldflags) = (line(cflags), line(ldflags));
            let text = format!(
                "{:#}",
                refuse_unreadable_flags(&[("--flags", &cflags), ("--ldflags", &ldflags)])
                    .expect_err("a relative -I is refused")
            );
            assert!(
                text.contains(named) && text.contains("followed by") == joined,
                "{cflags:?} {ldflags:?}: {text}"
            );
        }
    }

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
        while let Some((before, rest)) = line.split_once("${") {
            let (inner, after) = rest.split_once('}').expect("a closed ${");
            let default = inner.split_once(":-").map_or("", |(_, d)| d);
            line = format!("{before}{default}{after}");
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

    #[test]
    fn the_readers_selection_is_the_one_measure_resolves() {
        let corpus_ids = |probes: &[&'static Probe]| -> BTreeSet<&'static str> {
            probes.iter().flat_map(|p| p.checks).map(|c| c.id).collect()
        };
        let many = probe::CORPUS
            .iter()
            .find(|p| p.checks.len() > 1)
            .expect("a probe of several checks")
            .id;
        let one = probe::CORPUS
            .iter()
            .find(|p| p.checks.len() == 1)
            .expect("a probe of one check")
            .id;
        let joined = format!("--probe={one}");
        let cases: [&[&str]; 12] = [
            &["chard", "measure"],
            &["chard", "measure", "--probe", many],
            &["chard", "measure", "--probe", many, &joined],
            &["chard", "measure", "--flags", "--probe", "--probe", one],
            &["chard", "measure", "--probe", one, "--"],
            &["chard", "measure", "--probe", one, "--probe", one],
            &["chard", "measure", "--probe", "no-such-probe"],
            &["chard", "measure", "--probe"],
            &["chard", "measure", "--", "--probe", one],
            &["chard", "measure", "--probe="],
            &["chard", "measure", "stray"],
            &["chard", "measure", "--prob", one],
        ];
        let mut agreed = 0;
        for words in cases {
            let argv: Vec<String> = words.iter().map(|w| (*w).to_owned()).collect();
            let measured = match Cli::try_parse_from(&argv).map(|cli| cli.command) {
                Ok(Command::Measure(args)) => match select_probes(&args.probes) {
                    Ok((probes, _)) => Some(corpus_ids(&probes)),
                    Err(_) => None,
                },
                Ok(_) => panic!("{words:?} parsed as another command"),
                Err(_) => None,
            };
            match (report::selected_checks(&argv), measured) {
                (Ok(read), Some(measured)) => assert_eq!(read, measured, "{words:?}"),
                (Err(_), None) => {}
                (read, measured) => {
                    panic!("{words:?}: the reader read {read:?}, measure {measured:?}")
                }
            }
            agreed += 1;
        }
        assert_eq!(agreed, cases.len(), "every argv compared");
    }

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
        let line = contradicted(Some("r.json.contradicted"));
        assert!(
            line.starts_with("measure exits 3")
                && line.contains("2 places")
                && line.contains("kept it as r.json.contradicted")
                && line.contains(counts),
            "{line}"
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
        let line = closing_line(
            &Closed::DeclarationContradicted {
                execution: Box::new(execution),
                quarantine: Some(PathBuf::from("r.json.contradicted")),
            },
            error::EXIT_FAILURE,
            &ending,
        );
        assert!(
            line.starts_with("measure exits 2") && line.contains("r.json.contradicted"),
            "{line}"
        );
    }

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
        assert!(!machine_limited(&one));
        coverage.checks_expected = 3;
        let two = [
            report::Shortfall::NotAttempted {
                check: "pie".to_owned(),
            },
            report::Shortfall::NotAttempted {
                check: "relro".to_owned(),
            },
        ];
        let lines = gate(&coverage, &strict(), &two).1;
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
        let none = gate(&coverage, &strict(), &[]).1;
        assert_eq!(none.len(), 3, "{none:?}");
        assert!(
            none.get(1).is_some_and(|l| l.contains("no check is named")),
            "{none:?}"
        );
        assert!(
            !gate(&coverage, &strict(), &two)
                .1
                .iter()
                .any(|l| l.contains("no check is named")),
            "the fallback is written only where nothing is named"
        );
    }

    #[test]
    fn the_gate_exits_4_on_machine_limits_beside_target_limits_alone() {
        use report::gating_rule::{
            ARCH_OUTSIDE_TABLE, CPU_LACKS_SHADOW_STACK, CPU_SHOWS_NO_FPAC, MACHINE_LACKS_BTI,
            MACHINE_LACKS_PAC, NO_CHECK_ON_TARGET,
        };
        let total = probe::total_checks();
        let mut coverage =
            report::coverage(&[], &BTreeSet::new(), total, &profile("bare"), Vec::new());
        coverage.checks_expected = total;
        let held = |check: &str, rule: &'static str| report::Shortfall::Unsettled {
            check: check.to_owned(),
            verdict: Verdict::Indeterminate,
            withheld: None,
            rule: Some(rule),
            reason: None,
        };
        let status =
            |shortfalls: &[report::Shortfall]| gate(&coverage, &strict(), shortfalls).0.status();
        // An aarch64 machine whose kernel gives neither BTI nor PAC, where every other check
        // settles: the two machine limits beside the two checks the mechanism table leaves
        // unread on aarch64.
        let a1 = [
            held("bti-enforced", MACHINE_LACKS_BTI.id),
            held("linker-default-noexecstack", NO_CHECK_ON_TARGET.id),
            held("pac-ret-enforced", MACHINE_LACKS_PAC.id),
            held("shadow-stack-enforced", NO_CHECK_ON_TARGET.id),
        ];
        assert_eq!(status(&a1), error::EXIT_MACHINE_LIMIT);
        assert!(
            matches!(
                gate(&coverage, &strict(), &a1).0,
                Closed::GateFailed {
                    unsettled: 4,
                    excused: 0,
                    machine_limited: true
                }
            ),
            "the ending counts every shortfall it names"
        );
        // Every machine rule alone, and each beside a target outside the table.
        let machine = [
            held("shadow-stack-enforced", CPU_LACKS_SHADOW_STACK.id),
            held("bti-enforced", MACHINE_LACKS_BTI.id),
            held("pac-ret-enforced", MACHINE_LACKS_PAC.id),
            held("pac-ret-enforced", CPU_SHOWS_NO_FPAC.id),
        ];
        assert_eq!(status(&machine), error::EXIT_MACHINE_LIMIT);
        for (rule, _) in MACHINE_LIMITS {
            let pair = [held("x", rule), held("y", ARCH_OUTSIDE_TABLE.id)];
            assert_eq!(status(&pair), error::EXIT_MACHINE_LIMIT, "{rule}");
        }
        // Target limits alone keep exit 1: no machine settles them, and the line says so
        // without a rerun clause.
        let target = [
            held("bti-enforced", NO_CHECK_ON_TARGET.id),
            held("pac-ret-enforced", NO_CHECK_ON_TARGET.id),
        ];
        assert_eq!(status(&target), error::EXIT_GATE);
        assert_eq!(
            gate(&coverage, &strict(), &target)
                .1
                .last()
                .map(String::as_str),
            Some(
                "--fail-on-missing: exit 1, the report written; the 2 checks under gating.rule \
                 no-check-on-target are not read on this target architecture, so no run on it \
                 settles them; --allow no-check-on-target excuses them, and the report then \
                 lists them in coverage.gate.excused"
            )
        );
        assert_eq!(
            status(&[held("x", ARCH_OUTSIDE_TABLE.id)]),
            error::EXIT_GATE
        );
    }

    #[test]
    fn the_gate_keeps_1_for_any_other_shortfall() {
        use report::gating_rule::{MACHINE_LACKS_BTI, MACHINE_LACKS_PAC, NO_CHECK_ON_TARGET};
        let total = probe::total_checks();
        let mut coverage =
            report::coverage(&[], &BTreeSet::new(), total, &profile("bare"), Vec::new());
        coverage.checks_expected = total;
        let held = |check: &str, rule: &'static str| report::Shortfall::Unsettled {
            check: check.to_owned(),
            verdict: Verdict::Indeterminate,
            withheld: None,
            rule: Some(rule),
            reason: None,
        };
        let status =
            |shortfalls: &[report::Shortfall]| gate(&coverage, &strict(), shortfalls).0.status();
        let a1 = [
            held("bti-enforced", MACHINE_LACKS_BTI.id),
            held("linker-default-noexecstack", NO_CHECK_ON_TARGET.id),
            held("pac-ret-enforced", MACHINE_LACKS_PAC.id),
            held("shadow-stack-enforced", NO_CHECK_ON_TARGET.id),
        ];
        assert_eq!(status(&a1), error::EXIT_MACHINE_LIMIT);
        let no_rule = report::Shortfall::Unsettled {
            check: "ssp-level".to_owned(),
            verdict: Verdict::Indeterminate,
            withheld: None,
            rule: None,
            reason: None,
        };
        let not_attempted = report::Shortfall::NotAttempted {
            check: "pie".to_owned(),
        };
        for other in [
            held("ssp-level", "flag-unknown-to-driver"),
            held("ssp-level", "execution-mode-assumed"),
            no_rule,
            not_attempted,
        ] {
            let mut mixed = a1.to_vec();
            mixed.push(other.clone());
            assert_eq!(status(&mixed), error::EXIT_GATE, "{other}");
            assert_eq!(
                status(std::slice::from_ref(&other)),
                error::EXIT_GATE,
                "{other}"
            );
        }
        // A machine rule beside a verdict other than `indeterminate`, which the consistency
        // pass refuses, keeps 1 too.
        let probe_invalid = report::Shortfall::Unsettled {
            check: "bti-enforced".to_owned(),
            verdict: Verdict::ProbeInvalid,
            withheld: None,
            rule: Some(MACHINE_LACKS_BTI.id),
            reason: None,
        };
        assert_eq!(status(&[probe_invalid]), error::EXIT_GATE);
        // No shortfall at all (the gate's own inconsistency fallback) is chard's defect, not
        // a machine limit.
        assert_eq!(status(&[]), error::EXIT_GATE);
    }

    #[test]
    fn each_ending_has_the_status_measure_command_exits_with() {
        let gate = |machine_limited| Closed::GateFailed {
            unsettled: 4,
            excused: 0,
            machine_limited,
        };
        let execution = environment::Execution {
            mode: environment::ExecutionMode::Host,
            engine: None,
            image: None,
            detection: "fixture".to_owned(),
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
        let endings = [
            (Closed::Published, error::EXIT_OK),
            (gate(false), error::EXIT_GATE),
            (gate(true), error::EXIT_MACHINE_LIMIT),
            (
                Closed::Contradicted {
                    contradictions: 1,
                    quarantine: None,
                },
                error::EXIT_CONTRADICTION,
            ),
            (
                Closed::DeclarationContradicted {
                    execution: Box::new(execution),
                    quarantine: None,
                },
                error::EXIT_FAILURE,
            ),
            (
                Closed::Failed(std::io::Error::other("fixture").into()),
                error::EXIT_FAILURE,
            ),
        ];
        for (closed, want) in &endings {
            assert_eq!(closed.status(), *want);
        }
    }

    #[test]
    fn the_target_limits_are_the_target_rules_of_the_instrument_class() {
        use report::gating_rule::{ALL, Evidence, Premise, Stage};
        let class: Vec<&str> = ALL
            .iter()
            .filter(|r| {
                r.evidence == Evidence::TargetArch
                    && r.premise == Premise::InstrumentLimitation
                    && r.stage == Stage::Applicability
            })
            .map(|r| r.id)
            .collect();
        assert_eq!(TARGET_LIMITS, class);
    }

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
        for rule in [EXECUTION_MODE_ASSUMED.id, NEEDS_VM.id] {
            let line = remedies(&refs(&[held("x", rule)]));
            assert!(
                line.contains(&format!("gating.rule {rule}")),
                "{rule}: {line}"
            );
        }
        for (rule, _) in MACHINE_LIMITS {
            let line = remedies(&refs(&[held("x", rule)]));
            assert!(
                line.contains(&format!("gating.rule {rule}")),
                "{rule}: {line}"
            );
        }
    }

    #[test]
    fn the_machine_limits_are_the_machine_rules_of_the_instrument_class() {
        use report::gating_rule::{ALL, Evidence, Premise};
        let class: Vec<&str> = ALL
            .iter()
            .filter(|r| {
                r.evidence == Evidence::MachineWitness && r.premise == Premise::InstrumentLimitation
            })
            .map(|r| r.id)
            .collect();
        let listed: Vec<&str> = MACHINE_LIMITS.iter().map(|(rule, _)| *rule).collect();
        assert_eq!(listed, class);
    }

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
        std::fs::remove_dir_all(&dir).expect("removing the scratch directory");
    }

    /// A coverage block of a whole run whose completeness field is false, as the gate's unit
    /// tests hand it the shortfalls.
    fn gate_coverage() -> Coverage {
        let total = probe::total_checks();
        let mut coverage =
            report::coverage(&[], &BTreeSet::new(), total, &profile("bare"), Vec::new());
        coverage.checks_expected = total;
        coverage
    }

    /// The coverage block a report whose only shortfalls are `shortfalls` carries, as the gate
    /// reads it: every check attempted unless one is not, one withheld per unsettled shortfall,
    /// and complete where there are none.
    fn over(shortfalls: &[report::Shortfall]) -> Coverage {
        let mut coverage = gate_coverage();
        coverage.all_checks_attempted = !shortfalls
            .iter()
            .any(|s| matches!(s, report::Shortfall::NotAttempted { .. }));
        coverage.withholding.instrument_withholdings.count = shortfalls
            .iter()
            .filter(|s| matches!(s, report::Shortfall::Unsettled { .. }))
            .count();
        coverage.all_verdicts_published = shortfalls.is_empty();
        coverage
    }

    /// A check withheld `indeterminate` under `rule`.
    fn held(check: &str, rule: &'static str) -> report::Shortfall {
        report::Shortfall::Unsettled {
            check: check.to_owned(),
            verdict: Verdict::Indeterminate,
            withheld: None,
            rule: Some(rule),
            reason: None,
        }
    }

    /// The record of a gate run without `--allow`.
    fn strict() -> report::Gate {
        report::Gate::of(&[], BTreeSet::new())
    }

    /// The record of a gate run under every allowance, which excused `excused`.
    fn allowing(excused: &[report::Shortfall]) -> report::Gate {
        let allowed: BTreeSet<report::Allowance> = report::Allowance::ALL.into_iter().collect();
        report::Gate {
            excused: excused
                .iter()
                .filter_map(|shortfall| {
                    allowed
                        .iter()
                        .find(|a| a.excuses(shortfall))
                        .map(|a| report::Excused {
                            check: shortfall.check().to_owned(),
                            rule: *a,
                        })
                })
                .collect(),
            allowed,
        }
    }

    /// The shortfalls as the gate hands them to [`remedies`].
    fn refs(shortfalls: &[report::Shortfall]) -> Vec<&report::Shortfall> {
        shortfalls.iter().collect()
    }

    #[test]
    fn the_allowance_excuses_no_check_on_target_and_nothing_else() {
        use report::gating_rule::{ARCH_OUTSIDE_TABLE, NO_CHECK_ON_TARGET};
        let option = "--allow no-check-on-target excuses";
        // x86_64 (gcc 16.2.1, Fedora 44, openssf-tldr, --execution host) and aarch64: the
        // checks the mechanism table leaves unread on each.
        let x86_64 = vec![held("bti-enforced", NO_CHECK_ON_TARGET.id)];
        let aarch64 = vec![
            held("linker-default-noexecstack", NO_CHECK_ON_TARGET.id),
            held("shadow-stack-enforced", NO_CHECK_ON_TARGET.id),
        ];
        for shape in [&x86_64, &aarch64] {
            let (closed, lines) = gate(&over(shape), &strict(), shape);
            assert_eq!(closed.status(), error::EXIT_GATE, "{lines:?}");
            let last = lines.last().expect("a last line");
            assert!(last.contains(option), "{last}");
            let (closed, lines) = gate(&over(shape), &allowing(shape), shape);
            assert!(
                matches!(closed, Closed::GatePassed { excused } if excused == shape.len()),
                "{lines:?}"
            );
            assert_eq!(closed.status(), error::EXIT_OK);
            assert_eq!(lines.len(), shape.len() + 1, "{lines:?}");
            for (line, shortfall) in lines.iter().zip(shape.iter()) {
                assert_eq!(
                    *line,
                    format!(
                        "--fail-on-missing: excused by --allow no-check-on-target: {shortfall}"
                    )
                );
            }
        }
        // A target outside the table: no allowance, so 1 either way, and the line says so.
        let outside = [
            held("bti-enforced", ARCH_OUTSIDE_TABLE.id),
            held("cet-marked", ARCH_OUTSIDE_TABLE.id),
        ];
        for record in [strict(), allowing(&outside)] {
            let (closed, lines) = gate(&over(&outside), &record, &outside);
            assert_eq!(closed.status(), error::EXIT_GATE, "{lines:?}");
            assert!(
                record.excused.is_empty(),
                "a gate that closes excuses nothing: {:?}",
                record.excused
            );
            assert!(
                lines
                    .last()
                    .is_some_and(|l| l.contains("no --allow excuses them") && !l.contains(option)),
                "{lines:?}"
            );
        }
    }

    #[test]
    fn the_allowance_keeps_1_for_any_other_shortfall() {
        use report::gating_rule::{FRAME_REUSE_DID_NOT_HOLD, NO_CHECK_ON_TARGET};
        let coverage = gate_coverage();
        let option = "--allow no-check-on-target excuses";
        let x86_64 = vec![held("bti-enforced", NO_CHECK_ON_TARGET.id)];
        let probe_invalid = report::Shortfall::Unsettled {
            check: "no-delete-null-pointer-checks".to_owned(),
            verdict: Verdict::ProbeInvalid,
            withheld: Some(report::WithheldBecause::NegativeAlsoShows),
            rule: None,
            reason: None,
        };
        let not_attempted = report::Shortfall::NotAttempted {
            check: "pie".to_owned(),
        };
        let unearned = report::Shortfall::Unsettled {
            check: "cet-marked".to_owned(),
            verdict: Verdict::ProbeInvalid,
            withheld: None,
            rule: Some(NO_CHECK_ON_TARGET.id),
            reason: None,
        };
        for other in [
            held("zero-init-padding-bits", FRAME_REUSE_DID_NOT_HOLD.id),
            probe_invalid,
            not_attempted,
            unearned,
        ] {
            let mut shape = x86_64.clone();
            shape.push(other.clone());
            let record = allowing(&shape);
            assert_eq!(record.excused.len(), 1, "{other}");
            let (closed, lines) = gate(&over(&shape), &record, &shape);
            assert!(
                matches!(
                    closed,
                    Closed::GateFailed {
                        unsettled: 1,
                        excused: 1,
                        machine_limited: false
                    }
                ),
                "{other}"
            );
            assert_eq!(closed.status(), error::EXIT_GATE, "{other}");
            assert!(
                lines
                    .first()
                    .is_some_and(|l| l.contains("1 of the corpus's")),
                "{lines:?}"
            );
            assert!(
                lines.contains(&format!("--fail-on-missing: {other}")),
                "{lines:?}"
            );
            assert!(
                lines.iter().any(|l| l.starts_with(
                    "--fail-on-missing: excused by --allow no-check-on-target: bti-enforced"
                )),
                "{lines:?}"
            );
            assert!(
                lines.last().is_some_and(|l| !l.contains(option)),
                "nothing left is the allowance's: {lines:?}"
            );
        }
        let mut complete = coverage.clone();
        complete.all_verdicts_published = true;
        let (closed, _) = gate(&complete, &allowing(&[]), &[]);
        assert!(matches!(closed, Closed::GatePassed { excused: 0 }));
        let other = [held("ssp-level", "flag-unknown-to-driver")];
        let (closed, _) = gate(&over(&other), &allowing(&other), &other);
        assert_eq!(closed.status(), error::EXIT_GATE);
        // The report disagreeing with itself (no shortfall, completeness false) is no pass.
        let (closed, lines) = gate(&coverage, &allowing(&[]), &[]);
        assert_eq!(closed.status(), error::EXIT_GATE, "{lines:?}");
        assert!(
            lines.iter().any(|l| l.contains("no check is named")),
            "{lines:?}"
        );
    }

    #[test]
    fn an_excused_check_never_stands_in_for_another_cause() {
        use report::gating_rule::NO_CHECK_ON_TARGET;
        let x86_64 = vec![held("bti-enforced", NO_CHECK_ON_TARGET.id)];
        let excused = allowing(&x86_64);
        let mut unexpected = over(&x86_64);
        unexpected.checks_unexpected = vec!["no-such-check".to_owned()];
        let mut missing = over(&x86_64);
        missing.checks_missing = vec!["pie".to_owned()];
        let mut unattempted = over(&x86_64);
        unattempted.all_checks_attempted = false;
        let mut withheld = over(&x86_64);
        withheld.withholding.instrument_withholdings.count = 2;
        assert!(matches!(
            gate(&over(&x86_64), &excused, &x86_64).0,
            Closed::GatePassed { excused: 1 }
        ));
        for (name, coverage) in [
            ("unexpected", unexpected),
            ("missing", missing),
            ("unattempted", unattempted),
            ("withheld", withheld),
        ] {
            let (closed, lines) = gate(&coverage, &excused, &x86_64);
            assert_eq!(closed.status(), error::EXIT_GATE, "{name}: {lines:?}");
            assert!(
                lines.iter().any(|l| l.contains("no check is named")),
                "{name}: {lines:?}"
            );
        }
    }

    #[test]
    fn no_allowance_moves_exit_4() {
        use report::gating_rule::{
            ARCH_OUTSIDE_TABLE, FRAME_REUSE_DID_NOT_HOLD, MACHINE_LACKS_BTI, MACHINE_LACKS_PAC,
            NO_CHECK_ON_TARGET,
        };
        let total = probe::total_checks();
        let mut coverage =
            report::coverage(&[], &BTreeSet::new(), total, &profile("bare"), Vec::new());
        coverage.checks_expected = total;
        let held = |check: &str, rule: &'static str| report::Shortfall::Unsettled {
            check: check.to_owned(),
            verdict: Verdict::Indeterminate,
            withheld: None,
            rule: Some(rule),
            reason: None,
        };
        let pool = [
            held("bti-enforced", MACHINE_LACKS_BTI.id),
            held("pac-ret-enforced", MACHINE_LACKS_PAC.id),
            held("shadow-stack-enforced", NO_CHECK_ON_TARGET.id),
            held("linker-default-noexecstack", NO_CHECK_ON_TARGET.id),
            held("cet-marked", ARCH_OUTSIDE_TABLE.id),
            held("zero-init-padding-bits", FRAME_REUSE_DID_NOT_HOLD.id),
            report::Shortfall::NotAttempted {
                check: "pie".to_owned(),
            },
        ];
        let mut fours = 0;
        let mut zeros = 0;
        for mask in 1u32..(1 << pool.len()) {
            let shape: Vec<report::Shortfall> = pool
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, s)| s.clone())
                .collect();
            let strict_status = gate(&over(&shape), &strict(), &shape).0.status();
            let record = allowing(&shape);
            let allowed_status = gate(&over(&shape), &record, &shape).0.status();
            if record.excused.len() == shape.len() {
                assert_eq!(strict_status, error::EXIT_GATE, "{shape:?}");
                assert_eq!(allowed_status, error::EXIT_OK, "{shape:?}");
                zeros += 1;
            } else {
                assert_eq!(allowed_status, strict_status, "{shape:?}");
            }
            if strict_status == error::EXIT_MACHINE_LIMIT {
                fours += 1;
            }
        }
        // The pool reaches every ending: each nonempty subset of the two machine rules beside
        // any subset of the three target limits (3 x 8), and both no-check-on-target subsets
        // alone (3).
        assert_eq!((fours, zeros), (24, 3));
    }

    fn profile(name: &str) -> Profile {
        let args = MeasureArgs::try_parse_from(["chard", "--profile", name])
            .expect("the CLI must accept this profile name");
        resolve_profile(&args, "x86_64", &[])
            .expect("the profile must resolve without consulting the system")
    }

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
            assert!(noted.contains(toolchain::VERBOSE_QUERY), "{name}: {noted}");
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

    #[test]
    fn the_corpus_listing_carries_each_checks_positive_inputs() {
        let listing = corpus_listing();
        let mut with = Vec::new();
        for probe in listing["probes"].as_array().expect("probes is a list") {
            for check in probe["checks"].as_array().expect("checks is a list") {
                let inputs = check["positive_inputs"]
                    .as_array()
                    .unwrap_or_else(|| panic!("{}: positive_inputs is a list", check["id"]));
                if !inputs.is_empty() {
                    with.push((check["id"].clone(), inputs.clone()));
                }
            }
        }
        assert_eq!(
            with,
            vec![(
                serde_json::json!("rwx-segment-absent"),
                vec![serde_json::json!("rwx_segment.c")]
            )]
        );
    }

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

    #[test]
    fn bare_optimized_adds_only_the_enabling_condition() {
        let p = profile("bare-optimized");
        assert_eq!(p.cflags, vec!["-O2".to_owned()]);
        assert!(
            p.ldflags.is_empty(),
            "the profile must not touch the link step"
        );
    }

    #[test]
    fn bare_optimized_differs_from_bare_only_by_optimization() {
        let bare = profile("bare");
        let opt = profile("bare-optimized");
        assert!(
            bare.cflags.is_empty(),
            "the bare profile adds no flag: {:?}",
            bare.cflags
        );
        let added: Vec<_> = opt
            .cflags
            .iter()
            .filter(|f| !bare.cflags.contains(f))
            .collect();
        assert_eq!(added, vec![&"-O2".to_owned()]);
    }

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
    /// supplied two flag sets that happen to match.
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

    /// The flags must be attributable to chard rather than to the distribution: `bare`
    /// reports `flags_source: "none"`, and if `bare-optimized` did too, a reader or
    /// `attribute` would credit `-O2` to the compiler's own defaults and mis-attribute
    /// anything it unlocked.
    #[test]
    fn bare_optimized_declares_who_chose_its_flags() {
        assert_eq!(profile("bare").flags_source, "none");
        let p = profile("bare-optimized");
        assert_eq!(p.flags_source, "chard-enabling-condition");
    }

    /// A repeated `--probe` is refused, an unknown one is refused, and a distinct
    /// selection names its own size.
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
    /// profile says so where a reader of a bare column looks: `none` is reserved for
    /// compiled-in defaults, or a hardening flag in that file is credited to the compiler.
    /// `bare-optimized` keeps the value that attributes the `-O2` chard passed, and names the
    /// file in its note instead.
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
