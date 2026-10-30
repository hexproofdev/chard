<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Quickstart

This page takes you from a checkout to a first measurement, then shows where to find everything
else. [README.md](README.md) explains what chard is and why it exists.

## Terms

- **Probe**: a small C program that chard compiles with your compiler and then runs.
- **Check**: one question a probe answers about one flag, such as "is the binary PIE?". Each
  check gets a verdict.
- **Profile**: which flags chard adds when it builds the probes. `bare`, the default, adds none,
  so it measures the compiler's own defaults. `bare-optimized` adds `-O2`. `openssf-tldr` adds
  the OpenSSF guide's flags. `explicit` uses the flags you give.
- **Withheld**: chard could not tell whether the flag is in effect. A withheld check is not
  `off`.
- **Polarity**: whether a check's flag adds protection (`harden`) or removes it (`weaken`, such
  as `-Wl,-rpath`). For a `weaken` check, `off` is the protected state.
- **Level**: some checks grade a protection, such as FORTIFY 1, 2 or 3, or stack protector
  `basic`, `strong` or `all`. Such a check is `on` at or above its recommended level and
  `partial` below it.

## 1. Build

You need Rust, a C compiler (gcc or clang), and `jq` for the digest recipes in step 3.

```sh
make doctor                             # lists anything this machine is missing
make build                              # builds target/release/chard
export PATH="$PWD/target/release:$PATH"
```

[README.md](README.md#install) has the other ways to build.

## 2. Measure

Some probes crash on purpose, so turn off core files first.

```sh
ulimit -c 0
chard measure --cc gcc --execution host                         # gcc's own defaults
chard measure --cc gcc --execution host --profile openssf-tldr  # gcc with the OpenSSF guide's flags
```

The first command writes `chard-gcc-bare.json`, the second `chard-gcc-openssf-tldr.json`. `-o FILE`
names another file. Each run keeps its build files in `chard-work/`, and its last line on stderr
says how it ended. Step 3 reads the result.

To measure your own flags, use `--profile explicit`. Include an `-O` level: checks that need
optimization are withheld without one.

```sh
chard measure --cc gcc --execution host --profile explicit \
    --flags "-O2 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -fstack-clash-protection -fPIE" \
    --cxxflags "-O2 -D_GLIBCXX_ASSERTIONS -fstack-protector-strong -fPIE" \
    --ldflags "-pie -Wl,-z,relro,-z,now" -o mine.json
```

Two options change what a run can measure:

- `--execution` tells chard where it runs: `host` on a machine with its own kernel, `vm` inside a
  virtual machine. In a container, leave it out. Without it, the checks that depend on what the
  running kernel enforces (`noexecstack-enforced`, `shadow-stack-enforced`) are withheld. chard
  cannot verify `host` or `vm`, so the report records them as asserted. In a container that chard
  recognises, it refuses them.
- `--env NAME=VALUE` passes a variable to the compiler, which otherwise sees only `PATH`,
  `LC_ALL=C` and `TERM=dumb`. Pass every variable your toolchain reads: if you miss one, chard
  measures a differently configured toolchain. For a Nix cc-wrapper, that is
  `NIX_HARDENING_ENABLE` and `NIX_CC_WRAPPER_TARGET_HOST_<triple>=1`. The report lists the
  variables you passed.

## 3. Read the result

```sh
chard table chard-gcc-bare.json                               # one row per protection
chard table chard-gcc-bare.json chard-gcc-openssf-tldr.json   # two reports side by side
chard digest chard-gcc-bare.json                              # a summary, as JSON
```

Each check gets one verdict:

| Verdict | Meaning |
|---|---|
| `on`, `off`, `partial` | Measured. |
| `unsupported`, `not-applicable` | chard established that the mechanism does not exist for this toolchain, target or binary. If it could not establish that, the check is withheld instead. |
| `indeterminate`, `probe-invalid`, `build-failed`, `run-failed` | Withheld. **Not `off`.** |

To measure a check, chard builds its probe three ways: with the flag forced on, forced off, and as
configured. It publishes `on` or `off` only when the forced builds differ the way the flag
predicts. [DESIGN.md](DESIGN.md#verdict-vocabulary) has the full vocabulary.

Reading `table`:

- `--` means the protection is not in force. It is the only mark that means a measured absence.
- `?` means withheld, and `err` a build or run that failed.
- `n/a` usually means the protection does not apply here. If the notes list it as withheld, chard
  could not tell.
- Rows for a `weaken` flag, such as `-Wl,-rpath`, are inverted, so `--` still means unprotected.
- With `--by-defect`, `part` means some of the checks are on. `--?` means the checks that answered
  found nothing, but not every check answered. It is not a measured absence.
- The legend under the grid defines every mark. The notes under it give each withheld check's
  reason.
- A column is one configuration. `table` refuses two reports of the same configuration. With
  `--replace-repeated` the later report's column is kept whole, and a note names what changed.

Reading `digest`:

- `checks`: every check, with its `verdict` and `polarity`.
- `reasons`: every check that was not measured. Its `standing` is `earned-limitation` (the
  mechanism does not exist here) or `instrument-withholding` (chard could not tell), and its
  `reason` says why. Some also name the `rule` that decided it.
- `coverage`: how many checks were expected, attempted and published.
- `consistency`: `consistent`, unless the report contradicts itself.

### Use it in CI

chard has no built-in pass or fail for hardening. `measure` exits 0 when it writes a report,
whatever the verdicts. To act on the verdicts, read the digest. These recipes are from
[DESIGN.md](DESIGN.md#the-block-a-report-leads-with):

```sh
chard digest mine.json > digest.json
jq -r '.checks[] | select(.verdict == "off" and .polarity == "harden") | .check' digest.json
jq -r '.checks[] | select(.polarity == "weaken") | [.check, .verdict] | @tsv' digest.json
jq -r '.reasons[] | [.check, .standing, .reason] | @tsv' digest.json
```

- The first lists the protections measured absent.
- The second lists the `weaken` checks with their verdicts. For these, `off` is the protected
  state.
- The third lists every check that was not measured, and why.

These list; they do not fail a job. Which checks your build must have is your decision, and so is
how to treat a `partial` or a withheld check. A script that looks only for `off` lets both through.
`chard probes --format text` lists every check and its flag.

`--fail-on-missing` is not a hardening gate. It exits 1 if any check is withheld, which means the
run was incomplete. It exits 0 for a complete run even if every protection is `off`. A `bare` run,
a run without `--execution`, and a `--probe` run all fail it.

On exit 2 or 3, stdout holds a JSON error object instead of the document. Its `error.code` field
says who acts next:

| `error.code` | Next step |
|---|---|
| `TRANSIENT` | Retry. |
| `USER_INPUT`, `CONFIGURATION` | Fix the command. |
| `PERMISSION` | Fix the file permissions. |
| `INTERNAL` | Report a bug. |

[README.md](README.md#exit-status) lists every exit status.

## 4. Compare toolchains

Skip this unless you measure more than one toolchain.

```sh
chard matrix chard-gcc-bare.json chard-gcc-openssf-tldr.json mine.json -o matrix.json
```

`matrix` compares reports by their configuration settings: distribution, release, compiler,
compiler version, libc, architecture, profile, execution mode (and how it was established), and
the container or VM image. For each difference, it says which setting explains it.

- `variance` has one entry per flag, named as `chard probes` names it: `variance["-pie"]`, not
  `variance["pie"]`.
- `explained_by` lists the settings that explain the results. The schema calls them axes. An
  empty list means no single setting does. `strength`, `confounded_with` and `note` qualify the
  answer.
- `matrix` refuses reports from different chard revisions, probe sets or execution modes, unless
  you pass `--allow-mixed`.
- `matrix` refuses two reports of the same configuration, unless you pass `--replace-repeated`.

## 5. Look closer

```sh
chard probes --format text                                  # probe ids, check ids and flags
chard probes                                                # the same as JSON, with polarity and levels
chard measure --cc gcc --probe link-defaults -o one.json    # run one probe only
chard detect pie --evidence chard-gcc-bare.json             # re-run one check's decision from a report
chard elf "$(command -v ls)"                                # the ELF facts chard reads from a binary
chard detect pie --artifact "$(command -v ls)"              # what one binary shows, without a verdict
```

`detect` takes a check id. `--probe` takes a probe id. `detect --artifact` reports what the binary
has (`outcome`), not what a toolchain applies. It gives no verdict, because there were no
forced-on and forced-off builds to compare.

## Where things are

| To learn | Read |
|---|---|
| Every command, option and exit status | `chard --help`, `chard <command> --help` |
| Each check's flag, polarity and levels | `chard probes` |
| What a JSON field means | The schema for that document, in `schema/`. `chard-report.schema.json` covers reports and digests. `chard-matrix`, `chard-detect` and `chard-error` cover the rest. Most fields have a `description`. |
| Why a check was withheld | `chard digest <report>`, under `reasons` |
| What explains a difference between configurations | `chard matrix`, under `variance` |
| How chard decides a verdict | [DESIGN.md](DESIGN.md) |
| What chard defends against and trusts | [THREAT_MODEL.md](THREAT_MODEL.md) |
| Platforms and compiler versions | [SUPPORT.md](SUPPORT.md) |
| Changes to the output format | [CHANGELOG.md](CHANGELOG.md) |
| Reporting a bug or sending a change | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Working on chard itself | [CLAUDE.md](CLAUDE.md), `make help` |

## For scripts and agents

- Output is JSON, except `table` and `probes --format text`.
- A command writes to stdout, or to the file `-o` names. `measure` writes to
  `chard-<cc>-<profile>.json` by default.
- Progress and notes go to stderr, prefixed `chard: `.
- Every JSON document except `elf`'s carries `chard_schema`, the major version of its format.
  Check `chard_schema`, and ignore fields you do not know: new fields are not breaking changes.
- Branch on the exit status first. On exit 2 or 3, branch on `error.code`.
- [DESIGN.md](DESIGN.md#the-command-line-contract) states the full contract.
