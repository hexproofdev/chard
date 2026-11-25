<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Threat model

chard answers one question: which hardening flags a toolchain actually applied. It compiles
programs and reads what came out. So chard runs your compiler with your privileges, and it reads
binaries it did not build.

**chard is an instrument, not a boundary.** Its controls withhold a verdict where a
probe cannot tell a flag on from off, so a compiler that no longer responds to a flag does not
read `on`. It is not designed to survive a hostile toolchain. Short of one, a wrong answer
can still be published with no rule withholding it. A wrapper or header that recognises one
build can do that. So can a compile handed to another compiler, an editor of a report, and a
crafted binary the ELF reader misreads. Confining a measurement run is the caller's job.

## What chard protects

- **The verdict.** A published `on` or `off` says what the toolchain did to the build.
- **The report as the record of one run.** It says what was measured and what was withheld, it
  agrees with itself, and it is this run's file and not an earlier one's.
- **The evidence under a verdict.** A third party can re-derive a macro or elf-static reading
  from the report.
- **The process that reads a binary chard did not build.** It does not crash on a crafted file,
  and its work is bounded by the file's length. Its memory is a multiple of that length, except
  for one kind of table, which only the work budget bounds.

## Against whom, and under what assumptions

### Actors

- **The operator** runs chard, names the toolchain and writes the command line.
- **The toolchain under test** is the compiler, assembler and linker the operator named. It may
  be misconfigured. It is not taken to be hostile.
- **A program in front of the compiler** is a wrapper, a compiler cache or a distributed
  compiler earlier on `PATH`, a spec file, or a header a profile or a wrapper selects.
- **The author of a binary** given to `chard elf` or `chard detect --artifact`.
- **Whoever hands you a report**, and anyone who could edit it after `measure` wrote it.
- **Another local user** who can write the work directory or the directory of the output.

### Entry points

| input | who supplies it | how chard treats it |
|---|---|---|
| The command line: the toolchain it names, a profile's flags, `--env` pairs, `--execution`, `--workdir`, `-o` and the files its other options name | the operator | trusted, and published in the report |
| chard's own environment | whatever started chard | not passed on, except `PATH` |
| `PATH` | the operator's shell and the host | passed to the compiler, so a program earlier on it runs as the toolchain |
| What the toolchain writes: artifacts, macro dumps, diagnostics and the driver's answers | the toolchain under test | inside the boundary, and held against itself |
| A probe's exit, its signal and its output | a probe built from chard's own source, and the kernel | read by the check's decoder |
| The work directory and the file at `-o` | the operator, an earlier run, and anyone who can write there | not locked; an earlier report is set aside |
| A binary given to `chard elf` or `chard detect --artifact` | its author | untrusted |
| A report given to `table`, `matrix`, `digest` or `detect --evidence` | whoever hands it over | untrusted, and not authenticated |
| The probe corpus and chard's dependencies | chard's own release | chard's own |

### The trust boundary

```text
 outside the boundary                       inside the boundary
 -------------------------------------      ----------------------------------------------
 chard's own environment, but for PATH      the operator and the command line
 a binary given to `elf` or                 the toolchain the operator named, and a program
   `detect --artifact`                        PATH or an --env pair puts in front of it
 a report given to `table`, `matrix`,       chard's probe sources, and the probes built
   `digest` or `detect --evidence`            from them
                                            the kernel and C library of the measuring host
                                            the work directory and the output path, which
                                              the caller keeps other writers out of
```

Inside the boundary does not mean unchecked. The control triple, the twin rule and the run
witness hold a toolchain's output against itself. They catch one that is misconfigured or
redirected, not one built to deceive them.

The boundary rests on three assumptions:

- **The kernel and the C library are honest** about what they enforce. Where a protection also
  needs runtime support, the observation carries a `boundary` naming what the verdict does and
  does not establish.
- **The operator chose the toolchain.** `--cc /path/to/gcc` is a documented option. Pointing chard
  at a compiler is an act of trust in that compiler, not a request to sandbox it.
- **The build host is not already compromised.** chard cannot distinguish a hardening flag that
  is genuinely absent from one removed by something that owns the machine it runs on.

### Threats

| position | what they control | what stops them producing a wrong verdict |
|---|---|---|
| The environment chard is started in | every variable but `PATH` | **a cleared environment for the compiler, and a fixed one for each probe; a variable the toolchain needs and no `--env` pair gives leaves no sign** |
| A compiler cache or a distributed compiler on `PATH` | which object or compile a build is served | **the run witness, behind two pins that switch ccache off; a compile forwarded to another compiler is not held, and under `--normalize` an earlier run's object can pass** |
| A redirected toolchain, behaving the same for every build | a wrapper earlier on `PATH`; the driver's own redirecting variables are cleared | **the control triple** |
| A redirected toolchain that recognises which build it is compiling | the same, plus chard's variant naming, which is public | **the macro channel's twin rule where a twin measured, and nothing for the artifact channels** |
| A macro level forged inside a present reading, a forged `fortify-effective`, or a probe steered by a macro the list never named | the same inputs | **nothing beyond the corroboration group's note, and for a steered probe no note** |
| A forged `optimization-enabled` | the same inputs | **its artifact twin, `optimization-applied`, and the input clause where the twin is not a measurement; a header written against the twin's probe forges both readings, and nothing withholds them** |
| A spec file that lies | what `cc -dM -E` prints versus what the compiler emits | **the self-report the compiler writes into the artifact; a section a tool rewrote is read as it stands, and on a macOS run the dump is read** |
| A compiler built to recognise chard's probes | every arm of every control triple | **nothing** |
| A crafted ELF file | the bytes `chard elf` and `chard detect --artifact` parse | **a crash, an unfinished table and a cost the file amplifies; a misreading is not stopped.** |
| Whoever hands you the report | the JSON itself, after `measure` wrote it | **nothing cryptographic; the readers catch damage and an edit to one copy of a verdict** |
| A stale or mixed dataset | which reports get rendered together | corpus hash and harness revision are join keys. Mixing them is refused, and `--allow-mixed` puts the conflict into the output |
| Another user who can write the work directory | its claim, and the files a toolchain opens there | **nothing; keeping other writers out is the caller's job** |

## Reporting

A report to chard may be about a false verdict in either
direction, a `coverage` block that calls a partial run complete, a `discriminating` flag that was
not earned, or a panic in the ELF reader. [`SECURITY.md`](SECURITY.md) says how to report
privately something you believe is a vulnerability. Anything else is an ordinary issue.
