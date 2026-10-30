<!-- SPDX-License-Identifier: BSD-3-Clause -->

# 🥬 chard

chard measures which hardening protections a C and C++ toolchain applies: it builds small probe
programs with your gcc or clang, runs them, and reads the binaries it just built. It measures hosted
userspace builds against a libc, not freestanding targets such as the Linux kernel.

## Install

Building needs Rust, and the first build needs the network to fetch crates.

```sh
make build     # leaves the binary at target/release/chard
make doctor    # says what else is missing
make musl      # a static binary, probes embedded, for an image with another libc; it needs
               # rustup target add "$(uname -m)-unknown-linux-musl"
```

## Run

Some probes crash on purpose. On Linux each probe that dies by its own crash makes itself
non-dumpable first, so it leaves no core file. Off Linux, or where that call fails, a crash
leaves a core file, so run chard under `ulimit -c 0` or with a `core_pattern` you control.

```sh
ulimit -c 0
chard measure --execution host    # what a plain `cc foo.c` gives you
chard table chard-cc-bare.json    # a row per protection
```

`measure` writes `chard-<cc>-<profile>.json`, or the file `-o` names, and ends on a line naming its
exit status, the file and the command to run next; `--cc` names the compiler. `bare` is the
compiler's own defaults, `bare-optimized` adds only `-O2`, `openssf-tldr` builds with the TL;DR
flags of the [OpenSSF guide][openssf], and `explicit` measures the `--flags`, `--cxxflags` and
`--ldflags` you give.

The compiler runs with a cleared environment, so a toolchain configured through environment
variables (a Nix cc-wrapper's `NIX_*`, `GCC_SPECS`) is measured as it behaves without them. A
protection only those variables add reads `off`, and the report gives no sign that one was needed.
`--env NAME=VALUE` passes a variable to every toolchain invocation of the run;
[THREAT_MODEL.md](THREAT_MODEL.md) has the measurement and the rules.

An excerpt of `chard table tests/fixtures/sample-report.json`: `bare` with GCC 16.2.0 and GNU ld
2.44 as the gcc:16 container image ships them, on a system with no `os-release`:

```text
protection                                        unknown unknown gcc 16.2.0 bare cc
------------------------------------------------------------------------------------
auto-var-init x                                   --
cet a                                             --
fortify x                                         --
-fstrict-flex-arrays                              ?
implicit-decl-is-error d                          error
noexecstack a                                     on
pie a                                             --
relro a                                           partial
stack-clash x                                     --
stack-protector a                                 --
-Wformat d                                        --
```

`--` is off and `?` withheld; the full table prints each reason (here, an unoptimized build gives
the probe no object size to read) and defines levels such as `partial`. The letter is what the
verdict rests on: `x` the probe run and the mitigation seen to act or not, `a` the compiled
artifact, `d` the compiler's diagnostic, `m` a macro, the compiler's own claim. A row with no
check that reads `on`, `off` or `partial` carries no letter (`-fstrict-flex-arrays` here).

`--fail-on-missing` exits 1 when a check this system could reach went unattempted or chard withheld
its answer (a C++ check with no C++ driver among them): it says whether every check ran, not whether
the build is hardened. Without `--execution`, chard withholds the checks that depend on kernel
policy (`noexecstack-enforced`, `shadow-stack-enforced`), since nothing it reads tells a system
that owns its kernel from a container it does not recognise; `--execution host` or `vm` lets them
be measured.

chard has no hardening gate of its own; which checks a build must have is the reader's decision.
A list of the `off` verdicts is not such a gate. For a `weaken` check, such as `rpath-absent`,
`off` is the protected state. A `partial` or withheld verdict is neither `on` nor `off`.
[QUICKSTART.md](QUICKSTART.md#use-it-in-ci) shows how to list the protections measured absent, the
`weaken` checks and the checks not measured.

## Exit status

| Status | Meaning |
|---|---|
| `0` | The document is written; from `detect`, every reading it replayed agrees. |
| `1` | A gate tripped and the document is written: under `measure --fail-on-missing` a check did not settle, or under `detect` a reading disagrees with its replay. |
| `2` | chard refused the invocation or failed, a usage error among them, or a `--execution` was contradicted by what chard observed; stdout carries a JSON error envelope. |
| `3` | `measure` built a report that contradicts itself; it is written only to `<file>.contradicted`. |

A panic exits 101. What each command writes to stdout and stderr and the envelope's codes are in
`chard --help` and [DESIGN.md](DESIGN.md#the-command-line-contract).

## Platforms

| Platform | Tier |
|---|---|
| Linux x86_64, glibc | supported |
| Linux x86_64, musl | measured |
| Linux i386, glibc | measured |
| Linux aarch64, glibc | measured |
| Linux aarch64, musl | measured |
| Linux arm, glibc | measured |
| FreeBSD amd64 | measured |
| OpenBSD amd64 | measured |
| OpenBSD arm64 | measured |
| macOS arm64 | builds |

[SUPPORT.md](SUPPORT.md) defines the tiers and lists the compiler versions held on each.

## Why measure

Hardening flags do not fix bugs; each adds a step an exploit has to route around. A stack canary
turns a contiguous overwrite of the return address into an abort, and full RELRO makes the tables
the loader fills in read-only before the program's own code runs.

Which of them a toolchain applies is not in its documentation. Upstream gcc leaves most of them off
unless a distribution configured or patched it to (the sample's gcc was configured with none);
upstream clang adds PIE on linux-gnu, little else.[^defaults] No ordinary build log shows clang's
auto-loaded `<triple>.cfg`.

A command line is not the record either. `-D_FORTIFY_SOURCE=3` falls back to level 2 with an older
glibc or compiler, silently before glibc 2.33, and without optimization gives no checks at
all.[^fortify] A linked x86 program keeps its CET marking only where every input object carries it,
so one unmarked startup object drops it, and by default the linker says nothing.[^cet] GCC 14's
`-fhardened` skips any option already on the command line, so a weaker one stays in
effect.[^hardened] Nor is a clean build: enabling `pac-ret` by default misbuilt libunwind, whose
build completed and whose tests crashed, and the reporter could find no string in the build logs
that told a misbuilt libunwind from a correct one.[^pacret]

So chard reads what was built. Every check it attempts is built three ways: the flag forced on,
forced off, and as configured; a rule that stops one first (an aarch64 flag on x86_64, no C++
driver) gives its reason. A verdict is trusted only when the forced builds differ as expected,
judged on what each build produced rather than on the flag being accepted. A probe that cannot tell
them apart reads `probe-invalid`, never `off`; a mechanism the toolchain or target lacks is
`unsupported`, and a flag the artifact cannot carry is `not-applicable`. A verdict describes the
artifact, not a running process: where the CPU, the kernel or the libc also has to act, the report
says what else has to hold. A report shows whether a toolchain applies a flag and catches the
regression where one quietly stops arriving; it finds no miscompile and measures no cost. chard
measures a toolchain, not your build: a Makefile, a vendored dependency or a submodule can still
weaken the result.

## Further reading

[QUICKSTART.md](QUICKSTART.md) goes from a checkout to a first reading: your own flags, every
verdict, CI, and where each answer is documented. [DESIGN.md](DESIGN.md) has the mechanism,
[THREAT_MODEL.md](THREAT_MODEL.md) the trust decision, [CHANGELOG.md](CHANGELOG.md) the changes to
the output contract. [CONTRIBUTING.md](CONTRIBUTING.md) says where bugs and changes go.
[jvoisin/compiler-flags-distro](https://github.com/jvoisin/compiler-flags-distro) is a curated
table of the hardening flags distributions enable by default when they build their packages,
with its evidence linked where it is known. It records what a distribution configures; chard
measures what a toolchain applies.

[openssf]: https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++

[^defaults]: GCC's [configure options](https://gcc.gnu.org/install/configure.html) include
    `--enable-default-pie`, `--enable-default-ssp` and `--enable-cet`; fortify and `-Wformat-security`
    arrive by specs or patches. clang: `CLANG_DEFAULT_PIE_ON_LINUX` is ON; the rest is a vendor's.
[^fortify]: glibc, `include/features.h`: level 3 needs clang 9 or gcc 12 and later and falls
    back to level 2 otherwise, silently before glibc 2.33; `__USE_FORTIFY_LEVEL` is gated on
    `__OPTIMIZE__`, with `#warning _FORTIFY_SOURCE requires compiling with optimization (-O)`.
[^cet]: x86-64 psABI, `GNU_PROPERTY_X86_FEATURE_1_AND`; binutils ld [options](https://sourceware.org/binutils/docs/ld/Options.html):
    `-z cet-report=none` "is the default". Debian bug [#1070884](https://bugs.debian.org/1070884)
    found `endbr64` with no IBT property, the unmarked inputs being `Scrt1.o`, `crti.o` and
    `crtn.o`. aarch64's BTI, PAC and GCS markings merge the same way.
[^hardened]: GCC manual, [Instrumentation Options](https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html):
    "-fhardened only enables a particular option if it wasn't already specified anywhere on the
    command line". `-Whardened` reports it, except under `-w`; clang has no umbrella option.
[^pacret]: [LP#2041694](https://bugs.launchpad.net/bugs/2041694), fixed by libunwind
    [PR #793](https://github.com/libunwind/libunwind/pull/793); [LP#2040518](https://bugs.launchpad.net/bugs/2040518), the logs.
