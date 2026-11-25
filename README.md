<!-- SPDX-License-Identifier: BSD-3-Clause -->

# 🥬 chard

chard measures which hardening protections a C and C++ toolchain applies. It builds small probe
programs with your gcc or clang, runs them, and reads the binaries it built. It measures hosted
userspace builds against a libc, not freestanding targets such as a kernel.

## Install

```sh
make build     # target/release/chard; the first build fetches crates
make doctor    # what else this host lacks
make musl      # a static binary for an image with another libc
```

## Run

Some probes crash on purpose, so turn core files off:

```sh
ulimit -c 0
chard measure --execution host    # what a plain `cc foo.c` gives you
chard table chard-cc-bare.json    # a row per protection
```

`measure` writes `chard-<cc>-<profile>.json`, or the file `-o` names; `--cc` names the compiler.
The profiles: `bare` is the compiler's defaults, `bare-optimized` adds `-O2`, `openssf-tldr`
uses the TL;DR flags of the [OpenSSF guide][openssf], and `explicit` measures the `--flags`,
`--cxxflags` and `--ldflags` you give. The compiler runs in a cleared environment; `--env
NAME=VALUE` passes a variable through.

In the table, `--` is off and `?` withheld; the letter says what a verdict rests on (`x` a run,
`a` the artifact, `d` a diagnostic, `m` a macro). Without `--execution host` or `vm`, checks
that depend on kernel policy are withheld.

## Use it in CI

chard has no hardening gate of its own; which checks a build must have is your decision. Read
the digest:

```sh
chard digest mine.json > digest.json
jq -r '.checks[] | select(.verdict == "off" and .polarity == "harden") | .check' digest.json
jq -r '.reasons[] | [.check, .standing, .rule // "-"] | @tsv' digest.json
```

These list the protections measured absent and the checks not measured, with the rule that
withheld each. For a `weaken` check `off` is the protected state, and a script that looks only
for `off` lets `partial` and withheld checks through.

`--fail-on-missing` asks whether the run was complete, not whether the build is hardened. On
x86_64, x86 and aarch64 some check is one chard does not read, so pass `--allow
no-check-on-target`; stderr and `coverage.gate.excused` name what it excused.

## Exit status

| Status | Meaning |
|---|---|
| `0` | The document is written, and any gate passed. |
| `1` | A gate failed and the document is written. |
| `2` | chard refused the invocation or failed; stdout carries a JSON error envelope. |
| `3` | The report contradicts itself; it is written only to `<file>.contradicted`. |
| `4` | `--fail-on-missing` failed only on checks this machine or target cannot answer. |

Output is JSON except `table`; progress goes to stderr. A document other than `elf`'s carries
`chard_schema`, its format's major version; ignore unknown fields.
`chard --help` states the full contract.

## Platforms

Supported: Linux x86_64 with glibc, where CI builds and tests chard. Measured, where a check
the platform cannot carry is withheld by rule: Linux x86_64 and aarch64 with musl, Linux i386,
aarch64 and arm with glibc, FreeBSD amd64, OpenBSD amd64 and arm64. Builds: macOS arm64, where
no ELF artifact is read.

## Why measure

Hardening flags do not fix bugs; they make some exploits fail. A stack canary turns a contiguous
overwrite of the return address into an abort, and full RELRO makes the tables the loader fills
in read-only before the program's own code runs.

Which of them a toolchain applies is not in its documentation. Upstream gcc leaves most of them
off unless a distribution configured or patched it to; upstream clang adds PIE on linux-gnu,
little else.[^defaults] No ordinary build log shows clang's auto-loaded `<triple>.cfg`.

The command line does not say either. `-D_FORTIFY_SOURCE=3` falls back to level 2 with an older
glibc or compiler, silently before glibc 2.33, and without optimization gives no checks at
all.[^fortify] A linked x86 program keeps its CET marking only where every input object carries it,
so one unmarked startup object drops it, and by default the linker says nothing.[^cet] GCC 14's
`-fhardened` skips any option already on the command line, so a weaker one stays in
effect.[^hardened] A clean build does not say either: enabling `pac-ret` by default misbuilt
libunwind, whose build completed and whose tests crashed, and the reporter could find no string in
the build logs that told a misbuilt libunwind from a correct one.[^pacret]

So chard reads what was built. Every check is built three ways: the flag forced on, forced off,
and as configured. A verdict is trusted only when the forced builds differ as expected, judged on
what each build produced rather than on the flag being accepted; a probe that cannot tell them
apart reads `probe-invalid`, never `off`. A verdict describes the artifact, not a running process.
chard finds no miscompile and measures no cost. It measures a toolchain, not your build: a
Makefile, a vendored dependency or a submodule can still weaken the result.

## Further reading

[DESIGN.md](DESIGN.md) has the mechanism,
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
