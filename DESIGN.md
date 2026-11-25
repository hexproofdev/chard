<!-- SPDX-License-Identifier: BSD-3-Clause -->

# chard: design

## The question

> Given a C toolchain on some distro, which hardening flags are *actually in effect*
> for a build, and how does that differ across distros, distro versions, and gcc vs clang?

chard answers from the artifacts it compiles and from how they run.

The terms used here:

- A **probe** is a small C or C++ program under `probes/`.
- A **check** is one question asked of a probe's build, such as whether a stack canary was
  emitted.
- A **profile** is the set of flags the measured build uses.
- A **report** is the JSON document one `chard measure` run writes, with one verdict per check.
- A **sweep** is one run of the whole probe corpus over a set of machines.

## Non-goals

- chard reads no distribution's packaging spec. It does not ask rpm, dpkg-buildflags or another
  package tool for build flags, since such a query describes only its own image. Real build
  flags can be measured with `--profile explicit --flags`.
- On Linux, it reaches no verdict from a distribution's name or version.
- It gives no verdict about a binary it did not build. `chard elf` and `chard detect --artifact`
  report what a binary contains, with no controls and no verdict. They read it as untrusted
  input (`THREAT_MODEL.md`).
- It does not rank flags. It reports which defect classes the checks bear on (`defects`) and
  what a protection also needs at run time (`boundary`), and leaves the judgement to the caller.

## The control triple

The failure chard cannot tolerate is a **clean-looking zero**: a flag reported off when the probe
never ran or the detector looked in the wrong place. A detector that finds nothing proves
nothing unless it is known to see the thing on this toolchain. So each check builds three
variants, its **arms**:

```text
measured   cc <profile flags> probe.c      <- what's reported
positive   cc <flag forced on> probe.c     <- must show the observable
negative   cc <flag forced off> probe.c    <- must NOT show it
```

The positive and negative arms are the **controls**. The measured verdict is trusted only when
the positive arm shows the observable and the negative arm does not. Otherwise the recipe is
broken on this toolchain, and the check is `probe-invalid`, never `off`.

The driver's own stderr can make an exception:

- where it says it does not know, or refuses, the positive control's flag, the flag is one
  this toolchain lacks, and the check reads `unsupported` (`flag-unknown-to-driver`,
  `flag-refused-by-driver`);
- where it says it does not know the negative control's flag, the triple has no unhardened
  state to compare, and the check reads `indeterminate` (`unhardened-state-unbuildable`).

A bug in a reader that hides an observable everywhere, such as a wrong padding rule for ELF
notes, also silences the positive arm. The check then reads `probe-invalid` rather than `off`.

**The controls carry none of the profile's hardening flags.** They ask whether the detector can
tell on from off on this toolchain. Built on the profile, they would ask whether the profile lets
the flag be turned off.

Fedora's `%build_cflags` shows why the two questions differ. It injects hardening through a spec
file that no later flag can override, so every negative control built on that profile would
show the observable.

Some profile flags do reach the arms: those that select the target, the runtime, the headers
and the linker. None of them hardens anything. A check whose flag is off by default has no
negative control. It uses a **clean** build as its negative sample, which carries only the
target and runtime selections.

**Each arm publishes what built it:** its argv, its exit status and, where it ran, its run
record.

## Four observation channels

| channel | reads | examples |
|---|---|---|
| `macro` | predefined preprocessor macros | `__SSP_STRONG__`, `_FORTIFY_SOURCE`, `__PIE__` |
| `elf-static` | the artifact: dynamic tags, program headers, symbols, notes | `DF_1_PIE`, `PT_GNU_RELRO`, `__stack_chk_fail` |
| `runtime` | the program's exit status, signal and stderr when run | the live `_FORTIFY_SOURCE` level, `-fwrapv` |
| `compiler-diag` | the compiler's stderr | `-Wformat-security`, the default `-std` |

The channels are readers, not independent witnesses. The `macro`, `elf-static` and `runtime`
channels all read one artifact: its embedded macro record, its headers, and a run of it. A
report's `corroboration` says, for each group of checks, what each member read and how many
independent witnesses that is. Every witness comes from one compiler and one flag list, so the
count separates artifacts, not toolchains.

Any input of a build can set a macro: a `-D`, a forced include, a specs file, a wrapper. A macro
reading can therefore say what the artifact does not hold. So where another check reads the
same protection from the artifact or a run of it, that check is the macro check's **twin**. A
macro that reports the operator's request has no twin, and neither do the few checks
`report::MACRO_WITHOUT_TWIN` lists with their reasons. Where the twin reads the opposite, the
macro reading is withheld as `indeterminate` under `macro-contradicted-by-artifact`, and the
twin keeps its verdict.

## Verdict vocabulary

| verdict | meaning |
|---|---|
| `on` | present, and the controls show the detector sees it |
| `off` | absent, and the controls show the detector sees it |
| `partial` | present, but not at the level the OpenSSF guide asks for |
| `unsupported` | the toolchain, C library, architecture or kernel cannot provide it |
| `not-applicable` | the question has no referent in what was measured |
| `indeterminate` | ambiguous, or chard could not pose the question |
| `probe-invalid` | the controls did not discriminate |
| `build-failed` | the build the check needed failed |
| `run-failed` | the run the check needed failed |

A verdict describes the artifact, not the running system. Where the protection also needs
something outside the binary, such as ASLR for PIE, the observation's `boundary` names it.

A **level** is a word on a check's own scale, such as `explicit < basic < strong < all` for the
stack protector:

- `partial` means a level on the scale other than the ask, so only a check that grades a level
  can read it.
- On a check that grades nothing, such as PIE's code model, the word is information beside `on`.
- A level off the scale is `indeterminate`, never the strongest verdict.

`chard probes` lists each check's scale.

Each check has a **polarity**: under `harden` presence is good, and under `weaken` it is bad.

## One binary

chard is a single Rust binary. The machine under test needs only the toolchain under test, with
no Python. ELF is parsed with safe Rust over bytes, never by running `readelf`, whose output
format drifts across binutils versions.

## Containers vs VMs

A container covers `macro`, `compiler-diag`, `elf-static` and the runtime checks that do not
depend on the kernel. Behaviour the kernel enforces needs the run's own kernel, because a
container shares its host's.

Four checks declare `needs_vm`: `noexecstack-enforced`, `shadow-stack-enforced`,
`bti-enforced` and `pac-ret-enforced`.

They are measured only on the caller's word that the kernel is the system's own. chard cannot
confirm that word, but it refuses it where a sign of a container contradicts it. Where the
architecture gate lets the four through:

| `--execution` | the four checks read |
|---|---|
| `host` or `vm` | a measurement |
| `container` | `indeterminate` under `needs-vm` |
| not given | `indeterminate` under `execution-mode-assumed` |

Both are instrument withholdings, so they fail `--fail-on-missing`, and `--allow` excuses
neither. A plain `chard measure` on a bare host therefore needs `--execution host`. A
kernel or machine without the feature is named by its own rule, such as
`kernel-lacks-shadow-stack` or `machine-lacks-bti`. A run in a container uses its host's kernel,
so its kernel-dependent readings belong to the host, not to the distribution in the container.
