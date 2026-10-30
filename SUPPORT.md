<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Platforms and compilers

This page states where chard builds, where it runs, and which compiler versions it has been
held on. It names no distribution and carries no hardening verdict: a verdict measures one
toolchain under one profile, and a report is where one lives. `tests/support_matrix.rs` holds
the table to the fixture corpus, the assumption register, `README.md`'s platform table (this
table's first two columns) and `DESIGN.md`.

## Tiers

- **supported**: chard is built and its test suite run on the platform, its sweeps cover the
  versions held, and a change is measured there before it merges.
- **measured**: chard has produced reports on the platform, natively or in a guest or a
  container of it, and the fixture corpus replays detectors from them; a check the platform
  cannot carry withholds under a recorded rule rather than reading a verdict.
- **builds**: chard builds and runs; the artifact channel does not apply, since the toolchain
  writes no ELF, and what the other channels read there was measured by hand, not swept.

A platform not in the table is not held. chard has run natively on one Linux riscv64 board,
and the fixture corpus holds no report from it. That run was on Ubuntu 24.04.5,
with gcc 13.3.0 and clang 18.1.3 under `bare`, `bare-optimized` and `openssf-tldr`. ppc64le and
s390x have been cross-built or emulated only, Windows and Intel macOS not at all.

## The matrix

"Held" is the oldest and newest compiler version in the fixture corpus
(`tests/fixtures/detectors.json`), which `tests/detector_replay.rs` replays on every run; none
means the corpus holds no row from that compiler on that platform. "Rests on" names the
assumption register entries (`THREAT_MODEL.md`) that identify the platform's architecture,
libc and kernel, or decide what its kernel executes or enforces; an entry about one check's
reading is in that check's own documentation, not here.

| Platform | Tier | gcc held | clang held | Rests on | Notes |
|---|---|---|---|---|---|
| Linux x86_64, glibc | supported | 4.8.4 to 16.2.1 | 10.0.0 to 23.1.0 | `arch-macros-name-the-target`, `kernel-spelling-names-its-byte-order` | the host the suite, the cells and the sweeps run on |
| Linux x86_64, musl | measured | 15.2.0 | 22.1.3 to 23.1.2 | `arch-macros-name-the-target`, `kernel-spelling-names-its-byte-order`, `need-macros-identify-musl` | swept in containers and virtual machines; `make musl` builds the static binary that runs in a musl image |
| Linux i386, glibc | measured | 7.5.0 to 12.2.0 | none | `arch-macros-name-the-target`, `kernel-spelling-names-its-byte-order`, `x86-64-kernel-runs-i386-itself` | swept in a container and a virtual machine, chard built for i686 |
| Linux aarch64, glibc | measured | 12.2.0 to 16.2.1 | 22.1.8 | `arch-macros-name-the-target`, `kernel-spelling-names-its-byte-order` | the suite has run natively; the artifact-marking checks read BTI, PAC and GCS there |
| Linux aarch64, musl | measured | 15.2.0 | none | `arch-macros-name-the-target`, `kernel-spelling-names-its-byte-order`, `need-macros-identify-musl` | swept in a container on the aarch64 host |
| Linux arm, glibc | measured | 14.2.0 | 19.1.7 | `arch-macros-name-the-target`, `kernel-spelling-names-its-byte-order` | natively on one ARMv6 board, code in ARM state; gcc's Thumb builds fail there and clang's were read for one check only, and the ARMv7 and soft-float toolchains are unmeasured; chard itself is a static musl build cross-compiled for the board, measuring the board's glibc toolchains; the mechanism table has no arm rows, so the checks it gates withhold under `arch-outside-table` |
| FreeBSD amd64 | measured | none | 19.1.7 to 21.1.8 | `arch-macros-name-the-target`, `kernel-machine-is-chards-without-proc`, `openbsd-environment-unobserved` | two guests, 15.1 and 14.5; the libc reads as FreeBSD's from `__FreeBSD__` |
| OpenBSD amd64 | measured | none | 19.1.7 to 22.1.6 | `arch-macros-name-the-target`, `kernel-machine-is-chards-without-proc`, `openbsd-environment-unobserved`, `nobtcfi-switches-off-ibt-on-amd64` | a guest |
| OpenBSD arm64 | measured | none | 19.1.7 to 22.1.6 | `arch-macros-name-the-target`, `kernel-machine-is-chards-without-proc`, `openbsd-environment-unobserved`, `nobtcfi-switches-off-ibt-on-amd64` | a guest |
| macOS arm64 | builds | none | none | `arch-macros-name-the-target`, `kernel-machine-is-chards-without-proc`, `openbsd-environment-unobserved`, `proc-translated-zero-is-native` | Apple clang 21.0.0 by hand; the artifact channel withholds on Mach-O, and under a profile of Linux linker flags the builds fail, so those channels read build failures; chard reads no Mach-O record to hold to the kernel, so a `Machine` reading publishes where the probe read `sysctl.proc_translated` as 0 and is withheld otherwise (Homebrew gcc 16.2.0's `stack-clash-guard-page` is the one such reading the Mac's toolchains reach, since under Apple clang 21.0.0 and Homebrew clang 23.1.0 both of its control arms probe); the sysctl read rests on a hand measurement on one Apple silicon Mac, with no Darwin host in the suite |

## Measured in the sweeps

The sweeps through 2026-10-07 measured these ranges on one corpus,
wider than the fixture corpus holds where they differ: on Linux x86_64 with glibc, gcc 4.8.4
to 16.2.1 and clang 3.4.0 to 23.1.2; on Linux x86_64 with musl, gcc 14.2.0 to 15.2.0 and clang
19.1.4 to 23.1.2; on Linux i386, gcc 7.5.0 and clang 6.0.0 in a virtual machine; FreeBSD 15.1 and OpenBSD
7.9 guests at clang 19.1.7; and the aarch64 host at gcc 16.2.1 and clang 22.1.8. The records of
the sweeps are kept outside this repository. Where a
toolchain lacks a flag a check's arms need, the check withholds under a recorded gating rule
(`DESIGN.md`, the control triple) rather than reading a verdict.

## What the newest versions confirmed

- The `compiler-declared` rule, by which `trapv-helper-called` and `bidi-chars-any` read
  `unsupported` under clang because clang implements neither observable, held at clang 23.1.2
  in the sweeps and 22.1.8 on the host: no clang showed the observable.
- libc++ is held on Linux x86_64 with musl and nowhere else: the fixture corpus replays the
  three C++ standard-library checks from a libc++ system there, the request read at the mode
  the guide asks for; no libc++ build on glibc, the BSDs or macOS is held, and the modes beyond
  that one are unmeasured through chard.
