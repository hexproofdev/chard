<!-- SPDX-License-Identifier: BSD-3-Clause -->

# CLAUDE.md

chard measures which C hardening flags a toolchain applies: it compiles probe programs and
reads the artifacts it built, never a packaging spec or a binary it did not build. Read
[`DESIGN.md`](DESIGN.md) before changing a detector and [`THREAT_MODEL.md`](THREAT_MODEL.md)
before changing a trust boundary.

## Commands

- `make doctor`: what this host lacks.
- `make build`: the release binary.
- `make test`: the suite.
- `make fmt-check`, `make clippy-gate`, `make lints`: the quick checks.
- `make check`: the whole gate. It refuses to run before `make hooks`.

## Hard rules

- `off` must be earned. A probe that cannot tell the flag's two states apart is
  `probe-invalid`, and silence is never `off`: it is `probe-invalid`, `unsupported`,
  `not-applicable` or `indeterminate`.
- Every check passes its control triple (forced on, forced off, as configured) before its
  verdict is trusted.
- Code that enumerates work counts what it fed against what it expected; every report
  carries `coverage`.
- Output is deterministic. A derived field that contradicts its observations exits `3` and
  writes `<output>.contradicted` instead of publishing.
- Four direct dependencies (`serde`, `serde_json`, `clap`, `anyhow`), and `unsafe_code` is
  denied. The ELF reader is safe Rust over a byte slice, never a C binding or a call to
  `readelf`.
- The compiler runs under a cleared environment and a probe under exactly
  `run::PROBE_ENVIRONMENT`; chard reads nothing from the environment but `PATH`.
- No host name, home path or machine detail in a tracked file or a commit message.
- A test's expected values come from a spec written in the test, never from a file chard
  wrote.
