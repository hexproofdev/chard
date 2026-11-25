<!-- SPDX-License-Identifier: BSD-3-Clause -->

# chard fuzz targets

A development-only crate with its own workspace, so chard's build and dependency checks never
see `libfuzzer-sys`, and the published package excludes it. The targets under `fuzz_targets/`
feed arbitrary input to chard's readers of untrusted data: ELF bytes, report and evidence JSON,
macro dumps, flag lists, driver output, diagnostics and the files `env` reads.

They need `cargo-fuzz` and a nightly toolchain:

```sh
make fuzz-seed              # seed the corpora
make fuzz FUZZ_TIME=300     # each target for five minutes
make fuzz-replay            # every corpus, seed and kept crash once, without mutation
```

A crash worth keeping is minimised and committed under `crashes/<target>/` with a note, and
`make fuzz-replay` reruns it.
