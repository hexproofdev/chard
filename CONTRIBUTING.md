<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Contributing

Report bugs and propose changes in the repository's issues, and send changes as pull requests.
Report a vulnerability privately, as [SECURITY.md](SECURITY.md) says.

A contribution is made under the BSD 3-Clause licence in [LICENSE](LICENSE).

`make check` runs the lint tables' gate, the format check, clippy, the API docs' build, the
Markdown, shell and YAML gates, the tests, and the dependency and licence gates. It runs only
after `make hooks`, and needs rumdl, shellcheck, shfmt and yamllint beside the Rust toolchains
`make doctor` names. The tests run the route corpus under gcc and clang, and fail on a host that
lacks either; `make check ROUTE_DRIVERS=gcc` (or `clang`) runs it under the one there.

Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).
