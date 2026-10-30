<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Contributing

Report bugs and propose changes in the repository's issues, and send changes as pull requests.
Report a vulnerability privately, as [SECURITY.md](SECURITY.md) says.

A contribution is made under the BSD 3-Clause licence in [LICENSE](LICENSE).

A change must pass `make check` to merge. The leak gate in `make check` needs bash 4.4 or
later. macOS ships bash 3.2 as `/bin/bash`, so put a newer bash first on `PATH` there, such
as Homebrew's.

Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).
