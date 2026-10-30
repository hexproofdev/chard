<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Changelog

This file lists the changes to chard's output contract, the part a pipeline can break on.

The contract is the shape of a report, a matrix, `detect`'s output and the error envelope. The
schemas in [`schema/`](schema/) describe them, led by
[`schema/chard-report.schema.json`](schema/chard-report.schema.json). DESIGN.md states the rest:
the verdict vocabulary, the exit statuses and the error envelope's classes.

`chard_schema`, in every JSON document chard writes but `elf`'s, is the number to gate on. A key
chard adds is not a change, and a consumer ignores keys it does not know. Removing or renaming a
key, changing a value's type or meaning, or adding a value to an enumeration raises
`chard_schema`. The CLI's contract states this rule (`chard --help`, and DESIGN.md "The
command-line contract").

## 0.1.0

The first publication. `chard_schema` is `1`; the schemas under `schema/` and DESIGN.md
describe the contract as published, and no earlier report, matrix or `detect` output exists for
this file to compare against.
