<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Changelog

This file lists the changes to chard's output contract, the part a pipeline can break on.

The contract is the shape of a report, a matrix, `detect`'s output and the error envelope. The
schemas in [`schema/`](schema/) describe them, led by
[`schema/chard-report.schema.json`](schema/chard-report.schema.json). DESIGN.md states the
verdict vocabulary, and `chard --help` the exit statuses and the error envelope's classes.

`chard_schema`, in every JSON document chard writes but `elf`'s, is the number to gate on. A key
chard adds is not a change, and a consumer ignores keys it does not know. An enumeration is closed
or open: adding a value to a closed one raises `chard_schema`, and an open one, spelt `anyOf` of
the known values and any string, may gain one. Removing or renaming a key or a value, or changing
a value's type or meaning, raises `chard_schema`. The CLI's contract states this rule (`chard --help`).

## 0.2.0

What a pipeline that ran chard 0.1.0 changes:

1. Accept `chard_schema` `2` in a report and a matrix, and keep `1` for `detect`'s output, the
   probe listing and the error envelope. Validate each against its schema under `schema/`.
2. Read a stored 0.1.0 report with chard 0.1.0, or measure again: `table`, `matrix`, `digest`
   and `detect` refuse it. Build every matrix again from reports this release measured.
3. Accept `chard-predicate/2` where a pin on `decoder.language` names `chard-predicate/1`.
4. Give every switch over an open enumeration a default arm.
5. Where a list of check ids is fixed, add `rwx-segment-absent`, `bti-enforced`,
   `pac-ret-enforced` and `optimization-applied`.
6. Where a script tests `measure --fail-on-missing` for exit 1, take exit 4 too. Decide whether
   to pass `--allow no-check-on-target`, and if so compare `coverage.gate.excused` with the
   checks you expect excused.
7. In an explicit profile, name an input file in `--flags`, `--cxxflags` or `--ldflags` by its
   absolute path.
8. Pass ccache settings as `--env CCACHE_COMPILER=...`, `CCACHE_PATH` or `CCACHE_PREFIX`, and
   drop `CCACHE_DISABLE`, `CCACHE_NODISABLE` and `CCACHE_CONFIGPATH`.
9. Compare digests, run ids and macro-dump records only between reports of one chard build,
   and artifact digests only under `--normalize`.
10. Read `arch` in a matrix or table as the target's architecture, and expect `machine` in a
    cell's key.
11. Stop chard's child too where a supervisor stops chard, through its cgroup or container.
12. Match diagnostics on ids, rules and `context`, not on text.

Verdicts move where a check now reads a toolchain more exactly; run the checks your gate needs
on each toolchain, profile and architecture it covers before relying on 0.1.0's results.

## 0.1.0

The first publication. `chard_schema` is `1`; the schemas under `schema/` and DESIGN.md
describe the contract as published, and no earlier report, matrix or `detect` output exists for
this file to compare against.
