// SPDX-License-Identifier: BSD-3-Clause

//! chard — empirical measurement of C/C++ toolchain hardening defaults.
//!
//! chard answers "which hardening flags were *actually* in effect for this
//! build?" by measuring artifacts and behavior rather than reading a distro's
//! packaging spec. See `DESIGN.md` for the four observation channels, the
//! control-triple validation scheme, and the verdict vocabulary; the output
//! contract is `schema/chard-report.schema.json`.
//!
//! The whole tool is one static binary with the C probe corpus embedded
//! (`probe::CORPUS` via `include_str!`), so it can be copied into any guest
//! image and run with nothing present but the toolchain under test.
//!
//! ## Why the lint wall
//!
//! chard parses ELF files produced by compilers we have never seen, on
//! architectures we may not have tested, and runs programs that are *designed*
//! to crash. A panic in the parser would abort a sweep partway through and —
//! worse for this project — a partial sweep that looks like a completed one is
//! how a false "flag off" gets published. Malformed input must yield a typed
//! error that lands in the report as `probe-invalid`, never a crash.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_lossless,
        clippy::unused_result_ok,
        clippy::let_underscore_must_use,
        clippy::map_err_ignore,
        clippy::allow_attributes_without_reason,
    )
)]
// The modules' half of `main.rs`'s rule: a `println!` anywhere in chard is a panic on a
// closed pipe, and the binary's own lint does not reach this crate. Output goes through
// `write_stdout` in `main.rs`.
#![deny(clippy::print_stdout)]

pub mod compile;
pub mod compile_inputs;
pub mod composite;
pub mod dataset;
pub mod decode;
pub mod detect;
pub mod digest;
pub mod elf;
pub mod env;
pub mod error;
pub mod fixture;
pub mod guide;
pub mod link_inputs;
pub mod matrix;
pub mod measure;
pub mod mechanism;
pub mod predicate;
pub mod probe;
pub mod report;
pub mod run;
pub mod structured;
pub mod table;
pub mod toolchain;
