// SPDX-License-Identifier: BSD-3-Clause

//! chard: empirical measurement of C/C++ toolchain hardening defaults.

// The house standard's crate-root relief for test code, for the lints clippy.toml's test
// knobs do not reach: `expect`, not `allow`, so the line fails the build once no test needs
// it.
#![cfg_attr(
    test,
    expect(
        clippy::arithmetic_side_effects,
        clippy::as_conversions,
        clippy::string_slice,
        reason = "test code lays out fixture bytes, counts results and slices sources at offsets it found in the same string"
    )
)]

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
pub mod fingerprint;
pub mod fixture;
pub mod guide;
pub mod link_inputs;
pub mod listings;
pub mod matrix;
pub mod measure;
pub mod mechanism;
pub mod overridden;
pub mod predicate;
pub mod probe;
pub mod report;
pub mod run;
pub mod structured;
pub mod table;
pub mod toolchain;
