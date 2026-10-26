// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Controller drivers shared by firmware and its UEFI payload, exposed
//! through embedded-hal traits. Discovery, clocks, pads and power remain the
//! platform's responsibility.
#![no_std]

pub mod amd_gpio;
pub mod designware;

#[cfg(test)]
extern crate std;
