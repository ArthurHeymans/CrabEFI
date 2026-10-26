// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared controller transports. Bus discovery, clocks, pads and power remain
//! platform responsibilities; devices use the standard embedded-hal interface.
#![no_std]

pub mod designware;

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests;
