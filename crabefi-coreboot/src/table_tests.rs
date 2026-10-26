//! Host tests for the payload's table parser, using the real supporting types.
#![no_std]
#![cfg(test)]
#![allow(dead_code)]

extern crate alloc;
extern crate std;

#[cfg(feature = "ui")]
mod acpi;
#[cfg(feature = "ui")]
mod touchpad;

mod framebuffer;
mod memory;
mod tables;
