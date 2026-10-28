//! Host tests for the payload's table parser, using the real supporting types.
#![no_std]
#![cfg(test)]
#![allow(dead_code)]

extern crate alloc;
extern crate std;

mod acpi;
mod framebuffer;
mod memory;
mod tables;
