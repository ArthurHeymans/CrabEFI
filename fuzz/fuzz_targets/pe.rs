#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| crabefi::fuzzing::pe(data));
