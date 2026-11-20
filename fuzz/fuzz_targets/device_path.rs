#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| crabefi::fuzzing::device_path(data));
