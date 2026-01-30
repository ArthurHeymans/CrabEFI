//! Console output helpers for EFI applications
//!
//! Provides simple text output to the EFI console without requiring alloc.

use r_efi::efi::{Char16, SystemTable};
use r_efi::protocols::simple_text_output::Protocol as SimpleTextOutput;

/// Console wrapper for EFI text output
pub struct Console {
    con_out: *mut SimpleTextOutput,
}

impl Console {
    /// Create a new console from the system table
    pub fn new(system_table: *mut SystemTable) -> Self {
        let con_out = unsafe { (*system_table).con_out };
        Self { con_out }
    }

    /// Print a string to the console
    pub fn print(&mut self, s: &str) {
        if self.con_out.is_null() {
            return;
        }

        // Convert to UCS-2 and print in chunks
        let mut buffer: [Char16; 128] = [0; 128];
        let mut buf_idx = 0;

        for c in s.chars() {
            if c == '\n' {
                // Add CRLF for newline
                buffer[buf_idx] = '\r' as Char16;
                buf_idx += 1;
                if buf_idx >= buffer.len() - 2 {
                    buffer[buf_idx] = 0;
                    self.output_buffer(&buffer);
                    buf_idx = 0;
                }
            }

            // Add the character (truncate non-BMP to '?')
            let ch = if c as u32 <= 0xFFFF {
                c as Char16
            } else {
                '?' as Char16
            };

            buffer[buf_idx] = ch;
            buf_idx += 1;

            if buf_idx >= buffer.len() - 2 {
                buffer[buf_idx] = 0;
                self.output_buffer(&buffer);
                buf_idx = 0;
            }
        }

        // Flush remaining
        if buf_idx > 0 {
            buffer[buf_idx] = 0;
            self.output_buffer(&buffer);
        }
    }

    /// Print a string followed by a newline
    pub fn print_line(&mut self, s: &str) {
        self.print(s);
        self.print("\r\n");
    }

    /// Print a hexadecimal value
    pub fn print_hex(&mut self, value: u64) {
        let mut buffer: [Char16; 19] = [0; 19]; // "0x" + 16 hex digits + null
        buffer[0] = '0' as Char16;
        buffer[1] = 'x' as Char16;

        let hex_chars = b"0123456789ABCDEF";
        for i in 0..16 {
            let nibble = ((value >> (60 - i * 4)) & 0xF) as usize;
            buffer[2 + i] = hex_chars[nibble] as Char16;
        }
        buffer[18] = 0;

        // Skip leading zeros (but keep at least one digit)
        let mut start = 2;
        while start < 17 && buffer[start] == '0' as Char16 {
            start += 1;
        }

        // Print from start
        let mut print_buf: [Char16; 19] = [0; 19];
        print_buf[0] = '0' as Char16;
        print_buf[1] = 'x' as Char16;
        for (i, &ch) in buffer[start..].iter().enumerate() {
            print_buf[2 + i] = ch;
            if ch == 0 {
                break;
            }
        }
        self.output_buffer(&print_buf);
    }

    /// Print a decimal value
    pub fn print_dec(&mut self, value: u64) {
        let mut buffer: [Char16; 21] = [0; 21]; // max u64 is 20 digits + null
        let mut idx = 20;
        let mut v = value;

        if v == 0 {
            buffer[idx - 1] = '0' as Char16;
            idx -= 1;
        } else {
            while v > 0 {
                idx -= 1;
                buffer[idx] = ('0' as u64 + (v % 10)) as Char16;
                v /= 10;
            }
        }

        buffer[20] = 0;

        // Create output buffer starting from idx
        let mut print_buf: [Char16; 21] = [0; 21];
        for (i, &ch) in buffer[idx..].iter().enumerate() {
            print_buf[i] = ch;
            if ch == 0 {
                break;
            }
        }
        self.output_buffer(&print_buf);
    }

    /// Print a GUID
    pub fn print_guid(&mut self, guid: &r_efi::efi::Guid) {
        // Format: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
        let (time_low, time_mid, time_hi, clk_hi, clk_low, node) = guid.as_fields();
        self.print("{");
        self.print_hex_8(time_low);
        self.print("-");
        self.print_hex_4(time_mid as u32);
        self.print("-");
        self.print_hex_4(time_hi as u32);
        self.print("-");
        self.print_hex_2(clk_hi);
        self.print_hex_2(clk_low);
        self.print("-");
        for &b in node {
            self.print_hex_2(b);
        }
        self.print("}");
    }

    /// Print 8 hex digits (32-bit value)
    fn print_hex_8(&mut self, value: u32) {
        let hex_chars = b"0123456789ABCDEF";
        let mut buffer: [Char16; 9] = [0; 9];
        for i in 0..8 {
            let nibble = ((value >> (28 - i * 4)) & 0xF) as usize;
            buffer[i] = hex_chars[nibble] as Char16;
        }
        buffer[8] = 0;
        self.output_buffer(&buffer);
    }

    /// Print 4 hex digits (16-bit value)
    fn print_hex_4(&mut self, value: u32) {
        let hex_chars = b"0123456789ABCDEF";
        let mut buffer: [Char16; 5] = [0; 5];
        for i in 0..4 {
            let nibble = ((value >> (12 - i * 4)) & 0xF) as usize;
            buffer[i] = hex_chars[nibble] as Char16;
        }
        buffer[4] = 0;
        self.output_buffer(&buffer);
    }

    /// Print 2 hex digits (8-bit value)
    fn print_hex_2(&mut self, value: u8) {
        let hex_chars = b"0123456789ABCDEF";
        let mut buffer: [Char16; 3] = [0; 3];
        buffer[0] = hex_chars[(value >> 4) as usize] as Char16;
        buffer[1] = hex_chars[(value & 0xF) as usize] as Char16;
        buffer[2] = 0;
        self.output_buffer(&buffer);
    }

    /// Output a null-terminated UCS-2 buffer
    fn output_buffer(&self, buffer: &[Char16]) {
        if self.con_out.is_null() {
            return;
        }
        unsafe {
            let output_string = (*self.con_out).output_string;
            output_string(self.con_out, buffer.as_ptr() as *mut Char16);
        }
    }
}
