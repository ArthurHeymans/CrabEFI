//! Passphrase entry on the serial console and the framebuffer.

use alloc::string::String;
use zeroize::Zeroizing;

use crate::drivers::serial as serial_driver;
use crate::framebuffer_console::FramebufferConsole;
use crate::menu_common::{self, KeyPress};
use crate::time::delay_ms;

/// cryptsetup's interactive limit is 512 characters.
const MAX_PASSPHRASE: usize = 512;
/// The line the passphrase prompt is on (0-based).
const PROMPT_ROW: u32 = 7;

fn line(fb: &mut Option<FramebufferConsole<'_>>, row: u32, text: &str) {
    let _ = core::fmt::Write::write_fmt(
        &mut menu_common::SerialWriter,
        format_args!("\x1b[{};3H{text}", row + 1),
    );
    if let Some(console) = fb {
        console.set_position(2, row);
        let _ = core::fmt::Write::write_str(console, text);
    }
}

/// `name` is the volume's own label (disk data, already sanitized);
/// `place` is where the firmware found it.
fn draw(name: &str, place: &str, error: Option<&str>, fb: &mut Option<FramebufferConsole<'_>>) {
    menu_common::clear_screen(fb);
    let cols = fb.as_ref().map(|c| c.cols() as usize).unwrap_or(80);
    menu_common::draw_header("Encrypted Volume", fb, cols);
    line(fb, 4, &alloc::format!("Volume: {name}"));
    line(fb, 5, &alloc::format!("Disk:   {place}"));
    if let Some(error) = error {
        menu_common::draw_status_message(PROMPT_ROW as usize + 2, error, false, fb);
    }
    menu_common::draw_help(
        PROMPT_ROW as usize + 4,
        "Enter: Unlock | Esc: Back to the boot menu",
        fb,
        cols,
    );
    line(fb, PROMPT_ROW, "Passphrase: ");
}

/// Redraw the masked passphrase: one `*` per character.
fn draw_mask(count: usize, fb: &mut Option<FramebufferConsole<'_>>) {
    let shown = count.min(60);
    let _ = core::fmt::Write::write_fmt(
        &mut menu_common::SerialWriter,
        format_args!("\x1b[{};15H\x1b[K", PROMPT_ROW + 1),
    );
    for _ in 0..shown {
        serial_driver::write_str("*");
    }
    if let Some(console) = fb {
        console.clear_line(PROMPT_ROW);
        console.set_position(2, PROMPT_ROW);
        let _ = core::fmt::Write::write_str(console, "Passphrase: ");
        for _ in 0..shown {
            let _ = core::fmt::Write::write_str(console, "*");
        }
    }
}

/// Read a passphrase; `None` when the user pressed Escape.
pub(super) fn read_passphrase(
    name: &str,
    place: &str,
    error: Option<&str>,
) -> Option<Zeroizing<String>> {
    let config = crate::handoff::framebuffer();
    let mut fb = config.as_ref().map(FramebufferConsole::new);
    draw(name, place, error, &mut fb);
    // Never reallocate: a moved buffer would leave a copy behind.
    let mut passphrase = Zeroizing::new(String::with_capacity(MAX_PASSPHRASE * 4));
    let mut count = 0usize;
    // Also used by the QEMU tests to know when to type.
    log::info!("LUKS2: waiting for a passphrase");
    let result = loop {
        match menu_common::read_key() {
            Some(KeyPress::Enter) => {
                serial_driver::write_str("\r\n");
                break Some(passphrase);
            }
            Some(KeyPress::Escape) => break None,
            Some(KeyPress::Char('\x08' | '\x7f')) => {
                if passphrase.pop().is_some() {
                    count -= 1;
                    draw_mask(count, &mut fb);
                }
            }
            Some(KeyPress::Char('\x15')) => {
                // Ctrl+U clears the line.
                zeroize::Zeroize::zeroize(&mut *passphrase);
                passphrase.reserve(MAX_PASSPHRASE * 4);
                count = 0;
                draw_mask(count, &mut fb);
            }
            Some(KeyPress::Char(c)) if !c.is_control() && count < MAX_PASSPHRASE => {
                passphrase.push(c);
                count += 1;
                draw_mask(count, &mut fb);
            }
            _ => delay_ms(10),
        }
    };
    // Keyboards and the serial decoder must not keep what was typed, also
    // after Escape.
    crate::drivers::keyboard_common::scrub();
    menu_common::scrub_serial_input();
    result
}

/// Tell the user that key derivation is running; it can take seconds.
pub(super) fn show_progress(message: &str) {
    let config = crate::handoff::framebuffer();
    let mut fb = config.as_ref().map(FramebufferConsole::new);
    menu_common::draw_status_message(PROMPT_ROW as usize + 2, message, true, &mut fb);
}

/// Show why the last attempt failed, until a key press.
pub(super) fn show_failure(error: &str) {
    let config = crate::handoff::framebuffer();
    let mut fb = config.as_ref().map(FramebufferConsole::new);
    let cols = fb.as_ref().map(|c| c.cols() as usize).unwrap_or(80);
    menu_common::draw_status_message(PROMPT_ROW as usize + 2, error, false, &mut fb);
    menu_common::draw_help(
        PROMPT_ROW as usize + 4,
        "No attempts left. Press any key to return to the boot menu",
        &mut fb,
        cols,
    );
    while menu_common::read_key().is_none() {
        delay_ms(10);
    }
}

/// Explain why the firmware no longer unlocks volumes, until a key press.
pub(super) fn show_refusal() {
    let config = crate::handoff::framebuffer();
    let mut fb = config.as_ref().map(FramebufferConsole::new);
    menu_common::clear_screen(&mut fb);
    let cols = fb.as_ref().map(|c| c.cols() as usize).unwrap_or(80);
    menu_common::draw_header("Encrypted Volume", &mut fb, cols);
    line(
        &mut fb,
        4,
        "Other boot code has run since power-on, so the firmware no longer",
    );
    line(
        &mut fb,
        5,
        "asks for passphrases. Restart the machine to unlock this volume.",
    );
    menu_common::draw_help(8, "Press any key to return", &mut fb, cols);
    while menu_common::read_key().is_none() {
        delay_ms(10);
    }
}
