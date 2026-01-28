//! PS/2 Keyboard Driver (i8042 Controller)
//!
//! This module provides a driver for the Intel 8042 keyboard controller,
//! which is the standard PS/2 keyboard interface on x86 systems.
//!
//! # Scancode Translation
//!
//! The keyboard is configured to use scancode set 1 (or set 2 with controller
//! translation enabled), which is the IBM PC/AT compatible format.
//!
//! # References
//!
//! - libpayload: `payloads/libpayload/drivers/i8042/keyboard.c`
//! - OSDev Wiki: https://wiki.osdev.org/PS/2_Keyboard

use spin::Mutex;

/// i8042 controller I/O ports
mod ports {
    /// Data port (read/write)
    pub const DATA: u16 = 0x60;
    /// Status register (read) / Command register (write)
    pub const STATUS_CMD: u16 = 0x64;
}

/// Status register bits
mod status {
    /// Output buffer full - data available to read
    pub const OUTPUT_FULL: u8 = 1 << 0;
    /// Input buffer full - controller busy
    pub const INPUT_FULL: u8 = 1 << 1;
    /// Data is from auxiliary device (mouse) if set
    pub const AUX_DATA: u8 = 1 << 5;
}

/// Controller commands (written to port 0x64)
mod cmd {
    /// Read controller configuration byte
    pub const READ_CONFIG: u8 = 0x20;
    /// Write controller configuration byte
    pub const WRITE_CONFIG: u8 = 0x60;
    /// Disable auxiliary (mouse) port
    pub const DISABLE_AUX: u8 = 0xA7;
    /// Enable auxiliary (mouse) port
    pub const ENABLE_AUX: u8 = 0xA8;
    /// Test auxiliary port
    pub const TEST_AUX: u8 = 0xA9;
    /// Controller self-test
    pub const SELF_TEST: u8 = 0xAA;
    /// Test keyboard port
    pub const TEST_KB: u8 = 0xAB;
    /// Disable keyboard port
    pub const DISABLE_KB: u8 = 0xAD;
    /// Enable keyboard port
    pub const ENABLE_KB: u8 = 0xAE;
}

/// Keyboard commands (written to port 0x60)
mod kb_cmd {
    /// Set LEDs (followed by LED byte)
    pub const SET_LEDS: u8 = 0xED;
    /// Echo (for testing)
    pub const ECHO: u8 = 0xEE;
    /// Set scancode set
    pub const SET_SCANCODE: u8 = 0xF0;
    /// Enable scanning
    pub const ENABLE: u8 = 0xF4;
    /// Disable scanning
    pub const DISABLE: u8 = 0xF5;
    /// Set default parameters
    pub const SET_DEFAULT: u8 = 0xF6;
    /// Reset and self-test
    pub const RESET: u8 = 0xFF;
}

/// Configuration byte bits
mod config {
    /// Enable keyboard interrupt (IRQ1)
    pub const KB_INT: u8 = 1 << 0;
    /// Enable auxiliary interrupt (IRQ12)
    pub const AUX_INT: u8 = 1 << 1;
    /// System flag (POST passed)
    pub const SYSTEM: u8 = 1 << 2;
    /// Disable keyboard clock
    pub const KB_DISABLE: u8 = 1 << 4;
    /// Disable auxiliary clock
    pub const AUX_DISABLE: u8 = 1 << 5;
    /// Enable scancode translation (set 2 -> set 1)
    pub const TRANSLATION: u8 = 1 << 6;
}

/// Keyboard response codes
mod response {
    /// Command acknowledged
    pub const ACK: u8 = 0xFA;
    /// Resend last command
    pub const RESEND: u8 = 0xFE;
    /// Self-test passed
    pub const SELF_TEST_PASS: u8 = 0xAA;
    /// Echo response
    pub const ECHO: u8 = 0xEE;
}

/// Modifier key state
#[derive(Clone, Copy, Default)]
struct Modifiers {
    shift: bool,
    ctrl: bool,
    alt: bool,
    caps_lock: bool,
}

/// Keyboard driver state
struct KeyboardState {
    /// Whether the keyboard has been initialized
    initialized: bool,
    /// Current modifier key state
    modifiers: Modifiers,
    /// Whether we're in an extended scancode sequence (0xE0 prefix)
    extended: bool,
}

impl KeyboardState {
    const fn new() -> Self {
        KeyboardState {
            initialized: false,
            modifiers: Modifiers {
                shift: false,
                ctrl: false,
                alt: false,
                caps_lock: false,
            },
            extended: false,
        }
    }
}

/// Global keyboard state
static KEYBOARD: Mutex<KeyboardState> = Mutex::new(KeyboardState::new());

/// Read a byte from an I/O port
#[inline]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    core::arch::asm!(
        "in al, dx",
        out("al") value,
        in("dx") port,
        options(nostack, preserves_flags)
    );
    value
}

/// Write a byte to an I/O port
#[inline]
unsafe fn outb(port: u16, value: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") value,
        options(nostack, preserves_flags)
    );
}

/// Wait for the controller input buffer to be empty (ready to accept commands)
fn wait_input_ready() -> bool {
    for _ in 0..10000 {
        unsafe {
            if (inb(ports::STATUS_CMD) & status::INPUT_FULL) == 0 {
                return true;
            }
        }
        // Small delay
        for _ in 0..50 {
            core::hint::spin_loop();
        }
    }
    false
}

/// Wait for data to be available in the output buffer
fn wait_output_ready() -> bool {
    for _ in 0..10000 {
        unsafe {
            if (inb(ports::STATUS_CMD) & status::OUTPUT_FULL) != 0 {
                return true;
            }
        }
        // Small delay
        for _ in 0..50 {
            core::hint::spin_loop();
        }
    }
    false
}

/// Send a command to the controller (port 0x64)
fn send_controller_cmd(cmd: u8) -> bool {
    if !wait_input_ready() {
        return false;
    }
    unsafe {
        outb(ports::STATUS_CMD, cmd);
    }
    wait_input_ready()
}

/// Send a command to the keyboard (port 0x60) and wait for ACK
fn send_keyboard_cmd(cmd: u8) -> bool {
    if !wait_input_ready() {
        return false;
    }
    unsafe {
        outb(ports::DATA, cmd);
    }

    // Wait for response
    if !wait_output_ready() {
        return false;
    }

    unsafe {
        let response = inb(ports::DATA);
        response == response::ACK
    }
}

/// Flush any pending data from the controller
fn flush_output() {
    for _ in 0..100 {
        unsafe {
            if (inb(ports::STATUS_CMD) & status::OUTPUT_FULL) == 0 {
                break;
            }
            let _ = inb(ports::DATA);
        }
        for _ in 0..10 {
            core::hint::spin_loop();
        }
    }
}

/// Initialize the keyboard controller and keyboard
pub fn init() {
    let mut kb = KEYBOARD.lock();

    if kb.initialized {
        return;
    }

    log::debug!("Initializing PS/2 keyboard controller");

    // Check if controller exists
    unsafe {
        if inb(ports::STATUS_CMD) == 0xFF {
            log::warn!("No PS/2 keyboard controller found");
            return;
        }
    }

    // Disable both ports during initialization
    send_controller_cmd(cmd::DISABLE_KB);
    send_controller_cmd(cmd::DISABLE_AUX);

    // Flush any pending data
    flush_output();

    // Perform controller self-test
    if !send_controller_cmd(cmd::SELF_TEST) {
        log::warn!("PS/2 controller self-test command failed");
        return;
    }

    if !wait_output_ready() {
        log::warn!("PS/2 controller self-test timeout");
        return;
    }

    unsafe {
        let result = inb(ports::DATA);
        if result != 0x55 {
            log::warn!("PS/2 controller self-test failed: {:#x}", result);
            return;
        }
    }

    // Test keyboard port
    if !send_controller_cmd(cmd::TEST_KB) {
        log::warn!("PS/2 keyboard port test command failed");
        return;
    }

    if !wait_output_ready() {
        log::warn!("PS/2 keyboard port test timeout");
        return;
    }

    unsafe {
        let result = inb(ports::DATA);
        if result != 0x00 {
            log::warn!("PS/2 keyboard port test failed: {:#x}", result);
            return;
        }
    }

    // Enable keyboard port
    send_controller_cmd(cmd::ENABLE_KB);

    // Read and modify controller configuration
    if !send_controller_cmd(cmd::READ_CONFIG) {
        log::warn!("Failed to read PS/2 controller config");
        return;
    }

    if !wait_output_ready() {
        log::warn!("PS/2 controller config read timeout");
        return;
    }

    let mut config_byte = unsafe { inb(ports::DATA) };

    // Enable translation (scancode set 2 -> set 1) and disable interrupts
    // We poll the keyboard instead of using interrupts
    config_byte |= config::TRANSLATION;
    config_byte &= !config::KB_INT;
    config_byte &= !config::AUX_INT;

    if !send_controller_cmd(cmd::WRITE_CONFIG) {
        log::warn!("Failed to write PS/2 controller config");
        return;
    }

    if !wait_input_ready() {
        return;
    }

    unsafe {
        outb(ports::DATA, config_byte);
    }

    // Enable keyboard scanning
    if !send_keyboard_cmd(kb_cmd::ENABLE) {
        log::warn!("Failed to enable keyboard scanning");
        // Continue anyway - might still work
    }

    kb.initialized = true;
    log::info!("PS/2 keyboard initialized");
}

/// Check if keyboard data is available (PS/2 or USB)
pub fn has_key() -> bool {
    // Check USB keyboard first
    if crate::drivers::usb::keyboard_has_key() {
        return true;
    }

    // Check PS/2 keyboard
    let kb = KEYBOARD.lock();
    if !kb.initialized {
        return false;
    }
    drop(kb);

    unsafe {
        let status = inb(ports::STATUS_CMD);
        // Check output buffer full and not from auxiliary device
        (status & status::OUTPUT_FULL) != 0 && (status & status::AUX_DATA) == 0
    }
}

/// Cleanup the keyboard controller before ExitBootServices
///
/// This re-enables keyboard interrupts (IRQ1) so Linux can properly
/// initialize the i8042 driver. Without this, the keyboard may not
/// work after booting Linux.
pub fn cleanup() {
    let kb = KEYBOARD.lock();
    if !kb.initialized {
        return;
    }
    drop(kb);

    log::debug!("Cleaning up PS/2 keyboard controller for OS handoff");

    // Read current controller configuration
    if !send_controller_cmd(cmd::READ_CONFIG) {
        log::warn!("Failed to read PS/2 controller config during cleanup");
        return;
    }

    if !wait_output_ready() {
        log::warn!("PS/2 controller config read timeout during cleanup");
        return;
    }

    let mut config_byte = unsafe { inb(ports::DATA) };

    // Re-enable keyboard interrupt (IRQ1) for the OS
    // Keep translation enabled as most OSes expect scancode set 1
    config_byte |= config::KB_INT;

    if !send_controller_cmd(cmd::WRITE_CONFIG) {
        log::warn!("Failed to write PS/2 controller config during cleanup");
        return;
    }

    if !wait_input_ready() {
        return;
    }

    unsafe {
        outb(ports::DATA, config_byte);
    }

    log::debug!("PS/2 keyboard controller ready for OS (IRQ1 enabled)");
}

/// Try to read a key from the keyboard (PS/2 or USB)
///
/// Returns Some((scan_code, unicode_char)) if a key is available, None otherwise.
/// The scan_code and unicode_char follow EFI conventions:
/// - For printable characters: scan_code = 0, unicode_char = ASCII code
/// - For special keys: scan_code = EFI scan code, unicode_char = 0
pub fn try_read_key() -> Option<(u16, u16)> {
    // Try USB keyboard first
    if let Some(key) = crate::drivers::usb::keyboard_get_key() {
        return Some(key);
    }

    // Fall back to PS/2 keyboard
    let mut kb = KEYBOARD.lock();

    if !kb.initialized {
        return None;
    }

    unsafe {
        let status = inb(ports::STATUS_CMD);

        // Check if keyboard data is available (not mouse data)
        if (status & status::OUTPUT_FULL) == 0 {
            return None;
        }

        if (status & status::AUX_DATA) != 0 {
            // Mouse data, discard it
            let _ = inb(ports::DATA);
            return None;
        }

        let scancode = inb(ports::DATA);

        // Handle the scancode
        process_scancode(&mut kb, scancode)
    }
}

/// Process a scancode and return the corresponding EFI key
fn process_scancode(kb: &mut KeyboardState, scancode: u8) -> Option<(u16, u16)> {
    // Extended scancode prefix
    if scancode == 0xE0 {
        kb.extended = true;
        return None;
    }

    // Key release (high bit set)
    let is_release = (scancode & 0x80) != 0;
    let code = scancode & 0x7F;

    let extended = kb.extended;
    kb.extended = false;

    // Handle modifier keys
    if !extended {
        match code {
            0x2A | 0x36 => {
                // Left/Right Shift
                kb.modifiers.shift = !is_release;
                return None;
            }
            0x1D => {
                // Left Control
                kb.modifiers.ctrl = !is_release;
                return None;
            }
            0x38 => {
                // Left Alt
                kb.modifiers.alt = !is_release;
                return None;
            }
            0x3A if !is_release => {
                // Caps Lock toggle
                kb.modifiers.caps_lock = !kb.modifiers.caps_lock;
                return None;
            }
            _ => {}
        }
    } else {
        match code {
            0x1D => {
                // Right Control
                kb.modifiers.ctrl = !is_release;
                return None;
            }
            0x38 => {
                // Right Alt
                kb.modifiers.alt = !is_release;
                return None;
            }
            _ => {}
        }
    }

    // Only process key presses, not releases
    if is_release {
        return None;
    }

    // Convert scancode to EFI key
    if extended {
        scancode_to_efi_extended(code)
    } else {
        scancode_to_efi_normal(kb, code)
    }
}

/// Convert extended scancode (after 0xE0 prefix) to EFI key
fn scancode_to_efi_extended(code: u8) -> Option<(u16, u16)> {
    // EFI scan codes
    const SCAN_UP: u16 = 0x01;
    const SCAN_DOWN: u16 = 0x02;
    const SCAN_RIGHT: u16 = 0x03;
    const SCAN_LEFT: u16 = 0x04;
    const SCAN_HOME: u16 = 0x05;
    const SCAN_END: u16 = 0x06;
    const SCAN_INSERT: u16 = 0x07;
    const SCAN_DELETE: u16 = 0x08;
    const SCAN_PAGE_UP: u16 = 0x09;
    const SCAN_PAGE_DOWN: u16 = 0x0A;

    let scan_code = match code {
        0x48 => SCAN_UP,
        0x50 => SCAN_DOWN,
        0x4D => SCAN_RIGHT,
        0x4B => SCAN_LEFT,
        0x47 => SCAN_HOME,
        0x4F => SCAN_END,
        0x52 => SCAN_INSERT,
        0x53 => SCAN_DELETE,
        0x49 => SCAN_PAGE_UP,
        0x51 => SCAN_PAGE_DOWN,
        _ => return None,
    };

    Some((scan_code, 0))
}

/// Convert normal scancode to EFI key
fn scancode_to_efi_normal(kb: &KeyboardState, code: u8) -> Option<(u16, u16)> {
    // EFI scan codes for function keys
    const SCAN_F1: u16 = 0x0B;
    const SCAN_F2: u16 = 0x0C;
    const SCAN_F3: u16 = 0x0D;
    const SCAN_F4: u16 = 0x0E;
    const SCAN_F5: u16 = 0x0F;
    const SCAN_F6: u16 = 0x10;
    const SCAN_F7: u16 = 0x11;
    const SCAN_F8: u16 = 0x12;
    const SCAN_F9: u16 = 0x13;
    const SCAN_F10: u16 = 0x14;
    const SCAN_F11: u16 = 0x15;
    const SCAN_F12: u16 = 0x16;
    const SCAN_ESC: u16 = 0x17;

    // Function keys and Escape
    let scan_code = match code {
        0x01 => SCAN_ESC,
        0x3B => SCAN_F1,
        0x3C => SCAN_F2,
        0x3D => SCAN_F3,
        0x3E => SCAN_F4,
        0x3F => SCAN_F5,
        0x40 => SCAN_F6,
        0x41 => SCAN_F7,
        0x42 => SCAN_F8,
        0x43 => SCAN_F9,
        0x44 => SCAN_F10,
        0x57 => SCAN_F11,
        0x58 => SCAN_F12,
        _ => 0,
    };

    if scan_code != 0 {
        return Some((scan_code, 0));
    }

    // Regular character keys
    let shift = kb.modifiers.shift;
    let caps = kb.modifiers.caps_lock;
    let ctrl = kb.modifiers.ctrl;

    // US keyboard layout - unshifted characters
    #[rustfmt::skip]
    static UNSHIFTED: [u8; 89] = [
        0,    0x1B, b'1', b'2', b'3', b'4', b'5', b'6',     // 0x00-0x07
        b'7', b'8', b'9', b'0', b'-', b'=', 0x08, b'\t',    // 0x08-0x0F
        b'q', b'w', b'e', b'r', b't', b'y', b'u', b'i',     // 0x10-0x17
        b'o', b'p', b'[', b']', 0x0D, 0,    b'a', b's',     // 0x18-0x1F
        b'd', b'f', b'g', b'h', b'j', b'k', b'l', b';',     // 0x20-0x27
        b'\'', b'`', 0,   b'\\', b'z', b'x', b'c', b'v',    // 0x28-0x2F
        b'b', b'n', b'm', b',', b'.', b'/', 0,    b'*',     // 0x30-0x37
        0,    b' ', 0,    0,    0,    0,    0,    0,        // 0x38-0x3F
        0,    0,    0,    0,    0,    0,    0,    b'7',     // 0x40-0x47
        b'8', b'9', b'-', b'4', b'5', b'6', b'+', b'1',     // 0x48-0x4F
        b'2', b'3', b'0', b'.', 0,    0,    0,    0,        // 0x50-0x57
        0,                                                  // 0x58
    ];

    // US keyboard layout - shifted characters
    #[rustfmt::skip]
    static SHIFTED: [u8; 89] = [
        0,    0x1B, b'!', b'@', b'#', b'$', b'%', b'^',     // 0x00-0x07
        b'&', b'*', b'(', b')', b'_', b'+', 0x08, b'\t',    // 0x08-0x0F
        b'Q', b'W', b'E', b'R', b'T', b'Y', b'U', b'I',     // 0x10-0x17
        b'O', b'P', b'{', b'}', 0x0D, 0,    b'A', b'S',     // 0x18-0x1F
        b'D', b'F', b'G', b'H', b'J', b'K', b'L', b':',     // 0x20-0x27
        b'"', b'~', 0,    b'|', b'Z', b'X', b'C', b'V',     // 0x28-0x2F
        b'B', b'N', b'M', b'<', b'>', b'?', 0,    b'*',     // 0x30-0x37
        0,    b' ', 0,    0,    0,    0,    0,    0,        // 0x38-0x3F
        0,    0,    0,    0,    0,    0,    0,    b'7',     // 0x40-0x47
        b'8', b'9', b'-', b'4', b'5', b'6', b'+', b'1',     // 0x48-0x4F
        b'2', b'3', b'0', b'.', 0,    0,    0,    0,        // 0x50-0x57
        0,                                                  // 0x58
    ];

    if code as usize >= UNSHIFTED.len() {
        return None;
    }

    let mut ch = if shift {
        SHIFTED[code as usize]
    } else {
        UNSHIFTED[code as usize]
    };

    if ch == 0 {
        return None;
    }

    // Apply caps lock to letters
    if caps && ch.is_ascii_alphabetic() {
        if shift {
            ch = ch.to_ascii_lowercase();
        } else {
            ch = ch.to_ascii_uppercase();
        }
    }

    // Apply control modifier
    if ctrl && ch.is_ascii_alphabetic() {
        ch = ch.to_ascii_lowercase() - b'a' + 1;
    }

    Some((0, ch as u16))
}
