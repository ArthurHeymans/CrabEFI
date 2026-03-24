//! PS/2 Mouse Driver (i8042 Controller AUX Port)
//!
//! Supports standard 3-button PS/2 mice **and** Synaptics touchpads in
//! absolute mode with TrackPoint pass-through — the configuration found on
//! ThinkPad T480 / T470s / X280 / X1C5 / X1C6 and similar models.
//!
//! # T480 / ThinkPad Architecture
//!
//! On these machines Linux uses SMBus for the Synaptics touchpad (richer
//! protocol, multi-touch).  In our firmware there is no SMBus driver, so
//! the Synaptics runs in basic PS/2 mode as the only device on the AUX
//! port.  The TrackPoint sits behind the Synaptics **pass-through port**
//! and is **invisible** in basic relative mode.
//!
//! To access the TrackPoint we must:
//!  1. Detect the Synaptics (magic E8×4 + E9 identify query).
//!  2. Read its capability register to confirm pass-through support.
//!  3. Switch it to absolute mode (6-byte packets).
//!  4. Recognise pass-through packets and extract the 3-byte TrackPoint
//!     sub-packet (bytes 1, 4, 5 of the 6-byte frame).
//!  5. Also convert the touchpad's absolute X/Y to relative motion so the
//!     touchpad itself still works as a pointing device.
//!
//! # References
//!
//! - `linux/drivers/input/mouse/synaptics.c` — detection, capabilities,
//!   absolute mode, pass-through packet signature
//! - `linux/drivers/input/mouse/trackpoint.c` — TrackPoint protocol
//! - `linux/drivers/input/mouse/psmouse-base.c` — probe ordering, resets
//! - libpayload `payloads/libpayload/drivers/i8042/mouse.c`

use spin::Mutex;
use tock_registers::interfaces::{Readable, Writeable};

use crate::arch::x86_64::port_regs::{PortAliased8, PortReadWrite8};
use crate::drivers::keyboard::{Status, masks, ports};

// ============================================================================
// PS/2 Mouse Constants
// ============================================================================

mod mouse_cmd {
    pub const SET_SAMPLE_RATE: u8 = 0xF3;
    pub const GET_DEVICE_ID: u8 = 0xF2;
    pub const STATUS_REQUEST: u8 = 0xE9; // also used for Synaptics queries
    pub const SET_RESOLUTION: u8 = 0xE8; // also used for Synaptics sliced-cmd
    pub const ENABLE: u8 = 0xF4;
    pub const DISABLE: u8 = 0xF5;
    pub const SET_DEFAULTS: u8 = 0xF6;
    #[allow(dead_code)]
    pub const RESET: u8 = 0xFF;
}

mod aux_cmd {
    pub const ENABLE_AUX: u8 = 0xA8;
    pub const TEST_AUX: u8 = 0xA9;
    pub const WRITE_AUX: u8 = 0xD4;
}

/// Synaptics magic identification byte in the second byte of a GET_INFO
/// response after 4× SET_RESOLUTION 0. (From synaptics.c `synaptics_detect`.)
const SYN_ID_MAGIC: u8 = 0x47;

/// Synaptics capability bit 5 — pass-through port present.
const SYN_CAP_PASS_THROUGH_BIT: u8 = 1 << 5;

/// Synaptics mode byte bits.
///
/// Linux (`synaptics_set_mode()`) builds this from hardware queries:
///   - `SYN_BIT_ABSOLUTE_MODE` (bit 7) — absolute coordinate reporting
///   - `SYN_BIT_DISABLE_GESTURE` (bit 2) — suppress internal gesture
///     processing; without this the touchpad's firmware swallows raw
///     touches and only emits processed gesture events (or nothing at
///     all if no gesture is recognised), resulting in zero data on the
///     wire.  Set for `SYN_ID_MAJOR >= 4` (ours is 8).
///   - `SYN_BIT_W_MODE` (bit 0) — enable extended W field in NEWABS
///     packets.  Set when `SYN_CAP_EXTENDED` (our caps have bit 7 set).
const SYN_MODE_ABSOLUTE: u8 = 0x80;
const SYN_MODE_DISABLE_GESTURE: u8 = 0x04;
const SYN_MODE_W: u8 = 0x01;

/// Synaptics commit rate for `SET_RATE` after a sliced-command mode byte.
const SYN_MODE_COMMIT_RATE: u8 = 0x14; // 20 samples/sec

/// Synaptics pass-through commit rate — used to forward a byte to the
/// TrackPoint: sliced-command(byte) + SET_RATE(SYN_PT_COMMIT_RATE).
const SYN_PT_COMMIT_RATE: u8 = 0xC8; // 200 — SYN_PS_CLIENT_CMD

/// Minimum Z (pressure) to treat a Synaptics touch as intentional.
const SYN_Z_THRESHOLD: i32 = 30;

/// Divisor for converting Synaptics 12-bit absolute coordinates to relative
/// pixel motion. Larger → slower cursor; tune to taste.
const SYN_MOTION_SCALE: i32 = 8;

// ============================================================================
// Protocol
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MouseProtocol {
    /// Standard PS/2 mouse — 3-byte packets.
    Standard,
    /// Microsoft IntelliMouse — 4-byte packets (scroll wheel). Kept for
    /// non-ThinkPad hardware but not actively negotiated; we fall back to
    /// Standard to avoid multiplexing issues on EC-multiplexed ports.
    #[allow(dead_code)]
    IntelliMouse,
    /// Synaptics touchpad in absolute mode — 6-byte packets.
    /// Pass-through (TrackPoint) packets are embedded inside these.
    SynapticsAbsolute,
}

impl MouseProtocol {
    fn packet_size(self) -> usize {
        match self {
            MouseProtocol::Standard => 3,
            MouseProtocol::IntelliMouse => 4,
            MouseProtocol::SynapticsAbsolute => 6,
        }
    }
}

// ============================================================================
// State
// ============================================================================

struct MouseState {
    initialized: bool,
    protocol: MouseProtocol,
    /// Packet assembly buffer — large enough for 6-byte Synaptics packets.
    packet_buf: [u8; 6],
    packet_idx: usize,
    rel_x: i32,
    rel_y: i32,
    rel_z: i32,
    buttons: u32,
    data_port: PortReadWrite8<()>,
    status_port: PortAliased8<Status::Register, ()>,
    // Synaptics absolute → relative state
    /// Previous absolute X (Synaptics 12-bit, 0 = invalid / no finger).
    syn_prev_x: i32,
    /// Previous absolute Y (Synaptics 12-bit, 0 = invalid / no finger).
    syn_prev_y: i32,
    /// Previous Z (pressure, 0 = no contact).
    syn_prev_z: i32,
}

static AUX_FIFO: Mutex<heapless::Deque<u8, 128>> = Mutex::new(heapless::Deque::new());

impl MouseState {
    const fn new() -> Self {
        Self {
            initialized: false,
            protocol: MouseProtocol::Standard,
            packet_buf: [0; 6],
            packet_idx: 0,
            rel_x: 0,
            rel_y: 0,
            rel_z: 0,
            buttons: 0,
            data_port: PortReadWrite8::new(ports::DATA),
            status_port: PortAliased8::new(ports::STATUS_CMD),
            syn_prev_x: 0,
            syn_prev_y: 0,
            syn_prev_z: 0,
        }
    }

    // ── Port helpers ──────────────────────────────────────────────────────────

    fn wait_input_ready(&self) -> bool {
        for _ in 0..10000 {
            if (self.status_port.get() & (1 << 1)) == 0 {
                return true;
            }
            for _ in 0..50 {
                core::hint::spin_loop();
            }
        }
        false
    }

    fn wait_output_ready(&self) -> bool {
        for _ in 0..10000 {
            if (self.status_port.get() & masks::OUTPUT_FULL) != 0 {
                return true;
            }
            for _ in 0..50 {
                core::hint::spin_loop();
            }
        }
        false
    }

    fn wait_aux_output(&self) -> bool {
        for _ in 0..10000 {
            let st = self.status_port.get();
            if (st & masks::OUTPUT_FULL) != 0 && (st & masks::AUX_DATA) != 0 {
                return true;
            }
            for _ in 0..50 {
                core::hint::spin_loop();
            }
        }
        false
    }

    fn send_controller_cmd(&self, cmd: u8) -> bool {
        if !self.wait_input_ready() {
            return false;
        }
        self.status_port.set(cmd);
        self.wait_input_ready()
    }

    /// Send a single byte to the AUX device and wait for ACK (0xFA).
    fn send_mouse_byte(&self, b: u8) -> bool {
        if !self.send_controller_cmd(aux_cmd::WRITE_AUX) {
            return false;
        }
        if !self.wait_input_ready() {
            return false;
        }
        self.data_port.set(b);
        if !self.wait_aux_output() {
            return false;
        }
        self.data_port.get() == 0xFA
    }

    /// Send a two-byte command + argument to the AUX device, both with ACKs.
    fn send_mouse_cmd_data(&self, cmd: u8, data: u8) -> bool {
        self.send_mouse_byte(cmd) && self.send_mouse_byte(data)
    }

    fn read_aux_byte(&self) -> Option<u8> {
        if self.wait_aux_output() {
            Some(self.data_port.get())
        } else {
            None
        }
    }

    /// Drain any pending bytes from the output buffer.
    fn flush(&self) {
        for _ in 0..128 {
            if (self.status_port.get() & masks::OUTPUT_FULL) == 0 {
                break;
            }
            let _ = self.data_port.get();
            for _ in 0..10 {
                core::hint::spin_loop();
            }
        }
    }

    fn has_aux_data(&self) -> bool {
        let st = self.status_port.get();
        (st & masks::OUTPUT_FULL) != 0 && (st & masks::AUX_DATA) != 0
    }

    // ── Synaptics helpers ─────────────────────────────────────────────────────

    /// Encode `byte` as a Synaptics "sliced command": four consecutive
    /// `SET_RESOLUTION` bytes carrying 2 bits each (MSB pair first).
    ///
    /// This is how the Synaptics driver communicates a mode or query byte
    /// without ambiguity on the shared PS/2 bus.
    ///
    /// Reference: `ps2_sliced_command()` in Linux `drivers/input/serio/ps2.c`
    fn synaptics_sliced_cmd(&self, byte: u8) -> bool {
        for shift in [6u8, 4, 2, 0] {
            let pair = (byte >> shift) & 3;
            if !self.send_mouse_byte(mouse_cmd::SET_RESOLUTION) {
                return false;
            }
            if !self.send_mouse_byte(pair) {
                return false;
            }
        }
        true
    }

    /// Read N bytes from the AUX port (no ACK expected — raw data bytes).
    fn read_aux_bytes<const N: usize>(&self) -> Option<[u8; N]> {
        let mut out = [0u8; N];
        for b in &mut out {
            *b = self.read_aux_byte()?;
        }
        Some(out)
    }

    /// Detect a Synaptics touchpad and return (capabilities, has_passthrough).
    ///
    /// Detection sequence (from `synaptics_detect` in Linux `synaptics.c`):
    ///   4× SET_RESOLUTION 0  +  STATUS_REQUEST → read 3 bytes.
    ///   If byte[1] == 0x47 → Synaptics confirmed.
    ///
    /// Capability query (`SYN_QUE_CAPABILITIES = 0x02`):
    ///   sliced_cmd(0x02)  +  STATUS_REQUEST → read 3 bytes.
    ///   Byte[0] bit 5 = pass-through port present.
    fn detect_synaptics(&self) -> Option<bool> {
        // ── Identify ──────────────────────────────────────────────────────────
        if !self.synaptics_sliced_cmd(0x00) {
            return None;
        }
        if !self.send_mouse_byte(mouse_cmd::STATUS_REQUEST) {
            return None;
        }
        let id = self.read_aux_bytes::<3>()?;
        if id[1] != SYN_ID_MAGIC {
            return None; // Not Synaptics
        }
        log::info!(
            "Synaptics touchpad detected (id={:#x},{:#x},{:#x})",
            id[0],
            id[1],
            id[2]
        );

        // ── Capabilities (query 0x02) ─────────────────────────────────────────
        if !self.synaptics_sliced_cmd(0x02) {
            return None;
        }
        if !self.send_mouse_byte(mouse_cmd::STATUS_REQUEST) {
            return None;
        }
        let cap = self.read_aux_bytes::<3>()?;
        let has_pt = (cap[0] & SYN_CAP_PASS_THROUGH_BIT) != 0;
        log::info!(
            "Synaptics caps={:#010b} ext={:#x} pass-through={}",
            cap[0],
            cap[1],
            has_pt
        );
        Some(has_pt)
    }

    /// Switch the Synaptics touchpad to absolute mode.
    ///
    /// The full mode byte is sent as a sliced command followed by
    /// `SET_RATE(SYN_MODE_COMMIT_RATE)`.
    ///
    /// Reference: `synaptics_mode_cmd()` / `synaptics_set_mode()` in
    /// Linux `synaptics.c`.
    fn synaptics_set_absolute_mode(&self) -> bool {
        let mode = SYN_MODE_ABSOLUTE | SYN_MODE_DISABLE_GESTURE | SYN_MODE_W;
        if !self.synaptics_sliced_cmd(mode) {
            return false;
        }
        self.send_mouse_cmd_data(mouse_cmd::SET_SAMPLE_RATE, SYN_MODE_COMMIT_RATE)
    }

    /// Send a byte to the TrackPoint through the Synaptics pass-through port.
    ///
    /// Encoding (from `synaptics_pt_write()` in Linux `synaptics.c`):
    ///   sliced_cmd(byte)  +  SET_RATE(0xC8)
    ///
    /// The Synaptics interprets `SET_RATE(0xC8)` as "forward the buffered
    /// sliced byte to the pass-through device".
    fn synaptics_pt_send(&self, byte: u8) -> bool {
        if !self.synaptics_sliced_cmd(byte) {
            return false;
        }
        self.send_mouse_cmd_data(mouse_cmd::SET_SAMPLE_RATE, SYN_PT_COMMIT_RATE)
    }

    /// Detect Synaptics + enable absolute mode + enable TrackPoint via PT.
    ///
    /// Returns `true` if Synaptics is present and absolute mode was enabled.
    fn try_synaptics_init(&mut self) -> bool {
        match self.detect_synaptics() {
            None => return false,
            Some(has_pt) => {
                if !has_pt {
                    log::info!("Synaptics has no pass-through port, staying in relative mode");
                    return false;
                }
            }
        }

        // Switch to absolute mode
        if !self.synaptics_set_absolute_mode() {
            log::warn!("Failed to set Synaptics absolute mode");
            return false;
        }

        self.protocol = MouseProtocol::SynapticsAbsolute;
        self.packet_idx = 0;
        self.flush();

        log::info!("Synaptics absolute mode enabled");

        // Start data reporting (ENABLE).
        //
        // The touchpad was DISABLE'd during identification above and will not
        // send any packets until it receives ENABLE.  The non-Synaptics path
        // below does the same for standard mice; we must do it here too.
        if !self.send_mouse_byte(mouse_cmd::ENABLE) {
            log::warn!("Failed to enable Synaptics data reporting");
            return false;
        }

        // Enable TrackPoint data reporting through the pass-through port.
        // We send ENABLE (0xF4) to the TrackPoint via the pass-through mechanism.
        // The BIOS may have already done this; sending it again is harmless.
        // We don't check the result because the ACK comes back as a pass-through
        // packet which we haven't started reading yet.
        let _ = self.synaptics_pt_send(mouse_cmd::ENABLE);

        true
    }

    // ── Packet processing ──────────────────────────────────────────────────────

    fn process_byte(&mut self, byte: u8) {
        if self.packet_idx == 0 {
            // Sync check depends on protocol.
            // Standard PS/2: bit 3 of byte 0 is always 1.
            // Synaptics absolute (new-abs): bit 7 = 1, bit 6 = 0.
            //   Pass-through packets also satisfy this (0x84–0x87, 0xC4–0xC7, etc.)
            //   because (byte & 0xC0) == 0x80.
            let valid = match self.protocol {
                MouseProtocol::SynapticsAbsolute => (byte & 0xC0) == 0x80,
                _ => (byte & 0x08) != 0,
            };
            if !valid {
                return;
            }
        }

        self.packet_buf[self.packet_idx] = byte;
        self.packet_idx += 1;

        if self.packet_idx >= self.protocol.packet_size() {
            self.decode_packet();
            self.packet_idx = 0;
        }
    }

    fn decode_packet(&mut self) {
        match self.protocol {
            MouseProtocol::Standard | MouseProtocol::IntelliMouse => {
                self.decode_standard_packet();
            }
            MouseProtocol::SynapticsAbsolute => {
                self.decode_synaptics_packet();
            }
        }
    }

    /// Decode a standard 3-byte PS/2 relative-motion packet.
    fn decode_standard_packet(&mut self) {
        let b0 = self.packet_buf[0];
        let b1 = self.packet_buf[1];
        let b2 = self.packet_buf[2];

        let dx = b1 as i32 - (((b0 as i32) << 4) & 0x100);
        self.rel_x += dx;

        let dy = b2 as i32 - (((b0 as i32) << 3) & 0x100);
        self.rel_y -= dy; // PS/2 Y-up → screen Y-down

        self.buttons = (b0 & 0x07) as u32;
    }

    /// Decode a 6-byte Synaptics absolute-mode packet.
    ///
    /// Two packet types are handled:
    ///
    /// 1. **Pass-through** (TrackPoint data):
    ///    `(buf[0] & 0xFC) == 0x84 && (buf[3] & 0xCC) == 0xC4`
    ///    Data bytes: buf[1] = PS/2 byte0 (buttons+signs), buf[4] = ΔX, buf[5] = ΔY.
    ///    Decoded as a standard 3-byte PS/2 relative packet.
    ///
    /// 2. **Synaptics touchpad** (absolute position):
    ///    NEWABS format:
    ///      X = ((buf[3]&0x10)<<8) | ((buf[1]&0x0f)<<8) | buf[4]
    ///      Y = ((buf[3]&0x20)<<7) | ((buf[1]&0xf0)<<4) | buf[5]
    ///      Z = buf[2]
    ///    Converted to relative motion by differencing consecutive positions
    ///    while Z > threshold.
    ///
    /// Reference: `synaptics_is_pt_packet()`, `synaptics_pass_pt_packet()`,
    ///            `synaptics_parse_hw_state()` in Linux `synaptics.c`.
    fn decode_synaptics_packet(&mut self) {
        let buf = self.packet_buf;

        // ── Pass-through check (TrackPoint data) ──────────────────────────────
        // Signature from Linux `synaptics_is_pt_packet()`.
        if (buf[0] & 0xFC) == 0x84 && (buf[3] & 0xCC) == 0xC4 {
            // TrackPoint 3-byte PS/2 packet is at bytes 1, 4, 5.
            // (byte 2 would carry the 4th byte if TrackPoint were in IntelliMouse
            //  mode, but we keep TrackPoint in Standard 3-byte mode.)
            let tp0 = buf[1]; // buttons (L/R/M) + X/Y overflow/sign bits
            let tp1 = buf[4]; // X delta
            let tp2 = buf[5]; // Y delta

            let dx = tp1 as i32 - (((tp0 as i32) << 4) & 0x100);
            self.rel_x += dx;

            let dy = tp2 as i32 - (((tp0 as i32) << 3) & 0x100);
            self.rel_y -= dy;

            self.buttons = (tp0 & 0x07) as u32;
            return;
        }

        // ── Synaptics absolute touchpad motion ────────────────────────────────
        // New-abs format (all modern Synaptics devices).
        // Reference: `synaptics_parse_hw_state()`, NEWABS branch in Linux.
        let x =
            (((buf[3] as u32 & 0x10) << 8) | ((buf[1] as u32 & 0x0f) << 8) | buf[4] as u32) as i32;
        let y =
            (((buf[3] as u32 & 0x20) << 7) | ((buf[1] as u32 & 0xf0) << 4) | buf[5] as u32) as i32;
        let z = buf[2] as i32;

        // Buttons (left = bit 0, right = bit 1 of byte 0)
        self.buttons = (buf[0] & 0x03) as u32;

        if z > SYN_Z_THRESHOLD && self.syn_prev_z > SYN_Z_THRESHOLD {
            // Only count motion when there was continuous contact.
            let dx = x - self.syn_prev_x;
            let dy = y - self.syn_prev_y;
            self.rel_x += dx / SYN_MOTION_SCALE;
            self.rel_y -= dy / SYN_MOTION_SCALE; // Synaptics Y-up → screen Y-down
        }

        self.syn_prev_x = x;
        self.syn_prev_y = y;
        self.syn_prev_z = z;
    }
}

// ============================================================================
// Global state
// ============================================================================

static MOUSE: Mutex<MouseState> = Mutex::new(MouseState::new());

// ============================================================================
// Public API
// ============================================================================

/// Forward an AUX byte captured by the keyboard driver.
pub fn push_aux_byte(byte: u8) {
    let mut fifo = AUX_FIFO.lock();
    let _ = fifo.push_back(byte);
}

/// Initialize the PS/2 mouse.
///
/// After basic PS/2 init, detects whether the AUX device is a Synaptics
/// touchpad.  If so, switches it to absolute mode and enables TrackPoint
/// pass-through — this is the path required on ThinkPad T480 / T470s /
/// X280 and similar models.
pub fn init() {
    let mut mouse = MOUSE.lock();
    if mouse.initialized {
        return;
    }

    log::debug!("Initializing PS/2 mouse");

    if mouse.status_port.get() == 0xFF {
        log::debug!("No i8042 controller");
        return;
    }

    // ── Ensure AUX clock is running ───────────────────────────────────────────
    // keyboard::init() may have left AUX_DISABLE (bit 5) set in the
    // controller config byte, preventing any AUX communication.
    if mouse.send_controller_cmd(0x20) {
        if mouse.wait_output_ready() {
            let mut cfg = mouse.data_port.get();
            if cfg & (1 << 5) != 0 {
                cfg &= !(1 << 5);
                if mouse.send_controller_cmd(0x60) {
                    let _ = mouse.wait_input_ready();
                    mouse.data_port.set(cfg);
                }
            }
        }
    }

    mouse.flush();

    // ── AUX port self-test ────────────────────────────────────────────────────
    if !mouse.send_controller_cmd(aux_cmd::TEST_AUX) {
        log::debug!("AUX port test failed");
        return;
    }
    if !mouse.wait_output_ready() {
        log::debug!("AUX port test timeout");
        return;
    }
    let test = mouse.data_port.get();
    if test != 0x00 {
        log::debug!("AUX port test returned {:#x}", test);
        return;
    }

    // Enable AUX port (0xA8); response may be absent on Lenovo H8 EC.
    let _ = mouse.send_controller_cmd(aux_cmd::ENABLE_AUX);
    mouse.flush();

    // ── Basic PS/2 handshake (talks to the primary AUX device) ───────────────
    if !mouse.send_mouse_byte(mouse_cmd::DISABLE) {
        log::debug!("No AUX device responded to DISABLE");
        return;
    }
    if !mouse.send_mouse_byte(mouse_cmd::GET_DEVICE_ID) {
        log::debug!("GET_DEVICE_ID failed");
        return;
    }
    let id = mouse.read_aux_byte();
    if id != Some(0x00) {
        log::debug!("Unexpected device ID: {:?}", id);
        return;
    }

    // ── Try Synaptics absolute mode (required for ThinkPad TrackPoint) ────────
    //
    // If the AUX device is a Synaptics touchpad, switch it to absolute mode
    // so that TrackPoint pass-through packets become available.  The basic
    // DISABLE / GET_DEVICE_ID above always succeeds for Synaptics (it reports
    // ID 0x00 in basic mode), so we attempt the Synaptics init unconditionally
    // and fall back to Standard if it fails.
    let synaptics_ok = mouse.try_synaptics_init();

    if !synaptics_ok {
        // Standard PS/2 mouse (or Synaptics without pass-through — use relative mode)
        mouse.protocol = MouseProtocol::Standard;
        mouse.send_mouse_byte(mouse_cmd::SET_DEFAULTS);
        if !mouse.send_mouse_byte(mouse_cmd::ENABLE) {
            log::warn!("Failed to enable mouse data reporting");
            return;
        }
    }

    mouse.initialized = true;
    log::info!("PS/2 mouse initialized (protocol: {:?})", mouse.protocol);
}

/// Poll for new data from both the FIFO (filled by keyboard driver) and
/// directly from the i8042 output buffer.
pub fn poll() {
    let mut mouse = MOUSE.lock();
    if !mouse.initialized {
        return;
    }

    // Drain the FIFO filled by keyboard::try_read_key()
    {
        let mut fifo = AUX_FIFO.lock();
        while let Some(byte) = fifo.pop_front() {
            mouse.process_byte(byte);
        }
    }

    // Also poll the i8042 directly for any pending AUX bytes
    for _ in 0..64 {
        if !mouse.has_aux_data() {
            break;
        }
        let byte = mouse.data_port.get();
        mouse.process_byte(byte);
    }
}

/// Get and reset accumulated relative motion.
pub fn get_relative_motion() -> (i32, i32, i32) {
    let mut mouse = MOUSE.lock();
    let (dx, dy, dz) = (mouse.rel_x, mouse.rel_y, mouse.rel_z);
    mouse.rel_x = 0;
    mouse.rel_y = 0;
    mouse.rel_z = 0;
    (dx, dy, dz)
}

/// Get current button state bitmask (bit 0=left, 1=right, 2=middle).
pub fn get_buttons() -> u32 {
    MOUSE.lock().buttons
}

/// Returns `true` if the PS/2 mouse (or Synaptics+TrackPoint) is ready.
pub fn is_available() -> bool {
    MOUSE.lock().initialized
}
