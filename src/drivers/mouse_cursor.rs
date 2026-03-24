//! Unified Mouse Cursor Abstraction
//!
//! Aggregates mouse input from PS/2 and USB HID mouse drivers into a single
//! cursor position with acceleration and speed control.
//!
//! This follows the same pattern as libpayload's `drivers/mouse_cursor.c`:
//! relative deltas from all input sources are accumulated, optionally
//! accelerated, and converted to an absolute cursor position.
//!
//! # Coordinate Model
//!
//! - Internal accumulators use 1/256 fixed-point for sub-pixel precision
//! - Public API returns integer pixel coordinates
//! - Absolute position is clamped to screen boundaries

use spin::Mutex;

// ============================================================================
// Configuration
// ============================================================================

/// Default acceleration threshold (in raw delta units).
///
/// If the distance of a single mouse poll exceeds this value,
/// the speed multiplier is applied.
const DEFAULT_ACCELERATION_THRESHOLD: u32 = 16;

/// Default speed multiplier (in 1/256 fixed-point units).
///
/// ~2.6x acceleration when above threshold. Equivalent to 0x299
/// from libpayload.
const DEFAULT_SPEED: u32 = 0x299;

/// Base multiplier for non-accelerated movement (1x in 1/256 fixed-point).
const BASE_SPEED: u32 = 256;

// ============================================================================
// Cursor State
// ============================================================================

/// Mouse cursor state
struct CursorState {
    /// Whether the cursor system is initialized
    initialized: bool,
    /// Current absolute X position (pixels)
    abs_x: i32,
    /// Current absolute Y position (pixels)
    abs_y: i32,
    /// Screen width (pixels)
    screen_w: u32,
    /// Screen height (pixels)
    screen_h: u32,
    /// Acceleration threshold (raw delta units)
    acceleration: u32,
    /// Speed multiplier (1/256 fixed-point)
    speed: u32,
    /// Accumulated button state from all sources
    buttons: u32,
    /// Previous frame's button state (for edge detection)
    prev_buttons: u32,
    /// Pending click events (rising-edge: 0→1 transitions, consumed on read)
    click_pending: u32,
    /// Accumulated scroll delta
    scroll: i32,
}

impl CursorState {
    const fn new() -> Self {
        Self {
            initialized: false,
            abs_x: 0,
            abs_y: 0,
            screen_w: 0,
            screen_h: 0,
            acceleration: DEFAULT_ACCELERATION_THRESHOLD,
            speed: DEFAULT_SPEED,
            buttons: 0,
            prev_buttons: 0,
            click_pending: 0,
            scroll: 0,
        }
    }
}

static CURSOR: Mutex<CursorState> = Mutex::new(CursorState::new());

// ============================================================================
// Public API
// ============================================================================

/// Initialize the mouse cursor system.
///
/// # Arguments
/// * `screen_width` - Display width in pixels
/// * `screen_height` - Display height in pixels
pub fn init(screen_width: u32, screen_height: u32) {
    let mut cursor = CURSOR.lock();
    cursor.screen_w = screen_width;
    cursor.screen_h = screen_height;
    // Start cursor at center of screen
    cursor.abs_x = screen_width as i32 / 2;
    cursor.abs_y = screen_height as i32 / 2;
    cursor.initialized = true;

    // Initialize PS/2 mouse (x86 only)
    #[cfg(target_arch = "x86_64")]
    super::mouse::init();

    log::info!(
        "Mouse cursor initialized ({}x{}, start at {}, {})",
        screen_width,
        screen_height,
        cursor.abs_x,
        cursor.abs_y
    );
}

/// Poll all mouse input sources and update cursor position.
///
/// Should be called from the main event loop.
pub fn poll() {
    let mut cursor = CURSOR.lock();
    if !cursor.initialized {
        return;
    }

    let mut total_dx: i32 = 0;
    let mut total_dy: i32 = 0;
    let mut total_dz: i32 = 0;
    let mut combined_buttons: u32 = 0;

    // Poll PS/2 mouse
    #[cfg(target_arch = "x86_64")]
    {
        // Must drop cursor lock before calling poll (which acquires MOUSE lock)
        drop(cursor);
        super::mouse::poll();
        let (dx, dy, dz) = super::mouse::get_relative_motion();
        combined_buttons |= super::mouse::get_buttons();
        total_dx += dx;
        total_dy += dy;
        total_dz += dz;
        cursor = CURSOR.lock();
    }

    // Poll USB mouse
    {
        let mouse_ctrl_idx = super::usb::hid_mouse::controller_idx();
        if let Some(ctrl_idx) = mouse_ctrl_idx {
            drop(cursor);
            // Poll the USB controller that has the mouse
            super::usb::poll_mice_on_controller(ctrl_idx);
            let (udx, udy) = super::usb::hid_mouse::get_relative_motion();
            combined_buttons |= super::usb::hid_mouse::get_buttons();
            total_dx += udx;
            total_dy += udy;
            cursor = CURSOR.lock();
        }
    }

    if total_dx == 0 && total_dy == 0 && total_dz == 0 && combined_buttons == cursor.buttons {
        return;
    }

    // Apply acceleration (use i64 to avoid i32 overflow on large deltas)
    let distance_sq =
        (total_dx as i64 * total_dx as i64 + total_dy as i64 * total_dy as i64) as u32;
    let threshold_sq = cursor.acceleration * cursor.acceleration;
    let multiplier = if distance_sq > threshold_sq {
        cursor.speed
    } else {
        BASE_SPEED
    };

    // Scale deltas by multiplier (1/256 fixed-point → integer pixels)
    let scaled_dx = (total_dx * multiplier as i32) / BASE_SPEED as i32;
    let scaled_dy = (total_dy * multiplier as i32) / BASE_SPEED as i32;

    // Update absolute position with clamping
    cursor.abs_x = (cursor.abs_x + scaled_dx).clamp(0, cursor.screen_w as i32 - 1);
    cursor.abs_y = (cursor.abs_y + scaled_dy).clamp(0, cursor.screen_h as i32 - 1);

    // Edge detection: record rising edges (0→1) as pending clicks
    let rising = combined_buttons & !cursor.prev_buttons;
    cursor.click_pending |= rising;
    cursor.prev_buttons = combined_buttons;
    cursor.buttons = combined_buttons;
    cursor.scroll += total_dz;
}

/// Get the current absolute cursor position.
///
/// Returns `(x, y)` in pixel coordinates.
pub fn position() -> (i32, i32) {
    let cursor = CURSOR.lock();
    (cursor.abs_x, cursor.abs_y)
}

/// Get and reset the accumulated scroll delta.
pub fn get_scroll() -> i32 {
    let mut cursor = CURSOR.lock();
    let dz = cursor.scroll;
    cursor.scroll = 0;
    dz
}

/// Get the current button state.
///
/// Bit 0=left, 1=right, 2=middle, 3=btn4, 4=btn5.
pub fn buttons() -> u32 {
    CURSOR.lock().buttons
}

/// Check if the left mouse button is pressed (level-triggered).
pub fn left_pressed() -> bool {
    (buttons() & 1) != 0
}

/// Check if the left mouse button was just clicked (edge-triggered).
///
/// Returns `true` exactly once per press-down transition (0→1).
/// The click is consumed on read — subsequent calls return `false`
/// until the button is released and pressed again.
pub fn left_clicked() -> bool {
    let mut cursor = CURSOR.lock();
    let clicked = (cursor.click_pending & 1) != 0;
    cursor.click_pending &= !1; // consume the click
    clicked
}

/// Check if the right mouse button is pressed.
pub fn right_pressed() -> bool {
    (buttons() & 2) != 0
}

/// Check if the cursor system is initialized.
pub fn is_initialized() -> bool {
    CURSOR.lock().initialized
}

/// Set cursor speed multiplier (1/256 fixed-point).
///
/// 256 = 1x (no acceleration), 512 = 2x, etc.
pub fn set_speed(speed: u32) {
    CURSOR.lock().speed = speed;
}

/// Get current speed multiplier.
pub fn get_speed() -> u32 {
    CURSOR.lock().speed
}

/// Set acceleration threshold.
pub fn set_acceleration(threshold: u32) {
    CURSOR.lock().acceleration = threshold;
}

/// Set cursor position directly (e.g., for touchscreen/absolute input).
pub fn set_position(x: i32, y: i32) {
    let mut cursor = CURSOR.lock();
    cursor.abs_x = x.clamp(0, cursor.screen_w as i32 - 1);
    cursor.abs_y = y.clamp(0, cursor.screen_h as i32 - 1);
}

/// Get screen dimensions.
pub fn screen_size() -> (u32, u32) {
    let cursor = CURSOR.lock();
    (cursor.screen_w, cursor.screen_h)
}
