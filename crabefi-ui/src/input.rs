//! Keyboard and pointer input shared by the firmware menus and the setup UI.

/// One decoded key or pointer event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPress {
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    Tab,
    BackTab,
    Delete,
    F8,
    F10,
    Enter,
    Escape,
    Char(char),
    /// Mouse click at framebuffer pixel coordinates.
    MouseClick {
        x: u32,
        y: u32,
    },
    /// Mouse wheel (positive = down, negative = up).
    MouseScroll(i32),
}
