//! Platform-owned pointing devices follow the same raw-input path as PS/2
//! and USB mice. UI and EFI consumers do not poll the bus independently.
use crate::{
    cell::Local,
    platform::{PointerInput, PointerState},
};

static SOURCE: Local<Option<&'static mut dyn PointerInput>> = Local::new(None);
static STATE: Local<Pending> = Local::new(Pending::new());

struct Pending {
    state: PointerState,
    changed: bool,
}
impl Pending {
    const fn new() -> Self {
        Self {
            state: PointerState {
                dx: 0,
                dy: 0,
                dz: 0,
                buttons: 0,
            },
            changed: false,
        }
    }
    fn push(&mut self, sample: PointerState) {
        self.changed |= sample.dx != 0
            || sample.dy != 0
            || sample.dz != 0
            || self.state.buttons != sample.buttons;
        self.state.dx = self.state.dx.saturating_add(sample.dx);
        self.state.dy = self.state.dy.saturating_add(sample.dy);
        self.state.dz = self.state.dz.saturating_add(sample.dz);
        self.state.buttons = sample.buttons;
    }
    fn take(&mut self) -> PointerState {
        let state = self.state;
        self.state.dx = 0;
        self.state.dy = 0;
        self.state.dz = 0;
        self.changed = false;
        state
    }
}

pub(crate) fn install(source: &'static mut dyn PointerInput) {
    *SOURCE.borrow_mut() = Some(source);
    *STATE.borrow_mut() = Pending::new();
}

pub(crate) fn poll() {
    // Keep a button transition available between WaitForEvent and GetState.
    // Do not replace a pending press with a later release on a second poll.
    if STATE.borrow().changed {
        return;
    }
    // Never hold a Local borrow across a platform callback. Reentrant polling
    // sees no source until this callback has finished.
    let Some(source) = SOURCE.borrow_mut().take() else {
        return;
    };
    let sample = source.read_state();
    *SOURCE.borrow_mut() = Some(source);
    if let Some(sample) = sample {
        STATE.borrow_mut().push(sample);
    }
}
pub(crate) fn take_state() -> PointerState {
    STATE.borrow_mut().take()
}
pub(crate) fn buttons() -> u32 {
    STATE.borrow().state.buttons
}
pub(crate) fn has_pending() -> bool {
    STATE.borrow().changed
}

pub(crate) fn detach() {
    let source = SOURCE.borrow_mut().take();
    *STATE.borrow_mut() = Pending::new();
    if let Some(source) = source {
        source.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn polling_peeks_preserve_motion_and_button_only_transitions() {
        let mut pending = Pending::new();
        pending.push(PointerState {
            dx: 4,
            buttons: 1,
            ..Default::default()
        });
        pending.push(PointerState {
            dx: 3,
            buttons: 1,
            ..Default::default()
        });
        assert!(pending.changed);
        assert_eq!(pending.take().dx, 7);
        assert!(!pending.changed);
        assert_eq!(pending.take().buttons, 1);
        pending.push(PointerState::default());
        assert!(pending.changed);
        assert_eq!(pending.take().buttons, 0);
        pending.push(PointerState::default());
        assert!(!pending.changed);
    }
}
