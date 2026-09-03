//! EFI Boot Services event and timer management.
//!
//! Event slots, timers, event-group signaling, and the measured-boot
//! hooks surrounding image start. The [`super`] table owns the function
//! pointers; this module owns the slot state machine.

use super::super::guid_fmt::GuidFmt;
use super::super::tables::{EventEntry, MAX_EVENTS, TimerType, tables, with_tables_mut};
use core::ffi::c_void;
use r_efi::efi::{self, Guid, Status, Tpl};

/// Event types
const EVT_TIMER: u32 = 0x80000000;
const EVT_RUNTIME: u32 = 0x40000000;
const EVT_NOTIFY_WAIT: u32 = 0x00000100;
const EVT_NOTIFY_SIGNAL: u32 = 0x00000200;
pub(super) const EVT_SIGNAL_EXIT_BOOT_SERVICES: u32 = 0x00000201;
#[cfg(test)]
const EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE: u32 = 0x60000202;

/// Special event ID for keyboard input
pub const KEYBOARD_EVENT_ID: usize = 1;

/// Special event ID for pointer (mouse) input
#[cfg(feature = "ui")]
pub const POINTER_EVENT_ID: usize = 2;

#[cfg(feature = "ui")]
const FIRST_DYNAMIC_EVENT_ID: usize = POINTER_EVENT_ID + 1;
#[cfg(not(feature = "ui"))]
const FIRST_DYNAMIC_EVENT_ID: usize = KEYBOARD_EVENT_ID + 1;

// ============================================================================
// Event Functions (mostly unsupported)
// ============================================================================

const fn boot_event_type_supported(event_type: u32) -> bool {
    event_type & EVT_RUNTIME == 0
}

fn find_free_event_slot(events: &[EventEntry]) -> Option<usize> {
    events
        .iter()
        .enumerate()
        .skip(FIRST_DYNAMIC_EVENT_ID)
        .find_map(|(event_id, entry)| (!entry.in_use).then_some(event_id))
}

fn next_event_generation(generation: usize) -> usize {
    let max_generation = usize::MAX / MAX_EVENTS;
    if generation == 0 || generation == max_generation {
        1
    } else {
        generation + 1
    }
}

pub(super) fn event_handle(event_id: usize, generation: usize) -> efi::Event {
    (generation * MAX_EVENTS + event_id) as *mut c_void
}

fn event_id_for_handle(events: &[EventEntry], event: efi::Event) -> Option<usize> {
    let raw = event as usize;
    if raw == KEYBOARD_EVENT_ID {
        return Some(KEYBOARD_EVENT_ID);
    }
    #[cfg(feature = "ui")]
    if raw == POINTER_EVENT_ID {
        return Some(POINTER_EVENT_ID);
    }

    let event_id = raw % MAX_EVENTS;
    let generation = raw / MAX_EVENTS;
    (event_id >= FIRST_DYNAMIC_EVENT_ID
        && generation != 0
        && events[event_id].in_use
        && events[event_id].generation == generation)
        .then_some(event_id)
}

pub(super) fn dynamic_event_id_for_handle(
    events: &[EventEntry],
    event: efi::Event,
) -> Option<usize> {
    event_id_for_handle(events, event).filter(|event_id| *event_id >= FIRST_DYNAMIC_EVENT_ID)
}

pub(super) extern "efiapi" fn create_event(
    event_type: u32,
    notify_tpl: Tpl,
    notify_function: Option<efi::EventNotify>,
    notify_context: *mut c_void,
    event: *mut efi::Event,
) -> Status {
    log::debug!(
        "BS.CreateEvent(type={:#x}, tpl={:?})",
        event_type,
        notify_tpl
    );

    if event.is_null() {
        return Status::INVALID_PARAMETER;
    }
    if !boot_event_type_supported(event_type) {
        return Status::INVALID_PARAMETER;
    }

    // Allocate a reusable event slot from centralized state.
    with_tables_mut(|efi_state| {
        let Some(event_id) = find_free_event_slot(&efi_state.events) else {
            log::error!("  -> OUT_OF_RESOURCES (no more event slots)");
            return Status::OUT_OF_RESOURCES;
        };

        let generation = next_event_generation(efi_state.events[event_id].generation);

        // Store event info including notify callback.
        efi_state.events[event_id] = EventEntry {
            in_use: true,
            generation,
            event_type,
            notify_tpl,
            signaled: false,
            is_keyboard_event: false,
            notify_function,
            notify_context,
            event_group: None,
            timer_type: TimerType::Cancel,
            timer_trigger_time: 0,
            timer_deadline_tsc: 0,
        };

        let handle = event_handle(event_id, generation);
        unsafe {
            *event = handle;
        }

        log::debug!(
            "  -> SUCCESS (event={:?}, slot={}, generation={})",
            handle,
            event_id,
            generation
        );
        Status::SUCCESS
    })
}

pub(super) extern "efiapi" fn set_timer(
    event: efi::Event,
    timer_type: efi::TimerDelay,
    trigger_time: u64,
) -> Status {
    log::debug!(
        "BS.SetTimer(event={:?}, type={}, time={})",
        event,
        timer_type,
        trigger_time
    );

    let timer = match TimerType::try_from(timer_type) {
        Ok(t) => t,
        Err(e) => {
            log::debug!("BS.SetTimer: {e}");
            return Status::INVALID_PARAMETER;
        }
    };

    with_tables_mut(|efi_state| {
        let Some(event_id) = dynamic_event_id_for_handle(&efi_state.events, event) else {
            return Status::INVALID_PARAMETER;
        };
        let entry = &mut efi_state.events[event_id];

        // Verify this is a timer event
        if entry.event_type & EVT_TIMER == 0 {
            log::debug!("  -> INVALID_PARAMETER (not a timer event)");
            return Status::INVALID_PARAMETER;
        }

        entry.timer_type = timer;
        entry.timer_trigger_time = trigger_time;

        match timer {
            TimerType::Cancel => {
                entry.timer_deadline_tsc = 0;
                entry.signaled = false;
                log::debug!("  -> SUCCESS (timer cancelled)");
            }
            TimerType::Periodic | TimerType::Relative => {
                // Convert 100ns units to TSC ticks
                let tsc_freq = crate::time::tsc_frequency();
                if tsc_freq == 0 {
                    log::error!("  -> DEVICE_ERROR (TSC not calibrated)");
                    return Status::DEVICE_ERROR;
                }
                let tsc_per_us = tsc_freq / 1_000_000;
                let us = trigger_time / 10;
                let tsc_offset = us * tsc_per_us.max(1);
                let now = crate::time::rdtsc();
                entry.timer_deadline_tsc = now + tsc_offset;
                log::debug!("  -> SUCCESS (deadline in {}us)", us);
            }
        }

        Status::SUCCESS
    })
}

fn notify_wait_event(event_id: usize, event: efi::Event) {
    let notify_fn = with_tables_mut(|efi_state| {
        let entry = &efi_state.events[event_id];
        if !entry.signaled && entry.event_type & EVT_NOTIFY_WAIT != 0 {
            entry.notify_function.map(|f| (f, entry.notify_context))
        } else {
            None
        }
    });

    if let Some((func, context)) = notify_fn {
        log::trace!(
            "  -> Calling EVT_NOTIFY_WAIT function for event {}",
            event_id
        );
        func(event, context);
    }
}

pub(super) extern "efiapi" fn wait_for_event(
    number_of_events: usize,
    event: *mut efi::Event,
    index: *mut usize,
) -> Status {
    log::debug!("BS.WaitForEvent(count={})", number_of_events);

    if number_of_events == 0 || event.is_null() || index.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // Get the list of events to wait on
    let events_to_wait = unsafe { core::slice::from_raw_parts(event, number_of_events) };

    // Poll for events (keyboard input, timers, signaled events)
    loop {
        // Check each event
        for (i, &evt) in events_to_wait.iter().enumerate() {
            let Some(event_id) =
                with_tables_mut(|efi_state| event_id_for_handle(&efi_state.events, evt))
            else {
                return Status::INVALID_PARAMETER;
            };

            // Check if it's the keyboard event and there's actual key input.
            // We do a real read-ahead (not just peek at status registers) to
            // avoid false positives from modifier keys, mouse data, etc.
            if event_id == KEYBOARD_EVENT_ID
                && crate::efi::protocols::console::keyboard_check_ready()
            {
                unsafe { *index = i };
                log::debug!("  -> SUCCESS (keyboard input ready, index={})", i);
                return Status::SUCCESS;
            }

            // Check if it's the pointer event and there's mouse input.
            #[cfg(feature = "ui")]
            if event_id == POINTER_EVENT_ID
                && crate::efi::protocols::simple_pointer::pointer_check_ready()
            {
                unsafe { *index = i };
                log::debug!("  -> SUCCESS (pointer input ready, index={})", i);
                return Status::SUCCESS;
            }

            // Check if a regular dynamic event is signaled, including timers.
            if event_id >= FIRST_DYNAMIC_EVENT_ID {
                notify_wait_event(event_id, evt);
                check_timer_event(event_id);

                // Per UEFI spec: WaitForEvent clears the signaled state
                // of the event that triggered the return.
                let signaled = with_tables_mut(|efi_state| {
                    let was_signaled = efi_state.events[event_id].signaled;
                    if was_signaled {
                        efi_state.events[event_id].signaled = false;
                    }
                    was_signaled
                });
                if signaled {
                    unsafe { *index = i };
                    log::debug!("  -> SUCCESS (event signaled, index={})", i);
                    return Status::SUCCESS;
                }
            }
        }

        // Small delay to avoid busy-waiting too aggressively
        for _ in 0..1000 {
            core::hint::spin_loop();
        }
    }
}

/// Pending notify callback extracted when signaling an event.
type SignaledNotify = Option<(efi::EventNotify, *mut c_void)>;

/// Mark an event signaled and extract its pending `EVT_NOTIFY_SIGNAL` callback.
///
/// Factored out of `signal_event` so the lookup/state mutation is unit
/// testable without global tables. Uses the general handle lookup on purpose:
/// the handle's static/dynamic classification is an internal detail and must
/// not narrow public `SignalEvent` semantics — any valid event (including the
/// static keyboard/pointer events) signals successfully. Only the
/// notification behavior depends on the event type.
fn signal_event_entry(
    events: &mut [EventEntry],
    event: efi::Event,
) -> Result<(usize, SignaledNotify), Status> {
    let Some(event_id) = event_id_for_handle(events, event) else {
        return Err(Status::INVALID_PARAMETER);
    };
    events[event_id].signaled = true;
    let entry = &events[event_id];
    let notify_fn = if entry.event_type & EVT_NOTIFY_SIGNAL != 0 {
        entry.notify_function.map(|f| (f, entry.notify_context))
    } else {
        None
    };
    Ok((event_id, notify_fn))
}

pub(super) extern "efiapi" fn signal_event(event: efi::Event) -> Status {
    log::debug!("BS.SignalEvent(event={:?})", event);

    let notify = with_tables_mut(|efi_state| signal_event_entry(&mut efi_state.events, event));

    let (event_id, notify_fn) = match notify {
        Ok(result) => result,
        Err(status) => return status,
    };
    if let Some((func, context)) = notify_fn {
        log::debug!("  -> Calling notify function for event {}", event_id);
        func(event, context);
    }

    Status::SUCCESS
}

fn close_dynamic_event(events: &mut [EventEntry], event: efi::Event) -> bool {
    let Some(event_id) = dynamic_event_id_for_handle(events, event) else {
        return false;
    };
    let generation = events[event_id].generation;
    events[event_id] = EventEntry::empty();
    events[event_id].generation = generation;
    true
}

pub(super) extern "efiapi" fn close_event(event: efi::Event) -> Status {
    log::debug!("BS.CloseEvent(event={:?})", event);

    with_tables_mut(|efi_state| {
        if close_dynamic_event(&mut efi_state.events, event) {
            Status::SUCCESS
        } else {
            Status::INVALID_PARAMETER
        }
    })
}

pub(super) extern "efiapi" fn check_event(event: efi::Event) -> Status {
    let Some(event_id) = with_tables_mut(|efi_state| event_id_for_handle(&efi_state.events, event))
    else {
        return Status::INVALID_PARAMETER;
    };
    log::trace!("BS.CheckEvent(event={:?}, slot={})", event, event_id);

    // Special case for keyboard event — do a real read-ahead check
    if event_id == KEYBOARD_EVENT_ID {
        if crate::efi::protocols::console::keyboard_check_ready() {
            return Status::SUCCESS;
        } else {
            return Status::NOT_READY;
        }
    }

    // Special case for pointer event — poll hardware and peek
    #[cfg(feature = "ui")]
    if event_id == POINTER_EVENT_ID {
        if crate::efi::protocols::simple_pointer::pointer_check_ready() {
            return Status::SUCCESS;
        } else {
            return Status::NOT_READY;
        }
    }

    // Check regular dynamic events.
    if event_id >= FIRST_DYNAMIC_EVENT_ID {
        notify_wait_event(event_id, event);

        // Check timer expiration
        check_timer_event(event_id);

        // Per UEFI spec: CheckEvent clears the signaled state when
        // returning SUCCESS (for EVT_NOTIFY_WAIT events, the notify
        // function is called first, then the event is cleared).
        let signaled = with_tables_mut(|efi_state| {
            let was_signaled = efi_state.events[event_id].signaled;
            if was_signaled {
                efi_state.events[event_id].signaled = false;
            }
            was_signaled
        });
        if signaled {
            return Status::SUCCESS;
        }
    }

    Status::NOT_READY
}

/// Check if a timer event has expired and signal it if so
fn check_timer_event(event_id: usize) {
    with_tables_mut(|efi_state| {
        let entry = &mut efi_state.events[event_id];

        // Only process timer events with an active deadline
        if entry.event_type & EVT_TIMER == 0 || entry.timer_type == TimerType::Cancel {
            return;
        }

        if entry.timer_deadline_tsc == 0 {
            return;
        }

        let now = crate::time::rdtsc();
        if now >= entry.timer_deadline_tsc {
            entry.signaled = true;

            match entry.timer_type {
                TimerType::Periodic => {
                    // Reset deadline for next period
                    let tsc_per_us = (crate::time::tsc_frequency() / 1_000_000).max(1);
                    let us = entry.timer_trigger_time / 10;
                    let tsc_offset = us * tsc_per_us;
                    entry.timer_deadline_tsc = now + tsc_offset;
                }
                TimerType::Relative => {
                    // One-shot: clear the deadline
                    entry.timer_deadline_tsc = 0;
                }
                TimerType::Cancel => {}
            }
        }
    });
}

/// EFI_EVENT_GROUP_READY_TO_BOOT GUID
const EFI_EVENT_GROUP_READY_TO_BOOT: Guid = Guid::from_fields(
    0x7CE88FB3,
    0x4BD7,
    0x4679,
    0x87,
    0xA8,
    &[0xA8, 0xD8, 0xDE, 0xE5, 0x0D, 0x2B],
);

/// Signal all events belonging to a specific event group
pub(super) fn signal_event_group(group_guid: &Guid) {
    // Collect events to signal (must not hold a state borrow during callbacks)
    let mut events_to_signal: heapless::Vec<
        (usize, Option<efi::EventNotify>, *mut c_void),
        MAX_EVENTS,
    > = heapless::Vec::new();

    with_tables_mut(|efi_state| {
        for (i, entry) in efi_state.events.iter_mut().enumerate() {
            if entry.in_use
                && let Some(ref group) = entry.event_group
                && *group == *group_guid
            {
                entry.signaled = true;
                let notify = if entry.event_type & EVT_NOTIFY_SIGNAL != 0 {
                    entry.notify_function.map(|f| (f, entry.notify_context))
                } else {
                    None
                };
                let _ = events_to_signal.push((
                    event_handle(i, entry.generation) as usize,
                    notify.map(|(f, _)| f),
                    notify.map(|(_, c)| c).unwrap_or(core::ptr::null_mut()),
                ));
            }
        }
    });

    // Call notify functions outside the state borrow
    for (event_handle, notify_fn, context) in &events_to_signal {
        if let Some(func) = notify_fn {
            log::debug!(
                "signal_event_group: calling notify for event {:#x}",
                event_handle
            );
            func(*event_handle as efi::Event, *context);
        }
    }

    if !events_to_signal.is_empty() {
        log::info!(
            "signal_event_group: signaled {} events",
            events_to_signal.len()
        );
    }
}

/// Measure the beginning of an EFI boot application attempt.
///
/// The first attempt performs the ReadyToBoot measured-boot sequence and
/// signals the ReadyToBoot event group. Subsequent attempts only add the boot
/// action event so separators are not duplicated.
pub(crate) fn measure_efi_application_start(is_application: bool) {
    if !is_application {
        return;
    }

    let should_signal = with_tables_mut(|efi| {
        if !efi.ready_to_boot_signaled {
            efi.ready_to_boot_signaled = true;
            true
        } else {
            false
        }
    });

    if should_signal {
        // TCG measured boot: measure pre-OS handoff state, boot variables,
        // boot action, and separators before the first boot attempt, per TCG
        // PFP / EDK2 ReadyToBoot ordering.
        super::super::tcg::measured_boot::measure_handoff_tables_all();
        super::super::tcg::measured_boot::measure_boot_variables_all();
        super::super::tcg::measured_boot::measure_action_all(
            4,
            "Calling EFI Application from Boot Option",
        );

        // Measure separator events into PCR 0-6.
        // PCR 7 already has its separator from Secure Boot variable measurement.
        super::super::tcg::measured_boot::measure_all_separators_all();

        signal_event_group(&EFI_EVENT_GROUP_READY_TO_BOOT);
    } else {
        super::super::tcg::measured_boot::measure_action_all(
            4,
            "Calling EFI Application from Boot Option",
        );
    }
}

/// Measure return from an EFI boot application attempt.
pub(crate) fn measure_efi_application_return(is_application: bool) {
    if is_application && tables().ready_to_boot_signaled {
        super::super::tcg::measured_boot::measure_action_all(
            4,
            "Returning from EFI Application from Boot Option",
        );
    }
}

pub(super) extern "efiapi" fn create_event_ex(
    event_type: u32,
    notify_tpl: Tpl,
    notify_function: Option<efi::EventNotify>,
    notify_context: *const c_void,
    event_group: *const Guid,
    event: *mut efi::Event,
) -> Status {
    let group_display = if event_group.is_null() {
        None
    } else {
        Some(GuidFmt(unsafe { *event_group }))
    };
    log::debug!(
        "BS.CreateEventEx(type={:#x}, tpl={:?}, group={})",
        event_type,
        notify_tpl,
        group_display
            .as_ref()
            .map(|g| g as &dyn core::fmt::Display)
            .unwrap_or(&"NULL" as &dyn core::fmt::Display)
    );

    if event.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // Create the event with full parameters
    let status = create_event(
        event_type,
        notify_tpl,
        notify_function,
        notify_context as *mut c_void,
        event,
    );

    if status == Status::SUCCESS && !event_group.is_null() {
        let handle = unsafe { *event };
        with_tables_mut(|efi_state| {
            if let Some(event_id) = dynamic_event_id_for_handle(&efi_state.events, handle) {
                efi_state.events[event_id].event_group = Some(unsafe { *event_group });
            }
        });
    }

    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_event_rejects_all_runtime_event_types() {
        assert!(boot_event_type_supported(0));
        assert!(boot_event_type_supported(EVT_NOTIFY_SIGNAL));
        assert!(!boot_event_type_supported(EVT_RUNTIME));
        assert!(!boot_event_type_supported(
            EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE
        ));
    }

    /// Regression test for SignalEvent on static events: exercises the same
    /// `signal_event_entry` helper `signal_event` calls, so switching the
    /// implementation back to `dynamic_event_id_for_handle` fails this test
    /// instead of silently regressing to INVALID_PARAMETER.
    #[test]
    fn signal_helper_accepts_static_events() {
        let mut events = [EventEntry::empty(); MAX_EVENTS];
        let (event_id, notify) = signal_event_entry(&mut events, KEYBOARD_EVENT_ID as efi::Event)
            .expect("SignalEvent must accept the static keyboard event");
        assert_eq!(event_id, KEYBOARD_EVENT_ID);
        assert!(notify.is_none());
        assert!(events[KEYBOARD_EVENT_ID].signaled);
        #[cfg(feature = "ui")]
        {
            let (event_id, _) = signal_event_entry(&mut events, POINTER_EVENT_ID as efi::Event)
                .expect("SignalEvent must accept the static pointer event");
            assert_eq!(event_id, POINTER_EVENT_ID);
            assert!(events[POINTER_EVENT_ID].signaled);
        }
    }

    #[test]
    fn signal_helper_rejects_invalid_handles() {
        let mut events = [EventEntry::empty(); MAX_EVENTS];
        assert_eq!(
            signal_event_entry(&mut events, core::ptr::null_mut()).unwrap_err(),
            Status::INVALID_PARAMETER
        );
    }

    #[test]
    fn signal_helper_returns_notify_signal_callbacks() {
        extern "efiapi" fn notify(_event: efi::Event, _context: *mut c_void) {}
        let mut events = [EventEntry::empty(); MAX_EVENTS];
        let event_id = find_free_event_slot(&events).unwrap();
        let generation = next_event_generation(events[event_id].generation);
        events[event_id] = EventEntry {
            in_use: true,
            generation,
            event_type: EVT_NOTIFY_SIGNAL,
            notify_tpl: 0,
            signaled: false,
            is_keyboard_event: false,
            notify_function: Some(notify),
            notify_context: core::ptr::null_mut(),
            event_group: None,
            timer_type: TimerType::Cancel,
            timer_trigger_time: 0,
            timer_deadline_tsc: 0,
        };
        let handle = event_handle(event_id, generation);
        let (signaled_id, callback) =
            signal_event_entry(&mut events, handle).expect("dynamic notify event must signal");
        assert_eq!(signaled_id, event_id);
        assert!(callback.is_some());
        assert!(events[event_id].signaled);
    }

    #[test]
    fn static_events_are_not_dynamic_handles() {
        let events = [EventEntry::empty(); MAX_EVENTS];
        assert_eq!(
            dynamic_event_id_for_handle(&events, KEYBOARD_EVENT_ID as efi::Event),
            None
        );
        #[cfg(feature = "ui")]
        assert_eq!(
            dynamic_event_id_for_handle(&events, POINTER_EVENT_ID as efi::Event),
            None
        );
    }

    #[test]
    fn close_rejects_closed_events_and_double_close() {
        let mut events = [EventEntry::empty(); MAX_EVENTS];
        let event_id = find_free_event_slot(&events).unwrap();
        let generation = next_event_generation(events[event_id].generation);
        events[event_id].in_use = true;
        events[event_id].generation = generation;
        let handle = event_handle(event_id, generation);

        assert!(close_dynamic_event(&mut events, handle));
        assert_eq!(event_id_for_handle(&events, handle), None);
        assert!(!close_dynamic_event(&mut events, handle));
    }

    #[test]
    fn closed_event_slots_are_reused_without_reusing_handles() {
        let mut events = [EventEntry::empty(); MAX_EVENTS];
        let first = find_free_event_slot(&events).unwrap();
        let first_generation = next_event_generation(events[first].generation);
        events[first].in_use = true;
        events[first].generation = first_generation;
        let stale_handle = event_handle(first, first_generation);
        assert_eq!(event_id_for_handle(&events, stale_handle), Some(first));
        assert_eq!(find_free_event_slot(&events), Some(first + 1));

        assert!(close_dynamic_event(&mut events, stale_handle));
        let second_generation = next_event_generation(events[first].generation);
        events[first].in_use = true;
        events[first].generation = second_generation;
        let replacement_handle = event_handle(first, second_generation);

        assert_ne!(stale_handle, replacement_handle);
        assert_eq!(event_id_for_handle(&events, stale_handle), None);
        assert_eq!(
            event_id_for_handle(&events, replacement_handle),
            Some(first)
        );
    }
}
