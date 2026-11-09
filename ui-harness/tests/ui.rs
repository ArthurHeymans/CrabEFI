use crabefi_ui_harness::Playground;
use serde_json::{Value, json};

fn state(host: &Playground) -> Value {
    serde_json::from_str(&host.state_json()).unwrap()
}
fn key(host: &mut Playground, key: &str) -> Value {
    host.key(key).unwrap();
    host.advance(0);
    state(host)
}
fn select_security(host: &mut Playground, row: usize) {
    key(host, "s");
    key(host, "Home");
    for _ in 0..row {
        key(host, "ArrowDown");
    }
}
fn confirm(host: &mut Playground) -> Value {
    assert!(state(host)["dialog"].is_string());
    key(host, "Tab");
    key(host, "Enter")
}
fn tab(host: &mut Playground, index: usize) {
    let rect = &state(host)["navigation"][index]["rect"];
    let at = |i: usize| rect[i].as_u64().unwrap() as u32;
    host.click(at(0) + at(2) / 2, at(1) + at(3) / 2).unwrap();
    host.advance(0);
}

#[test]
fn keyboard_navigation_scrolls_and_boots_the_selected_entry() {
    for (width, height) in [(640, 400), (800, 600), (1024, 768), (1920, 1080)] {
        let mut host = Playground::new(width, height, "many").unwrap();
        for _ in 0..30 {
            key(&mut host, "ArrowDown");
        }
        assert_eq!(state(&host)["selected"], 15);
        if height <= 600 {
            assert!(state(&host)["scrollOffset"].as_u64().unwrap() > 0);
        }
        assert_eq!(key(&mut host, "Enter")["outcome"], "boot:15");
        assert!(host.key("Enter").is_err());
    }
}

#[test]
fn pointer_selects_without_activating_and_tabs_use_the_shared_geometry() {
    let mut host = Playground::new(800, 600, "normal").unwrap();
    host.click(300, 165).unwrap();
    host.advance(0); // second table row
    assert_eq!(state(&host)["selected"], 1);
    host.click(300, 165).unwrap();
    host.advance(0);
    assert_eq!(state(&host)["outcome"], Value::Null); // repeated row clicks never boot
    tab(&mut host, 1);
    assert_eq!(state(&host)["screen"], "security");
    tab(&mut host, 0);
    assert_eq!(state(&host)["screen"], "boot");
    assert_eq!(key(&mut host, "Enter")["outcome"], "boot:1");
}

#[test]
fn security_actions_require_confirmation_and_keep_the_safe_choice_first() {
    let mut host = Playground::new(800, 600, "normal").unwrap();
    select_security(&mut host, 4); // enforcement after the Keys group
    key(&mut host, "Enter");
    assert_eq!(state(&host)["dialog"], "Enable Secure Boot?");
    assert_eq!(state(&host)["requested"], false);
    key(&mut host, "Enter"); // default Cancel, not Enable
    assert_eq!(state(&host)["requested"], false);
    key(&mut host, "Enter");
    confirm(&mut host);
    assert_eq!(state(&host)["requested"], true);
    assert_eq!(state(&host)["enforcing"], false);
    select_security(&mut host, 2);
    key(&mut host, "Enter");
    confirm(&mut host);
    assert_eq!(state(&host)["keys"], json!([1, 1, 2, 0]));
    assert_eq!(state(&host)["enforcing"], true);
    select_security(&mut host, 5);
    key(&mut host, "Enter");
    confirm(&mut host);
    assert_eq!(state(&host)["setupMode"], true);
    assert_eq!(state(&host)["enforcing"], false);
    assert_eq!(state(&host)["keys"], json!([0, 0, 0, 0]));
    assert_eq!(key(&mut host, "Escape")["screen"], "boot");
}

#[test]
fn wheel_moves_the_viewport_without_retargeting_selection() {
    let mut host = Playground::new(640, 400, "many").unwrap();
    host.scroll(2).unwrap();
    host.advance(0);
    assert_eq!(state(&host)["selected"], 0);
    assert!(state(&host)["scrollOffset"].as_u64().unwrap() > 0);
}

#[test]
fn variable_write_failures_do_not_change_security_state() {
    let mut host = Playground::new(640, 400, "write-error").unwrap();
    select_security(&mut host, 4);
    key(&mut host, "Enter");
    confirm(&mut host);
    assert_eq!(state(&host)["requested"], false);
    assert!(
        state(&host)["actions"][0]
            .as_str()
            .unwrap()
            .contains("failure")
    );
}

#[test]
fn clock_is_deterministic_and_input_cancels_auto_boot() {
    let mut host = Playground::new(800, 600, "countdown").unwrap();
    host.advance(999);
    assert_eq!(state(&host)["countdown"], 5);
    host.advance(1);
    assert_eq!(state(&host)["countdown"], 4);
    host.advance(3999);
    assert_eq!(state(&host)["countdown"], 1);
    host.advance(1);
    assert_eq!(state(&host)["outcome"], "boot:0");
    assert_eq!(state(&host)["countdown"], 0);
    let mut cancelled = Playground::new(800, 600, "countdown").unwrap();
    assert_eq!(key(&mut cancelled, "ArrowDown")["countdown"], 0);
    cancelled.advance(60_000);
    assert_eq!(state(&cancelled)["outcome"], Value::Null);
    assert_eq!(state(&cancelled)["selected"], 1);
}

#[test]
fn restart_with_a_resting_pointer_keeps_the_new_countdown() {
    let mut host = Playground::new(800, 600, "countdown").unwrap();
    host.pointer(300, 300);
    host.advance(0);
    key(&mut host, "r");
    let restarted = confirm(&mut host);
    assert_eq!(restarted["outcome"], "reset");
    assert_eq!(restarted["countdown"], 5);
    host.pointer(320, 300);
    host.advance(0);
    assert_eq!(state(&host)["countdown"], 0);
}

#[test]
fn no_media_and_unavailable_firmware_settings_navigate_without_devices() {
    let mut host = Playground::new(640, 400, "empty").unwrap();
    assert_eq!(state(&host)["screen"], "no-media");
    assert_eq!(key(&mut host, "f")["screen"], "firmware");
    assert_eq!(key(&mut host, "s")["screen"], "security");
    assert_eq!(key(&mut host, "Escape")["screen"], "no-media");
    assert_eq!(key(&mut host, "Escape")["outcome"], "exit");
}

#[test]
fn restart_is_confirmed_and_preserves_simulated_variables() {
    let mut host = Playground::new(800, 600, "secure").unwrap();
    select_security(&mut host, 4);
    key(&mut host, "Enter");
    confirm(&mut host);
    assert_eq!(state(&host)["requested"], false);
    key(&mut host, "r");
    assert_eq!(state(&host)["dialog"], "Restart the computer?");
    key(&mut host, "Escape");
    assert_eq!(state(&host)["screen"], "security");
    key(&mut host, "r");
    let restarted = confirm(&mut host);
    assert_eq!(restarted["screen"], "boot");
    assert_eq!(restarted["requested"], false);
    assert_eq!(restarted["setupMode"], false);
    assert_eq!(restarted["keys"], json!([1, 1, 2, 1]));
}

#[test]
fn one_shot_command_line_editor_hands_off_the_edited_value() {
    for width in [800, 1024] {
        let mut host = Playground::new(width, 768, "normal").unwrap();
        key(&mut host, "ArrowDown");
        key(&mut host, "e");
        key(&mut host, "End");
        key(&mut host, "x");
        let booted = key(&mut host, "Enter");
        assert_eq!(booted["outcome"], "boot:1");
        assert_eq!(booted["commandLine"], "root=LABEL=demo quietx");
    }
}

#[test]
fn key_listing_and_missing_esp_imports_are_real_review_flows() {
    let mut host = Playground::new(1024, 768, "secure").unwrap();
    select_security(&mut host, 0);
    key(&mut host, "Enter");
    assert_eq!(state(&host)["dialog"], "Enrolled Secure Boot keys");
    key(&mut host, "Escape");
    assert_eq!(state(&host)["dialog"], Value::Null);
    assert_eq!(state(&host)["keys"], json!([1, 1, 2, 1]));
    let mut empty = Playground::new(800, 600, "normal").unwrap();
    select_security(&mut empty, 1);
    key(&mut empty, "Enter");
    assert_eq!(state(&empty)["keys"], json!([0, 0, 0, 0]));
    // A failure is reported in full, in a modal the user dismisses.
    assert_eq!(state(&empty)["dialog"], "Operation failed");
    key(&mut empty, "Escape");
    assert_eq!(state(&empty)["dialog"], Value::Null);
}

#[test]
fn independent_instances_have_identical_pixels_and_do_not_share_variables() {
    let mut a = Playground::new(800, 600, "normal").unwrap();
    let b = Playground::new(800, 600, "normal").unwrap();
    assert!(
        a.rgba() == b.rgba(),
        "independent fixtures must paint identically"
    );
    let rgba = a.rgba();
    assert_eq!(rgba.len(), 800 * 600 * 4);
    assert!(rgba.as_chunks::<4>().0.iter().all(|pixel| pixel[3] == 255));
    let accent = crabefi_ui::screens::theme::ACCENT;
    assert!(
        rgba.as_chunks::<4>()
            .0
            .iter()
            .any(|pixel| pixel[..3] == [accent.r, accent.g, accent.b])
    );
    select_security(&mut a, 4);
    key(&mut a, "Enter");
    confirm(&mut a);
    assert_eq!(state(&b)["requested"], false);
    assert!(a.rgba() != b.rgba());
}

#[test]
fn invalid_inputs_and_dimensions_are_rejected_without_panics() {
    for (width, height) in [(0, 0), (639, 400), (800, 399), (u32::MAX, u32::MAX)] {
        assert!(Playground::new(width, height, "normal").is_err());
    }
    assert!(Playground::new(800, 600, "unknown").is_err());
    let mut host = Playground::new(800, 600, "normal").unwrap();
    assert!(host.key("").is_err());
    assert!(host.key("invalid").is_err());
    assert!(host.click(800, 0).is_err());
    host.pointer(i32::MAX, i32::MIN);
    host.advance(0);
    for _ in 0..128 {
        host.key("ArrowDown").unwrap();
    }
    assert!(host.key("ArrowDown").is_err());
}

#[test]
fn dom_keys_carry_modifiers_and_leave_other_keys_to_the_page() {
    let mut host = Playground::new(800, 600, "normal").unwrap();
    let press = |host: &mut Playground, key: &str, ctrl: bool, shift: bool| {
        let taken = host.dom_key(key, ctrl, shift);
        host.advance(0);
        taken
    };
    // Shift alone, browser shortcuts and reload stay with the browser.
    for (key, ctrl) in [("Shift", false), ("F5", false), ("r", true), ("Tab", true)] {
        assert!(!press(&mut host, key, ctrl, false), "{key}");
    }
    assert!(press(&mut host, "ArrowDown", false, false));
    assert!(press(&mut host, "e", false, false));
    assert!(press(&mut host, "U", true, false)); // Ctrl+U clears the editor
    assert!(press(&mut host, "x", false, false));
    assert!(press(&mut host, "Tab", false, true)); // Shift+Tab is BackTab
    assert!(press(&mut host, "Tab", false, false));
    assert!(press(&mut host, "Enter", false, false));
    assert_eq!(state(&host)["commandLine"], "x");
    assert!(host.ended());
    assert!(!press(&mut host, "Enter", false, false));
}

#[test]
fn every_listed_scenario_starts() {
    let listed: Vec<(String, String)> = serde_json::from_str(&Playground::scenarios()).unwrap();
    assert_eq!(listed.len(), crabefi_ui_harness::SCENARIOS.len());
    for (name, _) in listed {
        Playground::new(800, 600, &name).unwrap();
    }
}
