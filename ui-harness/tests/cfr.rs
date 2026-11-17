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
fn firmware(host: &Playground) -> Value {
    state(host)["firmware"].clone()
}
fn row(host: &Playground, name: &str) -> Value {
    firmware(host)["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == name)
        .unwrap_or_else(|| panic!("missing row {name}"))
        .clone()
}
fn processor(host: &mut Playground) {
    if state(host)["screen"] != "firmware" {
        key(host, "f");
    }
    key(host, "BackTab");
    key(host, "ArrowDown");
    key(host, "Enter");
    assert_eq!(firmware(host)["section"], "Processor");
    assert_eq!(firmware(host)["selectedId"], 1);
}
fn fresh() -> Playground {
    Playground::new(1024, 768, "cfr").unwrap()
}
fn choose(host: &mut Playground, choice: usize) -> Value {
    assert!(state(host)["dialog"].is_string());
    for _ in 0..choice {
        key(host, "Tab");
    }
    key(host, "Enter")
}
fn text(host: &mut Playground, value: &str) {
    key(host, "\u{15}");
    for ch in value.chars() {
        key(host, &ch.to_string());
    }
}

#[test]
fn cfr_fixture_starts_on_the_real_firmware_page() {
    let host = fresh();
    assert_eq!(state(&host)["screen"], "firmware");
    assert_eq!(firmware(&host)["section"], "CrabEFI");
    assert_eq!(firmware(&host)["dirtyCount"], 0);
    assert_eq!(row(&host, "hyper_threading")["value"], true);
    assert_eq!(row(&host, "board_revision")["readOnly"], true);
    assert!(
        !firmware(&host)["rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["name"] == "factory_mode")
    );
}

#[test]
fn drafts_change_dependencies_but_not_saved_values_and_discard_is_guarded() {
    let mut host = fresh();
    processor(&mut host);
    key(&mut host, "ArrowRight");
    assert_eq!(row(&host, "hyper_threading")["value"], false);
    assert_eq!(row(&host, "hyper_threading")["saved"], true);
    assert_eq!(row(&host, "cpu_power_limit")["visible"], false);
    assert_eq!(
        state(&host)["savedSettings"]["hyper_threading"],
        Value::Null
    );
    key(&mut host, "b");
    assert_eq!(
        state(&host)["dialog"],
        "Leave Firmware with 1 unsaved change?"
    );
    choose(&mut host, 0); // safe initial choice keeps editing
    assert_eq!(state(&host)["screen"], "firmware");
    assert_eq!(firmware(&host)["dirtyCount"], 1);
    key(&mut host, "b");
    choose(&mut host, 1); // discard and leave
    assert_eq!(state(&host)["screen"], "boot");
    assert_eq!(firmware(&host)["dirtyCount"], 0);
    processor(&mut host);
    assert_eq!(row(&host, "hyper_threading")["value"], true);
    assert_eq!(row(&host, "cpu_power_limit")["visible"], true);
}

#[test]
fn f10_save_survives_page_navigation_and_confirmed_restart() {
    let mut host = fresh();
    processor(&mut host);
    key(&mut host, "ArrowRight");
    key(&mut host, "F10");
    assert_eq!(firmware(&host)["saveResult"], json!([1, 0]));
    assert_eq!(firmware(&host)["dirtyCount"], 0);
    assert_eq!(state(&host)["savedSettings"]["hyper_threading"], false);
    key(&mut host, "b");
    processor(&mut host);
    assert_eq!(row(&host, "hyper_threading")["value"], false);
    key(&mut host, "r");
    assert_eq!(state(&host)["dialog"], "Restart the computer?");
    choose(&mut host, 1);
    assert_eq!(state(&host)["screen"], "boot");
    assert_eq!(state(&host)["savedSettings"]["hyper_threading"], false);
    processor(&mut host);
    assert_eq!(row(&host, "hyper_threading")["value"], false);
}

#[test]
fn save_and_leave_and_save_and_restart_keep_their_distinct_guards() {
    let mut host = fresh();
    processor(&mut host);
    key(&mut host, "ArrowRight");
    key(&mut host, "b");
    choose(&mut host, 2);
    assert_eq!(state(&host)["screen"], "boot");
    assert_eq!(state(&host)["savedSettings"]["hyper_threading"], false);
    processor(&mut host);
    key(&mut host, "ArrowRight");
    key(&mut host, "r");
    assert_eq!(state(&host)["dialog"], "Restart with 1 unsaved change?");
    choose(&mut host, 2);
    assert_eq!(state(&host)["dialog"], "Restart the computer?");
    key(&mut host, "Escape"); // saving succeeds even though restart is cancelled
    assert_eq!(state(&host)["screen"], "firmware");
    assert_eq!(firmware(&host)["dirtyCount"], 0);
    assert_eq!(state(&host)["savedSettings"]["hyper_threading"], true);
}

#[test]
fn number_editor_validates_bounds_and_step_and_defaults_remain_drafts() {
    let mut host = fresh();
    processor(&mut host);
    key(&mut host, "ArrowDown");
    key(&mut host, "Enter");
    assert_eq!(state(&host)["dialog"], "CPU power limit");
    text(&mut host, "42");
    key(&mut host, "Enter");
    assert_eq!(state(&host)["dialog"], "CPU power limit"); // invalid step: editor stays open
    assert_eq!(firmware(&host)["dirtyCount"], 0);
    text(&mut host, "0x28");
    key(&mut host, "Enter");
    assert_eq!(row(&host, "cpu_power_limit")["value"], 40);
    assert_eq!(row(&host, "cpu_power_limit")["saved"], 35);
    key(&mut host, "w");
    assert_eq!(state(&host)["savedSettings"]["cpu_power_limit"], 40);
    key(&mut host, "d");
    assert_eq!(row(&host, "cpu_power_limit")["value"], 35);
    assert_eq!(row(&host, "cpu_power_limit")["saved"], 40);
    assert_eq!(firmware(&host)["dirtyCount"], 1);
}

#[test]
fn enum_picker_text_editor_and_readonly_rows_use_the_real_editors() {
    let mut host = fresh();
    processor(&mut host);
    key(&mut host, "ArrowDown");
    key(&mut host, "ArrowDown");
    key(&mut host, "Enter");
    assert_eq!(state(&host)["dialog"], "Power profile");
    key(&mut host, "ArrowDown");
    key(&mut host, "Escape");
    assert_eq!(row(&host, "power_profile")["value"], 0);
    key(&mut host, "Enter");
    key(&mut host, "ArrowDown");
    key(&mut host, "Enter");
    assert_eq!(row(&host, "power_profile")["value"], 1);
    key(&mut host, "ArrowDown");
    key(&mut host, "Enter");
    text(&mut host, "agent-lab");
    key(&mut host, "Enter");
    assert_eq!(row(&host, "asset_tag")["value"], "agent-lab");
    assert_eq!(firmware(&host)["dirtyCount"], 2);
    key(&mut host, "F10");
    assert_eq!(firmware(&host)["saveResult"], json!([2, 0]));
    key(&mut host, "ArrowDown");
    assert_eq!(firmware(&host)["selectedId"], 5);
    key(&mut host, "Enter");
    key(&mut host, "ArrowRight");
    key(&mut host, "d");
    assert_eq!(state(&host)["dialog"], Value::Null);
    assert_eq!(row(&host, "board_revision")["value"], "DEMO-BOARD-A");
    assert_eq!(firmware(&host)["dirtyCount"], 0);
    assert_eq!(state(&host)["savedSettings"]["board_revision"], Value::Null);
}

#[test]
fn advanced_and_suppressed_dependencies_and_inactive_options_are_respected() {
    let mut host = fresh();
    processor(&mut host);
    assert_eq!(row(&host, "debug_uart")["visible"], false);
    key(&mut host, "End");
    assert_eq!(firmware(&host)["selectedId"], 6);
    key(&mut host, "ArrowRight");
    assert_eq!(row(&host, "debug_uart")["visible"], true);
    key(&mut host, "End");
    assert_eq!(firmware(&host)["selectedId"], 7);
    key(&mut host, "BackTab");
    key(&mut host, "ArrowDown");
    key(&mut host, "Enter");
    assert_eq!(firmware(&host)["section"], "Boot policy");
    assert_eq!(row(&host, "recovery_tools")["visible"], true);
    key(&mut host, "Home");
    for _ in 0..4 {
        key(&mut host, "ArrowDown");
    }
    assert_eq!(firmware(&host)["selectedId"], 14);
    key(&mut host, "ArrowRight");
    key(&mut host, "Enter");
    assert_eq!(row(&host, "legacy_boot")["value"], false);
    assert_eq!(row(&host, "legacy_boot")["editable"], false);
}

#[test]
fn failed_save_cannot_leave_and_repair_retries_the_existing_draft() {
    let mut host = Playground::new(800, 600, "write-error").unwrap();
    processor(&mut host);
    key(&mut host, "ArrowRight");
    key(&mut host, "w");
    assert_eq!(firmware(&host)["saveResult"], json!([0, 1]));
    assert_eq!(firmware(&host)["dirtyCount"], 1);
    assert_eq!(
        state(&host)["savedSettings"]["hyper_threading"],
        Value::Null
    );
    key(&mut host, "b");
    choose(&mut host, 2);
    assert_eq!(state(&host)["screen"], "firmware");
    assert_eq!(firmware(&host)["dirtyCount"], 1);
    host.set_write_failures(false);
    host.advance(0);
    key(&mut host, "F10");
    assert_eq!(firmware(&host)["saveResult"], json!([1, 0]));
    assert_eq!(firmware(&host)["dirtyCount"], 0);
    assert_eq!(state(&host)["savedSettings"]["hyper_threading"], false);
}

#[test]
fn logging_is_simulated_and_no_settings_fixture_remains_available() {
    let mut host = fresh();
    let original = state(&host)["configuredLogLevel"].clone();
    key(&mut host, "ArrowLeft");
    key(&mut host, "w");
    assert_ne!(state(&host)["configuredLogLevel"], original);
    assert_eq!(firmware(&host)["saveResult"], json!([1, 0]));
    let mut none = Playground::new(800, 600, "no-settings").unwrap();
    key(&mut none, "f");
    assert_eq!(state(&none)["screen"], "firmware");
    assert_eq!(state(&none)["firmware"], Value::Null);
    key(&mut none, "b");
    assert_eq!(state(&none)["screen"], "boot");
}

#[test]
fn new_fixture_clears_previous_dirty_marker_and_typography() {
    let baseline = Playground::new(1024, 768, "normal").unwrap().rgba();
    let mut dirty = fresh();
    processor(&mut dirty);
    key(&mut dirty, "ArrowRight");
    key(&mut dirty, "F8");
    assert_eq!(firmware(&dirty)["dirtyCount"], 1);
    let reset = Playground::new(1024, 768, "normal").unwrap();
    assert!(
        reset.rgba() == baseline,
        "new fixture must not inherit Firmware * or text size"
    );
    assert_eq!(state(&reset)["savedSettings"], json!({}));
}

#[test]
fn cfr_fits_supported_sizes_and_variables_are_instance_local() {
    for (width, height) in [(640, 400), (800, 600), (1024, 768), (1920, 1080)] {
        let mut host = Playground::new(width, height, "cfr").unwrap();
        processor(&mut host);
        key(&mut host, "End");
        assert_eq!(firmware(&host)["selectedId"], 6);
        assert_eq!(host.rgba().len(), (width * height * 4) as usize);
    }
    let mut a = fresh();
    processor(&mut a);
    key(&mut a, "ArrowRight");
    key(&mut a, "w");
    let mut b = fresh();
    processor(&mut b);
    assert_eq!(row(&b, "hyper_threading")["value"], true);
    assert_eq!(state(&b)["savedSettings"]["hyper_threading"], Value::Null);
}
