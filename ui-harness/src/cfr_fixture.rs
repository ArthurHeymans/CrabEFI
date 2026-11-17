//! Synthetic CFR metadata and disposable storage. All editing/guards are the
//! real shared Firmware page, not a second implementation of its interaction.
use super::Simulation;
use crabefi_ui::cfr::{
    CFR_OPTFLAG_INACTIVE, CFR_OPTFLAG_READONLY, CFR_OPTFLAG_SUPPRESS, CfrEnumChoice, CfrForm,
    CfrInfo, CfrOption, CfrOptionType, CfrValue, LevelFilter, SettingsModel,
};
use crabefi_ui::settings::{
    FirmwareObservation, MenuItem, can_edit_item, get_option, is_item_visible,
};
use serde_json::{Value, json};
use std::{cell::RefCell, rc::Rc};

pub(super) struct Fixture {
    metadata: CfrInfo,
    simulation: Rc<RefCell<Simulation>>,
}
fn option(id: u64, name: &str, label: &str, kind: CfrOptionType, help: &str) -> CfrOption {
    CfrOption {
        object_id: id,
        dependency_id: 0,
        opt_name: name.into(),
        ui_name: label.into(),
        ui_helptext: help.into(),
        flags: 0,
        option_type: kind,
        dep_values: Vec::new(),
    }
}
fn number(default: u32, min: u32, max: u32, step: u32) -> CfrOptionType {
    CfrOptionType::Number {
        default,
        min,
        max,
        step,
        hex_display: false,
    }
}
fn choices(labels: &[&str]) -> CfrOptionType {
    CfrOptionType::Enum {
        default: 0,
        choices: labels
            .iter()
            .enumerate()
            .map(|(index, label)| CfrEnumChoice {
                value: index as u32,
                ui_name: (*label).into(),
            })
            .collect(),
    }
}
impl Fixture {
    pub(super) fn new(simulation: Rc<RefCell<Simulation>>) -> Self {
        let mut power_limit = option(
            2,
            "cpu_power_limit",
            "CPU power limit",
            number(35, 15, 65, 5),
            "Synthetic watt limit. Enter a decimal or hexadecimal value, from 15 to 65 in steps of 5. Hidden when Hyper-Threading is disabled to exercise live CFR dependencies.",
        );
        power_limit.dependency_id = 1;
        power_limit.dep_values = vec![1];
        let mut board = option(
            5,
            "board_revision",
            "Board revision",
            CfrOptionType::Varchar {
                default: "DEMO-BOARD-A".into(),
            },
            "A fictitious board identifier. Read-only: this is supplied by the simulated platform, not a configurable setting.",
        );
        board.flags = CFR_OPTFLAG_READONLY;
        let mut debug = option(
            7,
            "debug_uart",
            "Debug UART",
            number(0, 0, 3, 1),
            "Shown only while Advanced options is enabled. This does not configure an actual UART.",
        );
        debug.dependency_id = 6;
        let mut legacy = option(
            14,
            "legacy_boot",
            "Legacy boot",
            CfrOptionType::Bool { default: false },
            "Visible but unavailable. The synthetic platform marks this CFR option inactive.",
        );
        legacy.flags = CFR_OPTFLAG_INACTIVE;
        let mut factory = option(
            90,
            "factory_mode",
            "Factory mode (suppressed)",
            CfrOptionType::Bool { default: true },
            "A suppressed dependency, not a visible row.",
        );
        factory.flags = CFR_OPTFLAG_SUPPRESS;
        let mut recovery = option(
            15,
            "recovery_tools",
            "Recovery tools",
            CfrOptionType::Bool { default: true },
            "Depends on a suppressed stored value; the UI reads it once per settings session.",
        );
        recovery.dependency_id = 90;
        let processor = vec![
            option(
                1,
                "hyper_threading",
                "Hyper-Threading",
                CfrOptionType::Bool { default: true },
                "Synthetic boolean option for testing. Right/Left or Enter toggles a draft. Save is required to keep it; no CPU configuration is changed.",
            ),
            power_limit,
            option(
                3,
                "power_profile",
                "Power profile",
                choices(&["Balanced", "Performance", "Quiet"]),
                "Enter opens the real CFR enum picker. Arrow keys choose; Enter or Use value applies the draft. Escape cancels.",
            ),
            option(
                4,
                "asset_tag",
                "Asset tag",
                CfrOptionType::Varchar {
                    default: "CrabEFI demo".into(),
                },
                "Editable text, stored only in this simulated session. Ctrl+U clears the editor.",
            ),
            board,
            option(
                6,
                "advanced_options",
                "Advanced options",
                CfrOptionType::Bool { default: false },
                "Enables the dependent Debug UART row immediately, before saving.",
            ),
            debug,
            option(
                0,
                "",
                "Demo metadata only; no hardware is accessed.",
                CfrOptionType::Comment,
                "",
            ),
        ];
        let boot = vec![
            option(
                10,
                "boot_timeout",
                "Boot timeout",
                number(5, 0, 30, 1),
                "Synthetic boot timeout in seconds. This setting is a CFR example; it does not change the separate countdown test fixture.",
            ),
            option(
                11,
                "usb_boot",
                "USB boot",
                CfrOptionType::Bool { default: true },
                "A synthetic boot policy toggle.",
            ),
            option(
                12,
                "boot_order",
                "Boot order",
                choices(&["NVMe first", "USB first", "Network first"]),
                "Example enum with saved, default and unsaved markers.",
            ),
            option(
                13,
                "boot_banner",
                "Boot banner",
                CfrOptionType::Varchar {
                    default: "CrabEFI".into(),
                },
                "An example string. Saving never changes the host computer.",
            ),
            legacy,
            factory,
            recovery,
        ];
        Self {
            metadata: CfrInfo {
                version: 0,
                forms: vec![
                    CfrForm {
                        object_id: 100,
                        dependency_id: 0,
                        ui_name: "Processor".into(),
                        flags: 0,
                        options: processor,
                        dep_values: Vec::new(),
                    },
                    CfrForm {
                        object_id: 200,
                        dependency_id: 0,
                        ui_name: "Boot policy".into(),
                        flags: 0,
                        options: boot,
                        dep_values: Vec::new(),
                    },
                ],
            },
            simulation,
        }
    }
}
impl SettingsModel for Fixture {
    fn forms(&self) -> &[CfrForm] {
        &self.metadata.forms
    }
    fn read_option_value(&self, option: &CfrOption) -> CfrValue {
        self.simulation
            .borrow()
            .settings_saved
            .get(&option.opt_name)
            .cloned()
            .unwrap_or_else(|| CfrValue::from_option_type(&option.option_type))
    }
    fn write_option_value(&self, option: &CfrOption, value: &CfrValue) -> Result<(), &'static str> {
        if !option.is_editable() || !option.is_visible() {
            return Err("Read-only or suppressed fixture option");
        }
        let valid = match (&option.option_type, value) {
            (CfrOptionType::Bool { .. }, CfrValue::Bool(_)) => true,
            (CfrOptionType::Number { min, max, step, .. }, CfrValue::Number(n)) => {
                n >= min && n <= max && (n - min).is_multiple_of((*step).max(1))
            }
            (CfrOptionType::Enum { choices, .. }, CfrValue::Number(n)) => {
                choices.iter().any(|choice| choice.value == *n)
            }
            (CfrOptionType::Varchar { .. }, CfrValue::Varchar(text)) => text.len() <= 255,
            _ => false,
        };
        if !valid {
            return Err("Invalid fixture value");
        }
        let mut sim = self.simulation.borrow_mut();
        if sim.fail_writes {
            sim.log(format!(
                "CFR {}: simulated persistence failure",
                option.opt_name
            ));
            return Err("Simulated variable write failure");
        }
        sim.settings_saved
            .insert(option.opt_name.clone(), value.clone());
        sim.log(format!(
            "CFR {} saved: {}",
            option.opt_name,
            value_json(value)
        ));
        Ok(())
    }
    fn configured_level(&self) -> LevelFilter {
        self.simulation.borrow().configured_log_level
    }
    fn set_configured_level(&self, level: LevelFilter) -> Result<(), &'static str> {
        let mut sim = self.simulation.borrow_mut();
        if sim.fail_writes {
            sim.log("CFR log level: simulated persistence failure");
            return Err("Simulated variable write failure");
        }
        sim.configured_log_level = level;
        sim.log(format!("CFR log level saved: {level}"));
        Ok(())
    }
}
pub(super) fn value_json(value: &CfrValue) -> Value {
    match value {
        CfrValue::Bool(value) => json!(value),
        CfrValue::Number(value) => json!(value),
        CfrValue::Varchar(value) => json!(value),
    }
}
pub(super) fn observe(state: &FirmwareObservation<'_>) -> Value {
    let mut selected_id = None;
    let mut selected_name = None;
    let mut rows = Vec::new();
    for (index, item) in state.items.iter().enumerate() {
        if let MenuItem::Option {
            form_idx,
            option_idx,
            current_value,
            original_value,
        } = item
        {
            let Some(option) = get_option(state.model, *form_idx, *option_idx) else {
                continue;
            };
            if index == state.selected {
                selected_id = Some(option.object_id);
                selected_name = Some(option.ui_name.as_str());
            }
            let (kind, choices, range) = match &option.option_type {
                CfrOptionType::Bool { .. } => ("bool", Vec::new(), Value::Null),
                CfrOptionType::Number {
                    min,
                    max,
                    step,
                    hex_display,
                    ..
                } => (
                    "number",
                    Vec::new(),
                    json!({ "min": min, "max": max, "step": step, "hex": hex_display }),
                ),
                CfrOptionType::Enum { choices, .. } => (
                    "enum",
                    choices
                        .iter()
                        .map(|choice| json!({ "value": choice.value, "label": choice.ui_name }))
                        .collect(),
                    Value::Null,
                ),
                CfrOptionType::Varchar { .. } => ("varchar", Vec::new(), Value::Null),
                CfrOptionType::Comment => ("comment", Vec::new(), Value::Null),
            };
            rows.push(json!({
                "id": option.object_id, "name": option.opt_name, "label": option.ui_name,
                "section": state.model.forms()[*form_idx].ui_name,
                "type": kind, "choices": choices, "range": range, "help": option.ui_helptext,
                "value": value_json(current_value), "saved": value_json(original_value),
                "default": value_json(&CfrValue::from_option_type(&option.option_type)),
                "visible": is_item_visible(state.model, state.items, item),
                "editable": can_edit_item(state.model, state.items, index),
                "readOnly": !option.is_editable(),
            }));
        }
    }
    json!({ "section": state.section, "selectedId": selected_id, "selectedName": selected_name,
        "dirtyCount": state.dirty_count, "saveResult": state.save_result, "status": state.status,
        "rows": rows })
}
