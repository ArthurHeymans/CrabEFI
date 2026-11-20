use super::geometry::{fw_layout, section_rect};
use super::input::{graphical_key_allowed, open_section, section_hit};
use super::operations::{
    apply_graphical_edit, change_blocks, choice_tags, discard_graphical_changes,
    parse_graphical_number, restore_graphical_default,
};
use super::paint::{draw_graphical_menu, draw_setting_row, paint_option_row, strip_notice};
use super::state::{graphical_page_selection, section_of, section_rows, visible_sections};
use super::values::truncate_for_width;
use super::{FramebufferInfo, GraphicalState};
use crate::KeyPress;
use crate::cfr::{self, CfrForm, CfrInfo, CfrOption, CfrOptionType, CfrValue, OptionStore};
use crate::screens::controls::Group;
use crate::screens::dialog::Block;
use crate::screens::kit::Tone;
use crate::screens::render::FontSize;
use crate::settings::{
    MenuItem, SettingEdit, build_menu_items, has_changes, save_all_changes, stepped_number,
};
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[test]
fn later_status_messages_stay_visible_beside_save_results() {
    let message = Some(("This option cannot be changed.", false));
    // A newer message leads a failed save, which remains the detail.
    let (tone, headline, detail) = strip_notice(Some((0, 1)), message, 1, String::new());
    assert_eq!(tone, Tone::Bad);
    assert_eq!(headline, "This option cannot be changed.");
    assert_eq!(detail, "Could not save the change.");
    let (_, headline, detail) = strip_notice(Some((0, 1)), None, 1, String::new());
    assert_eq!(headline, "Could not save the change.");
    assert_eq!(detail, "Your edits are kept (starred).");
    // A successful save yields to a message raised after it.
    let (tone, headline, _) = strip_notice(Some((1, 0)), message, 0, String::new());
    assert_eq!(tone, Tone::Bad);
    assert_eq!(headline, "This option cannot be changed.");
    let (tone, headline, _) = strip_notice(Some((1, 0)), None, 0, String::new());
    assert_eq!(tone, Tone::Ok);
    assert_eq!(headline, "Saved 1 change.");
}

fn option(id: u64) -> CfrOption {
    CfrOption {
        object_id: id,
        dependency_id: 0,
        opt_name: alloc::format!("ui_regression_{id}"),
        ui_name: alloc::format!("Option {id}"),
        ui_helptext: String::new(),
        flags: 0,
        option_type: CfrOptionType::Bool { default: false },
        dep_values: Vec::new(),
    }
}
fn framebuffer(pixels: &mut [u32], width: u32, height: u32) -> FramebufferInfo {
    crate::test_surface(crate::FramebufferConfig {
        physical_address: pixels.as_mut_ptr() as u64,
        width,
        height,
        stride: width,
        bits_per_pixel: 32,
        red_mask_pos: 16,
        red_mask_size: 8,
        green_mask_pos: 8,
        green_mask_size: 8,
        blue_mask_pos: 0,
        blue_mask_size: 8,
    })
}

#[test]
fn changed_log_level_has_a_visible_dirty_marker_even_when_value_is_identical() {
    let mut clean_pixels = std::vec![0u32; 1024 * 768];
    let mut dirty_pixels = clean_pixels.clone();
    let clean = MenuItem::CrabLogLevel {
        current_level: log::LevelFilter::Info,
        original_level: log::LevelFilter::Info,
    };
    let dirty = MenuItem::CrabLogLevel {
        current_level: log::LevelFilter::Info,
        original_level: log::LevelFilter::Debug,
    };
    let cfr = CfrInfo::new();
    for (item, pixels) in [(&clean, &mut clean_pixels), (&dirty, &mut dirty_pixels)] {
        let fb = framebuffer(pixels, 1024, 768);
        let l = fw_layout(&fb);
        draw_setting_row(&fb, &l, &cfr, item, (240, 200, 460, 34), true, true, false);
    }
    assert_ne!(
        clean_pixels, dirty_pixels,
        "dirty marker must be rendered, independently of the displayed value"
    );
}

#[test]
fn long_unsaved_lists_cannot_hide_the_decision() {
    let cfr = CfrInfo {
        version: 0,
        forms: alloc::vec![CfrForm {
            object_id: 10,
            dependency_id: 0,
            ui_name: String::from("Test"),
            flags: 0,
            options: (1..=30).map(option).collect(),
            dep_values: Vec::new(),
        }],
    };
    let items: Vec<_> = (0..30)
        .map(|i| MenuItem::Option {
            form_idx: 0,
            option_idx: i,
            current_value: CfrValue::Bool(true),
            original_value: CfrValue::Bool(false),
        })
        .collect();
    let blocks = change_blocks(&cfr, &items, 5);
    assert_eq!(blocks.len(), 6);
    assert!(matches!(&blocks[5], Block::Muted(text) if text == "and 25 more"));
}

#[test]
fn paging_and_content_accelerators_cannot_retarget_other_focus_groups() {
    for group in [Group::Navigation, Group::Actions, Group::Sections] {
        for key in [
            KeyPress::Char('d'),
            KeyPress::Char('+'),
            KeyPress::PageDown,
            KeyPress::PageUp,
            KeyPress::Left,
        ] {
            assert!(!graphical_key_allowed(group, key));
            assert!(graphical_key_allowed(Group::Content, key));
        }
        assert!(graphical_key_allowed(group, KeyPress::Char('w')));
        assert!(graphical_key_allowed(group, KeyPress::F10));
    }
}

#[test]
fn section_keys_and_keyboard_edits_keep_feedback_consistent() {
    for key in [KeyPress::Right, KeyPress::Char('j'), KeyPress::Char('k')] {
        assert!(graphical_key_allowed(Group::Sections, key));
        assert!(!graphical_key_allowed(Group::Navigation, key));
    }
    let cfr = CfrInfo::new();
    let mut items = [MenuItem::CrabLogLevel {
        current_level: log::LevelFilter::Info,
        original_level: log::LevelFilter::Info,
    }];
    let mut state = GraphicalState::new(0);
    state.save_result = Some((1, 0));
    assert_eq!(
        apply_graphical_edit(
            &cfr,
            &mut items,
            &mut state,
            SettingEdit::SetLogLevel(log::LevelFilter::Info)
        ),
        Some(false),
    );
    assert_eq!(state.save_result, Some((1, 0)));
    assert_eq!(
        apply_graphical_edit(
            &cfr,
            &mut items,
            &mut state,
            SettingEdit::SetLogLevel(log::LevelFilter::Trace)
        ),
        Some(true),
    );
    assert_eq!(state.save_result, None);
}

#[test]
fn shortcuts_stay_on_the_editors_step_grid_without_overflow() {
    assert_eq!(stepped_number(10, 0, 12, 5, true), None);
    assert_eq!(stepped_number(12, 0, 12, 5, false), Some(10));
    assert_eq!(stepped_number(8, 2, 12, 5, true), Some(12));
    assert_eq!(stepped_number(8, 2, 12, 5, false), Some(7));
    assert_eq!(
        stepped_number(u32::MAX, u32::MAX - 1, u32::MAX, 5, false),
        Some(u32::MAX - 1)
    );
    assert_eq!(stepped_number(u32::MAX, 0, u32::MAX, 1, true), None);
    assert_eq!(stepped_number(0, 0, 12, 0, true), Some(1));
    for n in 0..=12 {
        for forward in [false, true] {
            if let Some(next) = stepped_number(n, 0, 12, 5, forward) {
                assert!(parse_graphical_number(&alloc::format!("{next}"), 0, 12, 5).is_ok());
            }
        }
    }
}

#[test]
fn long_help_text_is_capacity_aware_and_ascii_truncated() {
    let text = "Description ".repeat(30);
    let label = truncate_for_width(&text, 1800, FontSize::Small);
    assert!(label.starts_with("Description "));
    assert!(label.ends_with("..."));
    assert!(label.is_ascii() && label.len() <= 256);
}

#[test]
fn log_level_default_updates_the_draft_and_feedback() {
    let cfr = CfrInfo::new();
    let mut items = alloc::vec![MenuItem::CrabLogLevel {
        current_level: log::LevelFilter::Trace,
        original_level: log::LevelFilter::Trace,
    }];
    let mut state = GraphicalState::new(0);
    restore_graphical_default(&cfr, &mut items, &mut state);
    assert!(
        matches!(items[0], MenuItem::CrabLogLevel { current_level, original_level }
        if current_level == crate::cfr::DEFAULT_LEVEL && original_level == log::LevelFilter::Trace)
    );
    assert!(state.status_message.is_some_and(|(_, ok)| ok));
}

#[test]
fn external_boot_default_is_the_build_policy() {
    let cfr = CfrInfo::new();
    let mut items = alloc::vec![MenuItem::CrabExternalBoot {
        current: 2,
        original: 2,
        floor: 1,
    }];
    let mut state = GraphicalState::new(0);
    restore_graphical_default(&cfr, &mut items, &mut state);
    assert!(matches!(
        items[0],
        MenuItem::CrabExternalBoot {
            current: 1,
            original: 2,
            ..
        }
    ));
    apply_graphical_edit(
        &cfr,
        &mut items,
        &mut state,
        SettingEdit::SetExternalBoot(2),
    );
    assert!(!has_changes(&items));
}

#[test]
fn number_editor_validates_radix_bounds_step_and_overflow() {
    assert_eq!(parse_graphical_number("0x19", 0, 120, 5), Ok(25));
    assert_eq!(parse_graphical_number("25", 0, 120, 5), Ok(25));
    assert_eq!(parse_graphical_number("0XFF", 0, 255, 1), Ok(255));
    for text in ["", "-1", "999", "13", "4294967296", "abc"] {
        assert!(parse_graphical_number(text, 0, 120, 5).is_err(), "{text}");
    }
    assert_eq!(
        parse_graphical_number("4294967295", 0, u32::MAX, 1),
        Ok(u32::MAX)
    );
    assert_eq!(parse_graphical_number("7", 2, 12, 5), Ok(7));
}

#[test]
fn discard_restores_unsaved_values_only() {
    let mut items = alloc::vec![
        MenuItem::Option {
            form_idx: 0,
            option_idx: 0,
            current_value: CfrValue::Bool(true),
            original_value: CfrValue::Bool(true)
        },
        MenuItem::Option {
            form_idx: 0,
            option_idx: 1,
            current_value: CfrValue::Bool(false),
            original_value: CfrValue::Bool(true)
        },
        MenuItem::CrabLogLevel {
            current_level: log::LevelFilter::Trace,
            original_level: log::LevelFilter::Info
        },
    ];
    discard_graphical_changes(&mut items);
    assert!(!has_changes(&items));
    assert!(matches!(
        items[1],
        MenuItem::Option {
            current_value: CfrValue::Bool(true),
            ..
        }
    ));
    assert!(matches!(
        items[2],
        MenuItem::CrabLogLevel {
            current_level: log::LevelFilter::Info,
            ..
        }
    ));
}

fn two_sections() -> (CfrInfo, Vec<MenuItem>) {
    let mut options: Vec<_> = (1..=40).map(option).collect();
    options[20].dependency_id = 1;
    let cfr = CfrInfo {
        version: 0,
        forms: alloc::vec![
            CfrForm {
                object_id: 100,
                dependency_id: 0,
                ui_name: String::from("First"),
                flags: 0,
                options,
                dep_values: Vec::new(),
            },
            CfrForm {
                object_id: 101,
                dependency_id: 0,
                ui_name: String::from("Second"),
                flags: 0,
                options: alloc::vec![option(50)],
                dep_values: Vec::new(),
            }
        ],
    };
    let mut items = alloc::vec![MenuItem::FormHeader {
        name: String::from("First"),
        form_idx: Some(0),
    }];
    items.extend((0..40).map(|i| MenuItem::Option {
        form_idx: 0,
        option_idx: i,
        current_value: CfrValue::Bool(false),
        original_value: CfrValue::Bool(false),
    }));
    items.push(MenuItem::FormHeader {
        name: String::from("Second"),
        form_idx: Some(1),
    });
    items.push(MenuItem::Option {
        form_idx: 1,
        option_idx: 0,
        current_value: CfrValue::Bool(false),
        original_value: CfrValue::Bool(false),
    });
    (cfr, items)
}

#[test]
fn page_navigation_stays_in_its_section_and_skips_hidden_dependencies() {
    let (cfr, items) = two_sections();
    let rows = section_rows(&cfr, &items, 0);
    assert!(
        !rows.contains(&21),
        "option 21 depends on disabled option 1"
    );
    assert!(
        !rows.contains(&42),
        "the next section is not part of this one"
    );
    assert_eq!(
        graphical_page_selection(&items, &rows, 30, KeyPress::Home, 5),
        1
    );
    assert_eq!(
        graphical_page_selection(&items, &rows, 1, KeyPress::End, 5),
        40
    );
    assert_eq!(
        graphical_page_selection(&items, &rows, 1, KeyPress::PageDown, 5),
        6
    );
    assert_eq!(
        graphical_page_selection(&items, &rows, 20, KeyPress::Down, 1),
        22
    );
    assert_eq!(
        graphical_page_selection(&items, &rows, 1, KeyPress::PageUp, 5),
        1
    );
    assert_eq!(visible_sections(&cfr, &items), [0, 41]);
    assert_eq!(section_of(&items, 42), 41);
}

#[test]
fn x61_layout_fits_three_panes_and_rows() {
    let fb = framebuffer(&mut [], 1024, 768);
    let l = fw_layout(&fb);
    assert!(l.help.is_some());
    assert!(l.slots >= 12, "{}", l.slots);
    assert!(l.options.2 >= 400);
    let narrow = framebuffer(&mut [], 640, 480);
    assert!(fw_layout(&narrow).help.is_none());
}

#[test]
fn hover_repaint_matches_full_repaint() {
    let (cfr, items) = two_sections();
    let (width, height) = (1024, 768);
    let mut pixels = std::vec![0; width as usize * height as usize];
    let fb = framebuffer(&mut pixels, width, height);
    let mut state = GraphicalState::new(3);
    draw_graphical_menu(&cfr, &items, &state, &fb);
    let l = fw_layout(&fb);
    let rows = section_rows(&cfr, &items, 0);
    state.hovered = Some(5);
    paint_option_row(&fb, &l, &cfr, &items, &state, &rows, 4);
    let mut expected = std::vec![0; pixels.len()];
    draw_graphical_menu(
        &cfr,
        &items,
        &state,
        &framebuffer(&mut expected, width, height),
    );
    assert!(pixels == expected);
}

#[test]
fn hidden_dependencies_are_read_once_per_session_not_per_poll() {
    install_store();
    let mut hidden = option(900);
    hidden.opt_name = String::from("ui_hidden_900");
    hidden.flags = cfr::CFR_OPTFLAG_SUPPRESS;
    let mut dependent: Vec<_> = (1..=10).map(option).collect();
    for o in &mut dependent {
        o.dependency_id = 900;
    }
    let mut options = alloc::vec![hidden];
    options.extend(dependent);
    let cfr = CfrInfo {
        version: 0,
        forms: alloc::vec![CfrForm {
            object_id: 10,
            dependency_id: 0,
            ui_name: String::from("Test"),
            flags: 0,
            options,
            dep_values: Vec::new(),
        }],
    };
    let session = crate::settings::Session::new(&cfr);
    let items = build_menu_items(&session);
    let header = visible_sections(&session, &items)[1];
    for _ in 0..50 {
        assert_eq!(section_rows(&session, &items, header).len(), 10);
    }
    assert_eq!(STORE.hidden_reads.load(Ordering::SeqCst), 1);
}

#[test]
fn far_sections_scroll_into_view_and_hit_where_painted() {
    let forms: Vec<CfrForm> = (0..20)
        .map(|i| CfrForm {
            object_id: 1000 + i,
            dependency_id: 0,
            ui_name: alloc::format!("Section {i}"),
            flags: 0,
            options: alloc::vec![option(2000 + i)],
            dep_values: Vec::new(),
        })
        .collect();
    let cfr = CfrInfo { version: 0, forms };
    let mut items = Vec::new();
    for (f, form) in cfr.forms.iter().enumerate() {
        items.push(MenuItem::FormHeader {
            name: form.ui_name.clone(),
            form_idx: Some(f),
        });
        items.push(MenuItem::Option {
            form_idx: f,
            option_idx: 0,
            current_value: CfrValue::Bool(false),
            original_value: CfrValue::Bool(false),
        });
    }
    let fb = framebuffer(&mut [], 640, 400);
    let l = fw_layout(&fb);
    let sections = visible_sections(&cfr, &items);
    assert!(sections.len() > l.sec_slots, "fixture must overflow");
    let mut state = GraphicalState::new(1);
    let last = *sections.last().unwrap();
    open_section(&cfr, &items, &mut state, &fb, last);
    assert!(state.section_offset > 0);
    let rect = section_rect(&fb, &l, &state, sections.len() - 1, sections.len())
        .expect("selected section is visible");
    assert!(rect.1 + rect.3 as i32 <= l.sections.1 + l.sections.3 as i32);
    assert_eq!(
        section_hit(&cfr, &items, &state, &fb, rect.0 + 10, rect.1 + 5),
        Some(last)
    );
    assert_eq!(
        section_hit(&cfr, &items, &state, &fb, rect.0 + 10, l.sec_rows_y - 2),
        None
    );
}

#[test]
fn picker_tags_distinguish_saved_default_and_unsaved() {
    assert_eq!(
        choice_tags(Some(1), Some(1), 2),
        [(1, "saved, default"), (2, "unsaved")]
    );
    assert_eq!(
        choice_tags(Some(0), Some(1), 0),
        [(0, "saved"), (1, "default")]
    );
}

/// One store per test process: `set_option_store` may run only once.
struct TestStore {
    fail: AtomicBool,
    first_writes: AtomicUsize,
    second_writes: AtomicUsize,
    hidden_reads: AtomicUsize,
}
static STORE: TestStore = TestStore {
    fail: AtomicBool::new(true),
    first_writes: AtomicUsize::new(0),
    second_writes: AtomicUsize::new(0),
    hidden_reads: AtomicUsize::new(0),
};
fn install_store() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| cfr::set_option_store(&STORE));
}
impl OptionStore for TestStore {
    fn keeps(&self, option: &CfrOption) -> bool {
        option.opt_name.starts_with("ui_regression_") || option.opt_name.starts_with("ui_hidden_")
    }
    fn read(&self, option: &CfrOption) -> Option<CfrValue> {
        if option.opt_name.starts_with("ui_hidden_") {
            self.hidden_reads.fetch_add(1, Ordering::SeqCst);
            return Some(CfrValue::Bool(true));
        }
        None
    }
    fn write(&self, option: &CfrOption, _: &CfrValue) -> Result<(), &'static str> {
        if option.object_id == 1 {
            self.first_writes.fetch_add(1, Ordering::SeqCst);
        } else {
            self.second_writes.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Err("injected failure");
            }
        }
        Ok(())
    }
}

#[test]
fn partial_save_preserves_failed_drafts_and_retries_only_unsaved_options() {
    install_store();
    let cfr = CfrInfo {
        version: 0,
        forms: alloc::vec![CfrForm {
            object_id: 10,
            dependency_id: 0,
            ui_name: String::from("Test"),
            flags: 0,
            options: alloc::vec![option(1), option(2)],
            dep_values: Vec::new(),
        }],
    };
    let mut items: Vec<_> = (0..2)
        .map(|i| MenuItem::Option {
            form_idx: 0,
            option_idx: i,
            current_value: CfrValue::Bool(true),
            original_value: CfrValue::Bool(false),
        })
        .collect();
    assert_eq!(save_all_changes(&cfr, &mut items), (1, 1));
    assert!(has_changes(&items));
    STORE.fail.store(false, Ordering::SeqCst);
    assert_eq!(save_all_changes(&cfr, &mut items), (1, 0));
    assert!(!has_changes(&items));
    assert_eq!(STORE.first_writes.load(Ordering::SeqCst), 1);
    assert_eq!(STORE.second_writes.load(Ordering::SeqCst), 2);
}

#[test]
fn defaults_stay_in_draft_and_readonly_values_are_not_edited() {
    let mut read_only = option(1);
    read_only.flags = cfr::CFR_OPTFLAG_READONLY;
    let cfr = CfrInfo {
        version: 0,
        forms: alloc::vec![CfrForm {
            object_id: 10,
            dependency_id: 0,
            ui_name: String::from("Test"),
            flags: 0,
            options: alloc::vec![read_only, option(2)],
            dep_values: Vec::new(),
        }],
    };
    let mut items: Vec<_> = (0..2)
        .map(|i| MenuItem::Option {
            form_idx: 0,
            option_idx: i,
            current_value: CfrValue::Bool(true),
            original_value: CfrValue::Bool(true),
        })
        .collect();
    let mut state = GraphicalState::new(0);
    restore_graphical_default(&cfr, &mut items, &mut state);
    assert!(!has_changes(&items));
    state.selected = 1;
    restore_graphical_default(&cfr, &mut items, &mut state);
    assert!(has_changes(&items));
}
