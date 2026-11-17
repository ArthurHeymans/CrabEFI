#![cfg(feature = "cfr")]

use crabefi::cfr::{self, CfrOption, CfrOptionType, CfrValue, OptionStore};
use std::sync::Mutex;

struct Store(Mutex<Option<CfrValue>>);

impl OptionStore for Store {
    fn keeps(&self, option: &CfrOption) -> bool {
        option.opt_name == "kept"
    }

    fn read(&self, _option: &CfrOption) -> Option<CfrValue> {
        self.0.lock().unwrap().clone()
    }

    fn write(&self, _option: &CfrOption, value: &CfrValue) -> Result<(), &'static str> {
        *self.0.lock().unwrap() = Some(value.clone());
        Ok(())
    }
}

static STORE: Store = Store(Mutex::new(None));
static OTHER: Store = Store(Mutex::new(None));

#[test]
fn platform_store_is_authoritative_including_unset_and_delete() {
    let option = CfrOption {
        object_id: 1,
        dependency_id: 0,
        opt_name: "kept".into(),
        ui_name: "Kept option".into(),
        ui_helptext: String::new(),
        flags: 0,
        option_type: CfrOptionType::Bool { default: true },
        dep_values: Vec::new(),
    };
    cfr::set_option_store(&STORE);
    // No EFI initialization: a kept-but-unset value must use its CFR default,
    // without falling through to the runtime variable store.
    assert_eq!(cfr::read_option_value(&option), CfrValue::Bool(true));
    for invalid in [CfrValue::Number(1), CfrValue::Varchar("wrong type".into())] {
        *STORE.0.lock().unwrap() = Some(invalid);
        assert_eq!(cfr::read_option_value(&option), CfrValue::Bool(true));
    }
    assert_eq!(
        cfr::write_option_value(&option, &CfrValue::Bool(false)),
        Ok(())
    );
    assert_eq!(cfr::read_option_value(&option), CfrValue::Bool(false));
    assert_eq!(
        cfr::delete_option_value(&option),
        Err("Cannot delete option kept by platform store")
    );
    assert_eq!(cfr::read_option_value(&option), CfrValue::Bool(false));

    // Catching a duplicate-registration panic must not replace the first store.
    assert!(std::panic::catch_unwind(|| cfr::set_option_store(&OTHER)).is_err());
    assert_eq!(cfr::read_option_value(&option), CfrValue::Bool(false));
}
