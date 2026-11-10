//! CFR presentation data and host-owned option storage. No firmware I/O.
pub use crate::log_level::{DEFAULT_LEVEL, LEVEL_CHOICES, LevelFilter, level_index, level_name};
use alloc::{string::String, vec::Vec};

pub const CFR_VERSION: u32 = 0;
pub const CFR_OPTFLAG_READONLY: u32 = 1 << 0;
pub const CFR_OPTFLAG_INACTIVE: u32 = 1 << 1;
pub const CFR_OPTFLAG_SUPPRESS: u32 = 1 << 2;
pub const CFR_OPTFLAG_VOLATILE: u32 = 1 << 3;
pub const CFR_OPTFLAG_RUNTIME: u32 = 1 << 4;

#[derive(Debug, Clone)]
pub struct CfrEnumChoice {
    pub value: u32,
    pub ui_name: String,
}
#[derive(Debug, Clone)]
pub enum CfrOptionType {
    Bool {
        default: bool,
    },
    Number {
        default: u32,
        min: u32,
        max: u32,
        step: u32,
        hex_display: bool,
    },
    Enum {
        default: u32,
        choices: Vec<CfrEnumChoice>,
    },
    Varchar {
        default: String,
    },
    Comment,
}
#[derive(Debug, Clone)]
pub struct CfrOption {
    pub object_id: u64,
    pub dependency_id: u64,
    pub opt_name: String,
    pub ui_name: String,
    pub ui_helptext: String,
    pub flags: u32,
    pub option_type: CfrOptionType,
    pub dep_values: Vec<u32>,
}
impl CfrOption {
    pub fn is_editable(&self) -> bool {
        self.flags & (CFR_OPTFLAG_READONLY | CFR_OPTFLAG_INACTIVE | CFR_OPTFLAG_VOLATILE) == 0
            && !matches!(self.option_type, CfrOptionType::Comment)
    }
    pub fn is_visible(&self) -> bool {
        self.flags & CFR_OPTFLAG_SUPPRESS == 0
    }
}
#[derive(Debug, Clone)]
pub struct CfrForm {
    pub object_id: u64,
    pub dependency_id: u64,
    pub ui_name: String,
    pub flags: u32,
    pub options: Vec<CfrOption>,
    pub dep_values: Vec<u32>,
}
impl CfrForm {
    pub fn is_visible(&self) -> bool {
        self.flags & CFR_OPTFLAG_SUPPRESS == 0
    }
}
#[derive(Debug, Clone, PartialEq)]
pub enum CfrValue {
    Bool(bool),
    Number(u32),
    Varchar(String),
}
impl CfrValue {
    pub fn from_option_type(option_type: &CfrOptionType) -> Self {
        match option_type {
            CfrOptionType::Bool { default } => Self::Bool(*default),
            CfrOptionType::Number { default, .. } | CfrOptionType::Enum { default, .. } => {
                Self::Number(*default)
            }
            CfrOptionType::Varchar { default } => Self::Varchar(default.clone()),
            CfrOptionType::Comment => Self::Bool(false),
        }
    }
}

/// A platform can retain selected options outside EFI variable storage.
pub trait OptionStore: Sync {
    fn keeps(&self, option: &CfrOption) -> bool;
    fn read(&self, option: &CfrOption) -> Option<CfrValue>;
    fn write(&self, option: &CfrOption, value: &CfrValue) -> Result<(), &'static str>;
}

/// The graphical settings page consumes metadata and calls these services only
/// when loading/saving. Draft edits and confirmations belong to the real UI.
pub trait SettingsModel {
    fn forms(&self) -> &[CfrForm];
    fn read_option_value(&self, option: &CfrOption) -> CfrValue;
    fn write_option_value(&self, option: &CfrOption, value: &CfrValue) -> Result<(), &'static str>;
    fn configured_level(&self) -> LevelFilter {
        DEFAULT_LEVEL
    }
    fn set_configured_level(&self, _level: LevelFilter) -> Result<(), &'static str> {
        Err("Log level storage unavailable")
    }
    fn find_numeric_value(&self, object_id: u64) -> Option<u32> {
        if object_id == 0 {
            return None;
        }
        for option in self.forms().iter().flat_map(|form| &form.options) {
            if option.object_id == object_id {
                return match self.read_option_value(option) {
                    CfrValue::Bool(value) => Some(u32::from(value)),
                    CfrValue::Number(value) => Some(value),
                    _ => None,
                };
            }
        }
        None
    }
}

/// Metadata-only model, also used by geometry/state unit tests. Production
/// hosts implement SettingsModel to supply actual or simulated persistence.
#[derive(Debug, Clone, Default)]
pub struct CfrInfo {
    pub version: u32,
    pub forms: Vec<CfrForm>,
}
impl CfrInfo {
    pub fn new() -> Self {
        Self::default()
    }
}
impl SettingsModel for CfrInfo {
    fn forms(&self) -> &[CfrForm] {
        &self.forms
    }
    fn read_option_value(&self, option: &CfrOption) -> CfrValue {
        #[cfg(test)]
        if let Some(store) = TEST_STORE
            .get()
            .copied()
            .filter(|store| store.keeps(option))
        {
            return store
                .read(option)
                .unwrap_or_else(|| CfrValue::from_option_type(&option.option_type));
        }
        CfrValue::from_option_type(&option.option_type)
    }
    fn write_option_value(
        &self,
        _option: &CfrOption,
        _value: &CfrValue,
    ) -> Result<(), &'static str> {
        #[cfg(test)]
        if let Some(store) = TEST_STORE
            .get()
            .copied()
            .filter(|store| store.keeps(_option))
        {
            return store.write(_option, _value);
        }
        Err("Read-only metadata model")
    }
}
#[cfg(test)]
static TEST_STORE: std::sync::OnceLock<&'static dyn OptionStore> = std::sync::OnceLock::new();
#[cfg(test)]
pub fn set_option_store(store: &'static dyn OptionStore) {
    assert!(
        TEST_STORE.set(store).is_ok(),
        "test option store already installed"
    );
}
