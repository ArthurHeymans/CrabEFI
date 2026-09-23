//! Runtime image entry points shared by the image, the normalizer and the boot
//! client.

/// Invoke `$callback!` with every runtime image export in manifest order.
///
/// Each export is passed as `field: symbol => signature;`, where `symbol` is
/// the image's unmangled function and `signature` its function pointer type.
/// The image checks its definitions against this list, the normalizer writes
/// the export table in this order, and the boot client resolves typed entry
/// points from it.
#[macro_export]
macro_rules! runtime_exports {
    ($callback:ident) => {
        $callback! {
            init: runtime_image_init
                => unsafe extern "C" fn(*const $crate::RuntimeHandoff) -> usize;
            import_relocation: runtime_image_import_relocation
                => unsafe extern "C" fn(*const $crate::RelocationImport) -> usize;
            activate: runtime_image_activate => extern "C" fn(u64) -> usize;
            import_variable: runtime_image_import_variable
                => unsafe extern "C" fn(*const $crate::VariableImport) -> usize;
            prepare_retained_staging: runtime_image_prepare_retained_staging
                => extern "C" fn() -> usize;
            replay_deferred: runtime_image_replay_deferred => extern "C" fn() -> usize;
            enable_capsule_delivery: runtime_image_enable_capsule_delivery
                => extern "C" fn() -> usize;
            complete_import: runtime_image_complete_import => extern "C" fn() -> usize;
            register_configuration: runtime_image_register_configuration
                => unsafe extern "C" fn(*const $crate::ConfigurationRegistration) -> usize;
            set_console: runtime_image_set_console
                => unsafe extern "C" fn(*const $crate::ConsoleRegistration) -> usize;
            install_esrt: runtime_image_install_esrt
                => unsafe extern "C" fn(*const $crate::EsrtRegistration) -> usize;
            prepare_ebs: runtime_image_prepare_ebs
                => unsafe extern "C" fn(*const $crate::MemoryDescriptor, usize) -> usize;
            seal: runtime_image_seal => extern "C" fn() -> usize;
            runtime_services: runtime_image_get_runtime_services => extern "C" fn() -> u64;
            system_table: runtime_image_get_system_table => extern "C" fn() -> u64;
        }
    };
}

macro_rules! define_export_offsets {
    ($($field:ident: $symbol:ident => $signature:ty;)*) => {
        /// Number of runtime image exports.
        pub const EXPORT_COUNT: usize = [$(stringify!($symbol)),*].len();

        /// Image-relative offset of every runtime image export.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct ExportOffsets {
            $(pub $field: u32,)*
        }

        impl ExportOffsets {
            /// Linked symbol names in manifest order.
            pub const SYMBOLS: [&'static str; EXPORT_COUNT] = [$(stringify!($symbol)),*];

            /// Build the offsets from values in manifest order.
            pub const fn from_array(offsets: [u32; EXPORT_COUNT]) -> Self {
                let [$($field),*] = offsets;
                Self { $($field),* }
            }
        }
    };
}

crate::runtime_exports!(define_export_offsets);
