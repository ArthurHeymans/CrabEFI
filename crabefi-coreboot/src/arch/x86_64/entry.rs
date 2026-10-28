//! Select the payload entry at build time.
//!
//! Default builds retain coreboot's 32-bit protected-mode entry. The `entry64`
//! feature selects a separate long-mode entry for u-root/LinuxBoot. Exactly one
//! entry is linked; there is no runtime mode detection or fallback.

use crabefi::cell::StaticMut;

#[cfg(not(feature = "entry64"))]
#[path = "entry32.rs"]
mod selected;
#[cfg(feature = "entry64")]
#[path = "entry64.rs"]
mod selected;

#[repr(C, align(4096))]
pub struct PageTable {
    pub entries: [u64; 512],
}

impl PageTable {
    pub const fn empty() -> Self {
        PageTable { entries: [0; 512] }
    }
}

// Keep the active paging structures outside BSS. Both entries identity-map
// the first 64 GiB with 64 page directories of 512 2-MiB entries each.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".page_tables")]
static PML4: StaticMut<PageTable> = StaticMut::new(PageTable::empty());

#[unsafe(no_mangle)]
#[unsafe(link_section = ".page_tables")]
static PDPT: StaticMut<PageTable> = StaticMut::new(PageTable::empty());

#[unsafe(no_mangle)]
#[unsafe(link_section = ".page_tables")]
static PD: StaticMut<[PageTable; 64]> = StaticMut::new([const { PageTable::empty() }; 64]);

// Only the long-mode entry accepts a caller already using five-level paging.
#[cfg(feature = "entry64")]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".page_tables")]
static PML5: StaticMut<PageTable> = StaticMut::new(PageTable::empty());
