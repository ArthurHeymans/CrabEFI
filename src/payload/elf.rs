//! ELF Loader
//!
//! Loads standard ELF executables for chainloading as coreboot payloads.
//! Supports ELF64 executables for x86-64.

use core::mem;

/// ELF magic number
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// ELF class: 64-bit
const ELFCLASS64: u8 = 2;

/// ELF data encoding: little endian
const ELFDATA2LSB: u8 = 1;

/// ELF type: executable
const ET_EXEC: u16 = 2;

/// ELF machine: x86-64
const EM_X86_64: u16 = 62;

/// Program header type: loadable segment
const PT_LOAD: u32 = 1;

/// ELF64 header
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Elf64Header {
    /// ELF identification
    pub e_ident: [u8; 16],
    /// Object file type
    pub e_type: u16,
    /// Machine type
    pub e_machine: u16,
    /// Object file version
    pub e_version: u32,
    /// Entry point address
    pub e_entry: u64,
    /// Program header offset
    pub e_phoff: u64,
    /// Section header offset
    pub e_shoff: u64,
    /// Processor-specific flags
    pub e_flags: u32,
    /// ELF header size
    pub e_ehsize: u16,
    /// Program header entry size
    pub e_phentsize: u16,
    /// Number of program header entries
    pub e_phnum: u16,
    /// Section header entry size
    pub e_shentsize: u16,
    /// Number of section header entries
    pub e_shnum: u16,
    /// Section name string table index
    pub e_shstrndx: u16,
}

/// ELF64 program header
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Elf64Phdr {
    /// Segment type
    pub p_type: u32,
    /// Segment flags
    pub p_flags: u32,
    /// Offset in file
    pub p_offset: u64,
    /// Virtual address
    pub p_vaddr: u64,
    /// Physical address
    pub p_paddr: u64,
    /// Size in file
    pub p_filesz: u64,
    /// Size in memory
    pub p_memsz: u64,
    /// Alignment
    pub p_align: u64,
}

/// Errors during ELF loading
#[derive(Debug)]
pub enum ElfError {
    /// File too small
    TooSmall,
    /// Invalid ELF magic
    InvalidMagic,
    /// Not a 64-bit ELF
    Not64Bit,
    /// Not little endian
    NotLittleEndian,
    /// Not an executable
    NotExecutable,
    /// Wrong machine type
    WrongMachine,
    /// Invalid program header
    InvalidProgramHeader,
    /// Segment too large
    SegmentTooLarge,
    /// Segments overlap
    SegmentsOverlap,
}

/// Parsed ELF file ready for loading
#[derive(Debug)]
pub struct Elf64 {
    /// Entry point address
    pub entry: u64,
    /// Program headers
    pub segments: heapless::Vec<LoadSegment, 16>,
}

/// A loadable segment
#[derive(Debug, Clone)]
pub struct LoadSegment {
    /// Offset in the ELF file
    pub file_offset: u64,
    /// Virtual/physical load address
    pub load_addr: u64,
    /// Size in file (bytes to copy)
    pub file_size: u64,
    /// Size in memory (includes BSS)
    pub mem_size: u64,
}

impl Elf64 {
    /// Parse an ELF64 file
    ///
    /// # Arguments
    ///
    /// * `data` - Complete ELF file data
    pub fn parse(data: &[u8]) -> Result<Self, ElfError> {
        if data.len() < mem::size_of::<Elf64Header>() {
            return Err(ElfError::TooSmall);
        }

        // Parse header
        let header = unsafe {
            let ptr = data.as_ptr() as *const Elf64Header;
            ptr.read_unaligned()
        };

        // Validate magic
        if header.e_ident[0..4] != ELF_MAGIC {
            return Err(ElfError::InvalidMagic);
        }

        // Check class (64-bit)
        if header.e_ident[4] != ELFCLASS64 {
            return Err(ElfError::Not64Bit);
        }

        // Check endianness (little endian)
        if header.e_ident[5] != ELFDATA2LSB {
            return Err(ElfError::NotLittleEndian);
        }

        // Check type (executable)
        if header.e_type != ET_EXEC {
            return Err(ElfError::NotExecutable);
        }

        // Check machine (x86-64)
        if header.e_machine != EM_X86_64 {
            return Err(ElfError::WrongMachine);
        }

        log::debug!(
            "ELF64: entry={:#x}, {} program headers",
            header.e_entry,
            header.e_phnum
        );

        // Parse program headers
        let mut segments = heapless::Vec::new();
        let phdr_offset = header.e_phoff as usize;
        let phdr_size = header.e_phentsize as usize;

        for i in 0..header.e_phnum as usize {
            let offset = phdr_offset + i * phdr_size;
            if offset + phdr_size > data.len() {
                return Err(ElfError::InvalidProgramHeader);
            }

            let phdr = unsafe {
                let ptr = data.as_ptr().add(offset) as *const Elf64Phdr;
                ptr.read_unaligned()
            };

            // Only process PT_LOAD segments
            if phdr.p_type != PT_LOAD {
                continue;
            }

            log::debug!(
                "  LOAD: vaddr={:#x}, filesz={:#x}, memsz={:#x}",
                phdr.p_vaddr,
                phdr.p_filesz,
                phdr.p_memsz
            );

            let segment = LoadSegment {
                file_offset: phdr.p_offset,
                load_addr: phdr.p_vaddr,
                file_size: phdr.p_filesz,
                mem_size: phdr.p_memsz,
            };

            segments
                .push(segment)
                .map_err(|_| ElfError::SegmentTooLarge)?;
        }

        Ok(Self {
            entry: header.e_entry,
            segments,
        })
    }

    /// Load the ELF into memory
    ///
    /// # Safety
    ///
    /// Caller must ensure:
    /// - All load addresses point to valid, writable memory
    /// - Segments don't overlap with CrabEFI's own memory
    pub unsafe fn load(&self, data: &[u8]) -> Result<(), ElfError> {
        for segment in &self.segments {
            let src_offset = segment.file_offset as usize;
            let src_size = segment.file_size as usize;
            let dst = segment.load_addr as *mut u8;
            let mem_size = segment.mem_size as usize;

            // Copy file data
            if src_size > 0 {
                if src_offset + src_size > data.len() {
                    return Err(ElfError::InvalidProgramHeader);
                }
                core::ptr::copy_nonoverlapping(data.as_ptr().add(src_offset), dst, src_size);
            }

            // Zero BSS (mem_size > file_size)
            if mem_size > src_size {
                let bss_start = dst.add(src_size);
                let bss_size = mem_size - src_size;
                core::ptr::write_bytes(bss_start, 0, bss_size);
            }

            log::debug!(
                "Loaded segment to {:#x}: {} bytes data, {} bytes BSS",
                segment.load_addr,
                src_size,
                mem_size.saturating_sub(src_size)
            );
        }

        Ok(())
    }

    /// Get the entry point address
    pub fn entry_point(&self) -> u64 {
        self.entry
    }

    /// Get the lowest load address (useful for memory allocation)
    pub fn lowest_addr(&self) -> u64 {
        self.segments.iter().map(|s| s.load_addr).min().unwrap_or(0)
    }

    /// Get the highest end address (useful for memory allocation)
    pub fn highest_addr(&self) -> u64 {
        self.segments
            .iter()
            .map(|s| s.load_addr + s.mem_size)
            .max()
            .unwrap_or(0)
    }

    /// Calculate total memory required
    pub fn total_size(&self) -> u64 {
        self.highest_addr().saturating_sub(self.lowest_addr())
    }
}
