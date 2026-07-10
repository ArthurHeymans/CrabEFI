//! ELF Loader
//!
//! Loads standard ELF executables for chainloading as coreboot payloads.
//! Supports ELF64 executables for the current architecture.

use object::read::elf::{FileHeader, ProgramHeader};
use object::{LittleEndian, elf};

type Header = elf::FileHeader64<LittleEndian>;
#[cfg(test)]
type ProgramHeader64 = elf::ProgramHeader64<LittleEndian>;

const ELF64_HEADER_SIZE: usize = core::mem::size_of::<Header>();
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
#[cfg(test)]
const EI_VERSION: usize = 6;
#[cfg(test)]
const ELF64_PHDR_SIZE: usize = core::mem::size_of::<ProgramHeader64>();

#[cfg(target_arch = "x86_64")]
const EM_NATIVE: u16 = elf::EM_X86_64;
#[cfg(target_arch = "aarch64")]
const EM_NATIVE: u16 = elf::EM_AARCH64;
#[cfg(target_arch = "riscv64")]
const EM_NATIVE: u16 = elf::EM_RISCV;

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
        if data.len() < ELF64_HEADER_SIZE {
            return Err(ElfError::TooSmall);
        }
        if data[..elf::ELFMAG.len()] != elf::ELFMAG {
            return Err(ElfError::InvalidMagic);
        }
        if data[EI_CLASS] != elf::ELFCLASS64 {
            return Err(ElfError::Not64Bit);
        }
        if data[EI_DATA] != elf::ELFDATA2LSB {
            return Err(ElfError::NotLittleEndian);
        }

        let header = Header::parse(data).map_err(|_| ElfError::InvalidProgramHeader)?;
        let endian = header
            .endian()
            .map_err(|_| ElfError::InvalidProgramHeader)?;
        if header.e_type(endian) != elf::ET_EXEC {
            return Err(ElfError::NotExecutable);
        }
        if header.e_machine(endian) != EM_NATIVE {
            return Err(ElfError::WrongMachine);
        }
        if header.e_version(endian) != u32::from(elf::EV_CURRENT)
            || usize::from(header.e_ehsize(endian)) != ELF64_HEADER_SIZE
            || (header.e_phnum(endian) != 0 && header.e_phoff(endian) == 0)
        {
            return Err(ElfError::InvalidProgramHeader);
        }

        let entry = header.e_entry(endian);
        let program_headers = header
            .program_headers(endian, data)
            .map_err(|_| ElfError::InvalidProgramHeader)?;
        log::debug!(
            "ELF64: entry={:#x}, {} program headers",
            entry,
            program_headers.len()
        );

        let mut segments = heapless::Vec::new();
        for program_header in program_headers {
            if program_header.p_type(endian) != elf::PT_LOAD {
                continue;
            }

            let (file_offset, file_size) = program_header.file_range(endian);
            let mem_size = program_header.p_memsz(endian);
            let load_addr = program_header.p_vaddr(endian);
            if file_size > mem_size || program_header.data(endian, data).is_err() {
                return Err(ElfError::InvalidProgramHeader);
            }

            log::debug!(
                "  LOAD: vaddr={:#x}, filesz={:#x}, memsz={:#x}",
                load_addr,
                file_size,
                mem_size
            );
            segments
                .push(LoadSegment {
                    file_offset,
                    load_addr,
                    file_size,
                    mem_size,
                })
                .map_err(|_| ElfError::SegmentTooLarge)?;
        }

        Ok(Self { entry, segments })
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
                let src_end = src_offset
                    .checked_add(src_size)
                    .ok_or(ElfError::InvalidProgramHeader)?;
                if src_end > data.len() {
                    return Err(ElfError::InvalidProgramHeader);
                }
                // Safety: caller guarantees dst points to valid writable memory
                // and src_offset + src_size is within data bounds (checked above).
                unsafe {
                    core::ptr::copy_nonoverlapping(data.as_ptr().add(src_offset), dst, src_size);
                }
            }

            // Zero BSS (mem_size > file_size)
            if mem_size > src_size {
                // Safety: caller guarantees dst + mem_size is within valid writable memory.
                unsafe {
                    let bss_start = dst.add(src_size);
                    let bss_size = mem_size - src_size;
                    core::ptr::write_bytes(bss_start, 0, bss_size);
                }
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
}

#[cfg(all(
    test,
    any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )
))]
mod tests {
    extern crate alloc;

    use super::{
        EI_CLASS, EI_DATA, EI_VERSION, ELF64_HEADER_SIZE, ELF64_PHDR_SIZE, EM_NATIVE, Elf64,
        ElfError, elf,
    };
    use alloc::vec;
    use alloc::vec::Vec;

    #[derive(Clone, Copy)]
    struct TestPhdr {
        p_type: u32,
        p_offset: u64,
        p_vaddr: u64,
        p_filesz: u64,
        p_memsz: u64,
    }

    impl TestPhdr {
        fn load(p_offset: u64, p_vaddr: u64, p_filesz: u64, p_memsz: u64) -> Self {
            Self {
                p_type: elf::PT_LOAD,
                p_offset,
                p_vaddr,
                p_filesz,
                p_memsz,
            }
        }

        fn ignored() -> Self {
            Self {
                p_type: 2,
                p_offset: 0,
                p_vaddr: 0,
                p_filesz: 0,
                p_memsz: 0,
            }
        }
    }

    fn put_u16(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(data: &mut [u8], offset: usize, value: u64) {
        data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn elf_with_phdrs(entry: u64, phdrs: &[TestPhdr]) -> Vec<u8> {
        elf_with_phdrs_layout(entry, ELF64_HEADER_SIZE, ELF64_PHDR_SIZE, phdrs)
    }

    fn elf_with_phdrs_layout(
        entry: u64,
        phoff: usize,
        phentsize: usize,
        phdrs: &[TestPhdr],
    ) -> Vec<u8> {
        let table_end = phoff + phentsize * phdrs.len();
        let segment_end = phdrs
            .iter()
            .map(|phdr| (phdr.p_offset + phdr.p_filesz) as usize)
            .max()
            .unwrap_or(0);
        let mut data = vec![0; ELF64_HEADER_SIZE.max(table_end).max(segment_end)];

        data[..elf::ELFMAG.len()].copy_from_slice(&elf::ELFMAG);
        data[EI_CLASS] = elf::ELFCLASS64;
        data[EI_DATA] = elf::ELFDATA2LSB;
        data[EI_VERSION] = elf::EV_CURRENT;
        put_u16(&mut data, 16, elf::ET_EXEC);
        put_u16(&mut data, 18, EM_NATIVE);
        put_u32(&mut data, 20, 1);
        put_u64(&mut data, 24, entry);
        put_u64(&mut data, 32, phoff as u64);
        put_u16(&mut data, 52, ELF64_HEADER_SIZE as u16);
        put_u16(&mut data, 54, phentsize as u16);
        put_u16(&mut data, 56, phdrs.len() as u16);

        for (index, phdr) in phdrs.iter().enumerate() {
            let offset = phoff + index * phentsize;
            put_u32(&mut data, offset, phdr.p_type);
            put_u64(&mut data, offset + 8, phdr.p_offset);
            put_u64(&mut data, offset + 16, phdr.p_vaddr);
            put_u64(&mut data, offset + 32, phdr.p_filesz);
            put_u64(&mut data, offset + 40, phdr.p_memsz);
        }

        data
    }

    fn one_load() -> Vec<u8> {
        elf_with_phdrs(0x1234, &[TestPhdr::load(0x100, 0x2000, 4, 4)])
    }

    #[test]
    fn parses_native_elf64_load_segments_and_bss() {
        let data = elf_with_phdrs(
            0x4000,
            &[
                TestPhdr::ignored(),
                TestPhdr::load(0x100, 0x2000, 4, 8),
                TestPhdr::load(0x200, 0x5000, 3, 3),
            ],
        );
        let elf = Elf64::parse(&data).unwrap();

        assert_eq!(elf.entry_point(), 0x4000);
        assert_eq!(elf.segments.len(), 2);
        assert_eq!(elf.segments[0].file_offset, 0x100);
        assert_eq!(elf.segments[0].load_addr, 0x2000);
        assert_eq!(elf.segments[0].file_size, 4);
        assert_eq!(elf.segments[0].mem_size, 8);
        assert_eq!(elf.segments[1].file_offset, 0x200);
        assert_eq!(elf.segments[1].load_addr, 0x5000);
        assert_eq!(elf.segments[1].file_size, 3);
        assert_eq!(elf.segments[1].mem_size, 3);
    }

    #[test]
    fn rejects_invalid_ident_version() {
        let mut data = one_load();
        data[EI_VERSION] = 0;
        assert!(matches!(
            Elf64::parse(&data),
            Err(ElfError::InvalidProgramHeader)
        ));
    }

    #[test]
    fn rejects_oversized_program_header_stride() {
        let data = elf_with_phdrs_layout(
            0x4000,
            ELF64_HEADER_SIZE,
            ELF64_PHDR_SIZE + 8,
            &[TestPhdr::ignored(), TestPhdr::load(0x200, 0x5000, 3, 3)],
        );
        assert!(matches!(
            Elf64::parse(&data),
            Err(ElfError::InvalidProgramHeader)
        ));
    }

    #[test]
    fn rejects_pn_xnum_without_section_zero() {
        let mut data = one_load();
        put_u16(&mut data, 56, u16::MAX);
        assert!(matches!(
            Elf64::parse(&data),
            Err(ElfError::InvalidProgramHeader)
        ));
    }

    #[test]
    fn load_copies_file_data_and_zeros_bss() {
        let mut destination = [0xa5; 8];
        let data_offset: usize = 0x100;
        let data = elf_with_phdrs(
            destination.as_mut_ptr() as u64,
            &[TestPhdr::load(
                data_offset as u64,
                destination.as_mut_ptr() as u64,
                4,
                8,
            )],
        );
        let mut data = data;
        data.resize(data_offset + 4, 0);
        data[data_offset..data_offset + 4].copy_from_slice(b"data");
        let elf = Elf64::parse(&data).unwrap();

        unsafe { elf.load(&data).unwrap() };
        assert_eq!(&destination, b"data\0\0\0\0");
    }

    #[test]
    fn rejects_invalid_header_fields() {
        let mut data = one_load();
        data[0] = 0;
        assert!(matches!(Elf64::parse(&data), Err(ElfError::InvalidMagic)));

        let mut data = one_load();
        data[EI_CLASS] = elf::ELFCLASS32;
        assert!(matches!(Elf64::parse(&data), Err(ElfError::Not64Bit)));

        let mut data = one_load();
        data[EI_DATA] = elf::ELFDATA2MSB;
        assert!(matches!(
            Elf64::parse(&data),
            Err(ElfError::NotLittleEndian)
        ));

        let mut data = one_load();
        put_u16(&mut data, 16, elf::ET_REL);
        assert!(matches!(Elf64::parse(&data), Err(ElfError::NotExecutable)));

        let mut data = one_load();
        put_u16(&mut data, 18, EM_NATIVE.wrapping_add(1));
        assert!(matches!(Elf64::parse(&data), Err(ElfError::WrongMachine)));

        let mut data = one_load();
        put_u32(&mut data, 20, 0);
        assert!(matches!(
            Elf64::parse(&data),
            Err(ElfError::InvalidProgramHeader)
        ));

        let mut data = one_load();
        put_u16(&mut data, 52, 0);
        assert!(matches!(
            Elf64::parse(&data),
            Err(ElfError::InvalidProgramHeader)
        ));

        let mut data = one_load();
        put_u64(&mut data, 32, 0);
        assert!(matches!(
            Elf64::parse(&data),
            Err(ElfError::InvalidProgramHeader)
        ));
    }

    #[test]
    fn rejects_truncated_header_and_program_header_table() {
        assert!(matches!(
            Elf64::parse(&[0x7f, b'E', b'L']),
            Err(ElfError::TooSmall)
        ));

        let mut data = one_load();
        data.truncate(ELF64_HEADER_SIZE + ELF64_PHDR_SIZE - 1);
        assert!(matches!(
            Elf64::parse(&data),
            Err(ElfError::InvalidProgramHeader)
        ));

        let mut data = one_load();
        put_u16(&mut data, 54, (ELF64_PHDR_SIZE - 1) as u16);
        assert!(matches!(
            Elf64::parse(&data),
            Err(ElfError::InvalidProgramHeader)
        ));
    }

    #[test]
    fn rejects_filesz_larger_than_memsz() {
        let data = elf_with_phdrs(0, &[TestPhdr::load(0, 0, 5, 4)]);
        assert!(matches!(
            Elf64::parse(&data),
            Err(ElfError::InvalidProgramHeader)
        ));
    }

    #[test]
    fn rejects_seventeenth_load_segment() {
        let phdrs = [TestPhdr::load(0, 0, 0, 0); 17];
        let data = elf_with_phdrs(0, &phdrs);
        assert!(matches!(
            Elf64::parse(&data),
            Err(ElfError::SegmentTooLarge)
        ));
    }

    #[test]
    fn rejects_out_of_file_segment_data_during_parse() {
        let mut destination = [0u8; 4];
        let mut data = elf_with_phdrs(
            0,
            &[TestPhdr::load(
                0x1000,
                destination.as_mut_ptr() as u64,
                4,
                4,
            )],
        );
        data.truncate(ELF64_HEADER_SIZE + ELF64_PHDR_SIZE);

        assert!(matches!(
            Elf64::parse(&data),
            Err(ElfError::InvalidProgramHeader)
        ));
    }
}
