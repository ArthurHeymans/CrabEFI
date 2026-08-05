//! Build, audit, and normalize the separately linked runtime image.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use object::{
    Object, ObjectKind, ObjectSection, ObjectSegment, ObjectSymbol, Permissions, RelocationKind,
    RelocationTarget,
};
use serde_json::json;
use sha2::{Digest, Sha256};

use crabefi_runtime_abi::format::{
    EFI_PAGE_SIZE, EXPORTS_SIZE, EXPORTS_VERSION, FORMAT_VERSION, HEADER_SIZE, MAGIC, MAX_SECTIONS,
    RELOCATION_SIZE, SECTION_SIZE, ValidatedImage, architecture,
    relocation_kind as abi_relocation_kind, section_flags as abi_section_flags,
};

use crate::{Arch, project_root};

const PAGE_SIZE: u64 = EFI_PAGE_SIZE as u64;

#[derive(Clone)]
struct Segment {
    address: u64,
    memory_size: u64,
    alignment: u64,
    data: Vec<u8>,
    flags: u32,
    normalized_offset: u32,
}

#[derive(Clone, Copy)]
struct Relocation {
    patch_offset: u32,
    target_offset: u32,
    patch_section: u8,
    target_section: u8,
}

pub struct RuntimeArtifact {
    pub image: PathBuf,
    pub digest: [u8; 32],
}

pub fn build(arch: Arch) -> Result<RuntimeArtifact> {
    let root = project_root();
    let output = root.join("target/runtime").join(arch.dir_name());
    fs::create_dir_all(&output)?;
    let target = target_triple(arch);
    let cargo_target = root.join("target/runtime/.cargo").join(target);
    let map_path = output.join("runtime.map");
    let manifest = root.join("crabefi-runtime-image/Cargo.toml");
    let rustflags = runtime_rustflags(arch, &map_path);
    let parent = root.parent().context("project root has no parent")?;
    let status = Command::new("cargo")
        .args([
            "+nightly",
            "-Z",
            "build-std=core,compiler_builtins,alloc",
            "-Z",
            "build-std-features=compiler-builtins-mem",
            "build",
            "--manifest-path",
        ])
        .arg(&manifest)
        .args(["--release", "--target", target, "--target-dir"])
        .arg(&cargo_target)
        .current_dir(parent)
        .env_remove("RUSTFLAGS")
        .env("CARGO_ENCODED_RUSTFLAGS", rustflags)
        .status()
        .context("failed to invoke nightly Cargo for the runtime image")?;
    if !status.success() {
        bail!("runtime image Cargo build failed for {target}");
    }

    let linked = cargo_target
        .join(target)
        .join("release/crabefi-runtime-image");
    let elf_path = output.join("runtime.elf");
    fs::copy(&linked, &elf_path).with_context(|| {
        format!(
            "copy linked runtime image {} to {}",
            linked.display(),
            elf_path.display()
        )
    })?;
    fs::copy(&elf_path, output.join("runtime-image.elf"))?;
    if map_path.exists() {
        fs::copy(&map_path, output.join("runtime-image.map"))?;
    }
    normalize(&elf_path, &output, arch)
}

fn runtime_rustflags(arch: Arch, map_path: &Path) -> OsString {
    let code_model = match arch {
        Arch::X86_64 | Arch::Aarch64 => "code-model=small",
        Arch::Riscv64 => "code-model=medium",
    };
    let mut arguments = vec![
        OsString::from("-C"),
        OsString::from("relocation-model=pic"),
        OsString::from("-C"),
        OsString::from(code_model),
    ];
    if matches!(arch, Arch::Riscv64) {
        arguments.extend([OsString::from("-C"), OsString::from("link-arg=--no-relax")]);
    }
    arguments.extend([
        OsString::from("-C"),
        OsString::from("linker=rust-lld"),
        OsString::from("-C"),
        OsString::from("link-arg=-pie"),
        OsString::from("-C"),
    ]);
    let mut map_argument = OsString::from("link-arg=-Map=");
    map_argument.push(map_path.as_os_str());
    arguments.extend([
        map_argument,
        OsString::from("-Z"),
        OsString::from("emit-stack-sizes"),
        OsString::from("-Z"),
        OsString::from("plt=yes"),
    ]);

    let mut encoded = OsString::new();
    for (index, argument) in arguments.iter().enumerate() {
        if index != 0 {
            encoded.push("\u{1f}");
        }
        encoded.push(argument);
    }
    encoded
}

fn normalize(elf_path: &Path, output: &Path, arch: Arch) -> Result<RuntimeArtifact> {
    let elf_bytes = fs::read(elf_path)?;
    let file = object::File::parse(elf_bytes.as_slice()).context("parse runtime ELF")?;
    if file.kind() != ObjectKind::Dynamic || file.architecture() != object_arch(arch) {
        bail!("runtime ELF must be ET_DYN for the requested architecture");
    }
    let mut segments = file
        .segments()
        .filter_map(|segment| {
            let address = segment.address();
            let memory_size = segment.size();
            if memory_size == 0 {
                return None;
            }
            Some((segment, address, memory_size))
        })
        .map(|(segment, address, memory_size)| {
            let permissions = segment.permissions();
            let mut flags = section_flags(permissions);
            if segment.data()?.len() < usize::try_from(memory_size)? {
                flags |= abi_section_flags::ZERO_FILL;
            }
            if flags & abi_section_flags::WRITE != 0 && flags & abi_section_flags::EXECUTE != 0 {
                bail!("runtime ELF contains a writable/executable PT_LOAD");
            }
            if !address.is_multiple_of(PAGE_SIZE)
                || !memory_size.checked_add(address).is_some()
                || segment.align() < PAGE_SIZE
            {
                bail!("runtime ELF PT_LOAD alignment/range is invalid");
            }
            Ok(Segment {
                address,
                memory_size,
                // The normalized image is copied rather than mmap'd; its ABI
                // protection/allocation granule is uniformly 4 KiB even when
                // an ELF target advertises a larger maximum page size.
                alignment: PAGE_SIZE,
                data: segment.data()?.to_vec(),
                flags,
                normalized_offset: 0,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    segments.sort_by_key(|segment| segment.address);
    if segments.is_empty() || segments.len() > MAX_SECTIONS {
        bail!("runtime ELF has an unsupported PT_LOAD count");
    }
    for pair in segments.windows(2) {
        let end = pair[0]
            .address
            .checked_add(pair[0].memory_size)
            .context("runtime segment overflow")?;
        if end > pair[1].address {
            bail!("runtime ELF PT_LOAD segments overlap");
        }
    }
    let linked_image_end = segments
        .iter()
        .map(|segment| segment.address + segment.memory_size)
        .max()
        .context("missing runtime image segments")?
        .next_multiple_of(PAGE_SIZE);
    for index in 0..segments.len() {
        let original_address = segments[index].address;
        let normalized_start = if index == 0 { 0 } else { original_address };
        let normalized_end = segments
            .get(index + 1)
            .map_or(linked_image_end, |next| next.address);
        let prefix = usize::try_from(original_address - normalized_start)?;
        let mut data = vec![0u8; prefix + segments[index].data.len()];
        data[prefix..].copy_from_slice(&segments[index].data);
        segments[index].address = normalized_start;
        segments[index].memory_size = normalized_end - normalized_start;
        segments[index].data = data;
        if segments[index].data.len() < usize::try_from(segments[index].memory_size)? {
            segments[index].flags |= abi_section_flags::ZERO_FILL;
        }
    }
    let image_size = linked_image_end;
    let image_size_u32 = u32::try_from(image_size).context("runtime image exceeds 4 GiB")?;

    let relocations = collect_dynamic_relocations(&file, &segments, arch)?;
    if relocations.len() > crabefi_runtime_abi::MAX_RELOCATIONS {
        bail!(
            "runtime image has {} relocations, exceeding the {}-slot ABI manifest",
            relocations.len(),
            crabefi_runtime_abi::MAX_RELOCATIONS
        );
    }
    for relocation in &relocations {
        segments[usize::from(relocation.patch_section)].flags |=
            abi_section_flags::RELOCATION_SLOTS;
    }
    audit_native_relocations(&file, &segments, arch)?;
    let exports = collect_exports(&file, image_size)?;

    let section_offset = HEADER_SIZE;
    let relocation_offset = section_offset + segments.len() * SECTION_SIZE;
    let exports_offset = relocation_offset + relocations.len() * RELOCATION_SIZE;
    let mut data_offset = align_up(exports_offset + EXPORTS_SIZE, 16);
    for segment in &mut segments {
        segment.normalized_offset = u32::try_from(data_offset)?;
        data_offset = data_offset
            .checked_add(segment.data.len())
            .context("normalized runtime image size overflow")?;
    }
    let mut normalized = vec![0u8; data_offset];
    normalized[..8].copy_from_slice(&MAGIC);
    write_u16(&mut normalized, 8, FORMAT_VERSION);
    write_u16(&mut normalized, 10, architecture_id(arch));
    write_u16(&mut normalized, 12, HEADER_SIZE as u16);
    write_u32(&mut normalized, 16, image_size_u32);
    write_u32(&mut normalized, 20, section_offset as u32);
    write_u16(&mut normalized, 24, segments.len() as u16);
    write_u32(&mut normalized, 28, relocation_offset as u32);
    write_u32(&mut normalized, 32, relocations.len() as u32);
    write_u32(&mut normalized, 36, exports_offset as u32);
    write_u16(&mut normalized, 40, EXPORTS_SIZE as u16);
    write_u32(&mut normalized, 44, EFI_PAGE_SIZE);
    write_u64(
        &mut normalized,
        48,
        crabefi_runtime_abi::feature_bits::REQUIRED,
    );

    for (index, segment) in segments.iter().enumerate() {
        let offset = section_offset + index * SECTION_SIZE;
        write_u32(&mut normalized, offset, segment.normalized_offset);
        write_u32(&mut normalized, offset + 4, segment.address as u32);
        write_u32(&mut normalized, offset + 8, segment.data.len() as u32);
        write_u32(&mut normalized, offset + 12, segment.memory_size as u32);
        write_u32(&mut normalized, offset + 16, segment.alignment as u32);
        write_u32(&mut normalized, offset + 20, segment.flags);
        let destination = usize::try_from(segment.normalized_offset)?;
        normalized[destination..destination + segment.data.len()].copy_from_slice(&segment.data);
    }
    for (index, relocation) in relocations.iter().enumerate() {
        let offset = relocation_offset + index * RELOCATION_SIZE;
        write_u32(&mut normalized, offset, relocation.patch_offset);
        write_u32(&mut normalized, offset + 4, relocation.target_offset);
        write_u64(&mut normalized, offset + 8, 0);
        normalized[offset + 16] = relocation.patch_section;
        normalized[offset + 17] = relocation.target_section;
        write_u16(
            &mut normalized,
            offset + 18,
            abi_relocation_kind::ABSOLUTE64,
        );
    }
    write_u16(&mut normalized, exports_offset, EXPORTS_VERSION);
    write_u16(&mut normalized, exports_offset + 2, EXPORTS_SIZE as u16);
    for (index, value) in exports.iter().enumerate() {
        write_u32(&mut normalized, exports_offset + 8 + index * 4, *value);
    }

    let image_path = output.join("runtime.img");
    fs::write(&image_path, &normalized)?;
    fs::write(output.join("runtime-image.bin"), &normalized)?;
    let digest: [u8; 32] = Sha256::digest(&normalized).into();
    fs::write(output.join("sha256"), format!("{}\n", hex(&digest)))?;

    let section_report: Vec<_> = segments
        .iter()
        .enumerate()
        .map(|(id, section)| {
            json!({
                "id": id,
                "image_offset": section.address,
                "file_size": section.data.len(),
                "memory_size": section.memory_size,
                "alignment": section.alignment,
                "flags": section.flags,
            })
        })
        .collect();
    let relocation_report: Vec<_> = relocations
        .iter()
        .map(|relocation| {
            json!({
                "kind": "absolute64",
                "patch_offset": relocation.patch_offset,
                "patch_section": relocation.patch_section,
                "target_offset": relocation.target_offset,
                "target_section": relocation.target_section,
            })
        })
        .collect();
    write_json(output.join("sections.json"), &json!(section_report))?;
    write_json(output.join("relocations.json"), &json!(relocation_report))?;
    write_json(
        output.join("size.json"),
        &json!({ "elf": elf_bytes.len(), "normalized": normalized.len(), "memory": image_size }),
    )?;
    write_json(
        output.join("build.json"),
        &json!({ "target": target_triple(arch), "format": FORMAT_VERSION, "sha256": hex(&digest) }),
    )?;

    let symbols = file
        .symbols()
        .filter_map(|symbol| {
            let name = symbol.name().ok()?;
            (!name.is_empty()).then(|| format!("{:#018x} {name}\n", symbol.address()))
        })
        .collect::<String>();
    fs::write(output.join("symbols.txt"), &symbols)?;
    fs::write(output.join("runtime-image.sym"), symbols)?;
    ValidatedImage::parse(&normalized, architecture_id(arch)).map_err(|error| {
        anyhow::anyhow!("normalized runtime image failed ABI self-validation: {error}")
    })?;
    run_audit_tools(elf_path, output, arch, relocations.len())?;
    Ok(RuntimeArtifact {
        image: image_path,
        digest,
    })
}

fn collect_dynamic_relocations(
    file: &object::File<'_>,
    segments: &[Segment],
    arch: Arch,
) -> Result<Vec<Relocation>> {
    let expected = dynamic_relocation_count(file)?;
    let mut output = Vec::with_capacity(expected);
    let relocations = file
        .dynamic_relocations()
        .context("runtime ELF has no readable dynamic relocation table")?;
    for (patch, relocation) in relocations {
        let relative = relocation.kind() == RelocationKind::Relative
            || matches!(
                relocation.flags(),
                object::RelocationFlags::Elf { r_type }
                    if r_type == relative_relocation_type(arch)
            );
        if !relative
            || !matches!(relocation.size(), 0 | 64)
            || relocation.target() != RelocationTarget::Absolute
        {
            bail!("unsupported dynamic relocation at {patch:#x}: {relocation:?}");
        }
        let target = u64::try_from(relocation.addend())
            .with_context(|| format!("negative dynamic relocation target at {patch:#x}"))?;
        let patch_section = containing_segment(segments, patch, 8)
            .with_context(|| format!("relocation patch {patch:#x} is outside PT_LOAD"))?;
        let target_section = containing_segment(segments, target, 1)
            .with_context(|| format!("relocation target {target:#x} is outside PT_LOAD"))?;
        output.push(Relocation {
            patch_offset: u32::try_from(patch)?,
            target_offset: u32::try_from(target)?,
            patch_section: u8::try_from(patch_section)?,
            target_section: u8::try_from(target_section)?,
        });
    }
    if output.is_empty() || output.len() != expected {
        bail!(
            "dynamic relocation count mismatch: DT_RELASZ/DT_RELACOUNT={expected}, object parsed {}",
            output.len()
        );
    }
    Ok(output)
}

fn dynamic_relocation_count(file: &object::File<'_>) -> Result<usize> {
    const ELF64_DYN_SIZE: usize = 16;
    const ELF64_RELA_SIZE: u64 = 24;
    let dynamic = file
        .section_by_name(".dynamic")
        .context("runtime ELF is missing .dynamic")?
        .data()
        .context("read runtime .dynamic")?;
    if dynamic.len() % ELF64_DYN_SIZE != 0 {
        bail!("runtime .dynamic has a partial ELF64 dynamic entry");
    }
    audit_dynamic_entries(dynamic, ELF64_RELA_SIZE)
}

fn audit_dynamic_entries(dynamic: &[u8], rela_entry_size: u64) -> Result<usize> {
    const ELF64_DYN_SIZE: usize = 16;
    if dynamic.len() % ELF64_DYN_SIZE != 0 {
        bail!("runtime .dynamic has a partial ELF64 dynamic entry");
    }
    let mut rela_size = None;
    let mut rela_count = None;
    for entry in dynamic.chunks_exact(ELF64_DYN_SIZE) {
        let tag = i64::from_le_bytes(entry[..8].try_into()?);
        let value = u64::from_le_bytes(entry[8..].try_into()?);
        match tag {
            object::elf::DT_NULL => break,
            object::elf::DT_NEEDED => bail!("runtime ELF contains DT_NEEDED"),
            object::elf::DT_REL
            | object::elf::DT_RELSZ
            | object::elf::DT_RELENT
            | object::elf::DT_JMPREL
            | object::elf::DT_PLTRELSZ
            | object::elf::DT_PLTREL => {
                bail!("runtime ELF contains unsupported dynamic tag {tag}")
            }
            object::elf::DT_RELASZ => {
                if rela_size.replace(value).is_some() {
                    bail!("runtime .dynamic contains duplicate DT_RELASZ");
                }
            }
            object::elf::DT_RELAENT if value != rela_entry_size => {
                bail!("runtime DT_RELAENT is {value}, expected {rela_entry_size}")
            }
            object::elf::DT_RELACOUNT => {
                if rela_count.replace(value).is_some() {
                    bail!("runtime .dynamic contains duplicate DT_RELACOUNT");
                }
            }
            _ => {}
        }
    }
    let rela_size = rela_size.context("runtime .dynamic is missing DT_RELASZ")?;
    if rela_size == 0 || rela_size % rela_entry_size != 0 {
        bail!("runtime DT_RELASZ is not a non-zero multiple of ELF64 Rela size");
    }
    let from_size = usize::try_from(rela_size / rela_entry_size)?;
    let from_count =
        usize::try_from(rela_count.context("runtime .dynamic is missing DT_RELACOUNT")?)?;
    if from_size != from_count {
        bail!("runtime DT_RELASZ and DT_RELACOUNT disagree: {from_size} != {from_count}");
    }
    Ok(from_count)
}

fn audit_native_relocations(
    file: &object::File<'_>,
    segments: &[Segment],
    arch: Arch,
) -> Result<()> {
    for section in file.sections() {
        let source = section.address();
        let Some(source_domain) = containing_segment(segments, source, 1) else {
            continue;
        };
        for (_offset, relocation) in section.relocations() {
            if matches!(
                relocation.kind(),
                RelocationKind::Relative | RelocationKind::PltRelative
            ) {
                let target = match relocation.target() {
                    RelocationTarget::Section(index) => file.section_by_index(index)?.address(),
                    RelocationTarget::Symbol(index) => file.symbol_by_index(index)?.address(),
                    _ => continue,
                };
                if let Some(target_domain) = containing_segment(segments, target, 1)
                    && source_domain != target_domain
                    && !native_cross_domain_allowed(arch, relocation.flags())
                {
                    bail!(
                        "cross-domain PC-relative relocation from segment {source_domain} to {target_domain}: {relocation:?}"
                    );
                }
            }
        }
    }
    Ok(())
}

fn relative_relocation_type(arch: Arch) -> u32 {
    match arch {
        Arch::X86_64 => object::elf::R_X86_64_RELATIVE,
        Arch::Aarch64 => object::elf::R_AARCH64_RELATIVE,
        Arch::Riscv64 => object::elf::R_RISCV_RELATIVE,
    }
}

fn native_cross_domain_allowed(arch: Arch, flags: object::RelocationFlags) -> bool {
    let object::RelocationFlags::Elf { r_type } = flags else {
        return false;
    };
    match arch {
        Arch::X86_64 => matches!(
            r_type,
            object::elf::R_X86_64_PC32
                | object::elf::R_X86_64_GOTPCREL
                | object::elf::R_X86_64_GOTPCRELX
                | object::elf::R_X86_64_REX_GOTPCRELX
        ),
        Arch::Aarch64 => matches!(
            r_type,
            object::elf::R_AARCH64_ADR_GOT_PAGE | object::elf::R_AARCH64_LD64_GOT_LO12_NC
        ),
        Arch::Riscv64 => matches!(r_type, object::elf::R_RISCV_GOT_HI20),
    }
}

fn collect_exports(file: &object::File<'_>, image_size: u64) -> Result<[u32; 12]> {
    const NAMES: [&str; 12] = [
        "runtime_image_init",
        "runtime_image_import_relocation",
        "runtime_image_import_variable",
        "runtime_image_finish_import",
        "runtime_image_activate",
        "runtime_image_register_configuration",
        "runtime_image_set_console",
        "runtime_image_install_esrt",
        "runtime_image_prepare_ebs",
        "runtime_image_seal",
        "runtime_image_get_runtime_services",
        "runtime_image_get_system_table",
    ];
    let mut values = [0u32; 12];
    for (index, name) in NAMES.iter().enumerate() {
        let symbol = file
            .symbol_by_name(name)
            .with_context(|| format!("missing required runtime export {name}"))?;
        if symbol.address() >= image_size {
            bail!("runtime export {name} is outside the image");
        }
        values[index] = u32::try_from(symbol.address())?;
    }
    Ok(values)
}

#[derive(Clone, Copy)]
struct Instruction<'a> {
    mnemonic: &'a str,
    operands: &'a str,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct CallAudit {
    indirect: usize,
    register_indirect: usize,
}

fn parse_instruction(line: &str) -> Option<Instruction<'_>> {
    let (_, body) = line.split_once(':')?;
    let body = body.trim();
    if body.is_empty() || body.starts_with('<') {
        return None;
    }
    let split = body.find(char::is_whitespace).unwrap_or(body.len());
    let mnemonic = &body[..split];
    if mnemonic.is_empty() {
        return None;
    }
    Some(Instruction {
        mnemonic,
        operands: body[split..].trim(),
    })
}

fn instruction_is_call(arch: Arch, instruction: Instruction<'_>) -> Result<bool> {
    let (recognized, call) = match arch {
        Arch::X86_64 => {
            let call = matches!(instruction.mnemonic, "call" | "callq");
            (call, call)
        }
        Arch::Aarch64 => {
            let call = matches!(instruction.mnemonic, "bl" | "blr");
            (call, call)
        }
        Arch::Riscv64 => {
            let recognized = matches!(
                instruction.mnemonic,
                "jal" | "jalr" | "call" | "tail" | "jr"
            );
            let call = matches!(instruction.mnemonic, "jal" | "call")
                || (instruction.mnemonic == "jalr" && riscv_jalr_links(instruction.operands));
            (recognized, call)
        }
    };
    let suspicious_unknown = match arch {
        Arch::X86_64 => instruction.mnemonic.starts_with("call"),
        Arch::Aarch64 => instruction.mnemonic.starts_with("bl"),
        Arch::Riscv64 => instruction.mnemonic.starts_with("jal"),
    };
    if suspicious_unknown && !recognized {
        bail!(
            "unrecognized call instruction syntax: {} {}",
            instruction.mnemonic,
            instruction.operands
        );
    }
    Ok(call)
}

fn instruction_is_forbidden_in_transition_tail(
    arch: Arch,
    instruction: Instruction<'_>,
) -> Result<bool> {
    if arch == Arch::Riscv64
        && (matches!(instruction.mnemonic, "jr" | "tail") || instruction.mnemonic == "jalr")
    {
        // Non-linking register jumps are just as unsafe as calls after the
        // transition tail has changed relocation targets.
        return Ok(true);
    }
    instruction_is_call(arch, instruction)
}

fn riscv_auipc_direct(previous: Option<Instruction<'_>>, operands: &str) -> bool {
    let Some(previous) = previous.filter(|instruction| instruction.mnemonic == "auipc") else {
        return false;
    };
    let register = previous
        .operands
        .split(',')
        .next()
        .unwrap_or_default()
        .trim();
    let Some(base) = riscv_jalr_base(operands) else {
        return false;
    };
    register == base || matches!((register, base), ("ra", "x1") | ("x1", "ra"))
}

fn riscv_jalr_base(operands: &str) -> Option<&str> {
    let address = operands
        .split_once(',')
        .map_or(operands, |(_, address)| address)
        .trim();
    if let Some((_, tail)) = address.rsplit_once('(') {
        return tail.split_once(')').map(|(register, _)| register.trim());
    }
    address
        .split_whitespace()
        .next()
        .filter(|value| !value.is_empty())
}

fn riscv_jalr_links(operands: &str) -> bool {
    let Some((destination, _)) = operands.split_once(',') else {
        // The one-operand spelling has an implicit `ra` destination.
        return true;
    };
    !matches!(destination.trim(), "zero" | "x0")
}

fn audit_indirect_calls(arch: Arch, text: &str) -> Result<CallAudit> {
    let mut audit = CallAudit::default();
    let mut previous = None;
    for line in text.lines() {
        let Some(instruction) = parse_instruction(line) else {
            continue;
        };
        let _ = instruction_is_call(arch, instruction)?;
        match arch {
            Arch::X86_64
                if matches!(instruction.mnemonic, "call" | "callq")
                    && instruction.operands.starts_with('*') =>
            {
                audit.indirect += 1;
                if !instruction.operands.contains("(%rip)") {
                    audit.register_indirect += 1;
                }
            }
            Arch::Aarch64 if instruction.mnemonic == "blr" => {
                audit.indirect += 1;
                audit.register_indirect += 1;
            }
            Arch::Riscv64
                if instruction.mnemonic == "jalr"
                    && riscv_jalr_links(instruction.operands)
                    && !riscv_auipc_direct(previous, instruction.operands) =>
            {
                audit.indirect += 1;
                audit.register_indirect += 1;
            }
            _ => {}
        }
        previous = Some(instruction);
    }
    Ok(audit)
}

fn run_audit_tools(elf: &Path, output: &Path, arch: Arch, relocation_slots: usize) -> Result<()> {
    let disassembly = Command::new(llvm_tool("llvm-objdump")?)
        .args(["--disassemble", "--no-show-raw-insn"])
        .arg(elf)
        .output()
        .context("llvm-objdump is required for runtime image auditing")?;
    if !disassembly.status.success() {
        bail!("llvm-objdump failed for runtime image");
    }
    fs::write(output.join("disassembly.txt"), &disassembly.stdout)?;
    let text = String::from_utf8_lossy(&disassembly.stdout);
    let tail = disassembly_body(&text, "runtime_image_commit_tail_and_return")
        .context("runtime tail relocation function was removed or inlined")?;
    for line in tail.lines() {
        if let Some(instruction) = parse_instruction(line)
            && instruction_is_forbidden_in_transition_tail(arch, instruction)?
        {
            bail!("runtime tail relocation function contains a call or indirect tail jump");
        }
    }
    let call_audit = audit_indirect_calls(arch, &text)?;
    let indirect_calls = call_audit.indirect;
    let register_indirect_calls = call_audit.register_indirect;
    // PIC code may call compiler-builtins through relocation slots and has one
    // explicit BootActive bridge call. The packed-arena move operation can load
    // a GOT slot into a register first, so permit one additional register call.
    let allowed_indirect_calls = relocation_slots + 2;
    let violations =
        (indirect_calls > allowed_indirect_calls || register_indirect_calls > 2) as usize;
    if violations != 0 {
        bail!(
            "runtime disassembly has {indirect_calls} indirect calls ({register_indirect_calls} register calls) for {relocation_slots} relocation slots"
        );
    }
    write_json(
        output.join("disassembly-audit.json"),
        &json!({
            "indirect_calls": indirect_calls,
            "register_indirect_calls": register_indirect_calls,
            "relocation_slots": relocation_slots,
            "allowed_indirect_calls": allowed_indirect_calls,
            "violations": violations,
        }),
    )?;

    let stack = Command::new(llvm_tool("llvm-readobj")?)
        .arg("--stack-sizes")
        .arg(elf)
        .output()
        .context("llvm-readobj is required for runtime stack auditing")?;
    if !stack.status.success() {
        bail!("llvm-readobj --stack-sizes failed for runtime image");
    }
    fs::write(output.join("stack-sizes.txt"), &stack.stdout)?;
    let stack_text = String::from_utf8_lossy(&stack.stdout);
    let maximum = stack_text
        .lines()
        .filter_map(|line| line.trim().strip_prefix("Size: 0x"))
        .filter_map(|value| u64::from_str_radix(value, 16).ok())
        .max()
        .context("LLVM stack-size report contained no function sizes")?;
    const STACK_BUDGET: u64 = 16 * 1024;
    if maximum > STACK_BUDGET {
        bail!("runtime function stack size {maximum} exceeds {STACK_BUDGET}-byte budget");
    }
    write_json(
        output.join("stack-sizes.json"),
        &json!({
            "budget_bytes": STACK_BUDGET,
            "maximum_function_bytes": maximum,
            "raw_report": "stack-sizes.txt",
        }),
    )?;
    Ok(())
}

fn disassembly_body<'a>(text: &'a str, symbol: &str) -> Option<&'a str> {
    let start = text.find(&format!("<{symbol}>:"))?;
    let body = &text[start..];
    Some(body.split_once("\n\n").map_or(body, |(body, _)| body))
}

fn parse_rustc_host(verbose_version: &str) -> Option<&str> {
    let mut hosts = verbose_version.lines().filter_map(|line| {
        let host = line.strip_prefix("host:")?.trim();
        (!host.is_empty() && !host.chars().any(char::is_whitespace)).then_some(host)
    });
    let host = hosts.next()?;
    hosts.next().is_none().then_some(host)
}

fn llvm_tool(name: &str) -> Result<PathBuf> {
    if Command::new(name)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
    {
        return Ok(PathBuf::from(name));
    }
    let output = Command::new("rustc")
        .args(["+nightly", "--print", "sysroot"])
        .output()
        .context("locate nightly Rust sysroot for LLVM tools")?;
    if !output.status.success() {
        bail!("cannot locate required LLVM tool {name}");
    }
    let sysroot = String::from_utf8(output.stdout)?.trim().to_owned();
    let verbose = Command::new("rustc")
        .args(["+nightly", "-vV"])
        .output()
        .context("query nightly Rust host triple for LLVM tools")?;
    if !verbose.status.success() {
        bail!("cannot query nightly Rust host triple for required LLVM tool {name}");
    }
    let verbose = String::from_utf8(verbose.stdout)?;
    let host = parse_rustc_host(&verbose).context("nightly rustc -vV has no valid host line")?;
    let executable = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    let path = PathBuf::from(sysroot)
        .join("lib/rustlib")
        .join(host)
        .join("bin")
        .join(executable);
    if !path.exists() {
        bail!("required LLVM tool not found: {}", path.display());
    }
    Ok(path)
}

fn containing_segment(segments: &[Segment], address: u64, width: u64) -> Option<usize> {
    let end = address.checked_add(width)?;
    segments.iter().position(|segment| {
        address >= segment.address
            && end
                <= segment
                    .address
                    .checked_add(segment.memory_size)
                    .unwrap_or(0)
    })
}

fn section_flags(permissions: Permissions) -> u32 {
    let mut flags = abi_section_flags::READ;
    if permissions.writable() {
        flags |= abi_section_flags::WRITE;
    }
    if permissions.executable() {
        flags |= abi_section_flags::EXECUTE;
    }
    flags
}

fn object_arch(arch: Arch) -> object::Architecture {
    match arch {
        Arch::X86_64 => object::Architecture::X86_64,
        Arch::Aarch64 => object::Architecture::Aarch64,
        Arch::Riscv64 => object::Architecture::Riscv64,
    }
}

fn architecture_id(arch: Arch) -> u16 {
    match arch {
        Arch::X86_64 => architecture::X86_64,
        Arch::Aarch64 => architecture::AARCH64,
        Arch::Riscv64 => architecture::RISCV64,
    }
}

fn target_triple(arch: Arch) -> &'static str {
    match arch {
        Arch::X86_64 => "x86_64-unknown-none",
        Arch::Aarch64 => "aarch64-unknown-none",
        Arch::Riscv64 => "riscv64gc-unknown-none-elf",
    }
}

fn align_up(value: usize, alignment: usize) -> usize {
    value.next_multiple_of(alignment)
}

fn write_json(path: PathBuf, value: &serde_json::Value) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut output, byte| {
        let _ = write!(output, "{byte:02x}");
        output
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_portable_rustc_host_triples() {
        for host in [
            "x86_64-unknown-linux-gnu",
            "x86_64-unknown-linux-musl",
            "aarch64-apple-darwin",
            "x86_64-pc-windows-msvc",
        ] {
            let output = format!("rustc 1.90.0-nightly\nbinary: rustc\nhost: {host}\n");
            assert_eq!(parse_rustc_host(&output), Some(host));
        }
        assert_eq!(parse_rustc_host("rustc nightly\n"), None);
        assert_eq!(parse_rustc_host("host: malformed host\n"), None);
        assert_eq!(parse_rustc_host("host:\n"), None);
    }

    #[test]
    fn audits_indirect_calls_for_each_architecture() {
        let x86 = "0: callq *%rax\n1: callq *0x10(%rip)\n2: call 0x40\n";
        assert_eq!(
            audit_indirect_calls(Arch::X86_64, x86).unwrap(),
            CallAudit {
                indirect: 2,
                register_indirect: 1,
            }
        );

        let aarch64 = "0: bl 0x40\n4: blr x27\n8: ret\n";
        assert_eq!(
            audit_indirect_calls(Arch::Aarch64, aarch64).unwrap(),
            CallAudit {
                indirect: 1,
                register_indirect: 1,
            }
        );

        let riscv = concat!(
            "0: auipc ra, 0x7\n",
            "4: jalr ra <alloc::raw_vec::RawVecInner<A>::grow_amortized>\n",
            "8: auipc x1, 0\n",
            "c: jalr 16(ra)\n",
            "10: jalr s9\n",
            "14: jalr zero, 0(ra)\n",
            "18: jr s9\n",
            "1c: jal 0x80\n",
        );
        assert_eq!(
            audit_indirect_calls(Arch::Riscv64, riscv).unwrap(),
            CallAudit {
                indirect: 1,
                register_indirect: 1,
            }
        );
        let jr = parse_instruction("0: jr s9\n").unwrap();
        assert!(!instruction_is_call(Arch::Riscv64, jr).unwrap());
        assert!(instruction_is_forbidden_in_transition_tail(Arch::Riscv64, jr).unwrap());
        let non_linking_jalr = parse_instruction("0: jalr zero, 0(s9)\n").unwrap();
        assert!(!instruction_is_call(Arch::Riscv64, non_linking_jalr).unwrap());
        assert!(
            instruction_is_forbidden_in_transition_tail(Arch::Riscv64, non_linking_jalr).unwrap()
        );
        assert!(audit_indirect_calls(Arch::Aarch64, "0: blraa x0, x1\n").is_err());
    }

    #[test]
    fn encoded_rustflags_preserve_map_paths_with_spaces() {
        let directory =
            std::env::temp_dir().join(format!("crabefi xtask rustflags {}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let map_path = directory.join("runtime image.map");
        fs::write(&map_path, []).unwrap();

        let encoded = runtime_rustflags(Arch::Riscv64, &map_path);
        let arguments: Vec<_> = encoded.to_str().unwrap().split('\u{1f}').collect();
        let expected = format!("link-arg=-Map={}", map_path.display());
        assert!(arguments.contains(&expected.as_str()));
        assert!(arguments.contains(&"link-arg=--no-relax"));
        assert!(!arguments.iter().any(|argument| argument == &"runtime"));

        fs::remove_dir_all(directory).unwrap();
    }

    fn dynamic(entries: &[(i64, u64)]) -> Vec<u8> {
        entries
            .iter()
            .flat_map(|(tag, value)| {
                let mut entry = [0u8; 16];
                entry[..8].copy_from_slice(&tag.to_le_bytes());
                entry[8..].copy_from_slice(&value.to_le_bytes());
                entry
            })
            .collect()
    }

    #[test]
    fn dynamic_audit_accepts_relative_only_and_rejects_loader_dependencies() {
        let valid = dynamic(&[
            (object::elf::DT_RELASZ, 24),
            (object::elf::DT_RELAENT, 24),
            (object::elf::DT_RELACOUNT, 1),
            (object::elf::DT_NULL, 0),
        ]);
        assert_eq!(audit_dynamic_entries(&valid, 24).unwrap(), 1);

        for tag in [
            object::elf::DT_NEEDED,
            object::elf::DT_REL,
            object::elf::DT_JMPREL,
            object::elf::DT_PLTRELSZ,
        ] {
            let invalid = dynamic(&[
                (tag, 1),
                (object::elf::DT_RELASZ, 24),
                (object::elf::DT_RELACOUNT, 1),
            ]);
            assert!(audit_dynamic_entries(&invalid, 24).is_err());
        }
    }
}
