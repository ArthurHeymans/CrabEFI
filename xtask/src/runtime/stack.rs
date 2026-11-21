//! Static frame sums for the actual linked EFI table, not source-level callers.
use super::*;
use capstone::{InsnGroupType as group, arch::ArchOperand, prelude::*};
use std::collections::{BTreeMap, BTreeSet};

const SERVICES: [&str; 14] = [
    "GetTime",
    "SetTime",
    "GetWakeupTime",
    "SetWakeupTime",
    "SetVirtualAddressMap",
    "ConvertPointer",
    "GetVariable",
    "GetNextVariableName",
    "SetVariable",
    "GetNextHighMonotonicCount",
    "ResetSystem",
    "UpdateCapsule",
    "QueryCapsuleCapabilities",
    "QueryVariableInfo",
];

#[derive(Default)]
struct Node {
    frame: Option<u64>,
    targets: BTreeSet<u64>,
    /// Targets reached by at least one transfer that was NOT an unbypassed
    /// direct call immediately preceded by a non-noop `mov rsp, <reg>` write.
    unswitched_targets: BTreeSet<u64>,
    unknown: BTreeSet<String>,
    /// Calls into another image whose stack use this image cannot bound.
    external: BTreeSet<String>,
    /// SMC, HVC and ECALL instructions, accepted only in [`FIRMWARE_CALLS`].
    privileged: BTreeSet<String>,
    /// Calls that switch to the private runtime stack ([`PRIVATE_ENTRY`]).
    switches: BTreeSet<u64>,
}

/// Headroom reserved on the x86-64 private stack for OS interrupt frames
/// arriving while a runtime service runs with interrupts enabled.
const PRIVATE_STACK_HEADROOM: u64 = 16 * 1024;

/// The audited functions allowed to call PSCI (SMC/HVC) or SBI (ECALL), by
/// demangled path. The handler runs at a higher privilege level on its own
/// stack, so the call is a leaf for this image; anywhere else it is an
/// unknown transfer.
const FIRMWARE_CALLS: [&str; 2] = [
    "crabefi_runtime_image::arch::aarch64::reset",
    "crabefi_runtime_image::arch::riscv64::reset",
];

/// The function each service runs in after switching to the private stack.
/// Its instantiations are generic, so they share this path prefix.
const PRIVATE_ENTRY: &str = "crabefi_runtime_image::stack::trampoline::<";

/// The private stack itself; its size is the private budget.
const PRIVATE_STACK: &str = "crabefi_runtime_image::stack::STACK";

/// The stack UEFI guarantees a runtime caller (UEFI 2.10, 2.3.4.2 and
/// following): 4 KiB on x64, 8 KiB on AArch64 and RISC-V.
fn caller_budget(arch: Arch) -> u64 {
    match arch {
        Arch::X86_64 => 4 * 1024,
        Arch::Aarch64 | Arch::Riscv64 => 8 * 1024,
    }
}

/// A symbol's demangled path without its crate hash.
fn path(name: &str) -> String {
    format!("{:#}", rustc_demangle::demangle(name))
}

/// The one function allowed to call out of the image: the BootActive bridge
/// into boot firmware. Seal zeroes its address, so the call is unreachable
/// once the OS owns the machine. It must remain a distinct symbol; inlined
/// into a caller, its call fails the audit as an ordinary indirect call.
const BOOT_BRIDGE: &str = "crabefi_runtime_image::services::variables::bridge::call_boot_bridge";

fn decoder(arch: Arch) -> Result<Capstone> {
    let cs = match arch {
        Arch::X86_64 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .detail(true)
            .build(),
        Arch::Aarch64 => Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(true)
            .build(),
        Arch::Riscv64 => Capstone::new()
            .riscv()
            .mode(arch::riscv::ArchMode::RiscV64)
            .extra_mode([arch::riscv::ArchExtraMode::RiscVC].into_iter())
            .detail(true)
            .build(),
    }?;
    Ok(cs)
}

// The unrelaxed RISC-V linker emits PC-relative calls as AUIPC + JALR.
// Only substitute when the register matches and control cannot enter the
// second instruction alone (checked after collecting branch destinations).
fn riscv_pair(pc: u64, previous: Option<u32>, jalr: &[u8]) -> Option<u64> {
    let hi = previous?;
    let lo = u32::from_le_bytes(jalr.try_into().ok()?);
    let reg = (hi >> 7) & 31;
    if hi & 0x7f != 0x17 || lo & 0x707f != 0x67 || reg == 0 || (lo >> 15) & 31 != reg {
        return None;
    }
    let disp = i64::from((hi & 0xfffff000) as i32) + i64::from((lo as i32) >> 20);
    Some(pc.checked_sub(4)?.checked_add_signed(disp)? & !1)
}

fn decode(cs: &Capstone, arch: Arch, start: u64, bytes: &[u8], frame: Option<u64>) -> Result<Node> {
    let mut node = Node {
        frame,
        ..Node::default()
    };
    let end = start + bytes.len() as u64;
    let instructions = cs.disasm_all(bytes, start)?;
    let starts: BTreeSet<_> = instructions.iter().map(|i| i.address()).collect();
    let mut next = start;
    let mut falls_through = true;
    // A function never runs off its end, so a call as its last instruction
    // is a call that does not return, not a fall-through into the next symbol.
    let mut last_is_call = false;
    let mut previous = None;
    let mut prev_set_rsp = false;
    let mut pairs = Vec::new();
    let mut switched_calls = Vec::new();
    let mut destinations = BTreeSet::new();
    for insn in instructions.iter() {
        let pc = insn.address();
        next = pc + insn.bytes().len() as u64;
        last_is_call = false;
        let was_set_rsp = prev_set_rsp;
        let pair = (arch == Arch::Riscv64)
            .then(|| riscv_pair(pc, previous, insn.bytes()))
            .flatten();
        previous = insn.bytes().try_into().ok().map(u32::from_le_bytes);
        let d = cs.insn_detail(insn)?;
        let has = |group: u32| d.groups().iter().any(|g| u32::from(g.0) == group);
        let op = insn.mnemonic().unwrap_or("");
        let args = insn.op_str().unwrap_or("");
        prev_set_rsp =
            arch == Arch::X86_64 && op == "mov" && args.starts_with("rsp,") && args != "rsp, rsp";
        // Resolve matching RISC-V AUIPC+JALR pairs before the return shortcut:
        // Capstone prints `jalr zero, 0(ra)` as `ret` even when paired with `auipc ra, ...`.
        let ret = pair.is_none() && matches!((op, args), ("ret", "") | ("c.jr", "ra"));
        // Disassemblers may spell a non-linking RV tail transfer as JALR.
        // The encoded destination, not the mnemonic or CALL group, determines
        // whether it pushes another logical activation.
        let rv_jump = arch == Arch::Riscv64
            && (matches!(op, "c.j" | "c.jr")
                || previous.is_some_and(|word| {
                    matches!(word & 0x7f, 0x67 | 0x6f) && (word >> 7) & 31 == 0
                }));
        falls_through = !(ret || rv_jump || matches!(op, "jmp" | "b" | "br" | "j" | "jr"));
        if ret {
            continue;
        }
        // PSCI (SMC/HVC) and SBI (ECALL) run at a higher privilege level and
        // return to the next instruction. Whether that level has its own
        // stack is a platform property, so only audited stubs may do this.
        if matches!(op, "smc" | "hvc" | "ecall") {
            node.privileged.insert(format!("{op} at {pc:#x}"));
            continue;
        }
        if has(group::CS_GRP_INT)
            || has(group::CS_GRP_IRET)
            || has(group::CS_GRP_RET)
            || matches!(
                op,
                "eret" | "ud2" | "brk" | "sret" | "mret" | "ebreak" | "c.ebreak"
            )
        {
            node.unknown
                .insert(format!("exception or nonstandard return at {pc:#x}"));
            continue;
        }
        let call = !rv_jump
            && (has(group::CS_GRP_CALL)
                || matches!(op, "call" | "bl" | "blr" | "jal" | "jalr" | "c.jalr"));
        last_is_call = call;
        if !(call
            || rv_jump
            || has(group::CS_GRP_JUMP)
            || has(group::CS_GRP_BRANCH_RELATIVE)
            || matches!(op, "j" | "jr" | "c.j" | "c.jr" | "c.beqz" | "c.bnez"))
        {
            continue;
        }
        // RISC-V jalr has an immediate displacement, not an immediate target.
        let target = match d.arch_detail().operands().last() {
            Some(ArchOperand::X86Operand(x)) => match x.op_type {
                arch::x86::X86OperandType::Imm(n) => Some(n as u64),
                _ => None,
            },
            Some(ArchOperand::Arm64Operand(a)) => match a.op_type {
                arch::arm64::Arm64OperandType::Imm(n) => Some(n as u64),
                _ => None,
            },
            Some(ArchOperand::RiscVOperand(arch::riscv::RiscVOperand::Imm(n)))
                if !matches!(op, "jalr" | "jr" | "c.jalr" | "c.jr") =>
            {
                pc.checked_add_signed(*n)
            }
            _ => None,
        };
        if let Some(target) = target.or(pair) {
            destinations.insert(target);
        }
        match (target, pair) {
            (None, Some(addr)) => pairs.push((pc, addr)),
            (None, None) => {
                let kind = if call { "call" } else { "transfer" };
                node.unknown.insert(format!("indirect {kind} at {pc:#x}"));
            }
            (Some(addr), _) => {
                if call || !starts.contains(&addr) {
                    node.targets.insert(addr);
                    if call && was_set_rsp {
                        switched_calls.push((pc, addr));
                    } else {
                        node.unswitched_targets.insert(addr);
                    }
                }
            }
        }
    }
    for (pc, target) in switched_calls {
        if destinations.contains(&pc) {
            node.unswitched_targets.insert(target);
        }
    }
    for (pc, target) in pairs {
        if destinations.contains(&pc) {
            node.unknown.insert(format!("indirect transfer at {pc:#x}"));
        } else {
            node.targets.insert(target);
            node.unswitched_targets.insert(target);
        }
    }
    if next != end || bytes.is_empty() {
        node.unknown.insert(format!("undecoded bytes at {next:#x}"));
    } else if falls_through && !last_is_call {
        node.targets.insert(end);
        node.unswitched_targets.insert(end);
    }
    // LLVM's static frame excludes the return address pushed by x86 CALL.
    // Charge it even for tail transfers (safe overestimate).
    if arch == Arch::X86_64 {
        node.frame = node.frame.and_then(|n| n.checked_add(8));
    }
    Ok(node)
}

#[derive(Clone, Default)]
struct Usage {
    // Largest modeled sum, even if another branch has an unresolved edge.
    modeled: u64,
    bound: Option<u64>,
    unknown: BTreeSet<String>,
    external: BTreeSet<String>,
}

/// Trampolines reachable from `addr` on the caller's stack.
fn switches_from(addr: u64, nodes: &BTreeMap<u64, Node>) -> BTreeSet<u64> {
    let mut seen = BTreeSet::new();
    let mut pending = vec![addr];
    let mut switches = BTreeSet::new();
    while let Some(addr) = pending.pop() {
        if !seen.insert(addr) {
            continue;
        }
        if let Some(node) = nodes.get(&addr) {
            switches.extend(node.switches.iter().copied());
            pending.extend(node.targets.iter().copied());
        }
    }
    switches
}

fn usage(
    addr: u64,
    nodes: &BTreeMap<u64, Node>,
    active: &mut BTreeSet<u64>,
    cache: &mut BTreeMap<u64, Usage>,
) -> Usage {
    if let Some(u) = cache.get(&addr) {
        return u.clone();
    }
    let unknown = |reason: &str| Usage {
        unknown: [format!("{reason} at {addr:#x}")].into(),
        ..Usage::default()
    };
    let Some(n) = nodes.get(&addr) else {
        return unknown("unknown target");
    };
    if !active.insert(addr) {
        return unknown("cycle");
    }
    let mut reasons = n.unknown.clone();
    let mut external = n.external.clone();
    if n.frame.is_none() {
        reasons.insert(format!("missing frame (assembly or dynamic) at {addr:#x}"));
    }
    let mut largest = 0;
    for &target in &n.targets {
        let u = usage(target, nodes, active, cache);
        reasons.extend(u.unknown);
        external.extend(u.external);
        largest = largest.max(u.modeled);
    }
    active.remove(&addr);
    let modeled = n.frame.unwrap_or(0).saturating_add(largest);
    let u = Usage {
        modeled,
        bound: reasons.is_empty().then_some(modeled),
        unknown: reasons,
        external,
    };
    // A cycle reason is path-dependent; avoid caching partial cycle traversal.
    if !u.unknown.iter().any(|s| s.starts_with("cycle")) {
        cache.insert(addr, u.clone());
    }
    u
}

pub(super) fn audit(
    file: &object::File<'_>,
    arch: Arch,
    relocs: &[RuntimeRelocation],
    output: &Path,
) -> Result<()> {
    // .stack_sizes in the final ELF contains relocated addresses and ULEB128 sizes.
    let mut data = object::read::Bytes(
        file.section_by_name(".stack_sizes")
            .context("missing .stack_sizes")?
            .data()?,
    );
    let mut frames = BTreeMap::<u64, u64>::new();
    while !data.0.is_empty() {
        let addr = u64::from_le_bytes(
            data.read_bytes(8)
                .ok()
                .context("short stack address")?
                .0
                .try_into()?,
        );
        let size = data.read_uleb128().ok().context("bad stack frame size")?;
        frames
            .entry(addr)
            .and_modify(|s| *s = (*s).max(size))
            .or_insert(size);
    }
    let cs = decoder(arch)?;
    let mut nodes = BTreeMap::new();
    let mut private_entries = BTreeSet::new();
    let mut bridges = 0;
    for sym in file
        .symbols()
        .filter(|s| s.kind() == object::SymbolKind::Text && s.size() > 0)
    {
        let Some(section) = sym.section_index() else {
            continue;
        };
        let addr = sym.address();
        let bytes = file
            .section_by_index(section)?
            .data_range(addr, sym.size())?
            .context("function outside section")?;
        let mut n = decode(&cs, arch, addr, bytes, frames.get(&addr).copied())?;
        let name = path(sym.name()?);
        if name.starts_with(PRIVATE_ENTRY) {
            private_entries.insert(addr);
        }
        let privileged = core::mem::take(&mut n.privileged);
        if FIRMWARE_CALLS.contains(&name.as_str()) {
            n.external.extend(
                privileged
                    .into_iter()
                    .map(|call| format!("firmware {call}")),
            );
        } else {
            n.unknown.extend(
                privileged
                    .into_iter()
                    .map(|call| format!("unaudited privileged call {call}")),
            );
        }
        if name == BOOT_BRIDGE {
            bridges += 1;
            let calls: Vec<_> = n
                .unknown
                .iter()
                .filter(|reason| reason.starts_with("indirect call"))
                .cloned()
                .collect();
            anyhow::ensure!(
                calls.len() == 1 && n.unknown.len() == 1,
                "boot bridge must make exactly one indirect call: {:?}",
                n.unknown
            );
            n.unknown.clear();
            n.external
                .extend(calls.into_iter().map(|c| format!("boot bridge {c}")));
        }
        // Function aliases can share an address. Never drop a possible edge.
        let entry: &mut Node = nodes.entry(addr).or_default();
        entry.frame = n.frame;
        entry.targets.extend(n.targets);
        entry.unswitched_targets.extend(n.unswitched_targets);
        entry.unknown.extend(n.unknown);
        entry.external.extend(n.external);
    }
    anyhow::ensure!(bridges <= 1, "{bridges} symbols named {BOOT_BRIDGE}");
    if arch != Arch::X86_64 {
        anyhow::ensure!(
            private_entries.is_empty(),
            "private stack switching is only permitted on x86_64 (found {} trampoline(s) on {})",
            private_entries.len(),
            arch.dir_name(),
        );
    }
    // A call into a trampoline continues on the private stack only when every
    // transfer to it is an unbypassed direct call immediately preceded by a
    // non-noop SP write: charge it to the private stack, not the caller's.
    for node in nodes.values_mut() {
        let switches: BTreeSet<u64> = node
            .targets
            .intersection(&private_entries)
            .copied()
            .collect();
        for &target in &switches {
            anyhow::ensure!(
                !node.unswitched_targets.contains(&target),
                "transfer to private stack trampoline at {target:#x} was not an unbypassed call immediately preceded by an SP write"
            );
        }
        node.targets.retain(|target| !switches.contains(target));
        node.switches = switches;
    }
    let (private_stack_size, private_budget) = if arch == Arch::X86_64 {
        let size = file
            .symbols()
            .find(|sym| sym.name().is_ok_and(|name| path(name) == PRIVATE_STACK))
            .context("missing private runtime stack")?
            .size();
        let budget = size
            .checked_sub(PRIVATE_STACK_HEADROOM)
            .context("private runtime stack smaller than reserved IRQ headroom")?;
        (Some(size), Some(budget))
    } else {
        (None, None)
    };
    let caller_budget = caller_budget(arch);
    // LLVM may merge EFI entries. Resolve all 14 slots by relocation, rather
    // than guessing which Rust names survived LTO.
    let state = file
        .symbol_by_name("RUNTIME_STATE")
        .context("missing RUNTIME_STATE")?;
    let bytes = file
        .section_by_index(state.section_index().context("state section")?)?
        .data_range(state.address(), state.size())?
        .context("state extent")?;
    let mut headers = bytes
        .windows(8)
        .enumerate()
        .filter(|(_, sig)| *sig == b"RUNTSERV")
        .map(|(i, _)| i);
    let header = headers
        .next()
        .context("no runtime service table in state")?;
    anyhow::ensure!(
        headers.next().is_none()
            && bytes.get(header + 12..header + 16) == Some(&136u32.to_le_bytes()),
        "ambiguous or unexpected EFI table"
    );
    let slots = state.address() + header as u64 + 24;
    let mut report = Vec::new();
    let mut cache = BTreeMap::new();
    let mut over = Vec::new();
    let mut incomplete = Vec::new();
    for (i, name) in SERVICES.iter().enumerate() {
        let slot = slots + i as u64 * 8;
        let addr = u64::from(
            relocs
                .iter()
                .find(|r| u64::from(r.patch_offset) == slot)
                .context("unrelocated EFI service slot")?
                .target_offset,
        );
        let caller = usage(addr, &nodes, &mut BTreeSet::new(), &mut cache);
        // The private stack carries whatever any trampoline reachable from
        // this entry on the caller's stack runs. Entries that fit within the
        // UEFI caller budget do not switch.
        let mut private = Usage::default();
        let switches = switches_from(addr, &nodes);
        for switch in &switches {
            anyhow::ensure!(
                switches_from(*switch, &nodes).is_empty(),
                "{name} private stack trampoline at {switch:#x} reaches a nested switch"
            );
            let u = usage(*switch, &nodes, &mut BTreeSet::new(), &mut cache);
            private.modeled = private.modeled.max(u.modeled);
            private.unknown.extend(u.unknown);
            private.external.extend(u.external);
        }
        private.bound = if switches.is_empty() {
            Some(0)
        } else {
            private.unknown.is_empty().then_some(private.modeled)
        };
        // Every entry must retain a complete static bound on both stacks in
        // every release profile. Only the BootActive bridge is excluded, and
        // reported.
        if caller.bound.is_none() || private.bound.is_none() {
            incomplete.push(name);
        }
        if caller.modeled > caller_budget
            || private_budget.is_some_and(|budget| private.modeled > budget)
        {
            over.push(name);
        }
        let mut excluded = caller.external.clone();
        excluded.extend(private.external.iter().cloned());
        let mut unknown = caller.unknown.clone();
        unknown.extend(private.unknown.iter().cloned());
        report.push(json!({
            "entry": name,
            "address": addr,
            "caller_bound_bytes": caller.bound,
            "caller_modeled_bytes": caller.modeled,
            "private_bound_bytes": (!switches.is_empty()).then_some(private.bound).flatten(),
            "private_modeled_bytes": (!switches.is_empty()).then_some(private.modeled),
            "unknown": unknown,
            "excluded_external_calls": excluded,
        }));
    }
    write_json(
        output.join("stack-chains.json"),
        &json!({
            "model": "Sealed-phase, image-local bounds from LLVM static frames; tail edges charged as calls. The caller bound covers each entry up to any x86-64 private stack switch and is checked against the UEFI minimum for the architecture; on x86-64 the private bound covers what runs on the private stack and is checked against its size minus reserved OS IRQ headroom. AArch64 and RISC-V never switch stacks. Assumes the PSCI/SBI handlers called from the audited reset stubs run on their own stack, and excludes the BootActive boot bridge, which runs boot firmware and is disabled at seal. Each entry lists the calls it excludes.",
            "caller_budget_bytes": caller_budget,
            "private_stack_size_bytes": private_stack_size,
            "private_headroom_bytes": private_stack_size.map(|_| PRIVATE_STACK_HEADROOM),
            "private_budget_bytes": private_budget,
            "entries": report,
        }),
    )?;
    anyhow::ensure!(over.is_empty(), "EFI stack-chain budget exceeded: {over:?}");
    anyhow::ensure!(
        incomplete.is_empty(),
        "new unbounded EFI stack chains: {incomplete:?}"
    );
    let complete = SERVICES.len() - incomplete.len();
    match private_budget {
        Some(budget) => println!(
            "EFI stack audit: {complete}/{} entries bounded within {caller_budget} caller and {budget} private bytes ({PRIVATE_STACK_HEADROOM} IRQ headroom; see stack-chains.json)",
            SERVICES.len()
        ),
        None => println!(
            "EFI stack audit: {complete}/{} entries bounded within {caller_budget} caller bytes (no private stack; see stack-chains.json)",
            SERVICES.len()
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze(nodes: &[(u64, &[u8], Option<u64>)]) -> Usage {
        let cs = decoder(Arch::X86_64).unwrap();
        let graph = nodes
            .iter()
            .map(|&(pc, bytes, frame)| (pc, decode(&cs, Arch::X86_64, pc, bytes, frame).unwrap()))
            .collect();
        usage(0, &graph, &mut BTreeSet::new(), &mut BTreeMap::new())
    }

    #[test]
    fn nested_frames_can_exceed_budget_without_any_oversize_function() {
        // call 16; ret / jmp 32 / ret. Tail is deliberately overcharged.
        let u = analyze(&[
            (0, &[0xe8, 11, 0, 0, 0, 0xc3], Some(8000)),
            (16, &[0xeb, 14], Some(8000)),
            (32, &[0xc3], Some(500)),
        ]);
        assert_eq!(u.bound, Some(16524));
        assert!(u.unknown.is_empty());
    }

    #[test]
    fn unresolved_sibling_cannot_hide_an_oversize_chain() {
        let u = analyze(&[
            (0, &[0xe8, 11, 0, 0, 0, 0xff, 0xd0, 0xc3], Some(9000)),
            (16, &[0xc3], Some(8000)),
        ]);
        assert_eq!(u.bound, None);
        assert!(u.modeled > STACK_BUDGET);
    }

    #[test]
    fn local_loop_is_not_recursion_but_unresolved_paths_never_get_bounds() {
        assert_eq!(analyze(&[(0, &[0x75, 0xfe, 0xc3], Some(0))]).bound, Some(8));
        let call = &[0xe8, 11, 0, 0, 0, 0xc3];
        for (body, frame, reason) in [
            (&[0xff, 0xd0, 0xc3][..], Some(0), "indirect"), // call rax
            (&[0xff, 0xe0], Some(0), "indirect"),           // jmp rax
            (&[0xeb, 0xee], Some(0), "cycle"),              // jmp 0
            (&[0xeb, 0x20], Some(0), "unknown target"),
            (&[0xc3], None, "missing frame"),
            (&[0x0f], Some(0), "undecoded"),
        ] {
            let u = analyze(&[(0, call, Some(64)), (16, body, frame)]);
            assert_eq!(u.bound, None);
            assert!(
                u.unknown.iter().any(|s| s.starts_with(reason)),
                "{:?}",
                u.unknown
            );
        }
    }

    #[test]
    fn higher_privilege_calls_are_recorded_but_traps_are_unknown() {
        let cs = decoder(Arch::Aarch64).unwrap();
        // smc #0; ret
        let n = decode(
            &cs,
            Arch::Aarch64,
            0,
            &[3, 0, 0, 0xd4, 0xc0, 3, 0x5f, 0xd6],
            Some(16),
        )
        .unwrap();
        assert!(n.unknown.is_empty() && n.targets.is_empty());
        assert_eq!(n.privileged, ["smc at 0x0".to_string()].into());
        // brk #0; ret
        let n = decode(
            &cs,
            Arch::Aarch64,
            0,
            &[0, 0, 0x20, 0xd4, 0xc0, 3, 0x5f, 0xd6],
            Some(16),
        )
        .unwrap();
        assert!(n.unknown.iter().any(|s| s.starts_with("exception")));
        let cs = decoder(Arch::Riscv64).unwrap();
        // ecall; ret
        let n = decode(
            &cs,
            Arch::Riscv64,
            0,
            &[0x73, 0, 0, 0, 0x82, 0x80],
            Some(16),
        )
        .unwrap();
        assert!(n.unknown.is_empty() && n.targets.is_empty());
        assert_eq!(n.privileged, ["ecall at 0x0".to_string()].into());
    }

    #[test]
    fn aarch64_link_and_register_branch_are_distinct() {
        let cs = decoder(Arch::Aarch64).unwrap();
        let n = decode(
            &cs,
            Arch::Aarch64,
            0x100,
            &[4, 0, 0, 0x94, 0, 0, 0x1f, 0xd6],
            Some(48),
        )
        .unwrap(); // bl 0x110; br x0
        assert_eq!(n.targets, [0x110].into());
        assert!(n.unknown.contains("indirect transfer at 0x104"));
    }

    #[test]
    fn riscv_pair_requires_an_unbypassed_matching_auipc() {
        let cs = decoder(Arch::Riscv64).unwrap();
        // auipc ra,0; jalr ra,16(ra); ret
        let mut bytes = vec![0x97, 0, 0, 0, 0xe7, 0x80, 0, 1, 0x82, 0x80];
        let n = decode(&cs, Arch::Riscv64, 0x100, &bytes, Some(16)).unwrap();
        assert_eq!(n.targets, [0x110].into());
        assert!(n.unknown.is_empty());
        bytes.splice(..0, [0x6f, 0, 0x80, 0]); // jal zero,+8: bypass auipc
        let n = decode(&cs, Arch::Riscv64, 0x100, &bytes, Some(16)).unwrap();
        assert!(n.unknown.contains("indirect transfer at 0x108"));
        assert!(riscv_pair(4, Some(0x117), &[0xe7, 0x80, 0, 1]).is_none());
        // A non-linking JAL to a local epilogue is not recursion; a final
        // non-linking JALR through AUIPC does not fall into the next symbol.
        let n = decode(
            &cs,
            Arch::Riscv64,
            0x100,
            &[0x6f, 0, 0x40, 0, 0x82, 0x80],
            Some(0),
        )
        .unwrap();
        assert!(n.targets.is_empty() && n.unknown.is_empty());
        let n = decode(
            &cs,
            Arch::Riscv64,
            0x100,
            &[0x97, 0, 0, 0, 0x67, 0x80, 0, 1],
            Some(0),
        )
        .unwrap();
        assert_eq!(n.targets, [0x110].into());
        assert!(n.unknown.is_empty());
    }
}
