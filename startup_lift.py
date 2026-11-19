"""Bounded reachable-code discovery for original U5.1 CRT startup."""
from struct import unpack_from
from pathlib import Path
import hashlib
import lift

ENTRY = 0xF17D46
CHECKPOINT = 0xF17BD9
SEH_READY = 0xF17BE5
PE_READY = 0xF17C4D
HEAP_READY = 0xF17C52
TLS_RESOLVED = 0xF22F41
POINTERS_READY = 0xF22FA5
LOCKS_READY = 0xF22FAA
THREAD_SLOT_READY = 0xF22FCD
THREAD_ALLOCATED = 0xF22FE1
THREAD_READY = 0xF17C63
FILE_TABLE_READY = 0xF21E42
STOPS = {0xF23011, 0xF23016, 0xF17C56, 0xF22EB4, 0xF17C67,
         0xF17C98, 0xF209A8, 0xF1F0DC, 0xF22506, 0xF22357, 0xF20706,
         0xF2D4F3, 0xF1A754, 0xF303A5, 0xF303E3, 0xF21D4B, 0xF22AC4,
         0xF21E59, 0xF21F70}
COOKIE = 0x1310B30
# Explicit scope, not a list of individual blocks or call targets.
RANGES = ((ENTRY, ENTRY + 10), (0xF23039, 0xF230D4),
          (CHECKPOINT, 0xF17C98), (0xF21D70, 0xF21DB5),
          (0xF22AB0, 0xF22AD6), (0xF21DC9, 0xF21E59), (0xF21F5C, 0xF2200E),
          (0xF2301B, 0xF23039), (0xF22EA0, 0xF2301B), (0xF21BBC, 0xF21C06),
          (0xF22BBC, 0xF22C70), (0xF21DB5, 0xF21DC9), (0xF25870, 0xF258FF),
          (0xF21D36, 0xF21D69), (0xF21C5D, 0xF21C74),
          (0xF22053, 0xF2209F), (0xF3038D, 0xF3040F),
          (0xF2200E, 0xF22053), (0xF26278, 0xF2630C),
          (0xF22A19, 0xF22AB0),
          (0xF22B05, 0xF22B0E),
          (0xF20730, 0xF20763), (0xF22AFC, 0xF22B05),
          (0xF2D4E4, 0xF2D4F3), (0xF1A79D, 0xF1A7AC),
          (0xF23D32, 0xF23D41), (0xF2E4AF, 0xF2E4BE),
          (0xF2ABCF, 0xF2ABED), (0xF2E49E, 0xF2E4AF))
IMPORTS = {0x10A7268: ('GetSystemTimeAsFileTime', 1),
           0x10A7138: ('GetCurrentProcessId', 0),
           0x10A7154: ('GetCurrentThreadId', 0),
           0x10A7304: ('GetTickCount', 0),
           0x10A709C: ('QueryPerformanceCounter', 1),
           0x10A7280: ('GetStartupInfoW', 1),
           0x10A727C: ('HeapSetInformation', 4),
           0x10A7300: ('HeapCreate', 3),
           0x10A70A4: ('GetModuleHandleW', 1),
           0x10A70A8: ('GetProcAddress', 2),
           0x10A7088: ('TlsAlloc', 0),
           0x10A72F0: ('TlsSetValue', 2),
           0x10A7284: ('EncodePointer', 1),
           0x10A71A4: ('InitializeCriticalSectionAndSpinCount', 2),
           0x10A7288: ('DecodePointer', 1),
           0x50000: ('FlsAlloc', 1),
           0x10A7328: ('HeapAlloc', 3),
           0x10A71D8: ('Sleep', 1),
           0x50020: ('FlsSetValue', 2),
           0x10A70C8: ('EnterCriticalSection', 1),
           0x10A70C4: ('LeaveCriticalSection', 1),
           0x10A72F8: ('InterlockedIncrement', 1),
           0x10A72D4: ('GetStdHandle', 1),
           0x10A72D8: ('GetFileType', 1),
           0x10A72D0: ('SetHandleCount', 1),
           0x10A7278: ('GetCommandLineA', 0),
           0x10A72E4: ('GetEnvironmentStringsW', 0),
           0x10A72C4: ('WideCharToMultiByte', 8),
           0x10A72E0: ('FreeEnvironmentStringsW', 1)}
INDIRECT_IMPORTS = {pc: 0x10A70A8 for pc in (0xF22ECA, 0xF22ED7, 0xF22EE4, 0xF22EF1)}
INDIRECT_IMPORTS.update({0xF22F5C: 0x10A72F0})
INDIRECT_IMPORTS.update({pc: 0x10A7284 for pc in (0xF22F77, 0xF22F84, 0xF22F91, 0xF22F9E)})
INDIRECT_IMPORTS[0xF22FBF] = 0x10A7288
INDIRECT_IMPORTS[0xF22FEE] = 0x10A7288
INDIRECT_IMPORTS[0xF22A61] = 0x10A72C4
INDIRECT_IMPORTS[0xF22A84] = 0x10A72C4
INDIRECT_IMPORTS.update({pc: 0x10A72F8 for pc in (0xF25882, 0xF2588F, 0xF2589C, 0xF258A9, 0xF258B6, 0xF258D2, 0xF258E2, 0xF258F8)})
# A closed, verified set may mix guest functions and host import tokens.
INDIRECT_TARGETS = {0xF22FC1: (0x50000, 0xF22B05)}
INDIRECT_TARGETS[0xF22FF0] = (0x50020, 0x10A72F0)
DIGEST = '614c08f25b531d590c5aa6d9cf35b1e406e83d35fbd50e61188f19247fb176ae'


def translate(insn):
    """Startup arithmetic that can report a guest divide fault to its caller."""
    args = insn.operands
    if insn.mnemonic == 'div' and len(args) == 1 and args[0].size == 4:
        return [f'let divisor = u64::from({lift.value(insn, args[0])});',
                'let dividend = (u64::from(r.edx) << 32) | u64::from(r.eax);',
                f'let quotient = dividend.checked_div(divisor).ok_or("x86 divide by zero at {insn.address:#x}")?;',
                f'if quotient > u32::MAX as u64 {{ return Err("x86 divide overflow at {insn.address:#x}".into()); }}',
                'r.eax = quotient as u32;', 'r.edx = (dividend % divisor) as u32;']
    if insn.mnemonic == 'imul' and len(args) == 2 and args[0].size == 4:
        lhs, rhs = (lift.value(insn, arg) for arg in args)
        return [f'let product = i64::from({lhs} as i32) * i64::from({rhs} as i32);',
                'let result = product as u32;',
                'r.overflow = product != i64::from(result as i32);', 'r.carry = r.overflow;',
                lift.store(insn, args[0], 'result')]
    return lift.translate(insn)


def discover(image, entry, ranges, stops, imports, limit=2048):
    base, sections = lift.pe_sections(image)
    decoder = lift.Cs(lift.CS_ARCH_X86, lift.CS_MODE_32)
    decoder.detail = True
    pending, decoded, occupied = [entry], {}, {}
    while pending:
        pc = pending.pop()
        if pc in stops or pc in decoded:
            continue
        if len(decoded) >= limit:
            raise ValueError(f'discovery budget exceeded at {pc:#x}')
        end = next((hi for lo, hi in ranges if lo <= pc < hi), None)
        if end is None:
            raise ValueError(f'unresolved control-flow target {pc:#x} outside startup scope')
        section = next((s for s in sections if s[0] <= pc-base < s[0]+s[1]), None)
        if section is None:
            raise ValueError(f'unmapped instruction at {pc:#x}')
        rva, size, offset = section
        offset += pc-base-rva
        body = image[offset:offset+min(15, end-pc, rva+size-(pc-base))]
        insn = next(decoder.disasm(body, pc, count=1), None)
        if insn is None:
            raise ValueError(f'incomplete instruction at {pc:#x}')
        for byte in range(pc, pc+insn.size):
            if byte in occupied:
                raise ValueError(f'overlapping instruction at {pc:#x} with {occupied[byte]:#x}')
            occupied[byte] = pc
        decoded[pc] = insn
        op, args = insn.mnemonic, insn.operands
        following = pc + insn.size
        if op == 'ret':
            continue
        if op in ('call', 'jmp') or op in lift.CONDITIONS:
            arg = args[0]
            if arg.type == lift.X86_OP_IMM:
                pending.append(arg.imm)
            elif (op == 'call' and arg.type == lift.X86_OP_MEM
                  and not arg.mem.base and not arg.mem.index
                  and not arg.mem.segment and arg.mem.disp in imports):
                pass
            elif op == 'call' and arg.type == lift.X86_OP_REG and pc in INDIRECT_IMPORTS:
                pass
            elif op == 'call' and arg.type == lift.X86_OP_REG and pc in INDIRECT_TARGETS:
                pending.extend(target for target in INDIRECT_TARGETS[pc] if target not in imports)
            else:
                raise ValueError(f'unresolved {op} at {pc:#x}: {insn.op_str}')
            if op != 'jmp':
                pending.append(following)
        else:
            translate(insn)  # Reject unsupported instructions before writing output.
            pending.append(following)
    lift.validate_signed_branches(decoded.values())
    return decoded


def generate_startup(image):
    if hashlib.sha256(image).hexdigest() != DIGEST:
        raise ValueError('startup requires the verified U5.1 executable SHA-256')
    pe = unpack_from('<I', image, 60)[0]
    base, _ = lift.pe_sections(image)
    if base + unpack_from('<I', image, pe+40)[0] != ENTRY:
        raise ValueError('unexpected PE entry point')
    code = discover(image, ENTRY, RANGES, STOPS, IMPORTS)
    used = {'esp'}
    for insn in code.values():
        reads, writes = insn.regs_access()
        used.update(insn.reg_name(reg) for reg in (*reads, *writes))
    used.update(lift.LOW_WORD.get(reg, lift.LOW_BYTE.get(reg, reg)) for reg in list(used))
    lines = ['// Generated locally by lift.py; do not edit.', 'use super::Memory;',
             '#[derive(Default)]',
             'struct Registers { ' + ', '.join(f'{r}: u32' for r in lift.REGISTERS if r in used) + ', carry: bool, zero: bool, sign: bool, overflow: bool }',
             f'pub(super) fn run(m: &mut Memory, stop: u32) -> Result<(), String> {{ run_from(m, {ENTRY:#x}, stop) }}',
             'pub(super) fn run_from(m: &mut Memory, start: u32, stop: u32) -> Result<(), String> {',
             'let mut r = Registers { esp: 0x20000, ..Default::default() };',
             'let mut pc = start;',
             'for _ in 0..4096 {',
             'if pc == stop { m.stack = r.esp; m.frame = r.ebp; m.eax = r.eax; return Ok(()); }',
             'match pc {']
    for pc, insn in sorted(code.items()):
        lines.append(f'{pc:#x} => {{ // {insn.mnemonic} {insn.op_str}')
        op, args, following = insn.mnemonic, insn.operands, pc+insn.size
        if op == 'call':
            if args[0].type == lift.X86_OP_IMM:
                lines += ['r.esp -= 4;', f'm.write32(r.esp, {following:#x});', f'pc = {args[0].imm:#x};']
            elif pc in INDIRECT_TARGETS:
                lines += [f'let target = {lift.value(insn, args[0])};', 'r.esp -= 4;',
                          f'm.write32(r.esp, {following:#x});', 'match target {']
                for target in INDIRECT_TARGETS[pc]:
                    if target in IMPORTS:
                        argc = IMPORTS[target][1]
                        lines.append(f'{target:#x} => {{ r.eax = m.import(target, r.esp + 4)?; r.esp += {(argc+1)*4}; pc = {following:#x}; }},')
                    else:
                        lines.append(f'{target:#x} => {{ pc = target; }},')
                lines += [f'_ => return Err(format!("unresolved indirect call at {pc:#x}: target {{target:#x}}")),', '}']
            else:
                slot = args[0].mem.disp if args[0].type == lift.X86_OP_MEM else INDIRECT_IMPORTS[pc]
                argc = IMPORTS[slot][1]
                if args[0].type == lift.X86_OP_REG:
                    lines.append(f'if {lift.value(insn, args[0])} != {slot:#x} {{ return Err(format!("unresolved indirect call at {pc:#x}")); }}')
                lines += ['r.esp -= 4;', f'm.write32(r.esp, {following:#x});',
                          f'r.eax = m.import({slot:#x}, r.esp + 4)?;',
                          f'r.esp += {(argc+1)*4};', f'pc = {following:#x};']
        elif op == 'ret':
            cleanup = args[0].imm if args else 0
            lines += ['pc = m.read32(r.esp);', f'r.esp += {4+cleanup};']
        elif op == 'jmp':
            lines += [f'pc = {args[0].imm:#x};']
        elif op in lift.CONDITIONS:
            lines += [f'pc = if {lift.CONDITIONS[op]} {{ {args[0].imm:#x} }} else {{ {following:#x} }};']
        else:
            lines += translate(insn) + [f'pc = {following:#x};']
        lines.append('},')
    lines += ['_ => return Err(format!("unresolved startup address {pc:#x}")),',
              '} } Err(format!("startup execution budget exceeded at {pc:#x}"))', '}']
    header_size = unpack_from('<I', image, pe+24+60)[0]
    lines.append('pub(super) const PE_HEADERS: &[u8] = &[' + ','.join(str(b) for b in image[:header_size]) + '];')
    # Map initialized data as data, without embedding executable x86 sections.
    section_count = unpack_from('<H', image, pe+6)[0]
    section_table = pe+24+unpack_from('<H', image, pe+20)[0]
    data = bytearray()
    lines.append('pub(super) const IMAGE_DATA: &[u8] = include_bytes!("startup_data.bin");')
    lines.append('pub(super) const DATA_RANGES: &[(u32, usize, usize)] = &[')
    for index in range(section_count):
        record = section_table+40*index
        rva, size, offset = unpack_from('<III', image, record+12)
        flags = unpack_from('<I', image, record+36)[0]
        if flags & 0x20000000 or not size:
            continue
        lines.append(f'({base+rva:#x}, {len(data)}, {size}),')
        data.extend(image[offset:offset+size])
    lines.append('];')
    Path(__file__).with_name('src').joinpath('startup_data.bin').write_bytes(data)
    print(f'Startup: {len(code)} reachable instructions, PE {ENTRY:#x} -> file table {FILE_TABLE_READY:#x}')
    return '\n'.join(lines)+'\n'
