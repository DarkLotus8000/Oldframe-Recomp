"""Generate Rust from the U5.1 x86 cache block and stream routines."""

import argparse
import hashlib
from pathlib import Path
from struct import error as StructError
from struct import unpack_from

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

CALLER_RVA = 0x0B1C10
CALLER_END_RVA = 0x0B1C42
CALLER_HASH = "a3c4c38188703cabf3c394bacf298d497e4b63cf253fd372ff36b33c6c77b665"
DECODER_RVA = 0xB372B0
DECODER_END_RVA = 0xB37456
TABLE_RVA = 0xB37458
TABLE_SIZE = 32
DECODER_HASH = "e01d86dafc88c9c9332f27787292caff66e1c3e288b084e6c00c45c4bfa1c7c4"
STREAM_RVA = 0x0B3860
ENTRY_RVA = 0x0B3930
READ_PAGES_RVA = 0x0A5C60
START_IO_RVA = 0x0A6C20
READ_COMPLETE_RVA = 0x0A6BA0
SELECT_PAGE_SPAN_RVA = 0x0AA550
PAGE_SPAN_READY_RVA = 0x0AA70C
CTOR_RVA = 0x0B3460
SETUP_RVA = 0x0B3AA0
JOB_RVA = 0x0B3B0F
SYNC_RVA = 0x0B3BB4
SETUP_END_RVA = 0x0B3BD7
SETUP_HASH = "0a9a4a8f0809bd9124236e176b64245e5d59bbe8f60ecef22fe07f2cd1744a64"
STREAM_ROUTINES = (
    ("calculate archive read pages", READ_PAGES_RVA, 0x0A5EE2, "ac77ec1cb4b1156bd5b20f5816d65b0fd811cd0ef8354741cc876f67a123ff85"),
    ("signal I/O semaphore", 0x045B80, 0x045BA6, "5c590764d54a02d6e0d32d83fbce9169aec0dfa04d5425eca554512592e16a61"),
    ("finish archive page read", 0x0A6B00, 0x0A6B91, "15888d763df6c95241a752d9d4c9318f98b976c2e6f9433e9f0eb4a68d02845f"),
    ("archive read callback", READ_COMPLETE_RVA, 0x0A6C11, "25dd5f8407672eb40b6ffe2d5bd591295e340726052513d17ec757d4011bd5db"),
    ("submit archive page read", START_IO_RVA, 0x0A6DD7, "943dac81f0b6f0dad2dd2e9faef65178ec441c4ec169088c04a5733891dbe687"),
    ("select the ready page span", SELECT_PAGE_SPAN_RVA, PAGE_SPAN_READY_RVA, "bf6917d892b076899aad2c72626500efc52ae26788c8746834332b4d7108acd2"),
    ("query output buffer", 0x0B3290, 0x0B32E6, "019a7b60549dc457cf3fca98fe435c0bfc56ce8cc13fdd26154821017522b030"),
    ("construct stream", CTOR_RVA, 0x0B350E, "49b3c19f8fbf75af43e50227a1ee58dabcf7f3db903cf19a4d3390d37d6df721"),
    ("buffer space", 0x0B3550, 0x0B3587, "647823d1e158ed78d29f782dd30b9708dbbd9553a4d2201d7c72ec483dfd0dae"),
    ("flush", 0x0B3590, 0x0B3613, "35f7c0f5a2b59dbc961a460cc6c84ee1552bf851f65c8b0ee4a55cd4111a6da3"),
    ("decode or copy", 0x0B3620, 0x0B3722, "06a0d54767fa01d5a36004fff154dc0092580bb8fadfce00de2e3146ca0e4c8a"),
    ("refill", 0x0B3730, 0x0B3853, "e4c026d2f5a76750a8c1c0776ff8f287275d49f453a63a951f4f1a13505a3c51"),
    ("read frame", STREAM_RVA, 0x0B392F, "eeff37532dd39abe01546873823ab42ad5784ff2a536a80c5266faed7f0aed9b"),
    ("read entry", ENTRY_RVA, 0x0B3A9E, "614b903936c369c82b15aa654050651d259b19872588d0d3f18a3147e9a97e6b"),
)
COPY_RVA = 0xB18440
ALLOCATE_RVA = 0x015390
INTERLEAVE_RVA = 0x0B32F0
DIAGNOSTIC_SLOT_RVA = 0xE8D438
QUERY_SLOT_RVA = 0xCA7170
CLOCK_SLOT_RVA = 0xCA709C
READ_SLOT_RVA = 0xCA71F4
RELEASE_SLOT_RVA = 0xCA719C

REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
LOW_BYTE = {"al": "eax", "bl": "ebx", "cl": "ecx", "dl": "edx"}
LOW_WORD = {name[1:]: name for name in REGISTERS}
CONDITIONS = {
    "ja": "!r.carry && !r.zero",
    "jae": "!r.carry",
    "jb": "r.carry",
    "jbe": "r.carry || r.zero",
    "je": "r.zero",
    "jne": "!r.zero",
    "jl": "r.sign != r.overflow",
    "jns": "!r.sign",
}
TERMINATORS = {*CONDITIONS, "call", "int3", "jmp", "ret"}


def pe_sections(image):
    """Read the preferred image base and the PE32 section mappings."""
    pe = unpack_from("<I", image, 0x3C)[0]
    if image[:2] != b"MZ" or image[pe:pe + 4] != b"PE\0\0":
        raise ValueError("expected a Windows PE executable")
    machine, section_count = unpack_from("<HH", image, pe + 4)
    optional_size = unpack_from("<H", image, pe + 20)[0]
    optional = pe + 24
    if machine != 0x14C or optional_size < 32 or unpack_from("<H", image, optional)[0] != 0x10B:
        raise ValueError("expected a 32-bit x86 executable")
    image_base = unpack_from("<I", image, optional + 28)[0]

    first_section = optional + optional_size
    sections = [unpack_from("<III", image, first_section + 40 * i + 12)
                for i in range(section_count)]
    return image_base, sections


def verified_bytes(image, sections, name, start_rva, end_rva, digest):
    for rva, size, file_offset in sections:
        if rva <= start_rva and end_rva <= rva + size:
            start = file_offset + start_rva - rva
            body = image[start:start + end_rva - start_rva]
            if hashlib.sha256(body).hexdigest() != digest:
                raise ValueError(f"{name} bytes differ from the verified Warframe U5.1 executable")
            return body
    raise ValueError(f"{name} RVA is outside the PE sections")


def address(insn, mem):
    if mem.segment and insn.reg_name(mem.segment) != "fs":
        raise ValueError(f"unexpected segment at {insn.address:#x}")
    parts = []
    if mem.segment:
        parts.append("m.fs_base")
    if mem.base:
        parts.append(f"r.{insn.reg_name(mem.base)}")
    if mem.index:
        index = f"r.{insn.reg_name(mem.index)}"
        parts.append(f"{index}.wrapping_mul({mem.scale})" if mem.scale != 1 else index)
    if mem.disp or not parts:
        parts.append(f"{mem.disp & 0xFFFFFFFF:#x}u32")
    result, *offsets = parts
    return result + "".join(f".wrapping_add({offset})" for offset in offsets)


def value(insn, operand):
    if operand.type == X86_OP_IMM:
        return f"{operand.imm & 0xFFFFFFFF:#x}"
    if operand.type == X86_OP_REG:
        reg = insn.reg_name(operand.reg)
        if reg in LOW_BYTE:
            return f"u32::from(r.{LOW_BYTE[reg]} as u8)"
        if reg in LOW_WORD:
            return f"u32::from(r.{LOW_WORD[reg]} as u16)"
        if reg in REGISTERS:
            return f"r.{reg}"
    if operand.type == X86_OP_MEM and operand.size in (1, 2, 4):
        return f"m.read{operand.size * 8}({address(insn, operand.mem)})"
    raise ValueError(f"unsupported operand at {insn.address:#x}")


def store(insn, operand, expr):
    if operand.type == X86_OP_REG:
        reg = insn.reg_name(operand.reg)
        if reg in LOW_BYTE:
            full = f"r.{LOW_BYTE[reg]}"
            if expr == "0":
                return f"{full} &= !0xff;"
            return f"{full} = ({full} & !0xff) | {expr};"
        if reg in LOW_WORD:
            full = f"r.{LOW_WORD[reg]}"
            return f"{full} = ({full} & !0xffff) | (({expr}) & 0xffff);"
        if reg in REGISTERS:
            return f"r.{reg} = {expr};"
    if operand.type == X86_OP_MEM and operand.size in (1, 2, 4):
        return f"m.write{operand.size * 8}({address(insn, operand.mem)}, {expr});"
    raise ValueError(f"unsupported destination at {insn.address:#x}")


def translate(insn):
    op = insn.mnemonic
    operands = insn.operands
    if (op == "mov" and all(arg.type == X86_OP_REG for arg in operands)
            and operands[0].reg == operands[1].reg):
        return []
    if op == "not":
        return [store(insn, operands[0], f"!{value(insn, operands[0])}")]
    if op == "leave":
        return ["r.esp = r.ebp;", "r.ebp = m.read32(r.esp);", "r.esp += 4;"]
    if op in ("mov", "movzx"):
        return [store(insn, operands[0], value(insn, operands[1]))]
    if op in ("movq", "movlpd"):
        dest, source = operands
        if dest.type == X86_OP_REG and insn.reg_name(dest.reg) == "xmm0" and source.type == X86_OP_MEM:
            return [f"r.xmm0 = m.read64({address(insn, source.mem)});"]
        if source.type == X86_OP_REG and insn.reg_name(source.reg) == "xmm0" and dest.type == X86_OP_MEM:
            return [f"m.write64({address(insn, dest.mem)}, r.xmm0);"]
    if op in ("pxor", "xorpd") and all(operand.type == X86_OP_REG and insn.reg_name(operand.reg) == "xmm0"
                            for operand in operands):
        return ["r.xmm0 = 0;"]
    if op == "lea":
        if operands[1].mem.base == operands[0].reg and not operands[1].mem.index and not operands[1].mem.disp:
            return []
        return [store(insn, operands[0], address(insn, operands[1].mem))]
    if op == "push":
        return [f"let pushed = {value(insn, operands[0])};",
                "r.esp = r.esp.wrapping_sub(4);", "m.write32(r.esp, pushed);"]
    if op == "pop":
        return [store(insn, operands[0], "m.read32(r.esp)"),
                "r.esp = r.esp.wrapping_add(4);"]
    if op == "cmovae":
        assignment = store(insn, operands[0], value(insn, operands[1]))
        return [f"if !r.carry {{ {assignment} }}"]
    if op == "setb":
        return [store(insn, operands[0], "u32::from(r.carry)")]
    if op == "setne":
        return [store(insn, operands[0], "u32::from(!r.zero)")]
    if op in ("inc", "dec"):
        lhs = value(insn, operands[0])
        method = "wrapping_add" if op == "inc" else "wrapping_sub"
        return [f"let result = {lhs}.{method}(1);", "r.zero = result == 0;",
                store(insn, operands[0], "result")]
    if op in ("add", "sub", "cmp"):
        lhs, rhs = (value(insn, operand) for operand in operands)
        method = "overflowing_add" if op == "add" else "overflowing_sub"
        lines = [f"let (result, carry) = {lhs}.{method}({rhs});",
                 "r.carry = carry;", "r.zero = result == 0;"]
        sign_bit = 1 << (operands[0].size * 8 - 1)
        # Signed comparisons use SF/OF from the operand width, including word compares.
        if op == "cmp":
            lines += [f"r.sign = (result & {sign_bit:#x}) != 0;",
                      f"r.overflow = (({lhs} ^ {rhs}) & ({lhs} ^ result) & {sign_bit:#x}) != 0;"]
        if op != "cmp":
            lines.append(store(insn, operands[0], "result"))
        return lines
    if op == "neg":
        lhs = value(insn, operands[0])
        return [f"let (result, carry) = 0u32.overflowing_sub({lhs});",
                "r.carry = carry;", "r.zero = result == 0;",
                store(insn, operands[0], "result")]
    if op in ("adc", "sbb"):
        lhs, rhs = (value(insn, operand) for operand in operands)
        method = "overflowing_add" if op == "adc" else "overflowing_sub"
        return [f"let (result, first_carry) = {lhs}.{method}({rhs});",
                f"let (result, carry) = result.{method}(u32::from(r.carry));",
                "r.carry = first_carry || carry;", "r.zero = result == 0;",
                store(insn, operands[0], "result")]
    if op in ("shrd", "shld") and operands[0].size == 4 and operands[2].type == X86_OP_IMM:
        lhs, rhs, _ = (value(insn, operand) for operand in operands)
        count = operands[2].imm & 31
        if count == 0:
            return []
        primary, secondary = (">>", "<<") if op == "shrd" else ("<<", ">>")
        carry_bit = count - 1 if op == "shrd" else 32 - count
        return [f"let result = ({lhs} {primary} {count}) | ({rhs} {secondary} {32 - count});",
                f"r.carry = ({lhs} & {1 << carry_bit:#x}) != 0;", "r.zero = result == 0;",
                store(insn, operands[0], "result")]
    if op in ("and", "or", "xor", "test"):
        lhs, rhs = (value(insn, operand) for operand in operands)
        symbol = {"and": "&", "or": "|", "xor": "^", "test": "&"}[op]
        if op == "xor" and lhs == rhs:
            return ["r.carry = false;", "r.zero = true;", "r.sign = false;",
                    "r.overflow = false;", store(insn, operands[0], "0")]
        expr = lhs if lhs == rhs else f"{lhs} {symbol} {rhs}"
        sign_bit = 1 << (operands[0].size * 8 - 1)
        lines = [f"let result = {expr};", "r.carry = false;", "r.zero = result == 0;",
                 f"r.sign = (result & {sign_bit:#x}) != 0;", "r.overflow = false;"]
        if op != "test":
            lines.append(store(insn, operands[0], "result"))
        return lines
    if op in ("shl", "shr", "sar") and operands[0].size == 4 and operands[1].type == X86_OP_IMM:
        lhs = value(insn, operands[0])
        count = operands[1].imm & 31
        if count == 0:
            return []
        operator = "<<" if op == "shl" else ">>"
        carry_bit = 32 - count if op == "shl" else count - 1
        carry = f"({lhs} >> {carry_bit})" if carry_bit else lhs
        result = (f"(({lhs} as i32) >> {count}) as u32" if op == "sar"
                  else f"{lhs} {operator} {count}")
        return [f"r.carry = ({carry} & 1) != 0;",
                f"let result = {result};", "r.zero = result == 0;",
                store(insn, operands[0], "result")]
    if op in ("nop", "prefetcht0"):
        return []
    raise ValueError(f"unsupported instruction {op} at {insn.address:#x}")


def disassemble(decoder, body, address):
    instructions = list(decoder.disasm(body, address))
    if sum(insn.size for insn in instructions) != len(body):
        raise ValueError(f"incomplete disassembly at {address:#x}")
    return instructions


def validate_signed_branches(instructions):
    """Reject signed branches whose flag producer is not modeled."""
    instructions = list(instructions)
    by_end = {insn.address + insn.size: insn for insn in instructions}
    direct_targets = {insn.operands[0].imm for insn in instructions
                      if (insn.mnemonic in TERMINATORS and insn.operands
                          and insn.mnemonic != 'ret' and insn.operands[0].type == X86_OP_IMM)}
    for insn in instructions:
        if insn.mnemonic in ('jl', 'jns'):
            previous = by_end.get(insn.address)
            producers = ('cmp',) if insn.mnemonic == 'jl' else ('test',)
            if previous is None or previous.mnemonic not in producers or insn.address in direct_targets:
                raise ValueError(f'unsupported signed flag producer at {insn.address:#x}')


def generate(image):
    base, sections = pe_sections(image)
    caller = base + CALLER_RVA
    entry = base + DECODER_RVA
    table = base + TABLE_RVA
    copy = base + COPY_RVA
    allocate = base + ALLOCATE_RVA
    interleave = base + INTERLEAVE_RVA
    job = base + JOB_RVA
    diagnostic_slot = base + DIAGNOSTIC_SLOT_RVA
    query_slot = base + QUERY_SLOT_RVA
    clock_slot = base + CLOCK_SLOT_RVA
    read_slot = base + READ_SLOT_RVA
    release_slot = base + RELEASE_SLOT_RVA
    span_ready = base + PAGE_SPAN_READY_RVA
    imports = {
        query_slot: (3, "query_memory"),
        clock_slot: (1, "query_counter"),
        read_slot: (5, "submit_archive_read"),
        release_slot: (3, "release_io_semaphore"),
    }
    caller_code = verified_bytes(image, sections, "caller", CALLER_RVA, CALLER_END_RVA, CALLER_HASH)
    decoder_body = verified_bytes(image, sections, "decoder", DECODER_RVA,
                                  TABLE_RVA + 4 * TABLE_SIZE, DECODER_HASH)
    code = decoder_body[:DECODER_END_RVA - DECODER_RVA]
    jump_targets = unpack_from(f"<{TABLE_SIZE}I", decoder_body, TABLE_RVA - DECODER_RVA)
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    instructions = disassemble(decoder, caller_code, caller) + disassemble(decoder, code, entry)
    starts = {caller, entry, *jump_targets}
    for name, start, end, digest in STREAM_ROUTINES:
        body = verified_bytes(image, sections, name, start, end, digest)
        instructions.extend(disassemble(decoder, body, base + start))
        starts.add(base + start)
    setup = verified_bytes(image, sections, "set up stream", SETUP_RVA, SETUP_END_RVA, SETUP_HASH)
    # The synchronous branch skips the engine scheduler's job submission block.
    instructions.extend(disassemble(decoder, setup[:JOB_RVA - SETUP_RVA], base + SETUP_RVA))
    instructions.extend(disassemble(decoder, setup[SYNC_RVA - SETUP_RVA:], base + SYNC_RVA))
    starts.add(base + SETUP_RVA)
    validate_signed_branches(instructions)
    addresses = {insn.address for insn in instructions}
    for insn in instructions:
        following = insn.address + insn.size
        if insn.mnemonic in TERMINATORS and following in addresses:
            starts.add(following)
        if insn.mnemonic == "jmp" and insn.operands[0].type == X86_OP_MEM:
            mem = insn.operands[0].mem
            if mem.base or insn.reg_name(mem.index) != "edx" or mem.scale != 4 or mem.disp != table:
                raise ValueError("unexpected computed jump")
        elif insn.mnemonic == "call" and insn.operands[0].type == X86_OP_MEM:
            mem = insn.operands[0].mem
            if mem.base or mem.index or (mem.disp != diagnostic_slot and mem.disp not in imports):
                raise ValueError("unexpected indirect call")
        elif insn.mnemonic in ("call", "jmp") or insn.mnemonic in CONDITIONS:
            if insn.operands[0].type != X86_OP_IMM:
                raise ValueError(f"unsupported branch at {insn.address:#x}")
            dest = insn.operands[0].imm
            if insn.mnemonic != "call" or dest not in (copy, allocate, interleave):
                starts.add(dest)
    if not starts <= addresses | {span_ready}:
        raise ValueError("a branch target is outside the decoded functions")

    blocks = {}
    for insn in instructions:
        if insn.address in starts:
            block = blocks.setdefault(insn.address, [])
        block.append(insn)

    yield "// Derived locally from the verified U5.1 executable by lift.py."
    yield "use super::Memory;"
    yield "#[derive(Default)]"
    yield "struct Registers { " + ", ".join(f"{reg}: u32" for reg in REGISTERS) + ", xmm0: u64, carry: bool, zero: bool, sign: bool, overflow: bool }"
    yield f"const LITERAL_TARGETS: [u32; {TABLE_SIZE}] = ["
    for target in jump_targets:
        yield f"    {target:#x},"
    yield "];"
    yield f"pub(super) const CALLER: u32 = {caller:#x};"
    yield f"pub(super) const STREAM: u32 = {base + STREAM_RVA:#x};"
    yield f"pub(super) const CTOR: u32 = {base + CTOR_RVA:#x};"
    yield f"pub(super) const SETUP: u32 = {base + SETUP_RVA:#x};"
    yield f"pub(super) const READ_PAGES: u32 = {base + READ_PAGES_RVA:#x};"
    yield f"pub(super) const START_IO: u32 = {base + START_IO_RVA:#x};"
    yield f"pub(super) const READ_COMPLETE: u32 = {base + READ_COMPLETE_RVA:#x};"
    yield f"pub(super) const SELECT_PAGE_SPAN: u32 = {base + SELECT_PAGE_SPAN_RVA:#x};"
    yield "pub(super) fn run(m: &mut Memory, stack: u32, start: u32, ecx: u32) -> u32 {"
    yield "    let mut r = Registers { esp: stack, ecx, ..Registers::default() };"
    yield "    let mut block = start;"
    yield "    loop {"
    yield "        match block {"
    yield "            0 => return r.eax,"
    # At this checkpoint LoadBufferIntoOp has selected the half-open guest span.
    yield f"            {span_ready:#x} => {{"
    yield "                m.selected_span = Some((r.edi, r.esi));"
    yield "                return 1;"
    yield "            }"
    yield f"            {copy:#x} => {{"
    yield "                let dest = m.read32(r.esp + 4);"
    yield "                m.move_bytes(dest, m.read32(r.esp + 8), m.read32(r.esp + 12));"
    yield "                r.eax = dest;"
    yield "                block = m.read32(r.esp);"
    yield "                r.esp += 4;"
    yield "            }"
    yield f"            {allocate:#x} => {{"
    yield "                let Some(ptr) = m.allocate_scratch(m.read32(r.esp + 8), m.read32(r.esp + 12)) else {"
    yield "                    m.unsupported = true;"
    yield "                    return 0;"
    yield "                };"
    yield "                r.eax = ptr;"
    yield "                block = m.read32(r.esp);"
    yield "                r.esp += 4;"
    yield "            }"
    yield f"            {interleave:#x} | {job:#x} => {{ m.unsupported = true; return 0; }}"
    for location, instructions in blocks.items():
        yield f"            {location:#x} => {{"
        tail = instructions[-1]
        for insn in instructions[:-1] if tail.mnemonic in TERMINATORS else instructions:
            for line in translate(insn):
                yield f"                {line}"

        if tail.mnemonic == "ret":
            if entry <= tail.address < base + DECODER_END_RVA:
                yield "                m.decoded_lengths.push(r.eax);"
            yield "                block = m.read32(r.esp);"
            cleanup = tail.operands[0].imm if tail.operands else 0
            yield f"                r.esp = r.esp.wrapping_add({4 + cleanup});"
        elif tail.mnemonic == "int3":
            yield "                m.unsupported = true;"
            yield "                return 0;"
        elif tail.mnemonic == "call" and tail.operands[0].type == X86_OP_MEM:
            slot = tail.operands[0].mem.disp
            if slot in imports:
                # The stdcall import consumes its arguments at the fixed continuation.
                num_args, method = imports[slot]
                args = ["m.read32(r.esp)"] + [f"m.read32(r.esp + {n * 4})" for n in range(1, num_args)]
                yield f"                r.eax = m.{method}({', '.join(args)});"
                yield f"                r.esp += {num_args * 4};"
                yield f"                block = {tail.address + tail.size:#x};"
            else:
                yield "                m.unsupported = true;"
                yield "                return 0;"
        else:
            fallthrough = tail.address + tail.size
            if tail.mnemonic in CONDITIONS:
                expr = CONDITIONS[tail.mnemonic]
                target = tail.operands[0].imm
                next_block = f"if {expr} {{ {target:#x} }} else {{ {fallthrough:#x} }}"
            elif tail.mnemonic == "call":
                yield "                r.esp = r.esp.wrapping_sub(4);"
                yield f"                m.write32(r.esp, {fallthrough:#x});"
                next_block = f"{tail.operands[0].imm:#x}"
            elif tail.mnemonic == "jmp":
                operand = tail.operands[0]
                next_block = (f"{operand.imm:#x}" if operand.type == X86_OP_IMM
                              else "LITERAL_TARGETS[r.edx as usize]")
            else:
                if fallthrough not in starts:
                    raise ValueError(f"missing fallthrough at {tail.address:#x}")
                next_block = f"{fallthrough:#x}"
            yield f"                block = {next_block};"
        yield "            }"
    yield '            _ => unreachable!("unknown translated block {block:#x}"),'
    yield "        }"
    yield "    }"
    yield "}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    args = parser.parse_args()
    target = Path(__file__).resolve().parent / "src" / "lifted.rs"
    try:
        image = args.executable.read_bytes()
        source = "\n".join(generate(image)) + "\n"
        from startup_lift import generate_startup
        startup = generate_startup(image)
        target.with_name("startup_lifted.rs").write_text(startup, encoding="utf-8")
        with target.open("w", encoding="utf-8", newline="\n") as output:
            output.write(source)
    except (OSError, StructError, ValueError) as error:
        parser.exit(1, f"[Error] {error}\n")
    print("Generated src/lifted.rs from 17 x86 code regions and 32 jump targets.")


if __name__ == "__main__":
    main()
