"""Compare native translated startup with original x86 under identical API fixtures."""
import argparse
from pathlib import Path
import struct
import subprocess
import hashlib
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EAX,
                              UC_X86_REG_EBP, UC_X86_REG_FS, UC_X86_REG_GDTR,
                              UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_SS, UC_X86_REG_ES)
from startup_lift import ENTRY, CHECKPOINT, PE_READY, COOKIE, IMPORTS, DIGEST
from lift import pe_sections


def original(image, initial, entropy, stop=CHECKPOINT, variant=0, previous=0xffffffff, runtime_variant=None, allocator_variant=None, locale_case=False):
    base, sections = pe_sections(image)
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(0, 0x2000000)
    pe = struct.unpack_from('<I', image, 60)[0]
    header_size = struct.unpack_from('<I', image, pe+24+60)[0]
    uc.mem_write(base, image[:header_size])
    for rva, size, offset in sections:
        uc.mem_write(base+rva, image[offset:offset+size])
    def read(addr):
        return struct.unpack('<I', uc.mem_read(addr, 4))[0]
    def write(addr, value):
        uc.mem_write(addr, struct.pack('<I', value))
    write(COOKIE, initial)
    write(COOKIE+4, 0xdeadbeef)
    # A real 32-bit FS descriptor, rather than redirecting individual opcodes.
    descriptor = struct.pack('<HHBBBB', 0xfff, 0, 1, 0x93, 0x40, 0)
    uc.mem_write(0x40008, struct.pack('<Q', 0x00cf9b000000ffff))
    uc.mem_write(0x40010, descriptor)
    uc.mem_write(0x40018, struct.pack('<Q', 0x00cf93000000ffff))
    uc.reg_write(UC_X86_REG_GDTR, (0, 0x40000, 0x1f, 0))
    uc.reg_write(UC_X86_REG_CS, 8)
    for reg in (UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
        uc.reg_write(reg, 0x18)
    uc.reg_write(UC_X86_REG_FS, 0x10)
    write(0x10000, previous)
    write(0x1359dbc, variant & 1)
    if variant == 1: write(base, 0)
    elif variant == 2: write(base+pe, 0)
    elif variant == 3: write(base+pe+24, 0x20b)
    elif variant == 4: write(base+pe+0x74, 14)
    elif variant == 5: write(base+pe+0xe8, 0x1000)
    for slot in (0x10a72ec, 0x10a72f0, 0x10a72f4): write(slot, slot)
    for addr in (0x1358c68, 0x1358c6c, 0x1358c70, 0x1358c74, 0x1358c78): write(addr, 0)
    extra_globals = (0x1358d7c, 0x1358048, 0x1358c7c, 0x1358d90, 0x1358d68,
                     0x1358d6c, 0x1358d70, 0x1358d74, 0x1358d8c)
    for addr in extra_globals: write(addr, 0)
    uc.reg_write(UC_X86_REG_ESP, 0x20000)
    start = ENTRY
    allocation_failures = 1 if runtime_variant == 20 else 0
    if allocator_variant is not None:
        start, count, size, allocation_failures, retry, handler, stop = [
            (0xf3038d, 0, 123, 0, 0, 0, 0),
            (0xf3038d, 1, 32, 1, 0, 0, 0),
            (0xf3038d, 0xffffffff, 2, 0, 0, 0, 0xf303a5),
            (0xf3038d, 1, 32, 1, 0, 1, 0xf303e3),
            (0xf22053, 2, 16, 1, 2000, 0, 0),
            (0xf22053, 2, 16, 2, 1, 0, 0),
        ][allocator_variant]
        write(0x1358c78, 0x60000)
        write(0x1358208, retry)
        write(0x1358d80, handler)
        uc.mem_write(0x80000, bytes([0xa5])*0x400)
        for n, value in enumerate((0, count, size, 0x18000)): write(0x20000 + n*4, value)
    if locale_case:
        start, stop, obj = 0xf25870, 0, 0x70000
        write(obj, 3)
        for n, offset in enumerate((0xb0, 0xb8, 0xb4, 0xc0)):
            ptr = 0x70800+n*4
            write(obj+offset, ptr); write(ptr, 42)
        for n in range(6):
            field = obj+0x50+n*16
            write(field-8, 0x1311454 if n == 0 else 0)
            write(field-4, 0 if n == 2 else 1)
            write(field, 0 if n == 1 else 0x70820+n*8)
            write(field+4, 0 if n == 3 else 0x70824+n*8)
        write(obj+0xd4, 0x70a00)
        write(0x20000, 0); write(0x20004, obj)
    thunks = {}
    for index, (slot, (name, argc)) in enumerate(IMPORTS.items()):
        thunk = slot
        write(slot, thunk)
        thunks[thunk] = (slot, name, argc)
    calls = []
    visited = set()
    tls = {}
    locks = []
    tls_allocations = []
    heap_state = {'next': 0x80000, 'attempts': 0}
    def hook(uc, pc, size, _):
        visited.add(pc)
        if pc == stop:
            uc.emu_stop()
        elif pc in thunks:
            slot, name, argc = thunks[pc]
            calls.append(slot)
            sp = uc.reg_read(UC_X86_REG_ESP)
            if name in ('GetSystemTimeAsFileTime', 'QueryPerformanceCounter'):
                ptr = read(sp+4)
                value = 0x1122334455667788 if name == 'GetSystemTimeAsFileTime' else 0x0102030405060708
                uc.mem_write(ptr, struct.pack('<Q', value))
                result = 1
            elif name == 'GetCurrentProcessId':
                result = 0x1234
            elif name == 'GetCurrentThreadId':
                result = 0x5678
            elif name == 'GetTickCount':
                result = entropy ^ 0x11223344 ^ 0x55667788 ^ 0x1234 ^ 0x5678 ^ 0x01020304 ^ 0x05060708
            elif name == 'GetStartupInfoW':
                uc.mem_write(read(sp+4), struct.pack('<I', 68) + bytes(64))
                if runtime_variant in (28,33):
                    uc.mem_write(read(sp+4)+50, struct.pack('<H', 1))
                if runtime_variant == 33: write(read(sp+4)+52, 0x18000)
                result = 0
            elif name == 'HeapSetInformation':
                if [read(sp+4+n*4) for n in range(4)] != [0, 1, 0, 0]:
                    raise RuntimeError('unexpected original heap arguments')
                result = 1
            elif name == 'HeapCreate':
                if [read(sp+4+n*4) for n in range(3)] != [0, 0x1000, 0]:
                    raise RuntimeError('unexpected original HeapCreate arguments')
                result = 0 if runtime_variant == 0 else 0x60000
            elif name == 'GetModuleHandleW':
                if bytes(uc.mem_read(read(sp+4), 26)).decode('utf-16le') != 'KERNEL32.DLL\0':
                    raise RuntimeError('unexpected module name')
                result = 0 if runtime_variant == 1 else 0x70000000
            elif name == 'GetProcAddress':
                if read(sp+4) != 0x70000000: raise RuntimeError('unexpected module handle')
                ptr = read(sp+8)
                name_bytes = bytes(uc.mem_read(ptr, 32)).split(b'\0')[0]
                index = [b'FlsAlloc', b'FlsGetValue', b'FlsSetValue', b'FlsFree'].index(name_bytes)
                mask = ((0 if runtime_variant in (9,16,18,22,27) else 15) if runtime_variant >= 8 else
                        15 if runtime_variant < 3 else 0 if runtime_variant == 3 else 15 ^ (1 << (runtime_variant-4)))
                result = 0x50000 + index*16 if mask & (1 << index) else 0
            elif name == 'TlsAlloc':
                result = (0xffffffff if runtime_variant == 10 else 7) if not tls_allocations else (0xffffffff if runtime_variant == 18 else 8)
                tls_allocations.append(result)
            elif name == 'TlsSetValue':
                if read(sp+4) not in (7,8): raise RuntimeError('unexpected original TLS index')
                result = 0 if runtime_variant == 11 else 1
                if result: tls[read(sp+4)] = read(sp+8)
            elif name in ('EncodePointer', 'DecodePointer'): result = read(sp+4) ^ 0xa5a55a5a
            elif name == 'FlsAlloc':
                if read(sp+4) != 0xf22d03: raise RuntimeError('unexpected FLS cleanup callback')
                result = 0xffffffff if runtime_variant == 17 else 9
            elif name == 'FlsSetValue':
                if read(sp+4) != 9: raise RuntimeError('unexpected FLS slot')
                result = 0 if runtime_variant == 23 else 1
                if result: tls[9] = read(sp+8)
            elif name == 'InterlockedIncrement':
                ptr = read(sp+4)
                result = (read(ptr)+1)&0xffffffff
                write(ptr, result)
            elif name in ('EnterCriticalSection', 'LeaveCriticalSection'):
                ptr = read(sp+4)
                if ptr not in locks: raise RuntimeError('original lock is uninitialized')
                delta = 1 if name == 'EnterCriticalSection' else -1
                if delta < 0 and read(ptr+8) == 0: raise RuntimeError('unbalanced original lock')
                write(ptr+4, (read(ptr+4)+delta)&0xffffffff)
                write(ptr+8, (read(ptr+8)+delta)&0xffffffff)
                write(ptr+12, 0x5678 if read(ptr+8) else 0)
                result = 0
            elif name == 'HeapAlloc':
                if (read(sp+4), read(sp+8)) != (0x60000, 8): raise RuntimeError('unexpected original HeapAlloc arguments')
                heap_state['attempts'] += 1
                result = 0
                if heap_state['attempts'] > allocation_failures and not (runtime_variant == 25 and heap_state['attempts'] == 2):
                    result = heap_state['next']
                    size = read(sp+12)
                    if result + size > 0x100000: raise RuntimeError('original heap arena exhausted')
                    uc.mem_write(result, bytes(size))
                    heap_state['next'] = (result+size+15)&~15
            elif name == 'Sleep': result = 0
            elif name == 'GetStdHandle':
                selector = read(sp+4)
                index = [0xfffffff6, 0xfffffff5, 0xfffffff4].index(selector)
                result = 0 if runtime_variant == 29 else 0xffffffff if runtime_variant == 30 else 0x90000+index*4
            elif name == 'GetFileType':
                index = [0x90000,0x90004,0x90008].index(read(sp+4))
                result = 0 if runtime_variant == 31 else [2,3,1][index]
            elif name == 'SetHandleCount':
                if read(sp+4) != 32: raise RuntimeError('unexpected handle count')
                result = 32
            elif name == 'InitializeCriticalSectionAndSpinCount':
                ptr = read(sp+4)
                if read(sp+8) != 4000: raise RuntimeError('unexpected original lock spin count')
                locks.append(ptr)
                fail = 1 if runtime_variant == 13 else 7 if runtime_variant == 14 else 15 if runtime_variant == 32 else -1
                result = int(len(locks) != fail)
                if result: uc.mem_write(ptr, struct.pack('<6I', 0, 0xffffffff, 0, 0, 0, 4000))
            else:
                raise RuntimeError(f'unimplemented original fixture {name}')
            uc.reg_write(UC_X86_REG_EAX, result)
            uc.reg_write(UC_X86_REG_EIP, read(sp))
            uc.reg_write(UC_X86_REG_ESP, sp+4+argc*4)
    uc.hook_add(UC_HOOK_CODE, hook)
    uc.emu_start(start, 0x1ffffff, count=4096)
    if uc.reg_read(UC_X86_REG_EIP) != stop:
        raise RuntimeError('original x86 failed to reach checkpoint within budget')
    if stop == CHECKPOINT:
        return (read(COOKIE), read(COOKIE+4), uc.reg_read(UC_X86_REG_ESP), calls), visited
    if allocator_variant is not None:
        return (uc.reg_read(UC_X86_REG_EAX), uc.reg_read(UC_X86_REG_ESP), read(0x18000),
                heap_state['next'], heap_state['attempts'], bytes(uc.mem_read(0x80000, 0x400)).hex(), calls), visited
    if locale_case:
        return (uc.reg_read(UC_X86_REG_EAX), uc.reg_read(UC_X86_REG_ESP), bytes(uc.mem_read(0x70000, 0x1000)).hex(), calls), visited
    if runtime_variant is not None:
        state = [uc.reg_read(UC_X86_REG_EAX)] + [read(addr) for addr in (0x1358c78, 0x1358c68, 0x1358c6c, 0x1358c70, 0x1358c74, 0x1310ef4)] + [tls.get(7, 0)] + [read(addr) for addr in extra_globals] + [read(0x1310ef0), heap_state['next'], heap_state['attempts'], tls.get(8, tls.get(9, 0)), read(0x10000), read(0x1359ca0), read(0x1359c88)]
        lock_state = bytes(uc.mem_read(0x1310d90, 36*8) + uc.mem_read(0x13580b8, 36*24)).hex()
        thread_state = bytes(uc.mem_read(0x80000, 0x214)+uc.mem_read(0x1310f30, 0x770)).hex()
        return (uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), state, calls, lock_state, thread_state, bytes(uc.mem_read(0x80220, 0x800)).hex()), visited
    return (uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), read(0x10000),
            bytes(uc.mem_read(0x1ff70, 0x90)).hex(), calls), visited


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('executable', type=Path)
    parser.add_argument('--native', type=Path, default=Path('target/release/warframe-u51-decoder-recomp.exe'))
    args = parser.parse_args()
    image = args.executable.read_bytes()
    if hashlib.sha256(image).hexdigest() != DIGEST:
        raise RuntimeError('reference executable hash mismatch')
    output = subprocess.check_output([str(args.native.resolve()), '.', '--startup'], text=True)
    cases, frame_cases, runtime_cases, allocator_cases, locale_cases, visited = 0, 0, 0, 0, 0, set()
    for line in output.splitlines():
        if line.startswith('STARTUP_LOCALE_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            expected, trace = original(image, 0xbb40e64e, 0x12345678, locale_case=True)
            actual = (int(fields['eax'],16), int(fields['stack'],16), fields['data'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'locale mismatch: actual={actual}; original={expected}')
            visited.update(trace); locale_cases += 1
            print('STARTUP_LOCALE_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_ALLOCATOR_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            variant = int(fields['variant'])
            expected, trace = original(image, 0xbb40e64e, 0x12345678, allocator_variant=variant)
            actual = tuple(int(fields[key], 16) for key in ('eax', 'stack', 'error', 'next')) + (int(fields['attempts']), fields['heap'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'allocator mismatch variant={variant}; actual={actual}; original={expected}')
            visited.update(trace)
            allocator_cases += 1
            print(f'STARTUP_ALLOCATOR_READY variant={variant} eax={actual[0]:08x} attempts={actual[4]} original-x86=MATCH')
            continue
        if line.startswith('STARTUP_RUNTIME_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop, variant = (int(fields[key], 16) for key in ('stop', 'variant'))
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=variant)
            actual = tuple(int(fields[key], 16) for key in ('stack', 'frame')) + tuple([int(x,16) for x in fields[key].split(',') if x] for key in ('state', 'calls')) + (fields['locks'], fields['thread'], fields['files'])
            if actual != expected: raise RuntimeError(f'runtime mismatch: {line}; original={expected}')
            visited.update(trace)
            runtime_cases += 1
            print(f'STARTUP_RUNTIME_READY variant={variant} stop={stop:08x} eax={actual[2][0]:08x} calls={len(actual[3])} original-x86=MATCH')
            continue
        if line.startswith('STARTUP_FRAME_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop, variant, previous = (int(fields[key], 16) for key in ('stop', 'variant', 'previous'))
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop, variant, previous)
            actual = tuple(int(fields[key], 16) for key in ('stack', 'frame', 'head')) + (fields['snapshot'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected:
                raise RuntimeError(f'frame mismatch: {line}; original={expected}')
            visited.update(trace)
            frame_cases += 1
            print(f'STARTUP_FRAME_READY stop={stop:08x} variant={variant} stack={actual[0]:08x} frame={actual[1]:08x} head={actual[2]:08x} original-x86=MATCH')
            continue
        if not line.startswith('STARTUP_COOKIE_READY '):
            continue
        fields = dict(item.split('=') for item in line.split()[1:])
        initial, entropy = (int(fields[key], 16) for key in ('initial', 'entropy'))
        expected, trace = original(image, initial, entropy)
        visited.update(trace)
        actual = tuple(int(fields[key], 16) for key in ('cookie', 'complement', 'stack')) + ([int(x, 16) for x in fields['calls'].split(',') if x],)
        if actual != expected:
            raise RuntimeError(f'x86 mismatch: {line}; original={expected}')
        cases += 1
        print(line + ' original-x86=MATCH')
    if cases != 6:
        raise RuntimeError(f'expected six comparison cases, got {cases}')
    if frame_cases != 12:
        raise RuntimeError(f'expected twelve frame cases, got {frame_cases}')
    if runtime_cases != 34: raise RuntimeError(f'expected 34 runtime cases, got {runtime_cases}')
    if allocator_cases != 6: raise RuntimeError(f'expected six allocator cases, got {allocator_cases}')
    if locale_cases != 1: raise RuntimeError(f'expected one locale case, got {locale_cases}')
    from startup_lift import discover, RANGES, STOPS
    code = discover(image, ENTRY, RANGES, STOPS, IMPORTS)
    missing = set(code)-visited
    if missing:
        raise RuntimeError(f'unexercised instructions: {sorted(missing)}')
    print(f'PASS: {cases} cookie, {frame_cases} frame, {runtime_cases} runtime, {allocator_cases} allocator, {locale_cases} locale original-x86 comparisons; all {len(code)} reachable instructions exercised.')

if __name__ == '__main__':
    main()
