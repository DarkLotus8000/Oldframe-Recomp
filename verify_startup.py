"""Compare native translated startup with original x86 under identical API fixtures."""
import argparse
from pathlib import Path
import struct
import subprocess
import hashlib
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EAX,
                              UC_X86_REG_EBP, UC_X86_REG_ECX, UC_X86_REG_FS, UC_X86_REG_GDTR,
                              UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_SS, UC_X86_REG_ES)
from startup_lift import ENTRY, CHECKPOINT, PE_READY, COOKIE, IMPORTS, CDECL_IMPORTS, DIGEST
from lift import pe_sections


def original(image, initial, entropy, stop=CHECKPOINT, variant=0, previous=0xffffffff, runtime_variant=None, allocator_variant=None, locale_case=False, environment_variant=None, argv_case=False, envp_case=False, cinit_case=False, preinitializer_case=False, atexit_case=False, constructor_case=False, constructor_two_case=False, constructor_three_case=False, constructor_four_case=False, constructor_eight_case=False, constructor_nine_case=False, constructor_twelve_case=False, constructor_twenty_two_case=False, constructor_twenty_two_seed=0, constructor_twenty_four_case=False, constructor_twenty_five_case=False, constructor_thirty_two_case=False, constructor_thirty_three_case=False, constructor_thirty_seven_case=False, constructor_forty_one_case=False, constructor_forty_three_case=False, constructor_forty_four_case=False, constructor_forty_five_case=False, constructor_forty_six_case=False, constructor_forty_seven_case=False, constructor_forty_eight_case=False, constructor_forty_nine_case=False, constructor_fifty_case=False, constructor_fifty_one_case=False, constructor_fifty_two_case=False, constructor_fifty_three_case=False, constructor_fifty_five_case=False, constructor_fifty_six_case=False, constructor_fifty_seven_case=False, constructor_fifty_eight_case=False, constructor_fifty_nine_case=False, constructor_sixty_case=False, constructor_sixty_one_case=False, constructor_sixty_two_case=False, constructor_sixty_five_case=False, constructor_seventy_three_case=False, constructor_seventy_four_case=False, constructor_eighty_seven_case=False, constructor_ninety_one_case=False, constructor_ninety_two_case=False, constructor_one_hundred_two_case=False, constructor_one_hundred_ten_case=False, constructor_one_hundred_eleven_case=False, constructor_one_hundred_sixteen_case=False, constructor_one_hundred_seventeen_case=False, constructor_one_hundred_twenty_eight_case=False, constructor_one_hundred_twenty_nine_case=False, constructor_one_hundred_thirty_case=False, constructor_one_hundred_thirty_one_case=False, constructor_one_hundred_thirty_seven_case=False, constructor_one_hundred_forty_three_case=False, constructor_one_hundred_forty_four_case=False, constructor_one_hundred_forty_five_case=False, constructor_one_hundred_forty_six_case=False, constructor_one_hundred_forty_seven_case=False, constructor_one_hundred_forty_eight_case=False, constructor_one_hundred_fifty_case=False, constructor_one_hundred_fifty_four_case=False, constructor_one_hundred_fifty_six_case=False, constructor_one_hundred_sixty_four_case=False, constructor_one_hundred_sixty_eight_case=False, constructor_one_hundred_seventy_eight_case=False, constructor_one_hundred_eighty_five_case=False, constructor_one_hundred_eighty_seven_case=False, constructor_two_hundred_twenty_nine_case=False, constructor_two_hundred_thirty_three_case=False, constructor_two_hundred_sixty_seven_case=False, constructor_two_hundred_sixty_eight_case=False, constructor_two_hundred_eighty_four_case=False, constructor_three_hundred_five_case=False, constructor_three_hundred_twenty_one_case=False, constructor_three_hundred_twenty_six_case=False, constructor_three_hundred_thirty_six_case=False, constructor_three_hundred_forty_case=False, constructor_three_hundred_forty_five_case=False):
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
    uc.mem_write(0x18000, b'Warframe.exe -language:ru -fullscreen:0\0')
    uc.mem_write(0x18100, 'A=B\0LANG=ru\0\0'.encode('utf-16le'))
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
        if slot == 0x41d560:
            continue
        thunk = slot
        write(slot, thunk)
        thunks[thunk] = (slot, name, argc)
    calls = []
    visited = set()
    tls = {}
    locks = []
    tls_allocations = []
    heap_state = {'next': 0x80000, 'attempts': 0}
    if constructor_twenty_two_seed:
        # Match the native fixture and force the two-byte-at-a-time name
        # comparison to continue past its first pair.
        write(0x1316920, 0x70000)
        write(0x70004, 0x70100)
        write(0x70038, 0)
        uc.mem_write(0x70100, b'SysX\0' if constructor_twenty_two_seed == 1 else b'Sys\0')
    if constructor_forty_five_case == 2:
        write(0x131c364, 1)
        write(0x131c360, 0x10ba030)
    if constructor_fifty_seven_case == 2:
        uc.mem_write(0x131b234, b'\x01')
        write(0x131b1f0, 0x80000); write(0x131b1f4, 0x80000); write(0x131b1f8, 0x80004)
    if constructor_sixty_case == 2:
        uc.mem_write(0x131b234, b'\x01')
        write(0x131b1f0, 0x80000); write(0x131b1f4, 0x80000); write(0x131b1f8, 0x80008)
    if constructor_one_hundred_forty_five_case or constructor_one_hundred_forty_six_case or constructor_one_hundred_forty_seven_case or constructor_one_hundred_forty_eight_case or constructor_one_hundred_fifty_case or constructor_one_hundred_fifty_four_case or constructor_one_hundred_fifty_six_case or constructor_one_hundred_sixty_four_case or constructor_one_hundred_sixty_eight_case or constructor_one_hundred_seventy_eight_case or constructor_one_hundred_eighty_five_case or constructor_one_hundred_eighty_seven_case or constructor_two_hundred_twenty_nine_case or constructor_two_hundred_thirty_three_case or constructor_two_hundred_sixty_seven_case or constructor_two_hundred_sixty_eight_case or constructor_two_hundred_eighty_four_case or constructor_three_hundred_five_case or constructor_three_hundred_twenty_one_case or constructor_three_hundred_twenty_six_case or constructor_three_hundred_thirty_six_case or constructor_three_hundred_forty_case or constructor_three_hundred_forty_five_case:
        write(0x1317f10, 1)
        write(0x1317f18, 42)
    def hook(uc, pc, size, _):
        visited.add(pc)
        if pc == stop:
            uc.emu_stop()
        elif pc == 0x41d560:
            calls.append(pc)
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
                module = read(sp+4)
                ptr = read(sp+8)
                name_bytes = bytes(uc.mem_read(ptr, 32)).split(b'\0')[0]
                index = [b'FlsAlloc', b'FlsGetValue', b'FlsSetValue', b'FlsFree', b'GetFinalPathNameByHandleW'].index(name_bytes)
                if (index == 4 and module != 0x90000) or (index != 4 and module != 0x70000000):
                    raise RuntimeError('unexpected module handle')
                mask = ((0 if runtime_variant in (9,16,18,22,27) else 15) if runtime_variant >= 8 else
                        15 if runtime_variant < 3 else 0 if runtime_variant == 3 else 15 ^ (1 << (runtime_variant-4)))
                result = 0x50000 + index*16 if index == 4 or mask & (1 << index) else 0
            elif name == 'TlsAlloc':
                result = (0xffffffff if runtime_variant == 10 else 7) if not tls_allocations else (0xffffffff if runtime_variant == 18 else 8)
                tls_allocations.append(result)
            elif name == 'TlsSetValue':
                if read(sp+4) not in (7,8): raise RuntimeError('unexpected original TLS index')
                result = 0 if runtime_variant == 11 else 1
                if result: tls[read(sp+4)] = read(sp+8)
            elif name in ('EncodePointer', 'DecodePointer'): result = read(sp+4) ^ 0xa5a55a5a
            elif name == 'security_cookie_check':
                if uc.reg_read(UC_X86_REG_ECX) != read(COOKIE): raise RuntimeError('original security cookie mismatch')
                result = uc.reg_read(UC_X86_REG_ECX)
            elif name == 'concat_small_string':
                destination_obj, source_obj, suffix = read(sp+4), read(sp+8), read(sp+12)
                source_ptr, source_len = read(source_obj), read(source_obj+4)
                suffix_bytes = bytes(uc.mem_read(suffix, 256)).split(b'\0')[0]
                data = bytes(uc.mem_read(source_ptr, source_len)) + suffix_bytes
                destination = destination_obj+12
                if len(data) > 15:
                    destination = heap_state['next']; heap_state['next'] = (destination+len(data)+1+15)&~15
                write(destination_obj, destination); write(destination_obj+4, len(data)); write(destination_obj+8, len(data) if len(data)>15 else 15)
                uc.mem_write(destination, data+b'\0'); result = destination_obj
            elif name == 'concat_two_strings':
                destination_obj, left_obj, right_obj = read(sp+4), read(sp+8), read(sp+12)
                left_ptr, left_len = read(left_obj), read(left_obj+4)
                right_ptr, right_len = read(right_obj), read(right_obj+4)
                data = bytes(uc.mem_read(left_ptr, left_len)) + bytes(uc.mem_read(right_ptr, right_len))
                destination = destination_obj+12
                if len(data) > 15:
                    destination = heap_state['next']; heap_state['next'] = (destination+len(data)+1+15)&~15
                write(destination_obj, destination); write(destination_obj+4, len(data)); write(destination_obj+8, len(data) if len(data)>15 else 15)
                uc.mem_write(destination, data+b'\0'); result = destination_obj
            elif name == 'copy_small_string':
                obj, source = uc.reg_read(UC_X86_REG_ECX), read(sp+4)
                source_ptr, length = read(source), read(source+4)
                destination = obj+12
                if length > 15:
                    destination = heap_state['next']; heap_state['next'] = (destination+length+1+15)&~15
                write(obj, destination); write(obj+4, length); write(obj+8, length if length > 15 else 15)
                uc.mem_write(destination, bytes(uc.mem_read(source_ptr, length+1)))
                result = obj
            elif name == 'game_free':
                if read(sp+4) != 0x128cad0: raise RuntimeError('unexpected original game-free descriptor')
                result = 0
            elif name == 'inline_small_string':
                obj, source = uc.reg_read(UC_X86_REG_ECX), read(sp+4)
                data = bytes(uc.mem_read(source, 256))
                length = data.index(0)
                destination = obj+12
                if length > 15:
                    destination = heap_state['next']
                    heap_state['next'] = (destination+length+1+15)&~15
                write(obj, destination); write(obj+4, length); write(obj+8, length if length > 15 else 15)
                uc.mem_write(destination, data[:length+1])
                result = obj
            elif name == 'memset':
                destination, value, count = read(sp+4), read(sp+8) & 0xff, read(sp+12)
                uc.mem_write(destination, bytes([value]) * count)
                result = destination
            elif name == 'FlsAlloc':
                if read(sp+4) != 0xf22d03: raise RuntimeError('unexpected FLS cleanup callback')
                result = 0xffffffff if runtime_variant == 17 else 9
            elif name == 'FlsSetValue':
                if read(sp+4) != 9: raise RuntimeError('unexpected FLS slot')
                result = 0 if runtime_variant == 23 else 1
                if result: tls[9] = read(sp+8)
            elif name == 'assertion_predicate':
                if read(sp+4) != 0x12940b4: raise RuntimeError('unexpected original registry assertion descriptor')
                result = 0
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
                flags = read(sp+8)
                if read(sp+4) != 0x60000 or flags not in (0, 8): raise RuntimeError('unexpected original HeapAlloc arguments')
                heap_state['attempts'] += 1
                result = 0
                if heap_state['attempts'] > allocation_failures and not (runtime_variant == 25 and heap_state['attempts'] == 2):
                    result = heap_state['next']
                    size = read(sp+12)
                    if result + size > 0x100000: raise RuntimeError('original heap arena exhausted')
                    if flags & 8: uc.mem_write(result, bytes(size))
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
            elif name == 'GetCommandLineA': result = 0x18000
            elif name == 'GetEnvironmentStringsW': result = 0 if environment_variant == 1 else 0x18100
            elif name == 'WideCharToMultiByte':
                args = [read(sp+4+n*4) for n in range(8)]
                if args[:4] != [0,0,0x18100,13] or args[6:] != [0,0]:
                    raise RuntimeError(f'unexpected original WideCharToMultiByte arguments {args}')
                converted = b'A=B\0LANG=ru\0\0'
                result = 0 if environment_variant == 2 else len(converted)
                if result and args[4]: uc.mem_write(args[4], converted)
            elif name == 'FreeEnvironmentStringsW':
                if read(sp+4) != 0x18100: raise RuntimeError('unexpected original environment token')
                result = 1
            elif name == 'GetModuleFileNameA':
                if [read(sp+4+n*4) for n in range(3)] != [0,0x1358b60,0x104]:
                    raise RuntimeError('unexpected original GetModuleFileNameA arguments')
                uc.mem_write(0x1358b60, b'Warframe.exe\0')
                result = 12
            elif name == 'initialize_ctype':
                write(0x1359dac, 1)
                result = 0
            elif name == 'isleadbyte': result = 0
            elif name == 'strlen':
                ptr = read(sp+4)
                result = bytes(uc.mem_read(ptr, 0x1000)).index(0)
            elif name == 'copy_s':
                destination, size, source = [read(sp+4+n*4) for n in range(3)]
                source_bytes = bytes(uc.mem_read(source, size))
                length = source_bytes.index(0) + 1
                uc.mem_write(destination, source_bytes[:length])
                result = 0
            elif name == 'free': result = 0
            elif name == 'is_nonwritable_image_pointer':
                if read(sp+4) != 0x1210d58: raise RuntimeError('unexpected image-pointer slot')
                result = 1
            elif name == 'raw_dll_main':
                if read(sp+4) != 1: raise RuntimeError('unexpected raw DLL reason')
                result = 0
            elif name == 'IsProcessorFeaturePresent':
                if read(sp+4) != 10: raise RuntimeError('unexpected processor feature')
                result = 1
            elif name == 'SetUnhandledExceptionFilter':
                if read(sp+4) != 0xf222e1: raise RuntimeError('unexpected exception filter')
                result = 0
            elif name == 'allocation_size':
                if not read(sp+4): raise RuntimeError('unexpected null allocation')
                result = 128
            elif name == 'reallocate':
                old, size = read(sp+4), read(sp+8)
                if size != 256: raise RuntimeError(f'unexpected original atexit growth size {size}')
                result = heap_state['next']
                uc.mem_write(result, bytes(uc.mem_read(old, 128)) + bytes(size-128))
                heap_state['next'] = (result+size+15)&~15
            elif name == 'game_allocate':
                descriptor, size, count = read(sp+4), read(sp+8), read(sp+12)
                if descriptor not in (0x128f238, 0x129a4c8, 0x12a18a8) or count != 1 or not size or (descriptor == 0x129a4c8 and size != 8) or (descriptor == 0x12a18a8 and size != 0x30):
                    raise RuntimeError(f'unexpected original game allocation {[descriptor, size, count]}')
                result = 0 if descriptor == 0x129a4c8 and (constructor_one_hundred_thirty_one_case == 2 or constructor_one_hundred_thirty_seven_case == 2 or constructor_one_hundred_forty_three_case == 2 or constructor_one_hundred_forty_four_case == 2 or constructor_one_hundred_fifty_case == 2) else heap_state['next']
                total = size * count
                if result:
                    uc.mem_write(result, bytes(total))
                    heap_state['next'] = (result+total+15)&~15
            elif name == 'load_library_w':
                if read(sp+4) != 0x10abd8c: raise RuntimeError('unexpected original library name')
                result = 0x90000
            elif name == 'copy_bounded':
                destination, capacity, source = [read(sp+4+n*4) for n in range(3)]
                if not capacity:
                    result = 0
                else:
                    data = bytes(uc.mem_read(source, capacity)).split(b'\0', 1)[0][:capacity-1]
                    uc.mem_write(destination, data+b'\0')
                    result = len(data)
            elif name == 'lower_bound_empty':
                output, begin, end = [read(sp+4+n*4) for n in range(3)]
                key = read(read(sp+16))
                low, high = 0, (end-begin)//4
                def object_key(obj):
                    first = bytes(uc.mem_read(read(obj+4), 256)).split(b'\0',1)[0]
                    second = bytes(uc.mem_read(read(obj+8), 256)).split(b'\0',1)[0]
                    return first, second
                wanted = object_key(key)
                while low < high:
                    mid = low + (high-low)//2
                    if object_key(read(begin+mid*4)) < wanted: low = mid+1
                    else: high = mid
                write(output, begin+low*4)
                result = output
            elif name == 'vector_insert_ptr':
                vector = uc.reg_read(UC_X86_REG_ECX)
                position, count, source = [read(sp+4+n*4) for n in range(3)]
                begin, end, capacity = read(vector), read(vector+4), read(vector+8)
                if vector != read(0x131c580) or position < begin or position > end or (position-begin)%4 or count != 1 or end+4 > capacity or not begin:
                    raise RuntimeError(f'unexpected original registry-vector insertion {[vector, position, count, source]}')
                tail = bytes(uc.mem_read(position, end-position))
                uc.mem_write(position+4, tail)
                write(position, read(source)); write(vector+4, end+4)
                result = 0
            elif name == 'manager_register':
                manager = uc.reg_read(UC_X86_REG_ECX)
                obj, name_ptr = read(sp+4), read(sp+8)
                if manager != read(0x131ad88) or obj not in (0x131ad98, 0x131ae20, 0x131aec0, 0x131af48) or name_ptr not in (0x10b0a38, 0x10b07d4):
                    raise RuntimeError(f'unexpected original manager registration {[manager, obj, name_ptr]}')
                item, cursor = read(manager), read(manager+4)
                existing = 0
                while item < cursor:
                    node = read(item)
                    if read(node+0x14) == name_ptr:
                        existing = node
                        break
                    item += 4
                if existing:
                    write(obj+0x10, existing)
                else:
                    node = heap_state['next']
                    uc.mem_write(node, bytes(0x20))
                    write(node+0x14, name_ptr); write(node+0x1c, 0xffffffff)
                    cursor = read(manager+4)
                    if not cursor or cursor+4 > read(manager+8):
                        raise RuntimeError('original manager vector was not initialized')
                    write(cursor, node); write(manager+4, cursor+4); write(obj+0x10, node)
                    heap_state['next'] = (node+0x20+15)&~15
                result = 0
            elif name == 'vector_insert_u32':
                vector = uc.reg_read(UC_X86_REG_ECX)
                position, count, source = read(sp+4), read(sp+8), read(sp+12)
                begin, end, capacity = read(vector), read(vector+4), read(vector+8)
                if vector != 0x131b1f0 or position != end or count != 1 or end != capacity:
                    raise RuntimeError(f'unexpected original singleton vector insertion {[vector, position, count, source]}')
                existing = 0 if not begin else (end-begin)//4
                if existing > 1: raise RuntimeError(f'unexpected original singleton vector length {existing}')
                result = heap_state['next']
                if existing: uc.mem_write(result, bytes(uc.mem_read(begin, existing*4)))
                write(result+existing*4, read(source)); write(vector, result); write(vector+4, result+(existing+1)*4); write(vector+8, result+(existing+1)*4)
                heap_state['next'] = (result+(existing+1)*4+15)&~15
            elif name == 'vector_insert_u8':
                vector = uc.reg_read(UC_X86_REG_ECX)
                position, count, source = read(sp+4), read(sp+8), read(sp+12)
                begin, end, capacity = read(vector), read(vector+4), read(vector+8)
                if vector not in (0x131c2ac, 0x131c2c4) or position != begin or count != 1 or begin != end or end != capacity:
                    raise RuntimeError(f'unexpected original byte-vector insertion {[vector, position, count, source]}')
                result = heap_state['next']
                uc.mem_write(result, bytes(uc.mem_read(source, 1)))
                write(vector, result); write(vector+4, result+1); write(vector+8, result+1)
                heap_state['next'] = (result+1+15)&~15
            elif name == 'strrchr':
                ptr, needle = read(sp+4), read(sp+8) & 0xff
                value = bytes(uc.mem_read(ptr, 0x1000)).split(b'\0')[0]
                offset = value.rfind(bytes([needle]))
                result = ptr + offset if offset >= 0 else 0
            elif name == 'string_pool_init': result = 0x131a960
            elif name == 'intern_string': result = read(sp+4)
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
            uc.reg_write(UC_X86_REG_ESP, sp+4+(0 if slot in CDECL_IMPORTS else argc*4))
    uc.hook_add(UC_HOOK_CODE, hook)
    uc.emu_start(start, 0x1ffffff, count=131072)
    if uc.reg_read(UC_X86_REG_EIP) != stop:
        raise RuntimeError(f'original x86 failed to reach checkpoint within budget: eip={uc.reg_read(UC_X86_REG_EIP):#x} stop={stop:#x}')
    if stop == CHECKPOINT:
        return (read(COOKIE), read(COOKIE+4), uc.reg_read(UC_X86_REG_ESP), calls), visited
    if allocator_variant is not None:
        return (uc.reg_read(UC_X86_REG_EAX), uc.reg_read(UC_X86_REG_ESP), read(0x18000),
                heap_state['next'], heap_state['attempts'], bytes(uc.mem_read(0x80000, 0x400)).hex(), calls), visited
    if locale_case:
        return (uc.reg_read(UC_X86_REG_EAX), uc.reg_read(UC_X86_REG_ESP), bytes(uc.mem_read(0x70000, 0x1000)).hex(), calls), visited
    if environment_variant is not None:
        environment = read(0x1358030)
        data = bytes(uc.mem_read(environment, 13)).hex() if environment else ''
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX), read(0x1359db8), environment,
                 heap_state['next'], data, calls), visited)
    if argv_case:
        argc, argv = read(0x135806c), read(0x1358070)
        pointers = [read(argv+index*4) for index in range(argc+1)]
        data = bytes(uc.mem_read(argv, heap_state['next']-argv)).hex()
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX), argc, argv, heap_state['next'],
                 pointers, data, calls), visited)
    if constructor_three_hundred_forty_five_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 heap_state['next'], bytes(uc.mem_read(0x13240c0, 0x1e0)).hex(),
                 bytes(uc.mem_read(0x80000, heap_state['next']-0x80000)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_three_hundred_forty_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 heap_state['next'], bytes(uc.mem_read(0x1324028, 0x98)).hex(),
                 bytes(uc.mem_read(0x80000, heap_state['next']-0x80000)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_three_hundred_thirty_six_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 heap_state['next'], bytes(uc.mem_read(0x1323720, 0x690)).hex(),
                 bytes(uc.mem_read(0x80000, heap_state['next']-0x80000)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_three_hundred_twenty_six_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 bytes(uc.mem_read(0x129ff7c, 0xa4)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_three_hundred_twenty_one_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 heap_state['next'], bytes(uc.mem_read(0x1322e5c, 0x8c0)).hex(),
                 bytes(uc.mem_read(0x80000, heap_state['next']-0x80000)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_three_hundred_five_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 heap_state['next'], bytes(uc.mem_read(0x13223d8, 0xa80)).hex(),
                 bytes(uc.mem_read(0x80000, heap_state['next']-0x80000)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_two_hundred_eighty_four_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        registry_object = read(0x131c580)
        registry = [read(registry_object+n*4) for n in range(3)]
        registry_data = bytes(uc.mem_read(registry[0], registry[1]-registry[0])).hex()
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 heap_state['next'], registry_object, registry, registry_data, bytes(uc.mem_read(0x13220c8, 0x30c)).hex(),
                 bytes(uc.mem_read(0x80000, heap_state['next']-0x80000)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_two_hundred_sixty_eight_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        registry = [read(0x131c580+n*4) for n in range(3)]
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 heap_state['next'], registry, bytes(uc.mem_read(0x13220c8, 0x2c)).hex(),
                 bytes(uc.mem_read(0x80000, heap_state['next']-0x80000)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_two_hundred_sixty_seven_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 bytes(uc.mem_read(0x131f0a0, 0x3018)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_two_hundred_thirty_three_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 bytes(uc.mem_read(0x131ed24, 0x378)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_two_hundred_twenty_nine_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 bytes(uc.mem_read(0x131ed24, 0x1d0)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_one_hundred_eighty_seven_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 bytes(uc.mem_read(0x131ed28, 0x128)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_one_hundred_eighty_five_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 heap_state['next'], bytes(uc.mem_read(0x131e978, 0x3b0)).hex(),
                 bytes(uc.mem_read(0x80000, heap_state['next']-0x80000)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_one_hundred_seventy_eight_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 bytes(uc.mem_read(0x131e400, 0x578)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_one_hundred_sixty_eight_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 heap_state['next'], bytes(uc.mem_read(0x131def8, 0x1e0)).hex(),
                 bytes(uc.mem_read(0x80000, heap_state['next']-0x80000)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_one_hundred_sixty_four_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 bytes(uc.mem_read(0x131d9e8, 0x4f0)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_one_hundred_fifty_six_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 heap_state['next'], bytes(uc.mem_read(0x131d99c, 0x48)).hex(),
                 bytes(uc.mem_read(0x80000, heap_state['next']-0x80000)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_one_hundred_fifty_four_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 bytes(uc.mem_read(0x131d738, 0x260)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_one_hundred_fifty_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 heap_state['next'], bytes(uc.mem_read(0x131d5f0, 0x144)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_one_hundred_forty_eight_case:
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 read(0x131d6e0), calls), visited)
    if constructor_one_hundred_forty_seven_case:
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 heap_state['next'], bytes(uc.mem_read(0x131d5f0, 0x28)).hex(),
                 bytes(uc.mem_read(0x80000, heap_state['next']-0x80000)).hex(), calls), visited)
    if constructor_one_hundred_forty_six_case:
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 heap_state['next'], bytes(uc.mem_read(0x131d5f0, 0x24)).hex(),
                 bytes(uc.mem_read(0x80000, heap_state['next']-0x80000)).hex(), calls), visited)
    if constructor_one_hundred_forty_five_case:
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 bytes(uc.mem_read(0x131d5f0, 9)).hex(), calls), visited)
    if constructor_one_hundred_forty_four_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 heap_state['next'], bytes(uc.mem_read(0x131d17c, 0x474)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_one_hundred_forty_three_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 heap_state['next'], bytes(uc.mem_read(0x131d17c, 0x44c)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_one_hundred_thirty_seven_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 heap_state['next'], bytes(uc.mem_read(0x131d048, 0x1e8)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_one_hundred_thirty_one_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        callback_ptr = read(0x131d044)
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 heap_state['next'], bytes(uc.mem_read(0x131d020, 0x28)).hex(),
                 bytes(uc.mem_read(callback_ptr, 8)).hex(), bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_one_hundred_thirty_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        string_ptr, string_len = read(0x131d004), read(0x131d008)
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 heap_state['next'], bytes(uc.mem_read(0x131cffc, 0x18)).hex(),
                 bytes(uc.mem_read(string_ptr, string_len+1)).hex(), bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_one_hundred_twenty_nine_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        string_ptr, string_len = read(0x131cfe0), read(0x131cfe4)
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 heap_state['next'], bytes(uc.mem_read(0x131cfd8, 0x18)).hex(),
                 bytes(uc.mem_read(string_ptr, string_len+1)).hex(), bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_one_hundred_twenty_eight_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 bytes(uc.mem_read(0x131cad0, 0x508)).hex(), bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_one_hundred_seventeen_case:
        tail_start = max(heap_state['next']-128, 0x80000)
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 heap_state['next'], tail_start, bytes(uc.mem_read(0x131ca94, 0x3c)).hex(),
                 bytes(uc.mem_read(tail_start, heap_state['next']-tail_start)).hex(), calls), visited)
    if constructor_one_hundred_sixteen_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 bytes(uc.mem_read(0x131c7c8, 0x2cc)).hex(), bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_one_hundred_eleven_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        string_ptr, string_len = read(0x131c564), read(0x131c568)
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 heap_state['next'], bytes(uc.mem_read(0x131c55c, 0x18)).hex(),
                 bytes(uc.mem_read(string_ptr, string_len+1)).hex(), bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_one_hundred_ten_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        object_ptr = read(0x131c524)
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 heap_state['next'], bytes(uc.mem_read(0x131c4d4, 0x8c)).hex(),
                 bytes(uc.mem_read(0x1293e24, 0x10)).hex(), bytes(uc.mem_read(object_ptr, 24)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_one_hundred_two_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        string_ptr, string_len = read(0x131c4a8), read(0x131c4ac)
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 heap_state['next'], bytes(uc.mem_read(0x131c2e4, 0x1f0)).hex(),
                 bytes(uc.mem_read(string_ptr, string_len+1)).hex(), bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_ninety_two_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        first, second = read(0x131c2ac), read(0x131c2c4)
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 heap_state['next'], read(0x128d970), bytes(uc.mem_read(0x131c198, 0x14c)).hex(),
                 bytes(uc.mem_read(first, 1) + uc.mem_read(second, 1)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_ninety_one_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 bytes(uc.mem_read(0x131be38, 0x360)).hex(), bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_eighty_seven_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        string_ptr = read(0x131ba9c)
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 heap_state['next'], read(0x128d970), bytes(uc.mem_read(0x131b878, 0x5c0)).hex(),
                 bytes(uc.mem_read(string_ptr, 24)).hex(), bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_seventy_four_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 read(0x128d96c), read(0x128d970), bytes(uc.mem_read(0x131b808, 0x70)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_seventy_three_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 bytes(uc.mem_read(0x131b358, 0x4b0)).hex(), bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_sixty_five_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 bytes(uc.mem_read(0x131b26c, 0xe4)).hex(), bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_sixty_two_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 bytes(uc.mem_read(0x131b25c, 0x10)).hex(), bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_sixty_one_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EAX),
                 bytes(uc.mem_read(0x131b24c, 0x10)).hex(), bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_sixty_case:
        vector = read(0x131b1f0)
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX), heap_state['next'], read(0x128fbb0),
                 bytes(uc.mem_read(0x131b1e0, 0x50)).hex(),
                 bytes(uc.mem_read(vector, read(0x131b1f4)-vector)).hex(), calls), visited)
    if constructor_fifty_nine_case:
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX), bytes(uc.mem_read(0x131b23c, 0x10)).hex(), calls), visited)
    if constructor_fifty_eight_case:
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX), read(0x131b238), calls), visited)
    if constructor_fifty_seven_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX), heap_state['next'], read(0x80000),
                 bytes(uc.mem_read(0x131b1e0, 0x50)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_fifty_six_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX), read(0x131b1c8), read(0x128d970),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_fifty_five_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_fifty_three_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX), read(0x131b1b8), read(0x131b1bc),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_fifty_two_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX),
                 bytes(uc.mem_read(0x131aff8, 0x19c)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_fifty_one_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX), heap_state['next'],
                 bytes(uc.mem_read(0x128eb94, 12)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_fifty_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        shared = read(0x131ad88)
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX), shared, heap_state['next'],
                 bytes(uc.mem_read(0x131af48, 0x98)).hex(),
                 bytes(uc.mem_read(shared, heap_state['next']-shared)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_forty_nine_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        shared = read(0x131ad88)
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX), shared, heap_state['next'],
                 bytes(uc.mem_read(0x131aec0, 0x88)).hex(),
                 bytes(uc.mem_read(shared, heap_state['next']-shared)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_forty_eight_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        shared = read(0x131ad88)
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX), shared, heap_state['next'],
                 bytes(uc.mem_read(0x131ae20, 0xa0)).hex(),
                 bytes(uc.mem_read(shared, heap_state['next']-shared)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_forty_seven_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX), read(0x131ad88), heap_state['next'],
                 bytes(uc.mem_read(0x131ad98, 0x88)).hex(),
                 bytes(uc.mem_read(read(0x131ad88), heap_state['next']-read(0x131ad88))).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_forty_six_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX), read(0x131acb0),
                 bytes(uc.mem_read(0x80000, 0x1c)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_forty_five_case:
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX), read(0x131c360),
                 bytes(uc.mem_read(0x131ac9c, 20)).hex(), calls), visited)
    if constructor_forty_four_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX),
                 bytes(uc.mem_read(0x131ac80, 20)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_forty_three_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX), read(0x128d96c),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_forty_one_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX),
                 bytes(uc.mem_read(0x131a958, 0x1d0)).hex(),
                 bytes(uc.mem_read(0x128d594, 8)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_thirty_seven_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX),
                 bytes(uc.mem_read(0x131a024, 0x58)).hex(),
                 read(0x131a950), read(0x131a9e0), read(0x131a954),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_thirty_three_case:
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX), read(0x1317f3c),
                 read(0x1317f38), calls), visited)
    if constructor_thirty_two_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX),
                 bytes(uc.mem_read(0x1316d7c, 16)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_twenty_five_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX),
                 bytes(uc.mem_read(0x1316bc0, 0x1a5)).hex(),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_twenty_four_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX),
                 bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if constructor_twenty_two_case:
        begin = read(0x1359da8) ^ 0xa5a55a5a
        end = read(0x1359da4) ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX), read(0x1316920),
                 bytes(uc.mem_read(0x1316924,0x268)).hex(),
                 bytes(uc.mem_read(begin,end-begin)).hex(), calls), visited)
    if constructor_twelve_case:
        begin = read(0x1359da8) ^ 0xa5a55a5a
        end = read(0x1359da4) ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX), bytes(uc.mem_read(0x1316618,0x30c)).hex(),
                 bytes(uc.mem_read(begin,end-begin)).hex(), calls), visited)
    if constructor_nine_case:
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX), bytes(uc.mem_read(0x13165d0,0x40)).hex(), calls), visited)
    if constructor_eight_case:
        begin = read(0x1359da8) ^ 0xa5a55a5a
        end = read(0x1359da4) ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX), bytes(uc.mem_read(0x13163e0,0x1f0)).hex(),
                 bytes(uc.mem_read(begin,end-begin)).hex(), calls), visited)
    if constructor_four_case:
        begin = read(0x1359da8) ^ 0xa5a55a5a
        end = read(0x1359da4) ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX), read(0x131a9e0),
                 bytes(uc.mem_read(0x1316358,0x84)).hex(),
                 bytes(uc.mem_read(begin,end-begin)).hex(), calls), visited)
    if constructor_three_case:
        begin = read(0x1359da8) ^ 0xa5a55a5a
        end = read(0x1359da4) ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX), bytes(uc.mem_read(0x1316344,13)).hex(),
                 bytes(uc.mem_read(begin,end-begin)).hex(), calls), visited)
    if constructor_two_case:
        begin = read(0x1359da8) ^ 0xa5a55a5a
        end = read(0x1359da4) ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX), bytes(uc.mem_read(0x1316334,13)).hex(),
                 bytes(uc.mem_read(begin,end-begin)).hex(), calls), visited)
    if constructor_case:
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX), read(0x128b0fc), read(0x10a9cc8),
                 read(0x1316330), calls), visited)
    if atexit_case:
        encoded_begin, encoded_end = read(0x1359da8), read(0x1359da4)
        begin, end = encoded_begin ^ 0xa5a55a5a, encoded_end ^ 0xa5a55a5a
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX), begin, end, encoded_begin,
                 encoded_end, bytes(uc.mem_read(begin, end-begin)).hex(), calls), visited)
    if preinitializer_case:
        fields = [read(addr) for addr in (0x135ade0,0x1359dc0,0x1359da8,0x1359da4,
                  0x1358040,0x1358044,0x1359c84,0x1359c7c,0x1359dac)]
        table, count = fields[1], fields[0]
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX), heap_state['next'], fields,
                 bytes(uc.mem_read(table, count*4)).hex(), calls), visited)
    if cinit_case:
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX),
                 [read(0x1310ef8 + index*4) for index in range(10)], calls), visited)
    if envp_case:
        envp = read(0x1358078)
        pointers = [read(envp+index*4) for index in range(3)]
        data = bytes(uc.mem_read(envp, heap_state['next']-envp)).hex()
        return ((uc.reg_read(UC_X86_REG_ESP), uc.reg_read(UC_X86_REG_EBP),
                 uc.reg_read(UC_X86_REG_EAX), envp, read(0x1359da0),
                 heap_state['next'], pointers, data, calls), visited)
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
    cases, frame_cases, runtime_cases, allocator_cases, locale_cases, environment_cases, argv_cases, envp_cases, cinit_cases, preinitializer_cases, atexit_cases, constructor_cases, constructor_two_cases, constructor_three_cases, constructor_four_cases, constructor_eight_cases, constructor_nine_cases, constructor_twelve_cases, constructor_twenty_two_cases, constructor_twenty_four_cases, constructor_twenty_five_cases, constructor_thirty_two_cases, constructor_thirty_three_cases, constructor_thirty_seven_cases, constructor_forty_one_cases, constructor_forty_three_cases, constructor_forty_four_cases, constructor_forty_five_cases, constructor_forty_six_cases, constructor_forty_seven_cases, constructor_forty_eight_cases, constructor_forty_nine_cases, constructor_fifty_cases, constructor_fifty_one_cases, constructor_fifty_two_cases, constructor_fifty_three_cases, constructor_fifty_five_cases, constructor_fifty_six_cases, constructor_fifty_seven_cases, constructor_fifty_eight_cases, constructor_fifty_nine_cases, constructor_sixty_cases, constructor_sixty_one_cases, constructor_sixty_two_cases, constructor_sixty_five_cases, constructor_seventy_three_cases, constructor_seventy_four_cases, constructor_eighty_seven_cases, constructor_ninety_one_cases, constructor_ninety_two_cases, constructor_one_hundred_two_cases, constructor_one_hundred_ten_cases, constructor_one_hundred_eleven_cases, constructor_one_hundred_sixteen_cases, constructor_one_hundred_seventeen_cases, constructor_one_hundred_twenty_eight_cases, constructor_one_hundred_twenty_nine_cases, constructor_one_hundred_thirty_cases, constructor_one_hundred_thirty_one_cases, constructor_one_hundred_thirty_seven_cases, constructor_one_hundred_forty_three_cases, constructor_one_hundred_forty_four_cases, constructor_one_hundred_forty_five_cases, constructor_one_hundred_forty_six_cases, constructor_one_hundred_forty_seven_cases, constructor_one_hundred_forty_eight_cases, constructor_one_hundred_fifty_cases, constructor_one_hundred_fifty_four_cases, constructor_one_hundred_fifty_six_cases, constructor_one_hundred_sixty_four_cases, constructor_one_hundred_sixty_eight_cases, constructor_one_hundred_seventy_eight_cases, constructor_one_hundred_eighty_five_cases, constructor_one_hundred_eighty_seven_cases, constructor_two_hundred_twenty_nine_cases, constructor_two_hundred_thirty_three_cases, constructor_two_hundred_sixty_seven_cases, constructor_two_hundred_sixty_eight_cases, constructor_two_hundred_eighty_four_cases, constructor_three_hundred_five_cases, constructor_three_hundred_twenty_one_cases, constructor_three_hundred_twenty_six_cases, constructor_three_hundred_thirty_six_cases, constructor_three_hundred_forty_cases, constructor_three_hundred_forty_five_cases, visited = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, set()
    for line in output.splitlines():
        if line.startswith('STARTUP_CONSTRUCTOR_345_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_three_hundred_forty_five_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next')) + (fields['state'], fields['heap'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor three-hundred-forty-five mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_three_hundred_forty_five_cases += 1; print('STARTUP_CONSTRUCTOR_345_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_340_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_three_hundred_forty_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next')) + (fields['state'], fields['heap'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor three-hundred-forty mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_three_hundred_forty_cases += 1; print('STARTUP_CONSTRUCTOR_340_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_336_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_three_hundred_thirty_six_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next')) + (fields['state'], fields['heap'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor three-hundred-thirty-six mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_three_hundred_thirty_six_cases += 1; print('STARTUP_CONSTRUCTOR_336_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_326_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_three_hundred_twenty_six_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['state'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor three-hundred-twenty-six mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_three_hundred_twenty_six_cases += 1; print('STARTUP_CONSTRUCTOR_326_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_321_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_three_hundred_twenty_one_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next')) + (fields['state'], fields['heap'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor three-hundred-twenty-one mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_three_hundred_twenty_one_cases += 1; print('STARTUP_CONSTRUCTOR_321_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_305_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_three_hundred_five_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next')) + (fields['state'], fields['heap'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor three-hundred-five mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_three_hundred_five_cases += 1; print('STARTUP_CONSTRUCTOR_305_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_284_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_two_hundred_eighty_four_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next','registry_object')) + ([int(x,16) for x in fields['registry'].split(',')], fields['registry_data'], fields['state'], fields['heap'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor two-hundred-eighty-four mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_two_hundred_eighty_four_cases += 1; print('STARTUP_CONSTRUCTOR_284_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_268_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_two_hundred_sixty_eight_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next')) + ([int(x,16) for x in fields['registry'].split(',')], fields['state'], fields['heap'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor two-hundred-sixty-eight mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_two_hundred_sixty_eight_cases += 1; print('STARTUP_CONSTRUCTOR_268_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_267_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_two_hundred_sixty_seven_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['state'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor two-hundred-sixty-seven mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_two_hundred_sixty_seven_cases += 1; print('STARTUP_CONSTRUCTOR_267_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_233_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_two_hundred_thirty_three_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['state'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor two-hundred-thirty-three mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_two_hundred_thirty_three_cases += 1; print('STARTUP_CONSTRUCTOR_233_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_229_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_two_hundred_twenty_nine_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['state'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor two-hundred-twenty-nine mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_two_hundred_twenty_nine_cases += 1; print('STARTUP_CONSTRUCTOR_229_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_187_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_one_hundred_eighty_seven_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['state'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor one-hundred-eighty-seven mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_one_hundred_eighty_seven_cases += 1; print('STARTUP_CONSTRUCTOR_187_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_185_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_one_hundred_eighty_five_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next')) + (fields['state'], fields['heap'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor one-hundred-eighty-five mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_one_hundred_eighty_five_cases += 1; print('STARTUP_CONSTRUCTOR_185_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_178_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_one_hundred_seventy_eight_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['state'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor one-hundred-seventy-eight mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_one_hundred_seventy_eight_cases += 1; print('STARTUP_CONSTRUCTOR_178_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_168_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_one_hundred_sixty_eight_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next')) + (fields['state'], fields['heap'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor one-hundred-sixty-eight mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_one_hundred_sixty_eight_cases += 1; print('STARTUP_CONSTRUCTOR_168_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_164_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_one_hundred_sixty_four_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['state'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor one-hundred-sixty-four mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_one_hundred_sixty_four_cases += 1; print('STARTUP_CONSTRUCTOR_164_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_156_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_one_hundred_fifty_six_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next')) + (fields['state'], fields['heap'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor one-hundred-fifty-six mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_one_hundred_fifty_six_cases += 1; print('STARTUP_CONSTRUCTOR_156_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_154_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_one_hundred_fifty_four_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['state'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor one-hundred-fifty-four mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_one_hundred_fifty_four_cases += 1; print('STARTUP_CONSTRUCTOR_154_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_150_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16); variant = int(fields['variant'])
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_one_hundred_fifty_case=variant+1)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next')) + (fields['state'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor one-hundred-fifty mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_one_hundred_fifty_cases += 1; print('STARTUP_CONSTRUCTOR_150_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_148_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_one_hundred_forty_eight_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','value')) + ([int(x,16) for x in fields['calls'].split(',') if x],)
            if actual != expected: raise RuntimeError(f'constructor one-hundred-forty-eight mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_one_hundred_forty_eight_cases += 1; print('STARTUP_CONSTRUCTOR_148_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_147_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_one_hundred_forty_seven_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next')) + (fields['state'], fields['heap'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor one-hundred-forty-seven mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_one_hundred_forty_seven_cases += 1; print('STARTUP_CONSTRUCTOR_147_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_146_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_one_hundred_forty_six_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next')) + (fields['state'], fields['heap'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor one-hundred-forty-six mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_one_hundred_forty_six_cases += 1; print('STARTUP_CONSTRUCTOR_146_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_145_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_one_hundred_forty_five_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['state'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor one-hundred-forty-five mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_one_hundred_forty_five_cases += 1; print('STARTUP_CONSTRUCTOR_145_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_144_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16); variant = int(fields['variant'])
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_one_hundred_forty_four_case=variant+1)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next')) + (fields['state'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor one-hundred-forty-four mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_one_hundred_forty_four_cases += 1; print('STARTUP_CONSTRUCTOR_144_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_143_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16); variant = int(fields['variant'])
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_one_hundred_forty_three_case=variant+1)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next')) + (fields['state'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor one-hundred-forty-three mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_one_hundred_forty_three_cases += 1; print('STARTUP_CONSTRUCTOR_143_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_137_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16); variant = int(fields['variant'])
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_one_hundred_thirty_seven_case=variant+1)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next')) + (fields['state'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor one-hundred-thirty-seven mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_one_hundred_thirty_seven_cases += 1; print('STARTUP_CONSTRUCTOR_137_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_131_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            variant = int(fields['variant'])
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_one_hundred_thirty_one_case=variant+1)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next')) + (fields['object'], fields['callback'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor one-hundred-thirty-one mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_one_hundred_thirty_one_cases += 1; print('STARTUP_CONSTRUCTOR_131_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_130_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_one_hundred_thirty_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next')) + (fields['object'], fields['string'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor one-hundred-thirty mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_one_hundred_thirty_cases += 1; print('STARTUP_CONSTRUCTOR_130_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_129_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_one_hundred_twenty_nine_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next')) + (fields['object'], fields['string'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor one-hundred-twenty-nine mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_one_hundred_twenty_nine_cases += 1; print('STARTUP_CONSTRUCTOR_129_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_128_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_one_hundred_twenty_eight_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['state'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor one-hundred-twenty-eight mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_one_hundred_twenty_eight_cases += 1; print('STARTUP_CONSTRUCTOR_128_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_117_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_one_hundred_seventeen_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next','tail_start')) + (fields['object'], fields['heap_tail'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor one-hundred-seventeen mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_one_hundred_seventeen_cases += 1; print('STARTUP_CONSTRUCTOR_117_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_116_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_one_hundred_sixteen_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['state'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor one-hundred-sixteen mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_one_hundred_sixteen_cases += 1; print('STARTUP_CONSTRUCTOR_116_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_111_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_one_hundred_eleven_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next')) + (fields['state'], fields['string'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor one-hundred-eleven mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_one_hundred_eleven_cases += 1; print('STARTUP_CONSTRUCTOR_111_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_110_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_one_hundred_ten_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next')) + (fields['state'], fields['globals'], fields['object'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor one-hundred-ten mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_one_hundred_ten_cases += 1; print('STARTUP_CONSTRUCTOR_110_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_102_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_one_hundred_two_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next')) + (fields['state'], fields['string'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor one-hundred-two mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_one_hundred_two_cases += 1; print('STARTUP_CONSTRUCTOR_102_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_092_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_ninety_two_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next','counter')) + (fields['object'], fields['items'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor ninety-two mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_ninety_two_cases += 1; print('STARTUP_CONSTRUCTOR_092_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_091_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_ninety_one_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['state'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor ninety-one mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_ninety_one_cases += 1; print('STARTUP_CONSTRUCTOR_091_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_087_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_eighty_seven_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next','counter')) + (fields['state'], fields['string'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor eighty-seven mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_eighty_seven_cases += 1; print('STARTUP_CONSTRUCTOR_087_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_074_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_seventy_four_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','count_a','count_b')) + (fields['object'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor seventy-four mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_seventy_four_cases += 1; print('STARTUP_CONSTRUCTOR_074_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_073_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_seventy_three_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['objects'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor seventy-three mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_seventy_three_cases += 1; print('STARTUP_CONSTRUCTOR_073_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_065_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_sixty_five_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['objects'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor sixty-five mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_sixty_five_cases += 1; print('STARTUP_CONSTRUCTOR_065_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_062_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_sixty_two_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['object'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor sixty-two mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_sixty_two_cases += 1; print('STARTUP_CONSTRUCTOR_062_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_061_READY '):
            fields = dict(item.split('=') for item in line.split()[1:]); stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_sixty_one_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['object'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor sixty-one mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_sixty_one_cases += 1; print('STARTUP_CONSTRUCTOR_061_READY original-x86=MATCH'); continue
        if line.startswith('STARTUP_CONSTRUCTOR_060_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            variant = int(fields['variant'])
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_sixty_case=variant+1)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next','object')) + (fields['singleton'], fields['items'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor sixty mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_sixty_cases += 1
            print('STARTUP_CONSTRUCTOR_060_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_059_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_fifty_nine_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['object'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor fifty-nine mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_fifty_nine_cases += 1
            print('STARTUP_CONSTRUCTOR_059_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_058_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_fifty_eight_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','value')) + ([int(x,16) for x in fields['calls'].split(',') if x],)
            if actual != expected: raise RuntimeError(f'constructor fifty-eight mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_fifty_eight_cases += 1
            print('STARTUP_CONSTRUCTOR_058_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_057_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            variant = int(fields['variant'])
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_fifty_seven_case=variant+1)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next','item')) + (fields['singleton'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor fifty-seven mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_fifty_seven_cases += 1
            print('STARTUP_CONSTRUCTOR_057_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_056_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_fifty_six_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','object','counter')) + (fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor fifty-six mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_fifty_six_cases += 1
            print('STARTUP_CONSTRUCTOR_056_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_055_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_fifty_five_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor fifty-five mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_fifty_five_cases += 1
            print('STARTUP_CONSTRUCTOR_055_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_053_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_fifty_three_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','module','function')) + (fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor fifty-three mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_fifty_three_cases += 1
            print('STARTUP_CONSTRUCTOR_053_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_052_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_fifty_two_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['object'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor fifty-two mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_fifty_two_cases += 1
            print('STARTUP_CONSTRUCTOR_052_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_051_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_fifty_one_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next')) + (fields['vector'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor fifty-one mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_fifty_one_cases += 1
            print('STARTUP_CONSTRUCTOR_051_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_050_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_fifty_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','shared','next')) + (fields['object'], fields['manager'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor fifty mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_fifty_cases += 1
            print('STARTUP_CONSTRUCTOR_050_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_049_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_forty_nine_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','shared','next')) + (fields['object'], fields['manager'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor forty-nine mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_forty_nine_cases += 1
            print('STARTUP_CONSTRUCTOR_049_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_048_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_forty_eight_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','shared','next')) + (fields['object'], fields['manager'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor forty-eight mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_forty_eight_cases += 1
            print('STARTUP_CONSTRUCTOR_048_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_047_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_forty_seven_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','shared','next')) + (fields['object'], fields['manager'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor forty-seven mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_forty_seven_cases += 1
            print('STARTUP_CONSTRUCTOR_047_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_046_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_forty_six_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','pointer')) + (fields['object'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor forty-six mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_forty_six_cases += 1
            print('STARTUP_CONSTRUCTOR_046_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_045_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            variant = int(fields['variant'])
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_forty_five_case=variant + 1)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','source')) + (fields['object'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor forty-five mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_forty_five_cases += 1
            print('STARTUP_CONSTRUCTOR_045_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_044_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_forty_four_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['object'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor forty-four mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_forty_four_cases += 1
            print('STARTUP_CONSTRUCTOR_044_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_043_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_forty_three_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','counter')) + (fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor forty-three mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_forty_three_cases += 1
            print('STARTUP_CONSTRUCTOR_043_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_041_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_forty_one_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['objects'], fields['scalars'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor forty-one mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_forty_one_cases += 1
            print('STARTUP_CONSTRUCTOR_041_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_037_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_thirty_seven_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['digest'],) + tuple(int(fields[key],16) for key in ('scalar','pool','interned')) + (fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor thirty-seven mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_thirty_seven_cases += 1
            print('STARTUP_CONSTRUCTOR_037_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_033_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_thirty_three_case=True)
            timer = fields['timer']
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (int(timer[:8],16), int(timer[8:],16), [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor thirty-three mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_thirty_three_cases += 1
            print('STARTUP_CONSTRUCTOR_033_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_032_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_thirty_two_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['globals'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor thirty-two mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_thirty_two_cases += 1
            print('STARTUP_CONSTRUCTOR_032_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_025_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_twenty_five_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['object'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor twenty-five mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_twenty_five_cases += 1
            print('STARTUP_CONSTRUCTOR_025_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_024_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_twenty_four_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor twenty-four mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_twenty_four_cases += 1
            print('STARTUP_CONSTRUCTOR_024_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_022_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            variant = int(fields['variant'])
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_twenty_two_case=True, constructor_twenty_two_seed=variant)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','head')) + (fields['objects'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor twenty-two mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_twenty_two_cases += 1
            print('STARTUP_CONSTRUCTOR_022_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_012_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_twelve_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['objects'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor twelve mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_twelve_cases += 1
            print('STARTUP_CONSTRUCTOR_012_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_009_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_nine_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['object'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor nine mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_nine_cases += 1
            print('STARTUP_CONSTRUCTOR_009_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_008_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_eight_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['objects'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor eight mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_eight_cases += 1
            print('STARTUP_CONSTRUCTOR_008_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_004_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_four_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','pool')) + (fields['object'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor four mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_four_cases += 1
            print('STARTUP_CONSTRUCTOR_004_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_003_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_three_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['object'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor three mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_three_cases += 1
            print('STARTUP_CONSTRUCTOR_003_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_002_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_two_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + (fields['object'], fields['callbacks'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'constructor two mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_two_cases += 1
            print('STARTUP_CONSTRUCTOR_002_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CONSTRUCTOR_001_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, constructor_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','lhs','rhs','result')) + ([int(x,16) for x in fields['calls'].split(',') if x],)
            if actual != expected: raise RuntimeError(f'constructor mismatch: actual={actual}; original={expected}')
            visited.update(trace); constructor_cases += 1
            print('STARTUP_CONSTRUCTOR_001_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_ATEXIT_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, atexit_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','begin','end','encoded_begin','encoded_end')) + (fields['data'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'atexit mismatch: actual={actual}; original={expected}')
            visited.update(trace); atexit_cases += 1
            print('STARTUP_ATEXIT_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_PREINITIALIZERS_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, preinitializer_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','next')) + ([int(x,16) for x in fields['fields'].split(',') if x], fields['data'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'preinitializer mismatch: actual={actual}; original={expected}')
            visited.update(trace); preinitializer_cases += 1
            print('STARTUP_PREINITIALIZERS_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_CINIT_POINTERS_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, cinit_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax')) + ([int(x,16) for x in fields['pointers'].split(',') if x], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'cinit pointer mismatch: actual={actual}; original={expected}')
            visited.update(trace); cinit_cases += 1
            print('STARTUP_CINIT_POINTERS_READY original-x86=MATCH')
            continue
        if line.startswith('STARTUP_ENVP_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, envp_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','envp','initialized','next')) + ([int(x,16) for x in fields['pointers'].split(',') if x], fields['data'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'envp mismatch: actual={actual}; original={expected}')
            visited.update(trace); envp_cases += 1
            print(f'STARTUP_ENVP_READY envp={actual[3]:08x} original-x86=MATCH')
            continue
        if line.startswith('STARTUP_ARGV_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, argv_case=True)
            actual = tuple(int(fields[key],16) for key in ('stack','frame','eax','argc','argv','next')) + ([int(x,16) for x in fields['pointers'].split(',') if x], fields['data'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'argv mismatch: actual={actual}; original={expected}')
            visited.update(trace); argv_cases += 1
            print(f'STARTUP_ARGV_READY argc={actual[3]} argv={actual[4]:08x} original-x86=MATCH')
            continue
        if line.startswith('STARTUP_ENVIRONMENT_READY '):
            fields = dict(item.split('=') for item in line.split()[1:])
            variant = int(fields['variant'], 16)
            stop = int(fields['stop'], 16)
            expected, trace = original(image, 0xbb40e64e, 0x12345678, stop=stop, runtime_variant=34, environment_variant=variant)
            actual = tuple(int(fields[key], 16) for key in ('stack','frame','eax','command','environment','next')) + (fields['data'], [int(x,16) for x in fields['calls'].split(',') if x])
            if actual != expected: raise RuntimeError(f'environment mismatch variant={variant}; actual={actual}; original={expected}')
            visited.update(trace); environment_cases += 1
            print(f'STARTUP_ENVIRONMENT_READY variant={variant} environment={actual[4]:08x} original-x86=MATCH')
            continue
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
    if environment_cases != 2: raise RuntimeError(f'expected two environment cases, got {environment_cases}')
    if argv_cases != 1: raise RuntimeError(f'expected one argv case, got {argv_cases}')
    if envp_cases != 1: raise RuntimeError(f'expected one envp case, got {envp_cases}')
    if cinit_cases != 1: raise RuntimeError(f'expected one cinit case, got {cinit_cases}')
    if preinitializer_cases != 1: raise RuntimeError(f'expected one preinitializer case, got {preinitializer_cases}')
    if atexit_cases != 1: raise RuntimeError(f'expected one atexit case, got {atexit_cases}')
    if constructor_cases != 1: raise RuntimeError(f'expected one constructor case, got {constructor_cases}')
    if constructor_two_cases != 1: raise RuntimeError(f'expected one constructor two case, got {constructor_two_cases}')
    if constructor_three_cases != 1: raise RuntimeError(f'expected one constructor three case, got {constructor_three_cases}')
    if constructor_four_cases != 1: raise RuntimeError(f'expected one constructor four case, got {constructor_four_cases}')
    if constructor_eight_cases != 1: raise RuntimeError(f'expected one constructor eight case, got {constructor_eight_cases}')
    if constructor_nine_cases != 1: raise RuntimeError(f'expected one constructor nine case, got {constructor_nine_cases}')
    if constructor_twelve_cases != 1: raise RuntimeError(f'expected one constructor twelve case, got {constructor_twelve_cases}')
    if constructor_twenty_two_cases != 3: raise RuntimeError(f'expected three constructor twenty-two cases, got {constructor_twenty_two_cases}')
    if constructor_twenty_four_cases != 1: raise RuntimeError(f'expected one constructor twenty-four case, got {constructor_twenty_four_cases}')
    if constructor_twenty_five_cases != 1: raise RuntimeError(f'expected one constructor twenty-five case, got {constructor_twenty_five_cases}')
    if constructor_thirty_two_cases != 1: raise RuntimeError(f'expected one constructor thirty-two case, got {constructor_thirty_two_cases}')
    if constructor_thirty_three_cases != 1: raise RuntimeError(f'expected one constructor thirty-three case, got {constructor_thirty_three_cases}')
    if constructor_thirty_seven_cases != 1: raise RuntimeError(f'expected one constructor thirty-seven case, got {constructor_thirty_seven_cases}')
    if constructor_forty_one_cases != 1: raise RuntimeError(f'expected one constructor forty-one case, got {constructor_forty_one_cases}')
    if constructor_forty_three_cases != 1: raise RuntimeError(f'expected one constructor forty-three case, got {constructor_forty_three_cases}')
    if constructor_forty_four_cases != 1: raise RuntimeError(f'expected one constructor forty-four case, got {constructor_forty_four_cases}')
    if constructor_forty_five_cases != 2: raise RuntimeError(f'expected two constructor forty-five cases, got {constructor_forty_five_cases}')
    if constructor_forty_six_cases != 1: raise RuntimeError(f'expected one constructor forty-six case, got {constructor_forty_six_cases}')
    if constructor_forty_seven_cases != 1: raise RuntimeError(f'expected one constructor forty-seven case, got {constructor_forty_seven_cases}')
    if constructor_forty_eight_cases != 1: raise RuntimeError(f'expected one constructor forty-eight case, got {constructor_forty_eight_cases}')
    if constructor_forty_nine_cases != 1: raise RuntimeError(f'expected one constructor forty-nine case, got {constructor_forty_nine_cases}')
    if constructor_fifty_cases != 1: raise RuntimeError(f'expected one constructor fifty case, got {constructor_fifty_cases}')
    if constructor_fifty_one_cases != 1: raise RuntimeError(f'expected one constructor fifty-one case, got {constructor_fifty_one_cases}')
    if constructor_fifty_two_cases != 1: raise RuntimeError(f'expected one constructor fifty-two case, got {constructor_fifty_two_cases}')
    if constructor_fifty_three_cases != 1: raise RuntimeError(f'expected one constructor fifty-three case, got {constructor_fifty_three_cases}')
    if constructor_fifty_five_cases != 1: raise RuntimeError(f'expected one constructor fifty-five case, got {constructor_fifty_five_cases}')
    if constructor_fifty_six_cases != 1: raise RuntimeError(f'expected one constructor fifty-six case, got {constructor_fifty_six_cases}')
    if constructor_fifty_seven_cases != 2: raise RuntimeError(f'expected two constructor fifty-seven cases, got {constructor_fifty_seven_cases}')
    if constructor_fifty_eight_cases != 1: raise RuntimeError(f'expected one constructor fifty-eight case, got {constructor_fifty_eight_cases}')
    if constructor_fifty_nine_cases != 1: raise RuntimeError(f'expected one constructor fifty-nine case, got {constructor_fifty_nine_cases}')
    if constructor_sixty_cases != 2: raise RuntimeError(f'expected two constructor sixty cases, got {constructor_sixty_cases}')
    if constructor_sixty_one_cases != 1: raise RuntimeError(f'expected one constructor sixty-one case, got {constructor_sixty_one_cases}')
    if constructor_sixty_two_cases != 1: raise RuntimeError(f'expected one constructor sixty-two case, got {constructor_sixty_two_cases}')
    if constructor_sixty_five_cases != 1: raise RuntimeError(f'expected one constructor sixty-five case, got {constructor_sixty_five_cases}')
    if constructor_seventy_three_cases != 1: raise RuntimeError(f'expected one constructor seventy-three case, got {constructor_seventy_three_cases}')
    if constructor_seventy_four_cases != 1: raise RuntimeError(f'expected one constructor seventy-four case, got {constructor_seventy_four_cases}')
    if constructor_eighty_seven_cases != 1: raise RuntimeError(f'expected one constructor eighty-seven case, got {constructor_eighty_seven_cases}')
    if constructor_ninety_one_cases != 1: raise RuntimeError(f'expected one constructor ninety-one case, got {constructor_ninety_one_cases}')
    if constructor_ninety_two_cases != 1: raise RuntimeError(f'expected one constructor ninety-two case, got {constructor_ninety_two_cases}')
    if constructor_one_hundred_two_cases != 1: raise RuntimeError(f'expected one constructor one-hundred-two case, got {constructor_one_hundred_two_cases}')
    if constructor_one_hundred_ten_cases != 1: raise RuntimeError(f'expected one constructor one-hundred-ten case, got {constructor_one_hundred_ten_cases}')
    if constructor_one_hundred_eleven_cases != 1: raise RuntimeError(f'expected one constructor one-hundred-eleven case, got {constructor_one_hundred_eleven_cases}')
    if constructor_one_hundred_sixteen_cases != 1: raise RuntimeError(f'expected one constructor one-hundred-sixteen case, got {constructor_one_hundred_sixteen_cases}')
    if constructor_one_hundred_seventeen_cases != 1: raise RuntimeError(f'expected one constructor one-hundred-seventeen case, got {constructor_one_hundred_seventeen_cases}')
    if constructor_one_hundred_twenty_eight_cases != 1: raise RuntimeError(f'expected one constructor one-hundred-twenty-eight case, got {constructor_one_hundred_twenty_eight_cases}')
    if constructor_one_hundred_twenty_nine_cases != 1: raise RuntimeError(f'expected one constructor one-hundred-twenty-nine case, got {constructor_one_hundred_twenty_nine_cases}')
    if constructor_one_hundred_thirty_cases != 1: raise RuntimeError(f'expected one constructor one-hundred-thirty case, got {constructor_one_hundred_thirty_cases}')
    if constructor_one_hundred_thirty_one_cases != 2: raise RuntimeError(f'expected two constructor one-hundred-thirty-one cases, got {constructor_one_hundred_thirty_one_cases}')
    if constructor_one_hundred_thirty_seven_cases != 2: raise RuntimeError(f'expected two constructor one-hundred-thirty-seven cases, got {constructor_one_hundred_thirty_seven_cases}')
    if constructor_one_hundred_forty_three_cases != 2: raise RuntimeError(f'expected two constructor one-hundred-forty-three cases, got {constructor_one_hundred_forty_three_cases}')
    if constructor_one_hundred_forty_four_cases != 2: raise RuntimeError(f'expected two constructor one-hundred-forty-four cases, got {constructor_one_hundred_forty_four_cases}')
    if constructor_one_hundred_forty_five_cases != 1: raise RuntimeError(f'expected one constructor one-hundred-forty-five case, got {constructor_one_hundred_forty_five_cases}')
    if constructor_one_hundred_forty_six_cases != 1: raise RuntimeError(f'expected one constructor one-hundred-forty-six case, got {constructor_one_hundred_forty_six_cases}')
    if constructor_one_hundred_forty_seven_cases != 1: raise RuntimeError(f'expected one constructor one-hundred-forty-seven case, got {constructor_one_hundred_forty_seven_cases}')
    if constructor_one_hundred_forty_eight_cases != 1: raise RuntimeError(f'expected one constructor one-hundred-forty-eight case, got {constructor_one_hundred_forty_eight_cases}')
    if constructor_one_hundred_fifty_cases != 2: raise RuntimeError(f'expected two constructor one-hundred-fifty cases, got {constructor_one_hundred_fifty_cases}')
    if constructor_one_hundred_fifty_four_cases != 1: raise RuntimeError(f'expected one constructor one-hundred-fifty-four case, got {constructor_one_hundred_fifty_four_cases}')
    if constructor_one_hundred_fifty_six_cases != 1: raise RuntimeError(f'expected one constructor one-hundred-fifty-six case, got {constructor_one_hundred_fifty_six_cases}')
    if constructor_one_hundred_sixty_four_cases != 1: raise RuntimeError(f'expected one constructor one-hundred-sixty-four case, got {constructor_one_hundred_sixty_four_cases}')
    if constructor_one_hundred_sixty_eight_cases != 1: raise RuntimeError(f'expected one constructor one-hundred-sixty-eight case, got {constructor_one_hundred_sixty_eight_cases}')
    if constructor_one_hundred_seventy_eight_cases != 1: raise RuntimeError(f'expected one constructor one-hundred-seventy-eight case, got {constructor_one_hundred_seventy_eight_cases}')
    if constructor_one_hundred_eighty_five_cases != 1: raise RuntimeError(f'expected one constructor one-hundred-eighty-five case, got {constructor_one_hundred_eighty_five_cases}')
    if constructor_one_hundred_eighty_seven_cases != 1: raise RuntimeError(f'expected one constructor one-hundred-eighty-seven case, got {constructor_one_hundred_eighty_seven_cases}')
    if constructor_two_hundred_twenty_nine_cases != 1: raise RuntimeError(f'expected one constructor two-hundred-twenty-nine case, got {constructor_two_hundred_twenty_nine_cases}')
    if constructor_two_hundred_thirty_three_cases != 1: raise RuntimeError(f'expected one constructor two-hundred-thirty-three case, got {constructor_two_hundred_thirty_three_cases}')
    if constructor_two_hundred_sixty_seven_cases != 1: raise RuntimeError(f'expected one constructor two-hundred-sixty-seven case, got {constructor_two_hundred_sixty_seven_cases}')
    if constructor_two_hundred_sixty_eight_cases != 1: raise RuntimeError(f'expected one constructor two-hundred-sixty-eight case, got {constructor_two_hundred_sixty_eight_cases}')
    if constructor_two_hundred_eighty_four_cases != 1: raise RuntimeError(f'expected one constructor two-hundred-eighty-four case, got {constructor_two_hundred_eighty_four_cases}')
    if constructor_three_hundred_five_cases != 1: raise RuntimeError(f'expected one constructor three-hundred-five case, got {constructor_three_hundred_five_cases}')
    if constructor_three_hundred_twenty_one_cases != 1: raise RuntimeError(f'expected one constructor three-hundred-twenty-one case, got {constructor_three_hundred_twenty_one_cases}')
    if constructor_three_hundred_twenty_six_cases != 1: raise RuntimeError(f'expected one constructor three-hundred-twenty-six case, got {constructor_three_hundred_twenty_six_cases}')
    if constructor_three_hundred_thirty_six_cases != 1: raise RuntimeError(f'expected one constructor three-hundred-thirty-six case, got {constructor_three_hundred_thirty_six_cases}')
    if constructor_three_hundred_forty_cases != 1: raise RuntimeError(f'expected one constructor three-hundred-forty case, got {constructor_three_hundred_forty_cases}')
    if constructor_three_hundred_forty_five_cases != 1: raise RuntimeError(f'expected one constructor three-hundred-forty-five case, got {constructor_three_hundred_forty_five_cases}')
    from startup_lift import discover, RANGES, STOPS
    code = discover(image, ENTRY, RANGES, STOPS, IMPORTS)
    missing = set(code)-visited
    if missing:
        raise RuntimeError(f'unexercised instructions: {sorted(missing)}')
    print(f'PASS: {cases} cookie, {frame_cases} frame, {runtime_cases} runtime, {allocator_cases} allocator, {locale_cases} locale, {environment_cases} environment, {argv_cases} argv, {envp_cases} envp, {cinit_cases} cinit, {preinitializer_cases} preinitializer, {atexit_cases} atexit, {constructor_cases + constructor_two_cases + constructor_three_cases + constructor_four_cases + constructor_eight_cases + constructor_nine_cases + constructor_twelve_cases + constructor_twenty_two_cases + constructor_twenty_four_cases + constructor_twenty_five_cases + constructor_thirty_two_cases + constructor_thirty_three_cases + constructor_thirty_seven_cases + constructor_forty_one_cases + constructor_forty_three_cases + constructor_forty_four_cases + constructor_forty_five_cases + constructor_forty_six_cases + constructor_forty_seven_cases + constructor_forty_eight_cases + constructor_forty_nine_cases + constructor_fifty_cases + constructor_fifty_one_cases + constructor_fifty_two_cases + constructor_fifty_three_cases + constructor_fifty_five_cases + constructor_fifty_six_cases + constructor_fifty_seven_cases + constructor_fifty_eight_cases + constructor_fifty_nine_cases + constructor_sixty_cases + constructor_sixty_one_cases + constructor_sixty_two_cases + constructor_sixty_five_cases + constructor_seventy_three_cases + constructor_seventy_four_cases + constructor_eighty_seven_cases + constructor_ninety_one_cases + constructor_ninety_two_cases + constructor_one_hundred_two_cases + constructor_one_hundred_ten_cases + constructor_one_hundred_eleven_cases + constructor_one_hundred_sixteen_cases + constructor_one_hundred_seventeen_cases + constructor_one_hundred_twenty_eight_cases + constructor_one_hundred_twenty_nine_cases + constructor_one_hundred_thirty_cases + constructor_one_hundred_thirty_one_cases + constructor_one_hundred_thirty_seven_cases + constructor_one_hundred_forty_three_cases + constructor_one_hundred_forty_four_cases + constructor_one_hundred_forty_five_cases + constructor_one_hundred_forty_six_cases + constructor_one_hundred_forty_seven_cases + constructor_one_hundred_forty_eight_cases + constructor_one_hundred_fifty_cases + constructor_one_hundred_fifty_four_cases + constructor_one_hundred_fifty_six_cases + constructor_one_hundred_sixty_four_cases + constructor_one_hundred_sixty_eight_cases + constructor_one_hundred_seventy_eight_cases + constructor_one_hundred_eighty_five_cases + constructor_one_hundred_eighty_seven_cases + constructor_two_hundred_twenty_nine_cases + constructor_two_hundred_thirty_three_cases + constructor_two_hundred_sixty_seven_cases + constructor_two_hundred_sixty_eight_cases + constructor_two_hundred_eighty_four_cases + constructor_three_hundred_five_cases + constructor_three_hundred_twenty_one_cases + constructor_three_hundred_twenty_six_cases + constructor_three_hundred_thirty_six_cases + constructor_three_hundred_forty_cases + constructor_three_hundred_forty_five_cases} constructor original-x86 comparisons; all {len(code)} reachable instructions exercised.')

if __name__ == '__main__':
    main()
