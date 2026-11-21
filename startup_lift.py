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
         0xF17CC6, 0xF207F4, 0xF2081C,
         0xF17C80, 0xF17CA6, 0xF17CB7, 0xF209A8, 0xF22026, 0xF22A8A,
         0xF22AA2, 0xF22A11, 0xF22506, 0xF22357, 0xF20706, 0xF26291, 0xF262C9,
         0xF262B1, 0xF262F5,
         0xF227F4, 0xF22823, 0xF22872, 0xF22896, 0xF228A2, 0xF228CC,
         0xF22908, 0xF2292B, 0xF229A6,
         0xF227A0, 0xF227B7, 0xF1A8FC,
         0xF226F1, 0xF22704, 0xF22707,
         0xF17A06, 0xF17A24, 0xF17A3D, 0xF17A90, 0xF182D6,
         0xF18265, 0xF182AA,
         0x42507E,
         0x423B34,
         0x423AD7,
         0x10676F3,
         0x10683E3,
         0x106847C,
         0x1068949,
         0x10689E9,
         0x1068ABC,
         0x1068B8C, 0x1068C5C, 0x1068D2C, 0x1068DFC,
         0x1068F39, 0x1069089, 0x106915C,
         0x106922C,
         0x106937C, 0x106939D, 0x106944C, 0x106946D,
         0x1069629, 0x10696C9,
         0x1069A89,
         0x43EDFE, 0x43EE1F, 0x43EE08, 0x43EE43, 0x43EE6C, 0x43EECE, 0x43EEE9,
         0x422CB1, 0x422D2F,
         0x41D209,
         0x479174, 0x47919F,
         0x4A5244, 0x4A527E,
         0x106BD43,
         0x1067529,
         0xF2D4F3, 0xF1A754, 0xF303A5, 0xF303E3, 0xF21D4B, 0xF22AC4,
         0xF21E59, 0xF21F70}
COOKIE = 0x1310B30
# Explicit scope, not a list of individual blocks or call targets.
RANGES = ((ENTRY, ENTRY + 10), (0xF23039, 0xF230D4),
          (CHECKPOINT, 0xF17CC6), (0xF20787, 0xF207F4),
          (0xF23CB4, 0xF23CD7), (0xF21D70, 0xF21DB5),
          (0xF22AB0, 0xF22AD6), (0xF21DC9, 0xF21E59), (0xF21F5C, 0xF2200E),
          (0xF2301B, 0xF23039), (0xF22EA0, 0xF2301B), (0xF21BBC, 0xF21C06),
          (0xF22BBC, 0xF22C70), (0xF21DB5, 0xF21DC9), (0xF25870, 0xF258FF),
          (0xF21D36, 0xF21D69), (0xF21C5D, 0xF21C74),
          (0xF22053, 0xF2209F), (0xF3038D, 0xF3040F),
          (0xF2200E, 0xF22053), (0xF26278, 0xF2630C),
          (0xF22A19, 0xF22AB0),
          (0xF2295E, 0xF22A19), (0xF227C4, 0xF2295E),
          (0xF226E8, 0xF227C4),
          (0xF179F2, 0xF17AA3), (0xF182B1, 0xF182E2),
          (0xF181FB, 0xF182B1), (0xF182E2, 0xF18335),
          (0xF192AB, 0xF192D9), (0xF231D7, 0xF231E7),
          (0xF2615A, 0xF2616A), (0xF22323, 0xF22331),
          (0x10670D0, 0x10670E9),
          (0x10670F0, 0x1067112), (0x421AE0, 0x421B00),
          (0x1067120, 0x1067142),
          (0x1067150, 0x1067175), (0x425060, 0x4250DC),
          (0x1067180, 0x10671C7), (0x10671D0, 0x10671F5),
          (0x1067200, 0x106720C), (0x1067210, 0x1067257),
          (0x1067260, 0x106726A), (0x402B40, 0x402B79),
          (0x1067270, 0x10672B7), (0x10672C0, 0x10672CC),
          (0x10672D0, 0x10672DC),
          (0x10672E0, 0x106BEE0), (0x4172E0, 0x41739C),
          (0x445C60, 0x445C6F), (0x451550, 0x4515EC),
          (0x45B450, 0x45B4D1),
          (0x479120, 0x4791CC),
          (0x4BF4E0, 0x4BF5CA),
          (0xC60FE0, 0xC610CA),
          (0x4A1A30, 0x4A1A59),
          (0x441B90, 0x441BE1), (0x49DE20, 0x49DE29),
          (0x43ED70, 0x43EF2C), (0x43D3D0, 0x43D413),
          (0x422C70, 0x422CEC), (0x422CF0, 0x422D61),
          (0x48BC20, 0x48BC5C), (0x48BBE0, 0x48BC14),
          (0x423B10, 0x423B6A),
          (0x423AC0, 0x423B0D),
          (0x419DF0, 0x419F96),
          (0x41D1F0, 0x41D209), (0x41D2EF, 0x41D305),
          (0x446700, 0x446739),
          (0x424B60, 0x424BE1), (0x423B70, 0x423BCD),
          (0x4A5160, 0x4A52E6),
          (0x558E30, 0x558E5E),
          (0xF22B05, 0xF22B0E),
          (0xF2071E, 0xF20787), (0xF22AFC, 0xF22B05),
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
           0x10A72E0: ('FreeEnvironmentStringsW', 1),
           0x10A72DC: ('GetModuleFileNameA', 3),
           0xF25852: ('initialize_ctype', 0),
           0xF30820: ('isleadbyte', 1),
           0xF26890: ('strlen', 1),
           0xF28C15: ('copy_s', 3),
           0xF1F0DC: ('free', 1),
           0xF18390: ('memset', 3),
           0xF26500: ('is_nonwritable_image_pointer', 1),
           0xF18111: ('raw_dll_main', 1),
           0x41D560: ('duration_init', 1)}
IMPORTS.update({0x10A7308: ('IsProcessorFeaturePresent', 1),
                0x10A7160: ('SetUnhandledExceptionFilter', 1),
                0xF23CFF: ('allocation_size', 1),
                0xF2209F: ('reallocate', 2),
                0x4132A0: ('game_allocate', 3),
                0x43EB90: ('manager_register', 2),
                0x44AAE0: ('vector_insert_u32', 3),
                0x478D10: ('vector_insert_u8', 3),
                0x415AE0: ('copy_small_string', 1),
                0x4137D0: ('game_free', 2),
                0xF17BA1: ('security_cookie_check', 0),
                0x415E80: ('concat_small_string', 3),
                0x415E10: ('concat_two_strings', 3),
                0x418E10: ('load_library_w', 1),
                0xF1ABC0: ('strrchr', 2),
                0x415B30: ('inline_small_string', 1),
                0x423280: ('string_pool_init', 0),
                0x423730: ('intern_string', 3),
                0x43FD40: ('copy_bounded', 3),
                0x4A4EC0: ('lower_bound_empty', 6),
                0x460AC0: ('vector_insert_ptr', 3)})
IMPORTS[0x421860] = ('assertion_predicate', 1)
XMM_BOUNDARIES = {0xF187A1}
CDECL_IMPORTS = {0xF25852, 0xF30820, 0xF26890, 0xF28C15, 0xF1F0DC, 0xF18390, 0xF2209F,
                0xF26500, 0xF18111, 0xF23CFF, 0xF1ABC0, 0x423280}
CDECL_IMPORTS.update((0x4132A0, 0x4137D0))
CDECL_IMPORTS.add(0x415E80)
CDECL_IMPORTS.add(0x415E10)
CDECL_IMPORTS.update((0x43FD40, 0x4A4EC0))
INDIRECT_IMPORTS = {pc: 0x10A70A8 for pc in (0xF22ECA, 0xF22ED7, 0xF22EE4, 0xF22EF1)}
INDIRECT_IMPORTS.update({0xF22F5C: 0x10A72F0})
INDIRECT_IMPORTS.update({pc: 0x10A7284 for pc in (0xF22F77, 0xF22F84, 0xF22F91, 0xF22F9E)})
INDIRECT_IMPORTS[0xF22FBF] = 0x10A7288
INDIRECT_IMPORTS[0xF22FEE] = 0x10A7288
INDIRECT_IMPORTS[0xF22A61] = 0x10A72C4
INDIRECT_IMPORTS[0xF22A84] = 0x10A72C4
INDIRECT_IMPORTS.update({pc: 0x10A7288 for pc in (0xF18210, 0xF1821D)})
INDIRECT_IMPORTS.update({pc: 0x10A7284 for pc in (0xF18296, 0xF1829E)})
INDIRECT_IMPORTS.update({pc: 0x10A72F8 for pc in (0xF25882, 0xF2588F, 0xF2589C, 0xF258A9, 0xF258B6, 0xF258D2, 0xF258E2, 0xF258F8)})
# A closed, verified set may mix guest functions and host import tokens.
INDIRECT_TARGETS = {0xF22FC1: (0x50000, 0xF22B05)}
INDIRECT_TARGETS[0xF22FF0] = (0x50020, 0x10A72F0)
INDIRECT_TARGETS[0xF207A7] = (0xF18111,)
INDIRECT_TARGETS[0xF2077A] = (0xF179F2, 0xF182B1, 0xF192AB, 0xF231D7,
                              0xF25852, 0xF2615A, 0xF22323)
INDIRECT_TARGETS[0xF207EB] = (0x10670D0, 0x10670F0, 0x1067120, 0x1067150,
                              0x1067180, 0x10671D0, 0x1067200, 0x1067210,
                              0x1067260, 0x1067270, 0x10672C0, 0x10672D0)
INDIRECT_TARGETS[0xF207EB] += tuple(range(0x10672E0, 0x1067440, 0x20))
INDIRECT_TARGETS[0xF207EB] += (0x1067430,)
INDIRECT_TARGETS[0xF207EB] += (0x1067440,)
INDIRECT_TARGETS[0xF207EB] += tuple(range(0x1067460, 0x10674D0, 0x10))
INDIRECT_TARGETS[0xF207EB] += (0x10674D0,)
INDIRECT_TARGETS[0xF207EB] += (0x10674F0, 0x1067500, 0x1067510, 0x1067520)
INDIRECT_TARGETS[0xF207EB] += (0x1067560, 0x1067570, 0x1067580, 0x10675E0)
INDIRECT_TARGETS[0xF207EB] += (0x1067630, 0x1067640)
INDIRECT_TARGETS[0xF207EB] += (0x1067650, 0x1067670, 0x10676A0, 0x1067710, 0x1067780, 0x1067810, 0x1067880)
INDIRECT_TARGETS[0xF207EB] += (0x1067910,)
INDIRECT_TARGETS[0xF207EB] += (0x1067930,)
INDIRECT_TARGETS[0xF207EB] += (0x1067950,)
INDIRECT_TARGETS[0xF207EB] += (0x1067980, 0x1067990)
INDIRECT_TARGETS[0xF207EB] += (0x10679A0,)
INDIRECT_TARGETS[0xF207EB] += (0x10679C0,)
INDIRECT_TARGETS[0xF207EB] += (0x1067A10, 0x1067A20)
INDIRECT_TARGETS[0xF207EB] += (0x1067A50,)
INDIRECT_TARGETS[0xF207EB] += (0x1067AA0, 0x1067AD0)
INDIRECT_TARGETS[0xF207EB] += (0x1067B00, 0x1067B10, 0x1067B40, 0x1067B50)
INDIRECT_TARGETS[0xF207EB] += (0x1067BA0, 0x1067BF0, 0x1067C40, 0x1067C90,
                              0x1067CE0, 0x1067D30, 0x1067D80, 0x1067DD0)
INDIRECT_TARGETS[0xF207EB] += (0x1067E00,)
INDIRECT_TARGETS[0xF207EB] += (0x1067E20, 0x1067E50, 0x1067E70, 0x1067E80,
                              0x1067ED0, 0x1067F20, 0x1067F30, 0x1067F40,
                              0x1067F90, 0x1067FC0, 0x1067FF0, 0x1068020,
                              0x1068040)
INDIRECT_TARGETS[0xF207EB] += (0x1068060, 0x10680B0, 0x1068100, 0x1068150)
INDIRECT_TARGETS[0xF207EB] += (0x10681A0,)
INDIRECT_TARGETS[0xF207EB] += (0x10681C0, 0x10681F0, 0x1068220, 0x1068230,
                              0x1068240, 0x1068250, 0x1068270, 0x1068280,
                              0x10682A0, 0x10682B0)
INDIRECT_TARGETS[0xF207EB] += (0x10682C0, 0x10682F0, 0x1068320, 0x1068340,
                              0x1068360, 0x1068390, 0x1068400, 0x1068410)
INDIRECT_TARGETS[0xF207EB] += (0x1068420,)
INDIRECT_TARGETS[0xF207EB] += (0x10684D0, 0x10684E0, 0x1068530, 0x1068580,
                              0x10685D0)
INDIRECT_TARGETS[0xF207EB] += (0x1068620,)
INDIRECT_TARGETS[0xF207EB] += (0x1068640, 0x1068650, 0x10686A0, 0x10686F0,
                              0x1068740, 0x1068760, 0x10687B0, 0x1068800,
                              0x1068810, 0x1068860, 0x10688B0)
INDIRECT_TARGETS[0xF207EB] += (0x1068900,)
INDIRECT_TARGETS[0xF207EB] += (0x10689A0,)
INDIRECT_TARGETS[0xF207EB] += (0x1068A40,)
INDIRECT_TARGETS[0xF207EB] += (0x1068B10, 0x1068BE0, 0x1068CB0, 0x1068D80,
                              0x1068E50, 0x1068EA0)
INDIRECT_TARGETS[0xF207EB] += (0x1068EF0, 0x1068F90, 0x1068FE0, 0x1069030,
                              0x1069040, 0x10690E0)
INDIRECT_TARGETS[0xF207EB] += (0x10691B0,)
INDIRECT_TARGETS[0xF207EB] += (0x1069280,)
INDIRECT_TARGETS[0xF207EB] += (0x10692A0,)
INDIRECT_TARGETS[0xF207EB] += (0x10692C0,)
INDIRECT_TARGETS[0xF207EB] += (0x10692E0,)
INDIRECT_TARGETS[0xF207EB] += (0x1069300, 0x10693D0)
INDIRECT_TARGETS[0xF207EB] += (0x10694A0, 0x10694F0, 0x1069540, 0x1069590)
INDIRECT_TARGETS[0xF207EB] += (0x10695E0, 0x1069680)
INDIRECT_TARGETS[0xF207EB] += (0x1069720, 0x1069770, 0x10697C0, 0x1069810,
                              0x1069860, 0x10698B0, 0x1069900, 0x1069950)
INDIRECT_TARGETS[0xF207EB] += (0x10699A0, 0x10699F0, 0x1069A40, 0x1069AE0)
INDIRECT_TARGETS[0xF207EB] += (0x1069B30, 0x1069B80, 0x1069BD0, 0x1069C20,
                              0x1069C70, 0x1069CC0, 0x1069D10,
                              0x1069D60, 0x1069D70, 0x1069D80)
INDIRECT_TARGETS[0xF207EB] += (0x1069DC0, 0x1069DF0, 0x1069E10, 0x1069E30,
                              0x1069E40, 0x1069E50, 0x1069E60)
INDIRECT_TARGETS[0xF207EB] += (0x1069E80, 0x1069ED0)
INDIRECT_TARGETS[0xF207EB] += tuple(range(0x1069F20, 0x106A1C0, 0x10))
INDIRECT_TARGETS[0xF207EB] += (0x106A1C0, 0x106A1D0, 0x106A1E0, 0x106A1F0)
INDIRECT_TARGETS[0xF207EB] += (0x106A210, 0x106A260, 0x106A2B0, 0x106A2C0)
INDIRECT_TARGETS[0xF207EB] += tuple(range(0x106A310, 0x106AAE0, 0x50))
INDIRECT_TARGETS[0xF207EB] += (0x106AAE0, 0x106AB10, 0x106AB20, 0x106AB30, 0x106AB60)
INDIRECT_TARGETS[0xF207EB] += (0x106ABB0,)
INDIRECT_TARGETS[0xF207EB] += tuple(range(0x106ABF0, 0x106AFF0, 0x40))
INDIRECT_TARGETS[0xF207EB] += (0x106AFF0, 0x106B020, 0x106B050, 0x106B080,
                              0x106B0B0, 0x106B100, 0x106B120, 0x106B170,
                              0x106B1C0, 0x106B210, 0x106B260, 0x106B2B0,
                              0x106B300, 0x106B350, 0x106B370, 0x106B3C0,
                              0x106B3F0, 0x106B440, 0x106B490, 0x106B4B0,
                              0x106B500)
INDIRECT_TARGETS[0xF207EB] += (0x106B550, 0x106B570, 0x106B5A0, 0x106B5F0,
                              0x106B620, 0x106B670, 0x106B6A0, 0x106B6D0,
                              0x106B720, 0x106B740, 0x106B790, 0x106B7E0,
                              0x106B810, 0x106B840, 0x106B890, 0x106B8E0)
INDIRECT_TARGETS[0xF207EB] += (0x106B900, 0x106B930, 0x106B960, 0x106B990,
                              0x106B9C0)
INDIRECT_TARGETS[0xF207EB] += (0x106B9F0, 0x106BA40, 0x106BA90, 0x106BAE0,
                              0x106BB30, 0x106BB80, 0x106BBD0, 0x106BC20,
                              0x106BC50, 0x106BCA0)
INDIRECT_TARGETS[0xF207EB] += (0x106BCF0, 0x106BD60, 0x106BD70, 0x106BD90)
INDIRECT_TARGETS[0xF207EB] += (0x106BDB0, 0x106BDE0, 0x106BE10, 0x106BE40,
                              0x106BE90)
INDIRECT_TARGETS[0x4A5274] = (0x421860,)
DIGEST = '614c08f25b531d590c5aa6d9cf35b1e406e83d35fbd50e61188f19247fb176ae'


def translate(insn):
    """Startup arithmetic that can report a guest divide fault to its caller."""
    args = insn.operands
    if insn.mnemonic == 'cvtsd2ss' and insn.op_str == 'xmm0, xmm0':
        return ['let value = f64::from_bits(r.xmm0 as u64) as f32;',
                'r.xmm0 = (r.xmm0 & (!0u128 << 32)) | u128::from(value.to_bits());']
    if insn.mnemonic == 'mulss' and insn.op_str == 'xmm0, xmm0':
        return ['let value = f32::from_bits(r.xmm0 as u32);',
                'let result = (value * value).to_bits();',
                'r.xmm0 = (r.xmm0 & (!0u128 << 32)) | u128::from(result);']
    if insn.mnemonic == 'comiss' and len(args) == 2:
        lhs = 'r.xmm0'
        rhs = f'm.read32({lift.address(insn, args[1].mem)})'
        return [f'let lhs = f32::from_bits({lhs} as u32);',
                f'let rhs = f32::from_bits({rhs} as u32);',
                'let unordered = lhs.is_nan() || rhs.is_nan();',
                'r.carry = unordered || lhs < rhs;',
                'r.zero = unordered || lhs == rhs;',
                'r.overflow = false;', 'r.sign = false;']
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


def discover(image, entry, ranges, stops, imports, limit=8192):
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
                if not (op == 'call' and (arg.imm in imports or arg.imm in XMM_BOUNDARIES)):
                    pending.append(arg.imm)
            elif (op == 'call' and arg.type == lift.X86_OP_MEM
                  and not arg.mem.base and not arg.mem.index
                  and not arg.mem.segment and arg.mem.disp in imports):
                pass
            elif op == 'call' and arg.type == lift.X86_OP_REG and pc in INDIRECT_IMPORTS:
                pass
            elif op == 'call' and pc in INDIRECT_TARGETS:
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
             'struct Registers { ' + ', '.join(f'{r}: u32' for r in lift.REGISTERS if r in used) + ', xmm0: u128, carry: bool, zero: bool, sign: bool, overflow: bool }',
             f'pub(super) fn run(m: &mut Memory, stop: u32) -> Result<(), String> {{ run_from(m, {ENTRY:#x}, stop) }}',
             'pub(super) fn run_from(m: &mut Memory, start: u32, stop: u32) -> Result<(), String> {',
             'let mut r = Registers { esp: 0x20000, ..Default::default() };',
             'let mut pc = start;',
             'for _ in 0..131072 {',
             'if pc == stop { m.stack = r.esp; m.frame = r.ebp; m.eax = r.eax; return Ok(()); }',
             'match pc {']
    for pc, insn in sorted(code.items()):
        lines.append(f'{pc:#x} => {{ // {insn.mnemonic} {insn.op_str}')
        op, args, following = insn.mnemonic, insn.operands, pc+insn.size
        if op == 'call':
            if args[0].type == lift.X86_OP_IMM:
                target = args[0].imm
                if target == 0xF187A1:
                    lines += ['let input = f64::from_bits(r.xmm0 as u64);',
                              'let output = input.sin().to_bits();',
                              'r.xmm0 = (r.xmm0 & (!0u128 << 64)) | u128::from(output);',
                              f'pc = {following:#x};']
                elif target in IMPORTS:
                    argc = IMPORTS[target][1]
                    cleanup = 1 if target in CDECL_IMPORTS else argc + 1
                    lines += ['r.esp -= 4;', f'm.write32(r.esp, {following:#x});',
                              f'r.eax = m.import({target:#x}, r.esp + 4, r.ecx)?;',
                              f'r.esp += {cleanup*4};', f'pc = {following:#x};']
                else:
                    lines += ['r.esp -= 4;', f'm.write32(r.esp, {following:#x});', f'pc = {target:#x};']
            elif pc in INDIRECT_TARGETS:
                lines += [f'let target = {lift.value(insn, args[0])};', 'r.esp -= 4;',
                          f'm.write32(r.esp, {following:#x});', 'match target {']
                for target in INDIRECT_TARGETS[pc]:
                    if target in IMPORTS:
                        argc = IMPORTS[target][1]
                        cleanup = 1 if target in CDECL_IMPORTS else argc + 1
                        lines.append(f'{target:#x} => {{ r.eax = m.import(target, r.esp + 4, r.ecx)?; r.esp += {cleanup*4}; pc = {following:#x}; }},')
                    else:
                        lines.append(f'{target:#x} => {{ pc = target; }},')
                lines += ['_ if target == stop => { m.stack = r.esp; m.frame = r.ebp; m.eax = r.eax; return Ok(()); },',
                          f'_ => return Err(format!("unresolved indirect call at {pc:#x}: target {{target:#x}}")),', '}']
            else:
                slot = args[0].mem.disp if args[0].type == lift.X86_OP_MEM else INDIRECT_IMPORTS[pc]
                argc = IMPORTS[slot][1]
                if args[0].type == lift.X86_OP_REG:
                    lines.append(f'if {lift.value(insn, args[0])} != {slot:#x} {{ return Err(format!("unresolved indirect call at {pc:#x}")); }}')
                lines += ['r.esp -= 4;', f'm.write32(r.esp, {following:#x});',
                          f'r.eax = m.import({slot:#x}, r.esp + 4, r.ecx)?;',
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
