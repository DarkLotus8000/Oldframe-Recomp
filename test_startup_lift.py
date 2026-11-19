"""Focused synthetic PE tests for bounded recursive discovery (no game files)."""
import struct
import unittest
from startup_lift import discover


def pe(code):
    image = bytearray(0x200) + code
    image[:2] = b'MZ'
    struct.pack_into('<I', image, 60, 0x80)
    image[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HH', image, 0x84, 0x14c, 1)
    struct.pack_into('<H', image, 0x94, 0xe0)
    struct.pack_into('<H', image, 0x98, 0x10b)
    struct.pack_into('<I', image, 0xb4, 0x400000)
    struct.pack_into('<III', image, 0x184, 0x1000, len(code), 0x200)
    return image


class DiscoveryTests(unittest.TestCase):
    def test_signed_branch_requires_supported_flags(self):
        with self.assertRaisesRegex(ValueError, 'signed flag producer'):
            discover(pe(bytes.fromhex('83c0017c00c3')), 0x401000,
                     [(0x401000, 0x401006)], set(), {})
        code = bytes.fromhex('83f8247c00c3')
        self.assertEqual(len(discover(pe(code), 0x401000,
                                     [(0x401000, 0x401006)], set(), {})), 3)
    def test_calls_branches_and_unreachable_bytes(self):
        # call +3; jmp +3; unreachable int3; xor eax,eax; ret
        image = pe(bytes.fromhex('e803000000eb03cc31c0c3'))
        found = discover(image, 0x401000, [(0x401000, 0x40100b)], set(), {})
        self.assertEqual(set(found), {0x401000, 0x401005, 0x401008, 0x40100a})

    def test_unresolved_direct_target_and_checkpoint(self):
        image = pe(bytes.fromhex('eb7f'))
        with self.assertRaisesRegex(ValueError, '0x401081'):
            discover(image, 0x401000, [(0x401000, 0x401002)], set(), {})
        self.assertEqual(len(discover(image, 0x401000, [(0x401000, 0x401002)], {0x401081}, {})), 1)

    def test_unsupported_instruction_and_import(self):
        for code, message in [('0fa2', 'unsupported instruction cpuid at 0x401000'),
                              ('ff1578563412', 'unresolved call at 0x401000')]:
            with self.assertRaisesRegex(ValueError, message):
                discover(pe(bytes.fromhex(code)), 0x401000, [(0x401000, 0x401010)], set(), {})

    def test_overlap_truncation_and_budget(self):
        for code, limit, message in [('7501b800000000c3', 20, 'overlapping'),
                                      ('e8', 20, 'incomplete'),
                                      ('90c3', 1, 'budget')]:
            body = bytes.fromhex(code)
            with self.assertRaisesRegex(ValueError, message):
                discover(pe(body), 0x401000, [(0x401000, 0x401000+len(body))], set(), {}, limit)

if __name__ == '__main__':
    unittest.main()
