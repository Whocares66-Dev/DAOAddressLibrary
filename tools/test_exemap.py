"""The identity path requires the same linked bytes, not merely the same stamp."""

import struct
import unittest
from types import SimpleNamespace

import exemap


def side():
    value = object.__new__(exemap.Side)
    value.__dict__.update(
        base=0x400000,
        sections=[
            (".text", 0x400010, 0x400030, 0x400030),
            (".rdata", 0x400030, 0x400100, 0x400100),
        ],
        mem=bytearray(0x100),
        is_reloc=bytearray(0x100),
        img=SimpleNamespace(entry_point_rva=0x10, dirs=[(0, 0)] * 16, vtables=[]),
        text=(0x400010, 0x400030),
        data_targets={0x4000A0},
    )
    value.img.dirs[10] = (0x40, 0x40)
    struct.pack_into("<I", value.mem, 0x40, 0x48)
    value.u32 = lambda va: struct.unpack_from("<I", value.mem, va - value.base)[0]
    return value


class SameLayout(unittest.TestCase):
    def test_identical_code_gets_every_id_without_marking_data_as_changed_code(self):
        a, b = side(), side()
        b.mem[0x70] = 1
        functions = [0x400010, 0x400020]
        result = exemap.build(a, b, (functions, functions))
        for address in functions + [0x4000A0]:
            self.assertEqual(result.lookup(address), (address, "exact"))
        self.assertEqual(result.lookup(0x400015), (0x400015, "range"))
        self.assertNotEqual(result.lookup(0x400070)[1], "range")
        self.assertFalse(result.changed_functions())
        self.assertFalse(result.rejected)
        self.assertFalse(result.ambiguous)

    def test_equal_images_and_documented_pe_fields(self):
        a, b = side(), side()
        self.assertTrue(exemap.same_layout(a, b))
        for offset in (0x30, 0x40, 0x44):
            b.mem[0x40 + offset] = 1
        self.assertTrue(exemap.same_layout(a, b))

    def test_a_code_or_global_byte_difference_refuses_identity(self):
        for offset in (0x10, 0x30, 0xA0):
            a, b = side(), side()
            b.mem[offset] ^= 1
            self.assertFalse(exemap.same_layout(a, b))

    def test_relocations_layout_entry_and_directories_must_agree(self):
        a, b = side(), side()
        b.is_reloc[0x10] = 1
        self.assertFalse(exemap.same_layout(a, b))
        b = side()
        b.base += 0x1000
        self.assertFalse(exemap.same_layout(a, b))
        b = side()
        b.sections.pop()
        self.assertFalse(exemap.same_layout(a, b))
        b = side()
        b.img.entry_point_rva += 1
        self.assertFalse(exemap.same_layout(a, b))
        b = side()
        b.img.dirs[1] = (0x10, 4)
        self.assertFalse(exemap.same_layout(a, b))

    def test_unknown_load_config_is_not_masked(self):
        a, b = side(), side()
        a.mem[0x40] = b.mem[0x40] = 0x60
        b.mem[0x70] = 1
        self.assertFalse(exemap.same_layout(a, b))


if __name__ == "__main__":
    unittest.main()
