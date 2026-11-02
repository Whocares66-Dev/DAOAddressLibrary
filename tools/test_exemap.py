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


class NotEntries(unittest.TestCase):
    """A place inside a function is not a function, however it starts."""

    def code(self, hexes, relocs=(), pointers=()):
        value = object.__new__(exemap.Side)
        mem = bytearray(0x1000)
        body = bytes.fromhex(hexes)
        mem[0x10 : 0x10 + len(body)] = body
        reloc = bytearray(0x1000)
        for where in relocs:
            reloc[where - 0x400000] = 1
        value.__dict__.update(
            base=0x400000,
            mem=bytes(mem),
            is_reloc=reloc,
            text=(0x400010, 0x400010 + len(body) + 8),
            code_pointers=set(pointers),
        )
        return value

    def test_a_tail_reached_only_by_a_conditional_jump_is_not_one(self):
        # 0x400010: jne 0x400020; padding; 0x400020: the tail.
        a = self.code("750e" + "90" * 14 + "c3")
        self.assertEqual(exemap.not_entries(a, {0x400020}), {0x400020})

    def test_where_a_catch_funclet_resumes_is_not_one(self):
        # 0x400010: mov eax, 0x400016; ret; 0x400016: the continuation.
        a = self.code("b816004000" + "c3" + "90", relocs=[0x400011])
        self.assertEqual(exemap.not_entries(a, {0x400016}), {0x400016})

    def test_a_call_makes_it_one_though_a_jump_reaches_it_too(self):
        # jne 0x400020; call 0x400020 (rel32 9 from 0x400017); padding.
        a = self.code("750e" + "e809000000" + "90" * 9 + "c3")
        self.assertEqual(exemap.not_entries(a, {0x400020}), set())

    def test_a_pointer_in_data_makes_it_one(self):
        a = self.code("750e" + "90" * 14 + "c3", pointers=[0x400020])
        self.assertEqual(exemap.not_entries(a, {0x400020}), set())

    def test_an_address_held_by_other_code_is_one(self):
        # push 0x400020 hands over a callback; it is no continuation.
        a = self.code("6820004000" + "7509" + "90" * 9 + "c3", relocs=[0x400011])
        self.assertEqual(exemap.not_entries(a, {0x400020}), set())

    def test_an_export_nothing_reaches_stays(self):
        a = self.code("90" * 16 + "c3")
        self.assertEqual(exemap.not_entries(a, {0x400020}), set())


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
