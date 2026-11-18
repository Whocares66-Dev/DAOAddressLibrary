"""Tests for tools/receivers.py's judgement, which needs no game: what an
instruction puts in ECX, and which evidence settles a type.

    python -m unittest discover -s tools -p "test_*.py"
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import receivers  # noqa: E402

TEXT_END = 0x00AD0000


class Sources(unittest.TestCase):
    def test_a_global_loaded_is_a_pointer(self):
        self.assertEqual(
            receivers.source_of("mov", "ecx, dword ptr [0xc327ec]", TEXT_END, None),
            ("pointer", 0xC327EC),
        )

    def test_a_globals_address_is_an_object_but_code_is_not(self):
        self.assertEqual(
            receivers.source_of("mov", "ecx, 0xc33b20", TEXT_END, None),
            ("object", 0xC33B20),
        )
        self.assertIsNone(receivers.source_of("mov", "ecx, 0x401000", TEXT_END, None))

    def test_a_result_moved_to_ecx_is_that_functions(self):
        self.assertEqual(
            receivers.source_of("mov", "ecx, eax", TEXT_END, 0x5D57C0),
            ("returns", 0x5D57C0),
        )
        self.assertIsNone(receivers.source_of("mov", "ecx, eax", TEXT_END, None))

    def test_another_write_of_ecx_ends_it_and_a_read_does_not(self):
        self.assertIsNone(
            receivers.source_of("lea", "ecx, [esp + 0x18]", TEXT_END, None)
        )
        self.assertIs(receivers.source_of("push", "ecx", TEXT_END, None), False)
        self.assertIs(
            receivers.source_of("mov", "eax, dword ptr [ecx]", TEXT_END, None), False
        )


class Rows(unittest.TestCase):
    functions = {
        0x10: (1, "Base::Run"),
        0x20: (2, "Derived::Walk"),
        0x30: (3, "Other::Fly"),
        0x40: (4, "Derived::Derived"),
        0x50: (5, "Getter"),
    }
    bases = {"Base": set(), "Derived": {"Base"}, "Other": set()}

    def settle(self, **tables):
        found = receivers.Evidence()
        for table, held in tables.items():
            for key, seen in held.items():
                for cls, callees in seen.items():
                    getattr(found, table)[key][cls] |= set(callees)
        return receivers.rows(found, self.bases, self.functions, {0x900: "g_thing"})

    def test_two_callees_of_one_line_give_the_most_derived(self):
        settled, unsettled = self.settle(
            pointer={0x900: {"Base": [0x10], "Derived": [0x20]}}
        )
        self.assertEqual(
            [(a, what, value) for a, what, value, _ in settled],
            [(0x900, "datatype", "Derived *")],
        )
        self.assertEqual(unsettled, [])

    def test_one_callee_settles_nothing(self):
        settled, unsettled = self.settle(returns={0x50: {"Base": [0x10]}})
        self.assertEqual(settled, [])
        self.assertEqual(len(unsettled), 1)

    def test_two_unrelated_classes_settle_nothing(self):
        settled, unsettled = self.settle(
            pointer={0x900: {"Base": [0x10], "Other": [0x30]}}
        )
        self.assertEqual(settled, [])
        self.assertEqual(len(unsettled), 1)

    def test_its_own_constructor_alone_makes_a_global_an_object(self):
        settled, _ = self.settle(object={0x900: {"Derived": [0x40]}})
        self.assertEqual(
            [(a, what, value) for a, what, value, _ in settled],
            [(0x900, "datatype", "Derived")],
        )

    def test_a_constructors_name(self):
        self.assertTrue(receivers.is_constructor("A::B::B", "A::B"))
        self.assertTrue(
            receivers.is_constructor(
                "??0GRefCountBaseImpl@@QAE@XZ", "GRefCountBaseImpl"
            )
        )
        self.assertFalse(receivers.is_constructor("A::B::Run", "A::B"))


class FakeImage:
    """What subobject_methods reads of an image: its vftables and a
    function's first bytes."""

    def __init__(self, vtables, code=None):
        self.vtables = vtables
        self.code = code or {}

    def bytes_at(self, va, n):
        return self.code.get(va, b"\x55\x8b\xec\x56\x8b\xf1\x5e")[:n]


class SharedGetters(unittest.TestCase):
    def test_a_function_that_only_reads_a_field_is_one(self):
        code = {
            0x1000: b"\x8b\x01\xc3\xcc\xcc\xcc\xcc",  # mov eax,[ecx]; ret
            0x1010: b"\x8b\x41\x0c\xc3\xcc\xcc\xcc",  # mov eax,[ecx+0xC]; ret
            0x1020: b"\x8b\x81\x40\x0a\x00\x00\xc3",  # mov eax,[ecx+0xA40]; ret
            0x1030: b"\x8b\x41\x0c\x8b\x00\xc3\xcc",  # ...; mov eax,[eax]; ret
            0x1040: b"\x8a\x41\x0c\xc3\xcc\xcc\xcc",  # mov al,[ecx+0xC]; ret
            0x1050: b"\x8b\x41\x0c\xc2\x04\x00\xcc",  # ...; ret 4
        }
        functions = {va: (1, "f") for va in code} | {0x1060: (1, "g")}
        self.assertEqual(
            receivers.shared_getters(FakeImage([], code), functions),
            [(0x1000, 0), (0x1010, 0xC), (0x1020, 0xA40)],
        )


class SubobjectMethods(unittest.TestCase):
    functions = {
        0x10: (1, "Derived::OnSide"),
        0x20: (2, "Derived::Run"),
        0x30: (3, "Derived::Walk`adjustor{8}'"),
        0x40: (4, "Derived::Back"),
        0x50: (5, "Derived::Shared"),
    }
    bases = {"Derived": {"Base", "Side"}, "Most": {"Derived"}, "Other": set()}

    def found(self, vtables, code=None):
        rows = receivers.subobject_methods(
            FakeImage(vtables, code), self.functions, self.bases
        )
        return [(address, what, value) for address, what, value, _ in rows]

    def test_a_method_only_in_a_later_bases_table_has_this_there(self):
        self.assertEqual(
            self.found(
                [
                    (0x900, ".?AVDerived@@", 0, [0x20]),
                    (0x910, ".?AVDerived@@", 8, [0x10]),
                    (0x920, ".?AVMost@@", 8, [0x10]),
                ]
            ),
            [(0x10, "thisat", "Derived+0x8")],
        )

    def test_one_also_in_a_table_at_the_start_is_left(self):
        self.assertEqual(
            self.found(
                [
                    (0x900, ".?AVDerived@@", 0, [0x10]),
                    (0x910, ".?AVDerived@@", 8, [0x10]),
                ]
            ),
            [],
        )

    def test_an_adjustor_thunk_is_left_by_name_and_by_code(self):
        sub_ecx_jmp = b"\x83\xe9\x08\xe9\x00\x00\x00"
        self.assertEqual(
            self.found(
                [(0x910, ".?AVDerived@@", 8, [0x30, 0x40])], {0x40: sub_ecx_jmp}
            ),
            [],
        )

    def test_one_an_unrelated_class_holds_too_is_left(self):
        # The linker folds identical functions: the name is one class's.
        self.assertEqual(
            self.found(
                [
                    (0x910, ".?AVDerived@@", 8, [0x50]),
                    (0x930, ".?AVOther@@", 4, [0x50]),
                ]
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
