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


if __name__ == "__main__":
    unittest.main()
