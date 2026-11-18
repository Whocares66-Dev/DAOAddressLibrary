"""Tests for tools/vtables_dump.py's judgement, which needs no game: which
table a table continues, and which class declared and defined each slot.

    python -m unittest discover -s tools -p "test_*.py"
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vtables_dump  # noqa: E402

# Base has two slots. Side has one, and Derived holds it at +8. Derived
# overrides Base's second slot and adds a third; in Side's table at +8 it
# overrides the one slot. Lone's base has no table of its own in the exe.
KNOWN = {
    "Base": ({0: (0x100, [0x10, 0x11])}, [("Base", 0, 0, False)]),
    "Side": ({0: (0x200, [0x20])}, [("Side", 0, 0, False)]),
    "Derived": (
        {0: (0x300, [0x10, 0x31, 0x32]), 8: (0x310, [0x33])},
        [("Derived", 0, 2, False), ("Base", 0, 0, False), ("Side", 8, 0, False)],
    ),
    "Most": (
        {0: (0x400, [0x10, 0x31, 0x32]), 8: (0x410, [0x43])},
        [
            ("Most", 0, 3, False),
            ("Derived", 0, 2, False),
            ("Base", 0, 0, False),
            ("Side", 8, 0, False),
        ],
    ),
    "Lone": ({0: (0x500, [0x50])}, [("Lone", 0, 1, False), ("Abstract", 0, 0, False)]),
    "Through": (
        {4: (0x600, [0x60])},
        [("Through", 0, 1, False), ("Base", 0, 0, True)],
    ),
}


class Tables(unittest.TestCase):
    def test_a_table_continues_the_most_derived_base_at_its_place(self):
        self.assertEqual(vtables_dump.extends(KNOWN, "Derived", 0), ("Base", 0))
        self.assertEqual(vtables_dump.extends(KNOWN, "Derived", 8), ("Side", 0))
        self.assertEqual(vtables_dump.extends(KNOWN, "Most", 8), ("Derived", 8))
        self.assertIsNone(vtables_dump.extends(KNOWN, "Base", 0))

    def test_an_inherited_an_overridden_and_an_added_slot(self):
        self.assertEqual(
            vtables_dump.origins(KNOWN, "Derived", 0),
            [("Base", "Base"), ("Base", "Derived"), ("Derived", "Derived")],
        )
        self.assertEqual(
            vtables_dump.origins(KNOWN, "Derived", 8), [("Side", "Derived")]
        )

    def test_what_a_base_set_is_that_bases_two_classes_down(self):
        self.assertEqual(
            vtables_dump.origins(KNOWN, "Most", 0),
            [("Base", "Base"), ("Base", "Derived"), ("Derived", "Derived")],
        )
        self.assertEqual(vtables_dump.origins(KNOWN, "Most", 8), [("Side", "Most")])

    def test_a_base_with_no_table_declares_nothing(self):
        self.assertEqual(vtables_dump.origins(KNOWN, "Lone", 0), [("Lone", "Lone")])

    def test_a_virtual_base_leaves_the_origin_unsaid(self):
        self.assertIsNone(vtables_dump.extends(KNOWN, "Through", 4))
        self.assertEqual(vtables_dump.origins(KNOWN, "Through", 4), [(None, None)])

    def test_the_record(self):
        made = vtables_dump.record(KNOWN, "Most", {0x43: "Most::Fly"})
        self.assertEqual(
            made["bases"],
            [
                {"class": "Derived", "offset": 0, "direct": True, "virtual": False},
                {"class": "Base", "offset": 0, "direct": False, "virtual": False},
                {"class": "Side", "offset": 8, "direct": False, "virtual": False},
            ],
        )
        self.assertEqual([t["extends"] for t in made["vftables"]], ["Derived"] * 2)
        self.assertEqual(
            made["vftables"][1]["slots"],
            [
                {
                    "slot": 0,
                    "offset": "0x0",
                    "function": "0x00000043",
                    "name": "Most::Fly",
                    "declared": "Side",
                    "defined": "Most",
                }
            ],
        )
        self.assertIsNone(made["vftables"][0]["slots"][2]["name"])
        self.assertEqual(made["vftables"][0]["slots"][2]["offset"], "0x8")


class InheritedNames(unittest.TestCase):
    def test_a_slot_takes_the_one_name_its_overrides_go_by(self):
        # Base's second slot (0x11) has no name; Derived's and Most's tables
        # hold Derived::Walk there.
        names = {0x10: "Base::Stand", 0x31: "Derived::Walk", 0x43: "Most::Fly"}
        self.assertEqual(
            vtables_dump.inherited_names(KNOWN, names),
            {
                0x100: {1: ("Walk", [0x31])},
                0x200: {0: ("Fly", [0x43])},
                0x310: {0: ("Fly", [0x43])},
            },
        )

    def test_overrides_that_disagree_name_nothing(self):
        names = {0x33: "Derived::Swim", 0x43: "Most::Fly"}
        self.assertEqual(vtables_dump.inherited_names(KNOWN, names), {})

    def test_a_named_slot_keeps_its_name(self):
        names = {0x11: "Base::Run", 0x31: "Derived::Walk"}
        self.assertEqual(vtables_dump.inherited_names(KNOWN, names), {})

    def test_a_destructor_and_folded_code_say_nothing(self):
        for name in ("Derived::`scalar deleting destructor'", "Stub::ReturnFalse"):
            self.assertEqual(vtables_dump.inherited_names(KNOWN, {0x31: name}), {})


class Files(unittest.TestCase):
    def test_a_class_is_its_file(self):
        self.assertEqual(
            vtables_dump.file_name("AIMaster::LevelList", 0), "AIMaster__LevelList.json"
        )
        self.assertEqual(
            vtables_dump.file_name("std::map<unsigned int,void*>", 0),
            "std__map_unsigned int,void__.json",
        )

    def test_a_long_name_is_cut_and_ends_in_its_table(self):
        name = vtables_dump.file_name("A" * 200, 0xB0ED8C)
        self.assertEqual(name, "A" * 150 + "@00B0ED8C.json")


if __name__ == "__main__":
    unittest.main()
