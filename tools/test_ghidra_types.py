"""Tests for tools/ghidra_types.py's side that needs no Ghidra: how a `type`
cell of data/structs.csv is read.

    python -m unittest discover -s tools -p "test_*.py"
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import structs  # noqa: E402
from ghidra_types import field_type  # noqa: E402


class FieldType(unittest.TestCase):
    def test_scalars_by_any_of_their_names(self):
        for text in ("int", "int32", "int32_t"):
            self.assertEqual(field_type(text), {"k": "scalar", "name": "int"})
        self.assertEqual(field_type("uint8_t"), {"k": "scalar", "name": "uchar"})
        self.assertEqual(field_type("const float"), {"k": "scalar", "name": "float"})

    def test_what_says_nothing_is_none(self):
        for text in ("struct", "undefined4", "?", ""):
            self.assertIsNone(field_type(text))

    def test_pointers_and_arrays_nest(self):
        self.assertEqual(
            field_type("CCVisualEffect**"),
            {
                "k": "ptr",
                "to": {
                    "k": "ptr",
                    "to": {
                        "k": "class",
                        "parts": ["CCVisualEffect"],
                        "text": "CCVisualEffect",
                    },
                },
            },
        )
        self.assertEqual(
            field_type("unsigned char[0x30]"),
            {"k": "array", "of": {"k": "scalar", "name": "uchar"}, "n": 48},
        )
        self.assertEqual(
            field_type("void*"), {"k": "ptr", "to": {"k": "scalar", "name": "void"}}
        )

    def test_a_class_keeps_its_namespaces_as_ghidra_holds_them(self):
        self.assertEqual(
            field_type("std::map<unsigned int,void*>")["parts"],
            ["std", "map<unsigned_int,void*>"],
        )
        self.assertEqual(
            field_type("SmartData::Attribute<ECBase::ECString>")["parts"],
            ["SmartData", "Attribute<ECBase.ECString>"],
        )

    def test_a_union_has_its_members(self):
        read = field_type("union{wchar_t[8] buf;wchar_t* ptr}")
        self.assertEqual(read["k"], "union")
        self.assertEqual([name for _, name in read["members"]], ["buf", "ptr"])
        self.assertEqual(read["members"][0][0]["n"], 8)
        self.assertEqual(read["members"][1][0]["k"], "ptr")

    def test_every_type_in_the_table_is_read(self):
        # None is a type that says nothing; anything else must be a tree.
        for row in structs.read():
            read = field_type(row["type"])
            self.assertTrue(read is None or "k" in read, row["type"])


if __name__ == "__main__":
    unittest.main()
