"""Tests for tools/ghidra_types.py's side that needs no Ghidra: how a `type`
cell of data/structs.csv is read.

    python -m unittest discover -s tools -p "test_*.py"
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import structs  # noqa: E402
from ghidra_types import field_type, template_of, with_instances  # noqa: E402


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


def row(struct, offset, size, kind, field):
    return {
        "struct": struct,
        "offset": offset,
        "size": size,
        "type": kind,
        "field": field,
        "evidence": "0x00401000",
    }


class Families(unittest.TestCase):
    table = (
        row("std::vector<T>", "0x0", "0x10", "struct", "sizeof"),
        row("std::vector<T>", "0x4", "0x4", "T*", "first"),
        row("Pair<K,V>", "0x0", "0x4", "K", "key"),
        row("Pair<K,V>", "0x4", "0x4", "V*", "value"),
        row("Holder", "0x0", "0x10", "std::vector<unsigned int>", "ids"),
        row("Holder", "0x10", "0x10", "std::vector<Pair<int,Thing>>", "pairs"),
        row("Holder", "0x20", "0x10", "std::vector<Known>", "known"),
        row("std::vector<Known>", "0x4", "0x4", "Known*", "begin"),
    )

    def made(self):
        out = with_instances(self.table)
        return {(r["struct"], r["field"]): r["type"] for r in out}

    def test_a_template_ends_in_its_arguments(self):
        self.assertEqual(
            template_of("std::map<unsigned int,std::vector<void*>>"),
            ("std::map", ["unsigned int", "std::vector<void*>"]),
        )
        self.assertIsNone(template_of("CCArea"))

    def test_an_instance_a_field_names_gets_the_familys_rows(self):
        made = self.made()
        self.assertEqual(made["std::vector<unsigned int>", "first"], "unsigned int*")
        self.assertEqual(made["std::vector<unsigned int>", "sizeof"], "struct")

    def test_what_an_instance_names_in_turn_is_made_too(self):
        made = self.made()
        self.assertEqual(
            made["std::vector<Pair<int,Thing>>", "first"], "Pair<int,Thing>*"
        )
        self.assertEqual(made["Pair<int,Thing>", "key"], "int")
        self.assertEqual(made["Pair<int,Thing>", "value"], "Thing*")

    def test_a_struct_with_rows_of_its_own_keeps_them(self):
        made = self.made()
        self.assertEqual(made["std::vector<Known>", "begin"], "Known*")
        self.assertNotIn(("std::vector<Known>", "first"), made)

    def test_the_familys_own_rows_are_not_sent(self):
        self.assertFalse(
            any("<T>" in struct or "<K,V>" in struct for struct, _ in self.made())
        )

    def test_a_table_with_no_family_is_as_it_was(self):
        plain = [r for r in self.table if r["struct"] == "Holder"]
        self.assertEqual(with_instances(plain), plain)


if __name__ == "__main__":
    unittest.main()
