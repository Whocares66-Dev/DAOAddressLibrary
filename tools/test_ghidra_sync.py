"""Tests for tools/ghidra_sync.py's side that needs no Ghidra: how a table
name becomes Ghidra's namespaces and leaf, which must be what DAOLib's
tools/names.py writes for its ImportNames.java, and how the work is read.

    python -m unittest discover -s tools -p "test_*.py"

ctest runs this too (tests/CMakeLists.txt).
"""

import csv
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ghidra_sync import ghidra_c, ghidra_parts, work  # noqa: E402


class Parts(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(ghidra_parts("CCArea::AddObject"), ["CCArea", "AddObject"])
        self.assertEqual(ghidra_parts("g_hoverObject"), ["g_hoverObject"])

    def test_none_for_no_name(self):
        self.assertIsNone(ghidra_parts(""))

    def test_scope_inside_brackets_is_a_dot(self):
        self.assertEqual(
            ghidra_parts(
                "SmartData::Attribute<int,SmartData::NoMemberLookup,SmartData::InternalStorage,SmartData::ObserverNotification>::~Attribute"
            ),
            [
                "SmartData",
                "Attribute<int,SmartData.NoMemberLookup,SmartData.InternalStorage,SmartData.ObserverNotification>",
                "~Attribute",
            ],
        )

    def test_spaces_are_underscores(self):
        self.assertEqual(
            ghidra_parts("std::vector<unsigned short>::reserve"),
            ["std", "vector<unsigned_short>", "reserve"],
        )
        self.assertEqual(
            ghidra_parts("CameraControllerBase::`scalar deleting destructor'"),
            ["CameraControllerBase", "`scalar_deleting_destructor'"],
        )


class Fixes(unittest.TestCase):
    def test_every_line_is_four_cells(self):
        # A prototype holds commas: unquoted, it spills into the next cells
        # and the sync applies only its start.
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data",
            "ghidra_fixes.csv",
        )
        with open(path, newline="", encoding="utf-8") as f:
            for line, row in enumerate(csv.DictReader(f), start=2):
                self.assertNotIn(None, row, f"line {line} has more than four cells")
                self.assertTrue(row["why"], f"line {line} says no why")
                for cell in row.values():
                    self.assertFalse(
                        any(ord(c) < 32 for c in cell or ""),
                        f"line {line}: a control character",
                    )
                if row["what"] == "signature":
                    self.assertTrue(
                        row["value"].endswith(")"), f"line {line}: {row['value']}"
                    )


class CTypes(unittest.TestCase):
    def test_plain_c_is_left_alone(self):
        p = "bool __thiscall f(void *this, int *slot, void *name)"
        self.assertEqual(ghidra_c(p), p)

    def test_cpp_types_become_void_pointers(self):
        self.assertEqual(
            ghidra_c(
                "void __thiscall f(void *this, std::wstring const& name, GUI::Thing* t)"
            ),
            "void __thiscall f(void *this, void *name, void *t)",
        )

    def test_a_cpp_return_and_name(self):
        self.assertEqual(
            ghidra_c("std::vector<int>* __thiscall Foo::Bar(void *this, int n)"),
            "void * __thiscall f(void *this, int n)",
        )

    def test_template_commas_do_not_split(self):
        self.assertEqual(
            ghidra_c("void __cdecl f(std::map<int,int>* m, int x)"),
            "void __cdecl f(void *m, int x)",
        )


class Clears(unittest.TestCase):
    def test_a_clear_of_the_tables_own_name_is_dropped(self):
        rows, fixes = work()
        named = {}
        for _kind, address, parts in rows:
            if parts:
                named.setdefault(address, set()).update({"::".join(parts), parts[-1]})
        for address, what, value in fixes:
            if what == "clear":
                self.assertNotIn(value, named.get(address, set()), hex(address))


class Work(unittest.TestCase):
    def test_reads_the_table_and_the_fixes(self):
        rows, fixes = work(limit=10)
        self.assertEqual(len(rows), 10)
        for kind, address, _parts in rows:
            self.assertIn(kind, ("function", "data"))
            self.assertGreaterEqual(address, 0x00400000)
        for address, what, _value in fixes:
            self.assertGreaterEqual(address, 0x00400000)
            self.assertIn(what, ("convention", "signature", "clear"))


if __name__ == "__main__":
    unittest.main()
