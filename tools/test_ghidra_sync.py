"""Tests for tools/ghidra_sync.py's side that needs no Ghidra: how a table
name becomes Ghidra's namespaces and leaf, which must be what DAOLib's
tools/names.py writes for its ImportNames.java, and how the work is read.

    python -m unittest discover -s tools -p "test_*.py"

ctest runs this too (tests/CMakeLists.txt).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ghidra_sync import ghidra_parts, work  # noqa: E402


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
