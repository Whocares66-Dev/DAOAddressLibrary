"""Tests for tools/ghidra_sync.py's side that needs no Ghidra: how a table
name becomes Ghidra's namespaces and leaf, which must be what DAOLib's
tools/names.py writes for its ImportNames.java, and how the work is read.

    python -m unittest discover -s tools -p "test_*.py"

ctest runs this too (tests/CMakeLists.txt).
"""

import contextlib
import csv
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ghidra_sync  # noqa: E402
from ghidra_sync import ghidra_c, ghidra_parts, work  # noqa: E402


class Parts(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(ghidra_parts("CCArea::AddObject"), ["CCArea", "AddObject"])
        self.assertEqual(ghidra_parts("g_hoverObject"), ["g_hoverObject"])
        self.assertEqual(
            ghidra_parts("std::wstring::wstring(const std::wstring&)"),
            ["std", "wstring", "wstring(const_std.wstring&)"],
        )
        self.assertEqual(
            ghidra_parts("std::operator<(std::wstring const&,std::wstring const&)"),
            ["std", "operator<(std.wstring_const&,std.wstring_const&)"],
        )
        self.assertEqual(ghidra_parts("Functor::operator()"), ["Functor", "operator()"])

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

    def test_a_plain_return_is_kept_when_the_name_is_cpp(self):
        # 352 such fixes went in as void before 2026-11-05.
        self.assertEqual(
            ghidra_c("bool __thiscall Foo::IsSet(void *this, int n)"),
            "bool __thiscall f(void *this, int n)",
        )
        self.assertEqual(
            ghidra_c("unsigned int __cdecl Tactics::Bit(unsigned int type)"),
            "unsigned int __cdecl f(unsigned int type)",
        )
        self.assertEqual(
            ghidra_c("float Map<unsigned int, int>::Get(int key)"),
            "float f(int key)",
        )

    def test_a_pointer_to_a_plain_class_becomes_void_pointer(self):
        # Ghidra's parser knows no ECString (the sync of 2026-11-01 failed 13
        # prototypes on it); Windows' all-capital types it knows are kept.
        self.assertEqual(
            ghidra_c("void __thiscall f(void* this, ECString* name, HWND window)"),
            "void __thiscall f(void* this, void *name, HWND window)",
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
            self.assertIn(
                what,
                (
                    "convention",
                    "signature",
                    "clear",
                    "nofunction",
                    "returns",
                    "callfixup",
                    "datatype",
                    "returntype",
                    "registers",
                ),
            )

    def test_registers_rows_name_registers_and_a_stack(self):
        # eax,edx|8 or ecx|4c: registers, then what of the stack and who pops it.
        import re

        _rows, fixes = work()
        for _address, what, value in fixes:
            if what == "registers":
                self.assertRegex(
                    value, r"^(e[abcd]x|e[sd]i)(,(e[abcd]x|e[sd]i))*(\|\d+c?)?$"
                )
                self.assertTrue(
                    all(int(n) % 4 == 0 for n in re.findall(r"\|(\d+)", value))
                )

    def test_a_convention_is_one_ghidra_knows(self):
        # A note in the value ("__thiscall ret 0x18") fails in Ghidra.
        _rows, fixes = work()
        for address, what, value in fixes:
            if what == "convention":
                self.assertIn(
                    value,
                    ("__thiscall", "__stdcall", "__cdecl", "__fastcall"),
                    hex(address),
                )


class Options(unittest.TestCase):
    def test_a_word_it_does_not_know_starts_nothing(self):
        # main() asks the table and the server for nothing before this check,
        # so these return without either; --help once ran a whole sync.
        with contextlib.redirect_stdout(io.StringIO()) as said:
            for words in (["--help"], ["types"], ["--only"], ["--no-save", "--limit"]):
                self.assertEqual(ghidra_sync.main(words), 2, words)
        self.assertIn("--dry-run", said.getvalue())


if __name__ == "__main__":
    unittest.main()
