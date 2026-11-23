"""Tests for tools/evidence.py's judgement, which needs neither the game nor a
library: how names compare and which mark a proof gives.

    python -m unittest discover -s tools -p "test_*.py"
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evidence  # noqa: E402


def judge(name, length=100, own=None, lib=None, stl=None, classes=None):
    return evidence.judge(
        name, 0x1000, length, own or {}, lib or {}, stl or {}, classes or {}
    )


class Bare(unittest.TestCase):
    def test_a_string_is_its_basic_string(self):
        self.assertEqual(
            evidence.bare("std::wstring::~wstring"),
            evidence.bare(
                "std::basic_string<wchar_t,std::char_traits<wchar_t>,ECMemory::StringAllocator<wchar_t>>::~basic_string"
            ),
        )

    def test_a_map_is_its_tree(self):
        self.assertEqual(
            evidence.bare("std::map<?,?>::_Buynode"),
            evidence.bare("std::_Tree<std::wstring>::_Buynode"),
        )

    def test_parameters_and_underscores_go(self):
        self.assertEqual(evidence.bare("A::f(int,const B&)"), "A::f")
        self.assertEqual(evidence.bare("__vswprintf"), "vswprintf")


class Judge(unittest.TestCase):
    def test_the_build_s_own_reading_comes_first(self):
        own = {0x1000: ("export", "GSysFile::IsValid")}
        self.assertEqual(judge("GSysFile::IsValid", own=own)[0], "export")
        self.assertEqual(judge("GDelegatedFile::IsValid", own=own)[0], "inferred")

    def test_bytes_prove_a_name_and_not_another(self):
        lib = {
            0x1000: [{"how": "bytes", "symbol": "_strtoul", "library": "libcmt.lib"}]
        }
        self.assertEqual(judge("strtoul", lib=lib)[0], "bytes")
        mark, detail = judge("Engine::Parse", lib=lib)
        self.assertEqual(mark, "inferred")
        self.assertIn("strtoul", detail)

    def test_short_code_proves_nothing_alone(self):
        lib = {
            0x1000: [{"how": "bytes", "symbol": "_strtoul", "library": "libcmt.lib"}]
        }
        self.assertEqual(judge("strtoul", length=19, lib=lib)[0], "short")

    def test_a_slot_proves_the_class_only(self):
        classes = {0x1000: {"CResGFF"}}
        self.assertEqual(judge("CResGFF::~CResGFF", classes=classes)[0], "vftable")
        self.assertEqual(judge("CResLST::~CResLST", classes=classes)[0], "inferred")

    def test_a_recorded_fold_contradicts_nothing(self):
        own = {0x1000: ("export", "GSysFile::IsValid")}
        mark, detail = evidence.judge(
            "GDelegatedFile::IsValid",
            0x1000,
            100,
            own,
            {},
            {},
            {},
            ["GSysFile::IsValid"],
        )
        self.assertEqual(
            (mark, detail), ("inferred", "export proves the fold GSysFile::IsValid")
        )

    def test_nothing_is_inferred(self):
        self.assertEqual(judge("Anything::AtAll"), ("inferred", ""))


if __name__ == "__main__":
    unittest.main()
