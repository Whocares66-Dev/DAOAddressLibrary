"""Tests for tools/libmatch.py's judgement, which needs neither the game nor
a library: how a symbol becomes a name, what counts as a function's bytes,
and what a matched pair's calls name.

    python -m unittest discover -s tools -p "test_*.py"
"""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import libmatch  # noqa: E402


class Plain(unittest.TestCase):
    def test_a_c_symbol_loses_its_decoration(self):
        self.assertEqual(libmatch.plain("_memcpy"), "memcpy")
        self.assertEqual(libmatch.plain("__CIcos"), "_CIcos")
        self.assertEqual(
            libmatch.plain("_FMOD_EventSystem_Create@4"), "FMOD_EventSystem_Create"
        )

    def test_a_member_is_written_with_its_class(self):
        self.assertEqual(
            libmatch.plain("?_Setgloballocale@locale@std@@CAXPAX@Z"),
            "std::locale::_Setgloballocale",
        )
        self.assertEqual(
            libmatch.plain("??0_Lockit@std@@QAE@H@Z"), "std::_Lockit::_Lockit"
        )
        self.assertEqual(
            libmatch.plain("??1locale@std@@QAE@XZ"), "std::locale::~locale"
        )
        self.assertEqual(libmatch.plain("??2@YAPAXI@Z"), "operator new")

    def test_an_import_or_a_name_it_cannot_read_is_none(self):
        self.assertIsNone(libmatch.plain("__imp__Sleep@4"))
        self.assertIsNone(
            libmatch.plain(
                "??$?6U?$char_traits@D@std@@@std@@YAAAV?$basic_ostream@D@0@AAV10@PBD@Z"
            )
        )


class Bytes(unittest.TestCase):
    code = b"\x55\x8b\xec\xe8\x11\x22\x33\x44\x5d\xc3"
    relocs = {4: (libmatch.REL32, "_callee")}

    def test_a_relocation_is_any_four_bytes(self):
        pattern = libmatch.pattern_of(self.code, self.relocs)
        self.assertTrue(pattern.match(b"\x55\x8b\xec\xe8\xaa\xbb\xcc\xdd\x5d\xc3"))
        self.assertFalse(pattern.match(b"\x55\x8b\xec\xe9\xaa\xbb\xcc\xdd\x5d\xc3"))
        self.assertFalse(pattern.match(self.code + b"\x90"))

    def test_two_functions_alike_but_for_what_they_call_are_one_shape(self):
        other = b"\x55\x8b\xec\xe8\x00\x00\x00\x00\x5d\xc3"
        self.assertEqual(
            libmatch.shape(self.code, self.relocs), libmatch.shape(other, self.relocs)
        )

    def test_one_function_of_the_build_for_one_of_the_library(self):
        lib = [
            ("_once", self.code * 2, {}),
            ("_twice", b"\x33\xc0" * 10, {}),
            ("_a", b"\x90" * 16 + b"\xc3", {}),
            ("_b", b"\x90" * 16 + b"\xc3", {}),
        ]
        body = {
            0x1000: self.code * 2,
            0x2000: b"\x33\xc0" * 10,
            0x3000: b"\x33\xc0" * 10,
            0x4000: b"\x90" * 16 + b"\xc3",
        }
        found, shared = libmatch.by_bytes(lib, body)
        # _twice is two functions of the build; _a and _b are one shape.
        self.assertEqual(found, {0x1000: ("_once", {})})
        self.assertEqual(shared, 2)


class Calls(unittest.TestCase):
    def test_what_a_matched_function_calls_is_what_the_library_says(self):
        code = b"\xe8" + struct.pack("<i", 0x2000 - 0x1005) + b"\xc3"
        direct = {0x1000: ("_caller", {1: (libmatch.REL32, "_callee")})}
        extra, clash = libmatch.by_calls(
            direct, {0x1000: code}, {0x1000: {}, 0x2000: {}}
        )
        self.assertEqual(extra, {0x2000: "_callee"})
        self.assertEqual(clash, [])

    def test_a_call_that_disagrees_with_a_match_is_said(self):
        code = b"\xe8" + struct.pack("<i", 0x2000 - 0x1005) + b"\xc3"
        direct = {
            0x1000: ("_caller", {1: (libmatch.REL32, "_callee")}),
            0x2000: ("_other", {}),
        }
        extra, clash = libmatch.by_calls(direct, {0x1000: code, 0x2000: b""}, {})
        self.assertEqual(extra, {})
        self.assertEqual(clash, [(0x2000, {"_callee": 1})])


class Archive(unittest.TestCase):
    def test_members_are_read_with_their_long_names(self):
        def member(name, body):
            head = (
                name.ljust(16).encode()
                + b" " * 32
                + str(len(body)).ljust(10).encode()
                + b"`\n"
            )
            return head + body + (b"\n" if len(body) & 1 else b"")

        names = b"a_very_long_member_name.obj\0"
        path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..",
            "build",
            "test_libmatch.lib",
        )
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(
                b"!<arch>\n"
                + member("/", b"\0\0\0\0")
                + member("//", names)
                + member("/0", b"abc")
                + member("short.obj/", b"de")
            )
        self.assertEqual(
            list(libmatch.members(path)),
            [("a_very_long_member_name.obj", b"abc"), ("short.obj", b"de")],
        )


if __name__ == "__main__":
    unittest.main()
