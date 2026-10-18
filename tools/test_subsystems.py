"""Tests of tools/subsystems.py's placing, without the game: the rules, the
ranges, the vftable owners and the spreading along the call graph."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import subsystems  # noqa: E402

RULES = subsystems.Rules(
    [
        ("GUI::ScaleformManager", "GUI"),
        ("GFx*", "ThirdParty:Scaleform"),
        ("CCCreature", "Game"),
        ("CCObject", "Game"),
        ("ECString", "Core"),
        ("Renderer::*", "Rendering"),
    ]
)


class RulesTest(unittest.TestCase):
    def test_exact_and_prefix(self):
        self.assertEqual(RULES.subsystem("CCCreature"), "Game")
        self.assertEqual(RULES.subsystem("GFxMovieDef"), "ThirdParty:Scaleform")
        self.assertEqual(RULES.subsystem("Renderer::Mesh"), "Rendering")

    def test_exact_is_not_a_prefix(self):
        self.assertIsNone(RULES.subsystem("CCCreatureStats"))
        self.assertIsNone(RULES.subsystem(None))

    def test_owner_of_a_template_name(self):
        self.assertEqual(
            subsystems.owner_of("SmartData::Attribute<a::b,c>::Get"),
            "SmartData::Attribute<a::b,c>",
        )
        self.assertIsNone(subsystems.owner_of("_CIsqrt"))

    def test_owner_of_an_exported_name(self):
        owner = subsystems.owner_of
        self.assertEqual(owner("?Lock@GMutex@@QAEXXZ"), "GMutex")
        self.assertEqual(owner("??0GSysFile@@QAE@XZ"), "GSysFile")
        self.assertEqual(owner("??_FGMutex@@QAEXXZ"), "GMutex")
        self.assertEqual(owner("??EGSemaphore@@QAEHH@Z"), "GSemaphore")
        self.assertEqual(
            owner("?CallWaitHandlers@HandlerArray@GWaitable@@QAEXXZ"),
            "GWaitable::HandlerArray",
        )
        # A template scope is past what this reads.
        self.assertIsNone(owner("?Get@?$GArray@H@@QAEHXZ"))


class RangesTest(unittest.TestCase):
    def test_end_is_exclusive(self):
        ranges = [(0x100, 0x200, "ThirdParty:CRT"), (0x300, 0x400, "ThirdParty:zlib")]
        self.assertEqual(subsystems.in_ranges(ranges, 0x100), "ThirdParty:CRT")
        self.assertEqual(subsystems.in_ranges(ranges, 0x1FF), "ThirdParty:CRT")
        self.assertIsNone(subsystems.in_ranges(ranges, 0x200))
        self.assertIsNone(subsystems.in_ranges(ranges, 0x50))
        self.assertEqual(subsystems.in_ranges(ranges, 0x350), "ThirdParty:zlib")


class SetsVftableTest(unittest.TestCase):
    def test_into_this_but_not_into_the_frame(self):
        sets = subsystems.sets_vftable
        self.assertTrue(sets("mov", "dword ptr [esi], 0xb05dbc"))
        self.assertTrue(sets("mov", "dword ptr [ecx + 0x34], 0xb05dfc"))
        self.assertFalse(sets("mov", "dword ptr [esp + 0x18], 0xb05dbc"))
        self.assertFalse(sets("mov", "dword ptr [ebp - 0x40], 0xb05dbc"))
        self.assertFalse(sets("push", "0xb05dbc"))
        self.assertFalse(sets("cmp", "dword ptr [esi], 0xb05dbc"))


class PlaceTest(unittest.TestCase):
    def place(
        self,
        functions,
        calls=None,
        imports=None,
        vtables=(),
        ranges=(),
        writes=None,
        owned=None,
        refs=None,
        strings=None,
    ):
        calls = calls or {va: set() for va in functions}
        reading = subsystems.Reading(
            calls, imports, vtables, writes, owned, refs, strings
        )
        return subsystems.place(functions, reading, RULES, list(ranges))

    def test_a_name_outranks_a_vtable(self):
        out = self.place(
            {1: "CCCreature::Kill"},
            vtables=[("GFxMovieDef", set(), [1])],
        )
        self.assertEqual(out[1], ("Game", "name", "CCCreature"))

    def test_the_base_class_owns_an_inherited_slot(self):
        out = self.place(
            {1: ""},
            vtables=[("CCObject", set(), [1]), ("CCCreature", {"CCObject"}, [1])],
        )
        self.assertEqual(out[1], ("Game", "vtable", "CCObject"))

    def test_owners_that_disagree_place_nothing(self):
        # A stub the linker shares among unrelated classes' vftables.
        out = self.place(
            {1: ""},
            vtables=[("CCObject", set(), [1]), ("GFxMovieDef", set(), [1])],
        )
        self.assertEqual(out[1], ("unknown", "", ""))

    def test_a_constructor_is_its_most_derived_class(self):
        out = self.place(
            {1: "", 2: ""},
            vtables=[("CCObject", set(), []), ("CCCreature", {"CCObject"}, [])],
            writes={1: {"CCObject", "CCCreature"}, 2: {"CCCreature", "GFxMovieDef"}},
        )
        self.assertEqual(out[1], ("Game", "builds", "CCCreature"))
        # Two unrelated classes: no one class it builds.
        self.assertEqual(out[2], ("unknown", "", ""))

    def test_a_dll_places_its_callers(self):
        out = self.place(
            {1: "", 2: ""}, imports={1: {"fmodex.dll"}, 2: {"kernel32.dll"}}
        )
        self.assertEqual(out[1][:2], ("Audio", "import"))
        self.assertEqual(out[2][:2], ("unknown", ""))

    # Functions 0x100 apart: none of them is too small for its vote to count.
    A, B, C, D, E, F = (0x100 * k for k in range(1, 7))

    def test_callers_spread_one_step(self):
        A, B, C, D = self.A, self.B, self.C, self.D
        functions = {A: "CCCreature::A", B: "", C: "", D: ""}
        calls = {A: {B}, B: {C}, C: set(), D: set()}
        out = self.place(functions, calls)
        # B's one caller is Game; C's only caller, B, is Game only by B's caller.
        self.assertEqual(out[B][:2], ("Game", "callers"))
        self.assertEqual(out[C][:2], ("unknown", ""))

    def test_callees_need_two_votes(self):
        A, B, C, D, E = self.A, self.B, self.C, self.D, self.E
        functions = {A: "CCCreature::A", B: "CCObject::B", C: "", D: "", E: ""}
        calls = {A: set(), B: set(), C: {A, B}, D: {A}, E: set()}
        out = self.place(functions, calls)
        self.assertEqual(out[C][:2], ("Game", "callees"))
        self.assertEqual(out[D][:2], ("unknown", ""))

    def test_a_class_votes_once(self):
        A, B, C = self.A, self.B, self.C
        functions = {A: "CCCreature::A", B: "CCCreature::B", C: ""}
        calls = {A: set(), B: set(), C: {A, B}}
        self.assertEqual(self.place(functions, calls)[C][:2], ("unknown", ""))

    def test_a_tiny_callee_does_not_vote(self):
        # 0x101 is one byte long: a getter the linker may share.
        functions = {0x100: "CCCreature::A", 0x101: "CCObject::B", 0x200: "", 0x300: ""}
        calls = {0x100: set(), 0x101: set(), 0x200: {0x100, 0x101}, 0x300: set()}
        self.assertEqual(self.place(functions, calls)[0x200][:2], ("unknown", ""))

    def test_core_and_scripting_do_not_vote(self):
        A, B, C, D = self.A, self.B, self.C, self.D
        functions = {A: "ECString::A", B: "ScriptCommand::B", C: "", D: ""}
        calls = {A: set(), B: {D}, C: {A, B}, D: set()}
        out = self.place(functions, calls)
        self.assertEqual(out[C][:2], ("unknown", ""))
        # D is a script command's engine function: its caller says nothing.
        self.assertEqual(out[D][:2], ("unknown", ""))

    def test_an_unplaced_caller_holds_it_back(self):
        A, B, C = self.A, self.B, self.C
        functions = {A: "CCCreature::A", B: "", C: ""}
        calls = {A: {B}, B: set(), C: {B}}
        self.assertEqual(self.place(functions, calls)[B][:2], ("unknown", ""))

    def test_a_callback_goes_where_its_address_is_held(self):
        A, B = self.A, self.B
        functions = {A: "CCCreature::A", B: ""}
        out = self.place(functions, refs={A: {B}})
        self.assertEqual(out[B][:2], ("Game", "pointer"))

    def test_a_library_string_and_its_callers(self):
        A, B, C = self.A, self.B, self.C
        functions = {A: "", B: "", C: ""}
        calls = {A: set(), B: {A}, C: set()}
        out = self.place(functions, calls, strings={A: {"ThirdParty:STL"}})
        self.assertEqual(out[A][:2], ("ThirdParty:STL", "string"))
        self.assertEqual(out[B][:2], ("ThirdParty:STL", "string"))

    def test_calling_eas_online_library_is_online(self):
        A, B = self.A, self.B
        functions = {A: "", B: ""}
        calls = {A: set(), B: {A}}
        out = self.place(functions, calls, ranges=[(A, B, "ThirdParty:Fesl")])
        self.assertEqual(out[B][:2], ("Online", "import"))

    def test_a_funclet_goes_with_its_function(self):
        # 2 is 1's unwind funclet, in the compiler's range, and calls 3 for
        # 1; 4 is a funclet of an unplaced function, 5.
        functions = {1: "CCCreature::A", 2: "", 3: "", 4: "", 5: ""}
        calls = {1: set(), 2: {3}, 3: set(), 4: set(), 5: set()}
        out = self.place(
            functions,
            calls,
            owned={2: 1, 4: 5},
            ranges=[(2, 5, "Compiler:EHFunclets")],
        )
        self.assertEqual(out[2], ("Game", "owner", "CCCreature"))
        self.assertEqual(out[3][:2], ("Game", "callers"))
        self.assertEqual(out[4][:2], ("Compiler:EHFunclets", "range"))

    def test_callers_that_disagree_place_nothing(self):
        functions = {1: "CCCreature::A", 2: "Renderer::Mesh::B", 3: ""}
        calls = {1: {3}, 2: {3}, 3: set()}
        self.assertEqual(self.place(functions, calls)[3][:2], ("unknown", ""))


if __name__ == "__main__":
    unittest.main()
