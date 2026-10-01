"""Tests for tools/msvc_names.py, over names taken from DAOrigins.exe's RTTI.

    python -m unittest discover -s tools -p "test_*.py"

ctest runs this too (tests/CMakeLists.txt).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from msvc_names import parse, split_top, template_args, undecorate  # noqa: E402


class Plain(unittest.TestCase):
    def test_class_struct_enum(self):
        self.assertEqual(parse(".?AVAbility@@"), "Ability")
        self.assertEqual(parse(".?AUPod@@"), "Pod")
        self.assertEqual(parse(".?AW4Mode@@"), "Mode")

    def test_namespaces_innermost_first(self):
        self.assertEqual(parse(".?AVScaleformManager@GUI@@"), "GUI::ScaleformManager")
        self.assertEqual(
            parse(".?AVActionRotate@Actor@Cutscene@EC@@"),
            "EC::Cutscene::Actor::ActionRotate",
        )


class Templates(unittest.TestCase):
    PAUSE = (
        ".?AV?$MemberFunctionMessageHandler@VGameModeController@@VUserTogglePauseMessage@@"
        "$H?HandleMessage@1@QAE_NABV2@@ZA@@Private@Messages@@"
    )

    def test_member_function_pointer_argument(self):
        self.assertEqual(
            parse(self.PAUSE),
            "Messages::Private::MemberFunctionMessageHandler"
            "<GameModeController,UserTogglePauseMessage,&GameModeController::HandleMessage>",
        )

    def test_template_args_split_at_top_level(self):
        name = parse(self.PAUSE)
        self.assertEqual(
            template_args(name),
            [
                "GameModeController",
                "UserTogglePauseMessage",
                "&GameModeController::HandleMessage",
            ],
        )

    def test_integer_and_type_arguments(self):
        self.assertEqual(parse(".?AV?$Holder@H$0BA@@@"), "Holder<int,16>")
        self.assertEqual(parse(".?AV?$Holder@PAVThing@@@@"), "Holder<Thing*>")

    def test_split_top_ignores_template_brackets(self):
        self.assertEqual(
            split_top("A::B<C::D,E>::vftable"),
            ["A", "B<C::D,E>", "vftable"],
        )


class Fallback(unittest.TestCase):
    def test_unknown_mangling_returns_the_input(self):
        self.assertEqual(undecorate("Ability"), "Ability")
        self.assertEqual(undecorate(".?AV?$Broken@$$QAH@@"), ".?AV?$Broken@$$QAH@@")
        with self.assertRaises(ValueError):
            parse("Ability")


if __name__ == "__main__":
    unittest.main()
