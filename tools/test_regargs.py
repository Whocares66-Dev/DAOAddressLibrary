"""Tests for regargs.py: register arguments read from bytes alone."""

import unittest

import regargs


class Image:
    """Functions laid out at their addresses, and the calls among them."""

    def __init__(self, functions):
        self.functions = functions
        self.calls = {}
        for va, code in functions.items():
            for k in range(len(code) - 4):
                if code[k] == 0xE8:
                    target = (
                        va
                        + k
                        + 5
                        + int.from_bytes(code[k + 1 : k + 5], "little", signed=True)
                    )
                    self.calls.setdefault(target, []).append(va + k)

    def bytes_at(self, va, n):
        out = bytearray(b"\xcc" * n)
        for start, code in self.functions.items():
            for i in range(n):
                if start <= va + i < start + len(code):
                    out[i] = code[va + i - start]
        return bytes(out)

    def code_callers(self, va):
        return self.calls.get(va, [])


def call(at, target):
    return b"\xe8" + (target - at - 5).to_bytes(4, "little", signed=True)


def reader(functions):
    return regargs.Reader(
        Image(functions), dict(functions), {va: "" for va in functions}
    )


class LiveIn(unittest.TestCase):
    def test_read_before_written(self):
        # mov eax, [edx+4]; ret
        r = reader({0x1000: b"\x8b\x42\x04\xc3"})
        self.assertEqual(set(r.live_in(0x1000)), {"edx"})

    def test_written_first_is_no_argument(self):
        # xor eax, eax; mov ecx, [esp+4]; mov eax, [ecx]; ret
        r = reader({0x1000: b"\x33\xc0\x8b\x4c\x24\x04\x8b\x01\xc3"})
        self.assertEqual(set(r.live_in(0x1000)), set())

    def test_saving_is_no_use_but_a_later_read_is(self):
        # push esi; mov eax, [esi]; pop esi; ret
        r = reader({0x1000: b"\x56\x8b\x06\x5e\xc3"})
        self.assertEqual(set(r.live_in(0x1000)), {"esi"})
        # push esi; mov esi, [esp+8]; mov eax, esi; pop esi; ret
        r = reader({0x1000: b"\x56\x8b\x74\x24\x08\x8b\xc6\x5e\xc3"})
        self.assertEqual(set(r.live_in(0x1000)), set())

    def test_handed_on_to_a_callee(self):
        # 0x2000: mov eax, [ecx]; ret.  0x1000: call 0x2000; ret
        callee = b"\x8b\x01\xc3"
        r = reader({0x2000: callee, 0x1000: call(0x1000, 0x2000) + b"\xc3"})
        self.assertEqual(set(r.live_in(0x1000)), {"ecx"})


class Callers(unittest.TestCase):
    def test_every_caller_loads_it(self):
        callee = b"\x8b\x42\x04\xc3"  # mov eax, [edx+4]; ret
        caller = (
            b"\xba\x10\x00\x00\x00" + call(0x3005, 0x1000) + b"\xc3"
        )  # mov edx, 16; call
        r = reader({0x1000: callee, 0x3000: caller})
        taken, told = r.arguments(0x1000)
        self.assertEqual(taken, ["edx"])
        self.assertEqual(told["edx"], (1, 1))

    def test_a_caller_that_does_not_load_it(self):
        callee = b"\x8b\x42\x04\xc3"
        caller = (
            b"\x6a\x01" + call(0x3002, 0x1000) + b"\xc3"
        )  # push 1; call: edx not loaded
        r = reader({0x1000: callee, 0x3000: caller})
        self.assertEqual(r.arguments(0x1000)[0], [])


class Stack(unittest.TestCase):
    def test_ret_n_is_what_the_function_pops(self):
        r = reader({0x1000: b"\x8b\x42\x04\xc2\x08\x00"})  # mov eax, [edx+4]; ret 8
        self.assertEqual(r.stack(0x1000)[0], "|8")

    def test_add_esp_after_the_call_is_what_the_caller_pops(self):
        callee = b"\x8b\x42\x04\xc3"
        caller = (
            b"\x6a\x01" + call(0x3002, 0x1000) + b"\x83\xc4\x04\xc3"
        )  # push 1; call; add esp, 4
        r = reader({0x1000: callee, 0x3000: caller})
        self.assertEqual(r.stack(0x1000)[0], "|4c")

    def test_pushes_before_any_call_are_not_counted(self):
        callee = b"\x8b\x42\x04\xc3"
        caller = (
            b"\x56\x6a\x01" + call(0x3003, 0x1000) + b"\x5e\xc3"
        )  # push esi; push 1; call
        r = reader({0x1000: callee, 0x3000: caller})
        self.assertEqual(r.stack(0x1000)[0], "")


if __name__ == "__main__":
    unittest.main()
