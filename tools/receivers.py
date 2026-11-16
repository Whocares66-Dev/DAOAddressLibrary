"""What a global holds and what a function returns, read from what they are
passed to: types tools/ghidra_sync.py gives them in Ghidra.

    python tools/receivers.py            what the GOG build says, and what it does not settle

It also reads which methods are called with this inside their object
(`thisat`): subobject_methods says how.

A method takes its object in ECX. So where the code loads ECX and calls a
class's method with nothing between that writes ECX, what was loaded is an
object of that class:

    mov ecx, [G]      / call X::m    G holds an X*        `datatype`   X *
    mov ecx, offset G / call X::m    G is an X            `datatype`   X
    call F / mov ecx, eax / call X::m    F returns an X*  `returntype` X *

Ghidra's decompiler follows a type from where it is applied, and an
untyped global or getter stops it: `(**(code **)(*g_graphics + 0x10))()`
is `g_graphics->vftablePtr->Shutdown()` once g_graphics is an
Eclipse::IGraphicsInternal *. The user, 2026-11-16: "Consider what other
information we can feed into ghidra so it produces better decompilations."

What counts, so that a row is read and not guessed:

- the callee is a function the table names in a class the build's RTTI
  knows, and its convention is not known to be other than __thiscall;
- the callee is 32 bytes or more. The linker folds identical functions
  into one, and the small ones (a getter, an empty virtual) are the ones
  that are identical across classes: MessageRegistry::Get is every
  singleton's getter, 314 calls for 20 classes, and one such call made
  g_clientExoApp a ModuleResourceManager against 55 that did not;
- two different callees at least say so. One is not enough: __RTDynamicCast
  returned a Renderer::FBFloat32Resource on the word of one call. The
  exception is a global the class's own constructor is called on, which
  is an object of that class whatever else is done with it;
- every class seen for one global or function is one line of inheritance,
  and the type is the most derived of them (an object passed to its
  class's methods and its bases'). Two unrelated classes settle nothing
  and give no row;
- a global that is an object has room: no other name before its end.
  That needs the class's size, which Ghidra has, so tools/ghidra_sync.py
  checks it when it applies the row.

Nothing here is stored: the code and the table's names say it again at
each sync, so a class the table renames takes its globals with it. A
`datatype` or `returntype` row a reader writes in data/ghidra_fixes.csv for
the same address stands in place of what this finds.
"""

import collections
import csv
import os
import re
import sys

import addrlib
import daoexe
import msvc_names
import subsystems

BUILD = "gog-1.05"
FIXES = os.path.join(subsystems.REPO, "data", "ghidra_fixes.csv")
SMALL = 32
WRITES_ECX = re.compile(r"^(e?cx|cl|ch)\b")
WRITES_EAX = re.compile(r"^(e?ax|al|ah)\b")
READ_ONLY = ("cmp", "test", "push")


def conventions():
    """{address: convention} of the fixes that give one."""
    out = {}
    with open(FIXES, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            address = int(row["address"], 16)
            if row["what"] == "convention":
                out[address] = row["value"]
            elif row["what"] == "signature":
                found = re.search(r"__(thiscall|stdcall|cdecl|fastcall)", row["value"])
                if found:
                    out[address] = found.group(0)
    return out


def class_bases(img):
    """{class: its bases} of the build's RTTI."""
    bases = {}
    for _vftable, decorated, _offset, _table in img.vtables:
        cls = msvc_names.undecorate(decorated)
        if cls not in bases:
            found = img.bases(decorated) or []
            bases[cls] = {msvc_names.undecorate(b) for b, _, _ in found[1:] if b != "?"}
    return bases


class Evidence:
    """{key: {class: set of callees}} for each of the three patterns."""

    def __init__(self):
        self.pointer = collections.defaultdict(lambda: collections.defaultdict(set))
        self.object = collections.defaultdict(lambda: collections.defaultdict(set))
        self.returns = collections.defaultdict(lambda: collections.defaultdict(set))


def source_of(mnemonic, op, text_end, eax_from):
    """What an instruction puts in ECX that this reads: (table, key), None
    if it writes ECX some other way, or False if it leaves ECX alone."""
    if mnemonic == "mov" and op.startswith("ecx, dword ptr [0x") and op.endswith("]"):
        return ("pointer", int(op[len("ecx, dword ptr [") : -1], 16))
    if mnemonic == "mov" and re.fullmatch(r"ecx, 0x[0-9a-f]+", op):
        address = int(op[5:], 16)
        return ("object", address) if address >= text_end else None
    if mnemonic == "mov" and op == "ecx, eax" and eax_from is not None:
        return ("returns", eax_from)
    if WRITES_ECX.match(op) and mnemonic not in READ_ONLY:
        return None
    return False


def scan(img, functions, owner):
    """The evidence of every function's code. owner: {callee: its class},
    of the callees that count."""
    import capstone

    text_start, text_end, _ = img.section(".text")
    starts = sorted(functions)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    found = Evidence()
    for i, va in enumerate(starts):
        end = min(starts[i + 1] if i + 1 < len(starts) else text_end, va + 0x8000)
        source, eax_from = None, None
        for ins in md.disasm(img.bytes_at(va, end - va), va):
            mnemonic, op = ins.mnemonic, ins.op_str
            if mnemonic in ("call", "jmp") and op.startswith("0x"):
                target = int(op, 16)
                if source and target in owner:
                    getattr(found, source[0])[source[1]][owner[target]].add(target)
                source = None
                eax_from = (
                    target if mnemonic == "call" and target in functions else None
                )
            elif (
                mnemonic in ("call", "ret")
                or mnemonic[0] == "j"
                or mnemonic.startswith("loop")
            ):
                source, eax_from = None, None
            else:
                loaded = source_of(mnemonic, op, text_end, eax_from)
                if loaded is not False:
                    source = loaded
                if WRITES_EAX.match(op) and mnemonic not in READ_ONLY:
                    eax_from = None
    return found


def read():
    """(evidence, bases, functions {va: (id, name)}, data names {va: name})."""
    db = addrlib.Database.load()
    functions = subsystems.gog_functions(db)
    build = next(b for b in db.builds if b["key"] == BUILD)
    img = daoexe.Image(os.path.join(subsystems.REPO, build["image"]))
    bases = class_bases(img)
    conv = conventions()
    starts = sorted(functions)
    _, text_end, _ = img.section(".text")
    owner = {}
    for i, va in enumerate(starts):
        size = (starts[i + 1] if i + 1 < len(starts) else text_end) - va
        cls = subsystems.owner_of(functions[va][1])
        if (
            cls in bases
            and size >= SMALL
            and conv.get(va, "__thiscall") == "__thiscall"
        ):
            owner[va] = cls
    names = {
        row.addresses.get(BUILD): row.name
        for row in db.rows.values()
        if row.kind == "data" and row.name
    }
    return scan(img, functions, owner), bases, functions, names, img


# `sub ecx, N` or `add ecx, N`, then a jump: a thunk that moves this from
# a base to the object and goes on to the method.
ADJUSTOR = re.compile(rb"(\x83[\xe9\xc1].|\x81[\xe9\xc1].{4})\xe9", re.S)


def subobject_methods(img, functions, bases):
    """[(address, "thisat", "Class+0xN", why)]: the methods whose this points
    N bytes into their object.

    A class with several bases has a vftable for each, and a method it
    overrides in a later base's table is called with this at that base:
    CCObject::QueueEffectAnimation, in CCObject's table at +0x70, reads the
    object's effect list at [ecx+0xE8], which is CCObject +0x158. Ghidra
    gives every method of a class a this at the object's start, so it showed
    that read as a field 0x70 bytes before the right one, by name.

    What counts: the table names the function in a class; that class holds
    it in vftables at one offset, not 0; every other class holding it
    derives from that one; no class holds it in a table at +0, where this
    would be the object; and it is not an adjustor thunk, which is in such
    a table to move this back."""
    held = collections.defaultdict(set)
    for _vftable, decorated, offset, table in img.vtables:
        cls = msvc_names.undecorate(decorated)
        for function in table:
            held[function].add((cls, offset))
    out = []
    for address, places in sorted(held.items()):
        name = functions.get(address, (None, None))[1]
        owner = subsystems.owner_of(name)
        if owner is None or "adjustor{" in name:
            continue
        if ADJUSTOR.match(img.bytes_at(address, 7)):
            continue
        offsets = {offset for cls, offset in places if cls == owner}
        others = {cls for cls, _ in places if cls != owner}
        if (
            len(offsets) != 1
            or any(offset == 0 for _, offset in places)
            or any(owner not in bases.get(cls, ()) for cls in others)
        ):
            continue
        (offset,) = offsets
        out.append(
            (
                address,
                "thisat",
                f"{owner}+0x{offset:X}",
                f"in {owner}'s vftable at +0x{offset:X} and in none at +0",
            )
        )
    return out


def is_constructor(name, cls):
    """Whether a function's name is that of the class's constructor."""
    if name.startswith("??0"):
        return subsystems.owner_of(name) == cls
    leaf = msvc_names.split_top(cls)[-1]
    return name == f"{cls}::{leaf}"


def rows(found, bases, functions, names, img=None):
    """(settled rows [(address, what, value, why)], unsettled lines)."""
    settled, unsettled = [], []
    for table, what, form, noun in (
        (found.pointer, "datatype", "{} *", "holds a pointer passed"),
        (found.object, "datatype", "{}", "is an object passed"),
        (found.returns, "returntype", "{} *", "returns a pointer passed"),
    ):
        for key in sorted(table):
            seen = table[key]
            cls = subsystems.most_derived(set(seen), bases)
            label = (
                functions[key][1] if what == "returntype" else names.get(key)
            ) or f"0x{key:08X}"
            if cls is None:
                counts = ", ".join(f"{c} {len(s)}" for c, s in sorted(seen.items()))
                unsettled.append(f"0x{key:08X} {label}: {counts}")
                continue
            callees = sorted({callee for held in seen.values() for callee in held})
            built = table is found.object and any(
                is_constructor(functions[c][1], cls) for c in seen.get(cls, ())
            )
            if len(callees) < 2 and not built:
                unsettled.append(f"0x{key:08X} {label}: one callee only, of {cls}")
                continue
            shown = ", ".join(f"{functions[c][1]} 0x{c:08X}" for c in callees[:3]) + (
                f" and {len(callees) - 3} more" if len(callees) > 3 else ""
            )
            why = (
                f"{label} {noun} in ECX to {len(callees)} method"
                f"{'s' if len(callees) != 1 else ''} of {cls}"
                f"{' and its bases' if len(seen) > 1 else ''}: {shown} (tools/receivers.py)"
            )
            settled.append((key, what, form.format(cls), why))
    if img is not None:
        settled += subobject_methods(img, functions, bases)
    return settled, unsettled


def main(argv):
    if argv and argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    daoexe.low_priority()
    settled, unsettled = rows(*read())
    for address, what, value, why in settled:
        print(f"0x{address:08X} {what} {value}: {why}")
    print(f"{len(settled)} settled, {len(unsettled)} not:")
    for line in unsettled:
        print("  " + line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
