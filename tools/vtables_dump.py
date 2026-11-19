"""Writes the vtables store: one JSON file per class of the GOG build that
has a virtual table, its tables slot by slot and its bases.

    python tools/vtables_dump.py            write every class's file
    python tools/vtables_dump.py CCObject   print that class's record, writing nothing

The store is `$CHAIN_CACHE\\vtables`, else `%LOCALAPPDATA%\\paragon-chain\\vtables`,
beside the facts store (tools/facts_dump.py), and Paragon's writers read it.
paragon-agent asked for it on 2026-11-16: the folder held 374 files, each
`{"version": 3, "value": []}`. Paragon's old client (removed in Paragon
440ceac0) had asked Ghidra for symbols by a wildcard over a qualified name,
`Class::vftable*`, which Ghidra's symbol iterator matches against the bare
name only, so every class answered with nothing.

Nothing here comes from Ghidra. The tables and the bases are the exe's own
RTTI (tools/daoexe.py), and a slot's name is the table's
(data/addresses.csv), so a run takes seconds and is the same every time. Run
it after a commit that names functions.

A record: {"version": 1, "value": {
  "class":    the class,
  "bases":    [{"class", "offset" in the object, "direct", "virtual"}], each
              base before its own bases, as the class's hierarchy descriptor
              has them. A virtual base's offset is not known and is null.
  "vftables": [{"address", "offset" of its pointer in the object, "extends",
                "slots": [{"slot", "offset", "function", "name",
                           "declared", "defined"}]}], by offset.
}}

"extends" is the class whose table this one continues: the most derived
base that has, in the exe, a table whose pointer is at the same place in the
object. A slot's "offset" is the one a call shows (`CALL dword ptr [EDX +
0x48]`); "name" is null where the table has none. "declared" is the most
base class along "extends" whose table is long enough to have the slot, and
"defined" the most base one whose table holds this same function there. So
"defined" equal to the class itself is a slot the class overrides or adds,
and "declared" equal to it is one it adds.

What that cannot see, since it reads tables and not source:
- a base with no table in the exe (an abstract class the compiler never
  built a table for) declares nothing here: its slots read as declared by
  the first class below it that has one;
- an override whose code is the same as its base's is one function after
  the linker folds them, and reads as inherited;
- a table reached through a virtual base has no "extends", and its slots'
  "declared" and "defined" are null.

A class is its file: `::` becomes `__` and each of `<>:"/\\|?*` becomes `_`,
and a name past 150 characters is cut there and ends `@` and the address of
its first table. A class with no virtual table has no file.
"""

import json
import os
import sys

import addrlib
import daoexe
import facts_dump
import msvc_names
import subsystems

VERSION = 1
STORE = facts_dump.STORE.with_name("vtables")
LONGEST = 150  # characters of a class in a file's name; NTFS allows 255


def file_name(cls, first_table):
    name = cls.replace("::", "__")
    for c in '<>:"/\\|?*':
        name = name.replace(c, "_")
    if len(name) > LONGEST:
        name = f"{name[:LONGEST]}@{first_table:08X}"
    return name + ".json"


def classes(img):
    """{class: ({offset: (table address, [slot addresses])}, hierarchy)} with
    the hierarchy's names undecorated."""
    tables = {}
    decorated = {}
    for va, name, offset, slots in img.vtables:
        cls = msvc_names.undecorate(name)
        tables.setdefault(cls, {})[offset] = (va, slots)
        decorated[cls] = name
    return {
        cls: (
            tables[cls],
            [
                (msvc_names.undecorate(b), offset, contained, virtual)
                for b, offset, contained, virtual in img.hierarchy(decorated[cls])
            ],
        )
        for cls in tables
    }


def extends(known, cls, offset):
    """(base, the offset of the same table in it) for the class's table at an
    offset, or None: the first base, so the most derived, that has a table
    whose pointer is at that place in the object."""
    for base, at, _, virtual in known[cls][1][1:]:
        if not virtual and base in known and offset - at in known[base][0]:
            return base, offset - at
    return None


def origins(known, cls, offset):
    """[(declared, defined)] for each slot of the class's table at an offset,
    or None for each where a virtual base hides what the table continues."""
    slots = known[cls][0][offset][1]
    parent = extends(known, cls, offset)
    if parent is None:
        through_virtual = any(virtual for _, _, _, virtual in known[cls][1])
        return [(None, None) if through_virtual else (cls, cls)] * len(slots)
    theirs = known[parent[0]][0][parent[1]][1]
    above = origins(known, *parent)
    out = []
    for i, function in enumerate(slots):
        if i >= len(theirs):
            out.append((cls, cls))
        elif theirs[i] == function:
            out.append(above[i])
        else:
            out.append((above[i][0], cls))
    return out


def method_of(name):
    """The method a function's name says it is, or None where the name says
    nothing of that: a destructor, which every class has under its own name,
    a `Stub::` name, which is for what folded code does and not for any one
    class's method, and a name still decorated."""
    if not name or name.startswith(("Stub::", "?")) or "destructor" in name:
        return None
    return name.rsplit("::", 1)[-1]


def inherited_names(known, names):
    """{table address: {slot: (method, its overrides' addresses)}} for the
    slots the table (data/addresses.csv) has no name for, where every named
    function that a table continuing this one holds at the slot is the same
    method: an override goes by the name of what it overrides, so that is
    the slot's name. It names an abstract class's slots, which hold
    _purecall (C2DASource's, from G2DA's and M2DA's), and says nothing where
    the classes below disagree."""
    said = {}
    for cls, (tables, _) in known.items():
        for offset, (_, slots) in tables.items():
            above = extends(known, cls, offset)
            while above is not None:
                va, theirs = known[above[0]][0][above[1]]
                for i, function in enumerate(slots[: len(theirs)]):
                    method = method_of(names.get(function))
                    if method and not names.get(theirs[i]):
                        held = said.setdefault(va, {}).setdefault(i, {})
                        held.setdefault(method, set()).add(function)
                above = extends(known, *above)
    agreed = {
        va: {
            i: (method, sorted(functions))
            for i, methods in slots.items()
            if len(methods) == 1
            for method, functions in methods.items()
        }
        for va, slots in said.items()
    }
    return {va: slots for va, slots in agreed.items() if slots}


def shared_notes(known):
    """{function address: a sentence} for each function that is in the
    vftables of two classes or more that do not get it from one another:
    the linker folded identical functions into it, or the classes inherit it
    from a base the build has no table for. Its name is then one class's
    for all of them, and a reader of a call to it should know (decomp-agent,
    2026-11-20: callers' decompiles show another class's name). 411
    functions; the most shared after _purecall are the empty ones."""
    holders = {}
    for cls, (tables, _) in known.items():
        for offset, (_, slots) in tables.items():
            for i, (function, (_, defined)) in enumerate(
                zip(slots, origins(known, cls, offset), strict=True)
            ):
                holders.setdefault(function, {}).setdefault(defined or cls, i)
    notes = {}
    for function, classes in holders.items():
        if len(classes) < 2:
            continue
        listed = sorted(classes.items())
        shown = ", ".join(f"{cls} (slot {slot})" for cls, slot in listed[:6])
        more = f" and {len(listed) - 6} more" if len(listed) > 6 else ""
        notes[function] = (
            f"Shared: this one function is in the vftables of {len(listed)} classes that do "
            "not get it from one another (identical code the linker folded, or a base the "
            f"build has no table for), so its name is one class's for all: {shown}{more}."
        )
    return notes


def direct_bases(hierarchy):
    """Indexes into a hierarchy of the class's own bases: each is followed by
    the bases it contains."""
    out = []
    i = 1
    while i < len(hierarchy):
        out.append(i)
        i += 1 + hierarchy[i][2]
    return out


def record(known, cls, names):
    tables, hierarchy = known[cls]
    direct = set(direct_bases(hierarchy))
    vftables = []
    for offset in sorted(tables):
        va, slots = tables[offset]
        parent = extends(known, cls, offset)
        vftables.append(
            {
                "address": f"0x{va:08X}",
                "offset": offset,
                "extends": parent[0] if parent else None,
                "slots": [
                    {
                        "slot": i,
                        "offset": f"0x{4 * i:X}",
                        "function": f"0x{function:08X}",
                        "name": names.get(function) or None,
                        "declared": declared,
                        "defined": defined,
                    }
                    for i, (function, (declared, defined)) in enumerate(
                        zip(slots, origins(known, cls, offset), strict=True)
                    )
                ],
            }
        )
    return {
        "class": cls,
        "bases": [
            {
                "class": base,
                "offset": None if virtual else at,
                "direct": i in direct,
                "virtual": virtual,
            }
            for i, (base, at, _, virtual) in enumerate(hierarchy)
            if i
        ],
        "vftables": vftables,
    }


def read():
    """(classes, {function address: name}) of the GOG build."""
    db = addrlib.Database.load()
    build = next(b for b in db.builds if b["key"] == subsystems.BUILD)
    img = daoexe.Image(os.path.join(subsystems.REPO, build["image"]))
    names = {va: name for va, (_, name) in subsystems.gog_functions(db).items()}
    return classes(img), names


def main(argv):
    known, names = read()
    if argv:
        missing = [cls for cls in argv if cls not in known]
        for cls in missing:
            print(f"{cls}: no virtual table in the exe", file=sys.stderr)
        for cls in argv:
            if cls in known:
                print(json.dumps(record(known, cls, names), indent=1))
        return 1 if missing else 0
    STORE.mkdir(parents=True, exist_ok=True)
    for cls in sorted(known):
        path = STORE / file_name(cls, min(va for va, _ in known[cls][0].values()))
        tmp = path.with_name(path.name + ".%d.tmp" % os.getpid())
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"version": VERSION, "value": record(known, cls, names)}, f)
        os.replace(tmp, path)
    tables = sum(len(t) for t, _ in known.values())
    print(f"{len(known)} classes, {tables} tables written into {STORE}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
