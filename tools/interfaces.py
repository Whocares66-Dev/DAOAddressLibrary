"""The virtual tables of the interfaces the game calls into other people's
code through: data/interfaces.csv, a slot per row.

    python tools/interfaces.py --d3d9 d3d9.h --physx DIR [DIR ...]   read the headers, write the file
    python tools/interfaces.py --check                               the file is sound

Direct3D 9 and PhysX 2.8.1 are DLLs the game imports. Their objects' classes
have no RTTI in the exe, so tools/vtables_dump.py knows nothing of them, and a
call through one reads (**(code **)(*shape + 0x6c))(2) however much else is
typed (decomp-agent, 2026-11-20: the receivers that could not be given a
class were these). Their headers say the order of the virtual functions,
which is the order of the slots:

- d3d9.h declares each interface's methods with STDMETHOD, IUnknown's three
  first;
- a PhysX class's virtual functions in the order declared, a base's before
  its own, the destructor among them where it is virtual. Checked against
  the build: Physics::PhysicsParticleActor::GetRandomPointInShape
  (0x0081A030) calls slot 0x6C of its shape with a shape type, and slot 27
  of NxShape is `is(NxShapeType)`.

Where a class declares two virtual functions of one name the compiler lays
the group out together and in reverse; the names are the same either way, so
the second is written name_2 and which of the two a slot is, is left to the
reader of the call.

The headers are Microsoft's and NVIDIA's and in no repository; the file is
the method names in their slots and nothing else of them. tools/ghidra_sync.py
makes a type of each interface, a pointer to a table of named slots, so a
field or parameter typed `NxShape*` in data/structs.csv or a signature row
reads `(*shape->lpVtbl->is)(shape, 2)`.
"""

import collections
import csv
import os
import re
import sys

import subsystems

FILE = os.path.join(subsystems.REPO, "data", "interfaces.csv")
COLUMNS = ("interface", "slot", "method", "from")


def numbered(names):
    """Names made distinct: the second of a name is name_2."""
    seen = collections.Counter()
    out = []
    for name in names:
        seen[name] += 1
        out.append(name if seen[name] == 1 else f"{name}_{seen[name]}")
    return out


def com_interfaces(text):
    """{interface: [method in slot order]} of a COM header's DECLARE_INTERFACE
    blocks, which list a base's methods again in each interface."""
    found = {}
    for m in re.finditer(
        r"DECLARE_INTERFACE_?\((\w+)(?:,\s*\w+)?\)\s*\{(.*?)\n\};", text, re.S
    ):
        methods = re.findall(r"STDMETHOD_?\((?:[^,()]+,\s*)?(\w+)\)\s*\(", m.group(2))
        if methods:
            found[m.group(1)] = numbered(methods)
    return found


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def cpp_classes(text):
    """{class: (first public base or None, [its own virtual functions in the
    order declared])} of a C++ header."""
    text = strip_comments(text)
    found = {}
    # An export macro may stand between `class` and the name.
    for m in re.finditer(
        r"\bclass\s+(?:[A-Z][A-Z0-9_]*\s+)?(\w+)\s*(?::\s*(?:public\s+)?(\w+)[^{;]*)?\{",
        text,
    ):
        depth, i = 1, m.end()
        while depth and i < len(text):
            depth += text[i] == "{"
            depth -= text[i] == "}"
            i += 1
        body = text[m.end() : i]
        # A nested class's virtuals are its own.
        flat, depth, kept = [], 0, []
        for ch in body:
            depth += ch == "{"
            if depth == 0:
                kept.append(ch)
            depth -= ch == "}"
        flat = "".join(kept)
        names = re.findall(r"\bvirtual\s+[^;{()]*?(~?\b\w+)\s*\(", flat)
        if names:
            found[m.group(1)] = (m.group(2), names)
    return found


def flatten(classes):
    """{class: [method in slot order]}: a base's slots, then the class's own
    that are new. A destructor is `~`, whatever the class."""
    done = {}

    def slots(cls, seen=()):
        if cls in done:
            return done[cls]
        base, own = classes[cls]
        inherited = (
            list(slots(base, (*seen, cls)))
            if base in classes and base not in seen
            else []
        )
        names = [("~" if n.startswith("~") else n) for n in own]
        out = list(inherited)
        for n in names:
            # An override takes its base's slot; a second function of a
            # name in one class is an overload with a slot of its own.
            if n == "~":
                if "~" not in out:
                    out.append(n)
            elif n not in inherited or names.count(n) > 1:
                out.append(n)
        done[cls] = out
        return out

    for cls in classes:
        slots(cls)
    return {cls: numbered(names) for cls, names in done.items()}


def read():
    with open(FILE, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def tables(rows=None):
    """{interface: [method in slot order]} of the file."""
    out = collections.defaultdict(list)
    for row in sorted(
        rows if rows is not None else read(),
        key=lambda r: (r["interface"], int(r["slot"])),
    ):
        out[row["interface"]].append(row["method"])
    return dict(out)


def faults(rows):
    out, seen = [], collections.defaultdict(list)
    for row in rows:
        seen[row["interface"]].append(row)
    for interface, its in seen.items():
        slots = sorted(int(r["slot"]) for r in its)
        if slots != list(range(len(slots))):
            out.append(f"{interface}: slots are not 0 to {len(slots) - 1}")
        names = [r["method"] for r in its]
        if len(set(names)) != len(names):
            out.append(f"{interface}: a method name twice")
        if any(not re.match(r"^(~|[A-Za-z_]\w*)$", n) for n in names):
            out.append(f"{interface}: a method that is not a name")
    return out


def main(argv):
    if argv == ["--check"]:
        rows = read()
        wrong = faults(rows)
        print(
            "\n".join(wrong)
            if wrong
            else f"{len(rows)} slots of {len(tables(rows))} interfaces: 0 faults"
        )
        return 1 if wrong else 0
    if "--d3d9" not in argv and "--physx" not in argv:
        print(__doc__)
        return 2
    rows = []
    words = iter(argv)
    kind = None
    for word in words:
        if word in ("--d3d9", "--physx"):
            kind = word
            continue
        if kind == "--d3d9":
            with open(word, encoding="latin1") as f:
                found = com_interfaces(f.read())
            source = os.path.basename(word)
        else:
            classes = {}
            for name in sorted(os.listdir(word)):
                if name.lower().endswith(".h"):
                    with open(os.path.join(word, name), encoding="latin1") as f:
                        classes.update(cpp_classes(f.read()))
            found = flatten(classes)
            source = "PhysX 2.8.1 " + os.path.basename(
                os.path.normpath(os.path.join(word, ".."))
            )
        rows += [
            {"interface": interface, "slot": i, "method": method, "from": source}
            for interface, methods in sorted(found.items())
            for i, method in enumerate(methods)
        ]
    wrong = faults(rows)
    if wrong:
        print("\n".join(wrong))
        return 1
    with open(FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    print(f"{len(rows)} slots of {len(tables(rows))} interfaces")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
