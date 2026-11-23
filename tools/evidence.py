"""What proves each name in the table, derived, never kept by hand.

    python tools/evidence.py [FILE]     write it (default build/evidence.csv)

decomp-agent asked, 2026-11-23: its checker fails a function of DAODecomp
only where it disagrees with a proven name, and sends a disagreement with
any other name here as a report. So every named ID of the GOG build gets
one mark, the strongest that holds for the name the table has:

  export, import   the build's own export or import table names it
  rtti             the build's RTTI names it (a class's typeinfo or vftable)
  bytes            a library's function of that name is its code, relocations
                   masked: data/libmatch.csv how=bytes, data/stlmatch.csv
                   how=bytes. stlmatch's names hold ? where the element
                   type is not told, so only owner and member are proved
  targets          its bytes are two library functions', and what it calls
                   says which (data/stlmatch.csv how=targets)
  called           a matched library function calls it by that name
                   (data/libmatch.csv how=called); its own bytes were not
                   compared
  vftable          a slot of the class's own vftable holds it, the class
                   being the one that defines that slot (tools/vtables_dump.py's
                   "defined"): this proves the class, not the method's name
  short            bytes or called, but under 48 bytes: the same few
                   instructions can be an engine function the linker folded
                   into it (0x004C0D90, an empty string's constructor, is
                   std::wstring's, the pool string's and ECString's at once),
                   so it proves nothing on its own
  inferred         none of these: a reader's name (Ghidra, an agent, a
                   description, a string the code uses)

A proof of a name data/folds.csv records for the ID (the linker made
one function of several) contradicts nothing. A proof of another name is not a proof of the table's: such an ID is marked
inferred, and `detail` says what proves what (`bytes say X`), which is a
report for this repository. Names compare by owner and member, without
template arguments or a parameter list.

It reads game/ (the GOG executable) and the two match files, which keep what
needs the libraries and the compiler; the rest it reads from the executable
each time.
"""

import csv
import os
import re
import sys

import addrlib
import daoexe
import exemap
import libmatch
import stlmatch
import vtables_dump

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = "gog-1.05"
SHORT = 48  # stlmatch's MIN: under it an engine function can be the same code


def bare(name):
    """Owner and member, without template arguments, a parameter list or a
    C name's leading underscores."""
    if not name:
        return ""
    out, depth = "", 0
    for ch in name:
        if ch in "<(":
            depth += 1
        elif ch in ">)":
            depth -= 1
        elif depth == 0:
            out += ch
    parts = [p.strip() for p in out.split("::") if p.strip()][-2:]
    parts = [
        ("~" if p.startswith("~") else "") + SAME.get(p.lstrip("~"), p.lstrip("~"))
        for p in parts
    ]
    return "::".join(parts).lstrip("_")


# One template under two spellings. std::wstring is a basic_string, and its
# allocator is in neither spelling once arguments are gone: a library's
# basic_string member proves the member, not which allocator (stlmatch's
# rows, which keep the pool allocator, do). A map is its _Tree.
SAME = {
    "wstring": "basic_string",
    "string": "basic_string",
    "map": "_Tree",
    "multimap": "_Tree",
    "set": "_Tree",
    "multiset": "_Tree",
    "hash_map": "_Hash",
    "hash_set": "_Hash",
    "_Tree_const_iterator": "const_iterator",
    "_Tree_iterator": "iterator",
}


def library_name(symbol):
    """A library symbol's name as the table would write it."""
    name = libmatch.plain(symbol)
    if name is None and (symbol.startswith("??$") or "@?$" in symbol):
        name = stlmatch.norm_name(stlmatch.undecorate(symbol))
    elif name is None and symbol.startswith("?"):
        name = addrlib.undecorate_symbol(symbol)
    return name or symbol


def read_csv(name):
    path = os.path.join(ROOT, "data", name)
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def own_names(image):
    """{address: (mark, name)} from the build's own reading."""
    side = exemap.Side(image)
    out = {}
    for va, name in addrlib.names_in(side).items():
        if name == "entry":
            continue
        if "!" in name:
            out[va] = ("import", name)
        elif name.endswith("::typeinfo") or "::vftable" in name:
            out[va] = ("rtti", name)
        else:
            out[va] = ("export", name)
    return out


def defining_classes(img):
    """{function address: {classes whose own vftable slot holds it}}."""
    known = vtables_dump.classes(img)
    out = {}
    for cls, (tables, _) in known.items():
        for offset, (_, slots) in tables.items():
            for function, (_, defined) in zip(
                slots, vtables_dump.origins(known, cls, offset), strict=True
            ):
                if defined:
                    out.setdefault(function, set()).add(defined)
    return out


def owner(name):
    """The class a member's name says, without its member or parameters."""
    head = re.split(r"\(", name, maxsplit=1)[0]
    depth, cut = 0, -1
    for i, ch in enumerate(head):
        depth += (ch == "<") - (ch == ">")
        if depth == 0 and head[i : i + 2] == "::":
            cut = i
    return head[:cut] if cut > 0 else None


def judge(name, va, length, own, lib, stl, classes, folds=()):
    """(mark, detail) for one named ID; folds are its other true names
    (data/folds.csv), which a proof may name without contradicting it."""
    folded = {bare(f) for f in folds}
    if va in own:
        mark, theirs = own[va]
        if theirs == name or bare(theirs) == bare(name):
            return mark, theirs
        if bare(theirs) in folded:
            return "inferred", f"{mark} proves the fold {theirs}"
        return "inferred", f"{mark} says {theirs}"
    proofs = [(r["how"], r["name"], "stlmatch") for r in stl.get(va, ())] + [
        (
            "bytes" if r["how"] == "bytes" else "called",
            library_name(r["symbol"]),
            r["library"],
        )
        for r in lib.get(va, ())
    ]
    proofs = [p for p in proofs if bare(p[1]) not in folded or bare(p[1]) == bare(name)]
    for how, theirs, source in proofs:
        if bare(theirs) != bare(name):
            return "inferred", f"{how} ({source}) says {theirs}"
    if proofs:
        how, theirs, source = proofs[0]
        if length < SHORT:
            return "short", f"{how} ({source}) {theirs}, {length} bytes"
        return how, f"{source}: {theirs}"
    cls = owner(name)
    if va in classes:
        if cls in classes[va]:
            return "vftable", cls
        return "inferred", "a vftable slot of " + ", ".join(sorted(classes[va])[:3])
    return "inferred", ""


def main(argv):
    out_path = argv[0] if argv else os.path.join(ROOT, "build", "evidence.csv")
    db = addrlib.Database.load()
    image = addrlib.image_path(db.build(BUILD))
    img = daoexe.Image(image)
    rows = [r for r in read_csv("addresses.csv") if r["name"] and r[BUILD]]
    starts = sorted(
        int(r[BUILD], 16)
        for r in read_csv("addresses.csv")
        if r["kind"] == "function" and r[BUILD]
    )
    body = libmatch.build_functions(img, starts)
    lib, stl = {}, {}
    for r in read_csv("libmatch.csv"):
        lib.setdefault(int(r["address"], 16), []).append(r)
    for r in read_csv("stlmatch.csv"):
        stl.setdefault(int(r["address"], 16), []).append(r)
    own, classes = own_names(image), defining_classes(img)
    folds = {}
    for r in read_csv("folds.csv"):
        folds.setdefault(r["id"], []).append(r["name"])
    counts = {}
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(("id", "address", "name", "evidence", "detail"))
        for r in rows:
            va = int(r[BUILD], 16)
            mark, detail = judge(
                r["name"],
                va,
                len(body.get(va, b"")),
                own,
                lib,
                stl,
                classes,
                folds.get(r["id"], ()),
            )
            counts[mark] = counts.get(mark, 0) + 1
            w.writerow((r["id"], f"0x{va:08X}", r["name"], mark, detail))
    print(out_path, dict(sorted(counts.items(), key=lambda x: -x[1])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
