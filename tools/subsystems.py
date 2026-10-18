"""Which part of the game each function of DAOrigins.exe belongs to:
data/subsystems.csv, a bucket for every function of the GOG build.

    python tools/subsystems.py            read the GOG build and write data/subsystems.csv (needs game/)
    python tools/subsystems.py --stats    functions and named functions per subsystem, and how each was placed
    python tools/subsystems.py --check    the file and its rules are sound (no game needed)

Its purpose (the user, 2026-10-18): "identify the stuff that we want to
implement in our own version of the Dragon Age engine". So a bucket says
either that a function is a library's, which a new engine takes from that
library or replaces (`ThirdParty:CRT`, `ThirdParty:Scaleform`, ...), or
which of the engine's own subsystems it is part of (`Game`, `Rendering`,
`Scripting`, ...). A project reading the file counts, per subsystem, what
there is and what of it is understood.

A bucket is not a name. The name column of data/addresses.csv is the one
place a name is written; this file says where a function belongs and how
that was found, and is made again from the table, the build and two files
of rules kept by hand:

- data/subsystem_rules.csv: a class or namespace (exact, a prefix ending
  in `*`, or an ending after a `*`; the first match wins) and the
  subsystem it belongs to;
- data/subsystem_ranges.csv: a run of GOG addresses that is one library's
  code, bounded by functions proven to be that library's (the linker lays
  out a library's object files together), or the linker's or compiler's.

Each function is placed by the first of these that answers, most trusted
first, and its `how` column says which:

  name     the table names it, and its class or namespace has a rule (a
           name with no class, such as operator_new, may have one itself)
  vtable   it is a slot in the vftables of classes that all have the same
           subsystem; `class` is the one the others derive from, if any
  builds   it stores the addresses of vftables into an object outside
           its own stack frame, as a constructor or a destructor does into
           `this`, and the class that derives from all the others has a
           rule; `class` is that one. A function that makes an object on
           the heap with its constructor inlined does so too, so this is
           the class it builds, which is most often, not always, the class
           it is a method of
  range    it is inside one of the ranges
  string   it refers to a string only a library uses (the STL's "vector<T>
           too long"), or calls a function that does
  import   it calls a DLL, or a library linked in, that only one subsystem
           uses: FMOD is Audio, EA's Fesl and DirtySDK are Online (not a
           tiny function the linker may have shared with the engine)
  pointer  nothing calls it directly, and the functions that hold its
           address (to hand it to a library as a callback, to register it
           as a handler) are all one subsystem's
  callers  everything that calls it was placed by one of the above, and
           those are one subsystem
  callees  what it calls of at least two classes was placed by one of
           the above, and agrees, leaving out Core, Data, Messaging,
           Scripting, the libraries, the linker's import stubs and tiny
           functions, which everything calls or the linker shares
  owner    it is part of another function's exception handling: the
           __ehhandler stub that function's prologue pushes, or a funclet
           or catch block its FuncInfo lists. It goes where its function
           went, by whichever of the above, and has its class

`callers` and `callees` say less than the rest: a helper of one
subsystem's is most often that subsystem's, but not always. They take one
step from what the evidence placed and no more: chains of them were wrong
in 13 of 29 an audit read (2026-10-18), and the rest in none of 40. In the
call graph a function's exception handling is the function. A range whose
subsystem begins `Compiler:` (the exception handling, initializers and
destructors of globals the compiler puts after all other code) places only
what nothing else has, last. What nothing answers stays `unknown`. The call
graph is the direct calls and jumps from each function's start up to the
next function's, read linearly.
"""

import bisect
import collections
import csv
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import addrlib  # noqa: E402
import daoexe  # noqa: E402
import msvc_names  # noqa: E402

REPO = addrlib.REPO
OUT = os.path.join(REPO, "data", "subsystems.csv")
RULES = os.path.join(REPO, "data", "subsystem_rules.csv")
RANGES = os.path.join(REPO, "data", "subsystem_ranges.csv")
BUILD = "gog-1.05"
UNKNOWN = "unknown"
THIRD_PARTY = "ThirdParty:"
# What a callee's subsystem does not say about its caller: everything calls
# them. With Data counted, 2,469 functions were Data by their callees alone
# (2026-10-18): every part of the engine reads its objects' attributes.
NOT_A_VOTE = ("Core", "Data", "Messaging", "Scripting")
# The ways of placing a function that rest on the evidence, not on its
# neighbours in the call graph.
STRONG = ("name", "vtable", "builds", "range", "string", "import", "pointer")
# A callee this small or smaller votes for nothing (bytes to the next start):
# the linker keeps one copy of identical small functions (a setter, a
# three-instruction constructor) wherever one of them was, and 78 engine
# functions were Online for calling such a copy in Fesl's run (2026-10-18).
TINY = 16
# Strings only a library's own code uses: a function that refers to one is
# that library's, and so is one that calls such a function, as a container's
# methods call the one that throws its length_error. The STL's messages, of
# MSVC 2008's Dinkumware library.
LIBRARY_STRINGS = {
    b"vector<T> too long": "ThirdParty:STL",
    b"deque<T> too long": "ThirdParty:STL",
    b"list<T> too long": "ThirdParty:STL",
    b"map/set<T> too long": "ThirdParty:STL",
    b"string too long": "ThirdParty:STL",
    b"invalid string position": "ThirdParty:STL",
    b"invalid map/set<T> iterator": "ThirdParty:STL",
}
# Code a library runs for one subsystem's sake: calling it is that
# subsystem's, as calling a DLL is.
LIBRARY_SUBSYSTEMS = {
    "ThirdParty:Fesl": "Online",
    "ThirdParty:DirtySDK": "Online",
}

# The DLLs whose callers are one subsystem's code (data/builds.csv's GOG
# image imports them; `daoexe.py --imports`). The system DLLs are left out:
# every part of the engine calls KERNEL32.
DLL_SUBSYSTEMS = {
    "fmod_event.dll": "Audio",
    "fmodex.dll": "Audio",
    "d3d9.dll": "Rendering",
    "d3dx9_36.dll": "Rendering",
    "speedtreert.dll": "Rendering",
    "binkw32.dll": "Video",
    "nxcharacter.dll": "Physics",
    "nxcooking.dll": "Physics",
    "physxloader.dll": "Physics",
    "umbra.dll": "World",
    "dinput8.dll": "Input",
    "ws2_32.dll": "Network",
}

HOWS = (*STRONG, "callers", "callees", "owner")
EH_MAGIC = (0x19930520, 0x19930521, 0x19930522)
# Ranges of these are code the compiler made for others: a function's
# exception handling, a global's initializer or destructor. A piece placed
# by nothing else falls back to its range.
COMPILER = "Compiler:"
HEX = re.compile(r"0x[0-9a-f]+")


class Rules:
    """data/subsystem_rules.csv: (pattern, subsystem), in order."""

    def __init__(self, rules):
        self.rules = rules

    @classmethod
    def load(cls, path=None):
        with open(path or RULES, encoding="utf-8", newline="") as f:
            return cls([(r["pattern"], r["subsystem"]) for r in csv.DictReader(f)])

    def subsystem(self, owner):
        """The subsystem of a class or namespace, or None."""
        if not owner:
            return None
        for pattern, subsystem in self.rules:
            if pattern.startswith("*"):
                if owner.endswith(pattern[1:]):
                    return subsystem
            elif pattern.endswith("*"):
                if owner.startswith(pattern[:-1]):
                    return subsystem
            elif owner == pattern:
                return subsystem
        return None


def load_ranges(path=None):
    """[(start, end, subsystem)], sorted, end exclusive."""
    path = path or RANGES
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", newline="") as f:
        return sorted(
            (int(r["start"], 16), int(r["end"], 16), r["subsystem"])
            for r in csv.DictReader(f)
        )


def in_ranges(ranges, va):
    i = bisect.bisect_right(ranges, (va, float("inf"), "")) - 1
    if i >= 0 and ranges[i][0] <= va < ranges[i][1]:
        return ranges[i][2]
    return None


def owner_of(name):
    """The class or namespace a qualified name is in, or None. A name the
    build exports is still decorated: ?Lock@GMutex@@QAEXXZ is in GMutex,
    ??0GSysFile@@QAE@XZ (a constructor; ??1 a destructor, ??_F a default
    constructor closure, ??E an operator) in GSysFile."""
    if not name:
        return None
    if name.startswith("?"):
        rest = name[1:]
        if rest.startswith("?_"):
            scopes = rest[3:]
        elif rest.startswith("?"):
            scopes = rest[2:]
        else:
            scopes = rest.split("@", 1)[1] if "@" in rest else ""
        scopes = scopes.split("@@", 1)[0]
        if not scopes or "?" in scopes:
            return None
        return "::".join(reversed(scopes.split("@")))
    if "::" not in name:
        return None
    return "::".join(msvc_names.split_top(name)[:-1]) or None


def most_base(owners, bases):
    """Of the classes whose vftables hold a function, the one every other
    derives from, or None. bases: {class: set of its bases}."""
    for candidate in sorted(owners):
        if all(o == candidate or candidate in bases.get(o, ()) for o in owners):
            return candidate
    return None


def most_derived(owners, bases):
    """Of the classes whose vftables a function writes into an object, the
    one that derives from every other, or None: a constructor or destructor
    sets its bases' vftables and its own."""
    for candidate in sorted(owners):
        if all(o == candidate or o in bases.get(candidate, ()) for o in owners):
            return candidate
    return None


def agreed(subsystems):
    """The one subsystem of a non-empty collection, or None."""
    found = set(subsystems)
    return found.pop() if len(found) == 1 else None


def spread(placed, calls, callers, sizes, classes):
    """Places what callers or callees agree on, until nothing changes.
    placed: {va: (subsystem, how)}, filled in; calls and callers: {va: set};
    sizes: {va: bytes to the next function}."""

    # Only what the evidence placed may vote, not what the call graph did: a
    # function called from a few placed places and many unplaced ones took
    # the few's subsystem, and its callees after it, when it could (first
    # run, 2026-10-18: 28,675 functions went to GUI from 148 named ones), and
    # an audit of 29 placed by chains of callers and callees found 13 wrong.
    # Scripting votes for nothing: a script command's engine function is the
    # engine's. A callee needs a second to agree, and a tiny one (a getter
    # the linker shares among unrelated classes) does not count.
    # A class votes once: every reader of a resource calls both
    # Resources::Data and Resources::Size, which are one thing's two votes.
    def votes(va, others, *, tiny_ok):
        found = {}
        for c in others:
            if (
                c in placed
                and placed[c][1] in STRONG
                and placed[c][0] not in NOT_A_VOTE
                and ":" not in placed[c][0]
                and (tiny_ok or sizes.get(c, 0) > TINY)
            ):
                found[classes.get(c) or c] = placed[c][0]
        return list(found.values())

    functions = set(calls) | set(callers)
    for va in sorted(functions - set(placed)):
        mine = callers.get(va, ())
        if mine and all(c in placed and placed[c][1] in STRONG for c in mine):
            found = votes(va, mine, tiny_ok=True)
            if found and (s := agreed(found)):
                placed[va] = (s, "callers")
    for va in sorted(functions - set(placed)):
        found = votes(va, calls.get(va, ()), tiny_ok=False)
        if len(found) >= 2 and (s := agreed(found)):
            placed[va] = (s, "callees")
    return placed


def sets_vftable(mnemonic, op):
    """Whether an instruction holding a vftable's address stores it into an
    object that is not in the function's own stack frame, as a constructor
    or destructor does into `this`. A function that makes a local object
    stores it at [esp+x] or [ebp-x]: the engine's XML loaders each build a
    TiXmlDocument so, and with them counted were TinyXML (2026-10-18)."""
    if mnemonic != "mov" or not op.startswith("dword ptr ["):
        return False
    address = op[len("dword ptr [") : op.index("]")]
    return "esp" not in address and "ebp" not in address


class Reading:
    """What a build's code says: calls {va: set of functions it calls or
    jumps to}, imports {va: set of DLLs it calls}, vtables [(class, bases,
    slots)], writes {va: set of classes whose vftable addresses it stores},
    owned {va: the function it is part of}, refs {va: set of functions whose
    addresses it holds other than to call them}, strings {va: set of
    subsystems of LIBRARY_STRINGS it refers to}."""

    def __init__(
        self,
        calls,
        imports=None,
        vtables=(),
        writes=None,
        owned=None,
        refs=None,
        strings=None,
    ):
        self.calls = calls
        self.imports = imports or {}
        self.vtables = list(vtables)
        self.writes = writes or {}
        self.owned = owned or {}
        self.refs = refs or {}
        self.strings = strings or {}


def eh_pieces(img, handler, func_info):
    """The pieces of one function its exception handling is made of: its
    __ehhandler stub, and from the stub's FuncInfo (magic 0x1993052x) the
    unwind funclets of its unwind map and the catch blocks of its try map."""
    pieces = {handler}
    max_state, unwind, tries, try_map = struct.unpack(
        "<iIiI", img.bytes_at(func_info + 4, 16)
    )
    for i in range(max(0, min(max_state, 4096))):
        action = img.u32(unwind + 8 * i + 4)
        if action:
            pieces.add(action)
    for t in range(max(0, min(tries, 4096))):
        catches, handlers = struct.unpack("<iI", img.bytes_at(try_map + 20 * t + 12, 8))
        for c in range(max(0, min(catches, 256))):
            block = img.u32(handlers + 16 * c + 12)
            if block:
                pieces.add(block)
    return pieces


def read_build(path, starts):
    """A build's Reading (above)."""
    import capstone

    import daoexe

    img = daoexe.Image(path)
    text_start, text_end, _ = img.section(".text")
    function_set = set(starts)
    slots = {}
    rva = img.dirs[1][0]
    o = img.offset(rva)
    while True:
        _, _, _, name, iat = struct.unpack_from("<IIIII", img.data, o)
        if name == 0:
            break
        dll = img.cstring(name).lower()
        p = iat
        while img.u32(img.image_base + p):
            slots[img.image_base + p] = dll
            p += 4
        o += 20
    vtables, vftable_class, bases_of = [], {}, {}
    for vftable, decorated, _offset, table in img.vtables:
        cls = msvc_names.undecorate(decorated)
        if decorated not in bases_of:
            found = img.bases(decorated) or []
            bases_of[decorated] = {
                msvc_names.undecorate(b) for b, _, _ in found[1:] if b != "?"
            }
        vtables.append((cls, bases_of[decorated], table))
        vftable_class[vftable] = cls
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    # An __ehhandler stub ends `mov eax, FuncInfo; jmp __CxxFrameHandler3`,
    # and the function it handles pushes its address in its prologue.
    handlers = {}
    for i, va in enumerate(starts):
        size = (starts[i + 1] if i + 1 < len(starts) else text_end) - va
        head = list(md.disasm(img.bytes_at(va, min(48, size)), va))
        for a, b in zip(head, head[1:], strict=False):
            if (
                a.mnemonic == "mov"
                and a.op_str.startswith("eax, 0x")
                and b.mnemonic == "jmp"
                and img.u32(int(a.op_str[5:], 16)) in EH_MAGIC
            ):
                handlers[va] = int(a.op_str[5:], 16)
                break
    marker = {}
    for text, subsystem in LIBRARY_STRINGS.items():
        at = img.data.find(text + b"\0")
        while at >= 0:
            if (va := img.va_of_offset(at)) is not None:
                marker[va] = subsystem
            at = img.data.find(text + b"\0", at + 1)
    owned, refs, strings = {}, {}, {}
    calls, imports, writes = {}, {}, {}
    for i, va in enumerate(starts):
        end = min(starts[i + 1] if i + 1 < len(starts) else text_end, va + 0x8000)
        out, dlls, held, held_refs, held_strings = set(), set(), set(), set(), set()
        for ins in md.disasm(img.bytes_at(va, end - va), va):
            op = ins.op_str
            if "0x" in op:
                for word in HEX.findall(op):
                    value = int(word, 16)
                    if (cls := vftable_class.get(value)) is not None:
                        if sets_vftable(ins.mnemonic, op):
                            held.add(cls)
                    elif ins.mnemonic == "push" and value in handlers:
                        for piece in eh_pieces(img, value, handlers[value]):
                            if piece in function_set and piece != va:
                                owned.setdefault(piece, va)
                    elif value in marker:
                        held_strings.add(marker[value])
                    elif (
                        value in function_set
                        and value != va
                        and ins.mnemonic not in ("call", "jmp")
                    ):
                        held_refs.add(value)
            if ins.mnemonic not in ("call", "jmp"):
                continue
            if op.startswith("0x"):
                target = int(op, 16)
                if target in function_set and target != va:
                    out.add(target)
            elif op.startswith("dword ptr [0x"):
                dll = slots.get(int(op[len("dword ptr [") : -1], 16))
                if dll:
                    dlls.add(dll)
        calls[va] = out
        imports[va] = dlls
        if held:
            writes[va] = held
        if held_refs:
            refs[va] = held_refs
        if held_strings:
            strings[va] = held_strings
    return Reading(calls, imports, vtables, writes, owned, refs, strings)


def place(functions, reading, rules, ranges):
    """{va: (subsystem, how, class)} for every function. functions: {va: name}."""
    owned = reading.owned
    library_ranges = [r for r in ranges if not r[2].startswith(COMPILER)]
    compiler_ranges = [r for r in ranges if r[2].startswith(COMPILER)]
    starts = sorted(functions)
    sizes = {a: b - a for a, b in zip(starts, starts[1:], strict=False)}
    placed, classes = {}, {}
    for va, name in functions.items():
        owner = owner_of(name)
        if owner:
            classes[va] = owner
        # A name with no class (operator_new, _CIsqrt) may have a rule of its own.
        if s := rules.subsystem(owner or (name if name and "?" not in name else None)):
            placed[va] = (s, "name")
    owners, bases = collections.defaultdict(set), {}
    for cls, cls_bases, table in reading.vtables:
        bases.setdefault(cls, set()).update(cls_bases)
        for slot in table:
            if slot in functions:
                owners[slot].add(cls)
    for va, found in owners.items():
        if va in placed:
            continue
        base = most_base(found, bases)
        if base and va not in classes:
            classes[va] = base
        s = agreed(rules.subsystem(c) or UNKNOWN for c in found)
        if s and s != UNKNOWN:
            placed[va] = (s, "vtable")
    for va, found in reading.writes.items():
        if va not in functions:
            continue
        cls = most_derived(found, bases)
        if cls and va not in classes:
            classes[va] = cls
        if va not in placed and cls and (s := rules.subsystem(cls)):
            placed[va] = (s, "builds")
    for va in functions:
        if va not in placed and (s := in_ranges(library_ranges, va)):
            placed[va] = (s, "range")
    marked = {}
    for va, found in reading.strings.items():
        if va in functions and (s := agreed(found)):
            marked[va] = s
            if va not in placed:
                placed[va] = (s, "string")
    for va in functions:
        if va in placed:
            continue
        found = {marked[c] for c in reading.calls.get(va, ()) if c in marked}
        if s := agreed(found) if found else None:
            placed[va] = (s, "string")
    for va in functions:
        if va in placed:
            continue
        found = [
            DLL_SUBSYSTEMS[d]
            for d in reading.imports.get(va, ())
            if d in DLL_SUBSYSTEMS
        ] + [
            LIBRARY_SUBSYSTEMS[placed[c][0]]
            for c in reading.calls.get(va, ())
            if c in placed
            and placed[c][0] in LIBRARY_SUBSYSTEMS
            and sizes.get(c, 0) > TINY
        ]
        if found and (s := agreed(found)):
            placed[va] = (s, "import")
    # A piece of a function's exception handling calls what the function
    # does (a funclet runs its locals' destructors): in the call graph it is
    # the function, and afterwards it goes where the function went.
    calls = collections.defaultdict(set)
    for va, targets in reading.calls.items():
        calls[owned.get(va, va)].update(t for t in targets if t not in owned)
    for va in owned:
        calls.pop(va, None)
        placed.pop(va, None)
    callers = collections.defaultdict(set)
    for va, targets in calls.items():
        for t in targets:
            if t != va:
                callers[t].add(va)
    # A function nothing calls directly is called through its address: a
    # callback handed to a library, a handler registered by name.
    referrers = collections.defaultdict(set)
    for va, held in reading.refs.items():
        for t in held:
            referrers[t].add(owned.get(va, va))
    for va, mine in referrers.items():
        if va in placed or va not in functions or callers.get(va):
            continue
        found = [
            placed[r][0]
            for r in mine
            if r in placed
            and placed[r][1] in STRONG
            and placed[r][0] != "Messaging"
            and not placed[r][0].startswith(COMPILER)
        ]
        if found and (s := agreed(found)):
            placed[va] = (s, "pointer")
    spread(placed, calls, callers, sizes, classes)
    for va, owner in owned.items():
        if owner in placed:
            placed[va] = (placed[owner][0], "owner")
            if owner in classes:
                classes[va] = classes[owner]
    for va in functions:
        if va not in placed and (s := in_ranges(compiler_ranges, va)):
            placed[va] = (s, "range")
    return {
        va: (*placed.get(va, (UNKNOWN, "")), classes.get(va, "")) for va in functions
    }


def gog_functions(db):
    """{va: (id, name)} of the table's functions in the GOG build."""
    out = {}
    for number, row in db.rows.items():
        va = row.addresses.get(BUILD)
        if row.kind == "function" and va is not None:
            out.setdefault(va, (number, row.name))
    return out


def write(db):
    build = next(b for b in db.builds if b["key"] == BUILD)
    path = os.path.join(REPO, build["image"])
    functions = gog_functions(db)
    starts = sorted(functions)
    placed = place(
        {va: name for va, (_, name) in functions.items()},
        read_build(path, starts),
        Rules.load(),
        load_ranges(),
    )
    lines = ["id,subsystem,class,how"]
    for va, (number, _) in sorted(functions.items(), key=lambda kv: kv[1][0]):
        subsystem, how, cls = placed[va]
        lines.append(",".join(csv_cell(c) for c in (str(number), subsystem, cls, how)))
    addrlib.write_if_changed(OUT, addrlib.LF.join(lines) + addrlib.LF)
    return stats(db)


def csv_cell(text):
    if any(c in text for c in ',"\n'):
        return '"' + text.replace('"', '""') + '"'
    return text


def load():
    with open(OUT, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def stats(db):
    """Per subsystem: its functions, how many are named, how they were
    placed, and apart from them the pieces of exception handling that went
    with them (`owner`), which nobody writes as functions of their own."""
    rows = load()
    named = {n for n, row in db.rows.items() if row.name}
    by = collections.defaultdict(lambda: [0, 0, 0, collections.Counter()])
    for r in rows:
        entry = by[r["subsystem"]]
        if r["how"] == "owner":
            entry[2] += 1
            continue
        entry[0] += 1
        entry[1] += int(r["id"]) in named
        entry[3][r["how"] or "-"] += 1
    functions = sum(e[0] for e in by.values())
    print(
        f"{len(rows)} functions of {BUILD}: {functions} placed on their own, "
        f"{sum(e[1] for e in by.values())} of them named, and "
        f"{sum(e[2] for e in by.values())} pieces of exception handling"
    )
    print(f"{'subsystem':26} {'functions':>9} {'named':>6} {'pieces':>6}  placed by")
    for subsystem, (count, n, pieces, hows) in sorted(
        by.items(), key=lambda kv: -kv[1][0]
    ):
        how = ", ".join(f"{h} {c}" for h, c in hows.most_common())
        print(f"{subsystem:26} {count:9} {n:6} {pieces:6}  {how}")
    return 0


def check(db):
    """Whether the file and the rules are sound: each line a fault."""
    faults = []
    subsystems = set()
    with open(RULES, encoding="utf-8", newline="") as f:
        for i, r in enumerate(csv.DictReader(f), 2):
            if not r["pattern"] or r["subsystem"] in ("", UNKNOWN):
                faults.append(f"{RULES}:{i}: a rule needs a pattern and a subsystem")
            subsystems.add(r["subsystem"])
    subsystems.update(DLL_SUBSYSTEMS.values())
    ranges = load_ranges()
    for (s1, e1, n1), (s2, _, n2) in zip(ranges, ranges[1:], strict=False):
        if s2 < e1:
            faults.append(f"ranges {n1} at {s1:#x} and {n2} at {s2:#x} overlap")
    subsystems.update(n for _, _, n in ranges)
    seen = set()
    for r in load():
        number = int(r["id"])
        row = db.rows.get(number)
        if row is None or row.kind != "function" or BUILD not in row.addresses:
            faults.append(f"ID {number} is not a function of {BUILD}")
        if number in seen:
            faults.append(f"ID {number} is in the file twice")
        seen.add(number)
        if r["subsystem"] != UNKNOWN and r["subsystem"] not in subsystems:
            faults.append(f"ID {number}: {r['subsystem']} is no rule's subsystem")
        if r["how"] not in HOWS and not (r["subsystem"] == UNKNOWN and not r["how"]):
            faults.append(f"ID {number}: placed by {r['how']!r}")
    for fault in faults:
        print(fault)
    print(f"{len(seen)} functions placed: {len(faults)} faults")
    return 1 if faults else 0


def main(argv):
    if argv and argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    daoexe.low_priority()
    db = addrlib.Database.load()
    if "--stats" in argv:
        return stats(db)
    if "--check" in argv:
        return check(db)
    return write(db)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
