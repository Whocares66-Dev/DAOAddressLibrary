"""The address library: a number for every function and global of Dragon
Age: Origins, and where each is in every build of DAOrigins.exe.

    python tools/addrlib.py add KEY              read a build (data/builds.csv) into the table
    python tools/addrlib.py lookup 0x005D6740    what is at an address, in any build
    python tools/addrlib.py lookup 23456         an ID's row
    python tools/addrlib.py lookup SetPaused     rows by name
    python tools/addrlib.py lookup 0x5D6740 --build gog
    python tools/addrlib.py pack DIR             write each build's runtime file into DIR
    python tools/addrlib.py check                the table is sound (no game needed)
    python tools/addrlib.py stats

An ID is a number, given once and never given again. It names a thing, not a
place: the function or global is wherever each build's linker put it, and
the table, data/addresses.csv, has a row per ID and a column per build, an
empty cell where a build lacks the thing or it was not found there. A
plugin holds IDs; at run time it reads the file for the game it finds itself
in (pack writes them; src/daoaddr reads them), so a new build of the game
needs a new column here and nothing rebuilt anywhere.

What gets an ID is a build's inventory (tools/exemap.py): every address in
its code that something calls or points at, and every address outside its
code that a relocated word holds. `add` takes that inventory for a build,
finds each known ID in it by comparing the build with the ones already in
the table, earliest first, and gives new IDs to what is left: the things
only this build has. The first build added numbers everything it holds, in
address order.

data/notes.csv says what a cell alone cannot: a function that is not the
same code as in the build its ID came from (`changed`), an address two IDs
share because the linker made one function of two (`shared`), and a function
that was one of several identical candidates (`ambiguous`).

Reading a build needs its executable, under game/ (ignored by git); the
table, lookup, pack and check do not.
"""

import bisect
import collections
import csv
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, ".."))
ADDRESSES = os.path.join(REPO, "data", "addresses.csv")
BUILDS = os.path.join(REPO, "data", "builds.csv")
NOTES = os.path.join(REPO, "data", "notes.csv")

KINDS = ("function", "data", "retired")

# The runtime file (src/daoaddr/Library.h reads it): a header, then one
# 32-bit word per ID from 0 to the highest, the word at an ID's index: its
# RVA in the low 24 bits and flags in the high 8, or NONE.
MAGIC = b"DAOADDR\0"
FORMAT = 1
NONE = 0xFFFFFFFF
FLAG_DATA = 0x01
FLAG_CHANGED = 0x02
FLAG_SHARED = 0x04
FLAG_AMBIGUOUS = 0x08
NOTE_FLAGS = {
    "changed": FLAG_CHANGED,
    "shared": FLAG_SHARED,
    "ambiguous": FLAG_AMBIGUOUS,
}


class Row:
    def __init__(self, kind, name, addresses):
        self.kind = kind
        self.name = name
        self.addresses = addresses  # {build key: address}


class Database:
    """The table, the builds and the notes, as the three files hold them."""

    def __init__(self):
        self.builds = []  # dicts, in data/builds.csv's order
        self.columns = []  # the keys with a column in the table, in order
        self.rows = {}  # id -> Row, ascending
        self.notes = []  # (id, build key, flag, detail)

    @classmethod
    def load(cls):
        db = cls()
        with open(BUILDS, encoding="utf-8", newline="") as f:
            db.builds = list(csv.DictReader(f))
        if os.path.exists(ADDRESSES):
            with open(ADDRESSES, encoding="utf-8", newline="") as f:
                reader = csv.reader(f)
                header = next(reader)
                db.columns = header[3:]
                for line in reader:
                    addresses = {
                        key: int(cell, 16)
                        for key, cell in zip(db.columns, line[3:], strict=True)
                        if cell
                    }
                    db.rows[int(line[0])] = Row(line[1], line[2], addresses)
        if os.path.exists(NOTES):
            with open(NOTES, encoding="utf-8", newline="") as f:
                db.notes = [
                    (int(r["id"]), r["build"], r["flag"], r["detail"])
                    for r in csv.DictReader(f)
                ]
        return db

    def save(self):
        with open(ADDRESSES, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f, lineterminator="\n")
            writer.writerow(["id", "kind", "name", *self.columns])
            for number, row in self.rows.items():
                cells = [
                    f"{row.addresses[key]:#010x}" if key in row.addresses else ""
                    for key in self.columns
                ]
                writer.writerow([number, row.kind, row.name, *cells])
        with open(NOTES, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f, lineterminator="\n")
            writer.writerow(["id", "build", "flag", "detail"])
            writer.writerows(sorted(self.notes))

    def build(self, key):
        for build in self.builds:
            if build["key"] == key:
                return build
        raise KeyError(f"no build {key!r} in data/builds.csv")

    def by_address(self, key):
        """{address: [ids]} for one build."""
        out = collections.defaultdict(list)
        for number, row in self.rows.items():
            if key in row.addresses:
                out[row.addresses[key]].append(number)
        return out

    def next_id(self):
        return max(self.rows, default=0) + 1


# -- reading a build --


def image_path(build):
    return os.path.join(REPO, build["image"])


def names_in(side):
    """{address: name} for what a build's own image names: its entry point,
    exports, imports, and the RTTI classes' vftables and type descriptors."""
    import daoexe

    img = side.img
    out = {}
    for va, decorated in img.type_descriptors.items():
        out[va] = f"{daoexe.undecorate(decorated)}::typeinfo"
    for va, decorated, offset, _ in img.vtables:
        leaf = "vftable" if offset == 0 else f"vftable_at_{offset:x}"
        out[va] = f"{daoexe.undecorate(decorated)}::{leaf}"
    for (dll, function), slot in side.import_slots().items():
        out[slot] = f"{dll}!{function}"
    out |= {va: name for name, va in side.exports().items()}
    out[img.image_base + img.entry_point_rva] = "entry"
    return out


def add(db, key):
    import exemap

    build = db.build(key)
    side = exemap.Side(image_path(build))
    functions, data = exemap.inventory(side)
    kind_of = dict.fromkeys(data, "data") | dict.fromkeys(functions, "function")
    print(f"{key}: {len(functions)} functions and {len(data)} globals referred to")

    # The build's notes are made again from this reading; its cells are not.
    # A cell already filled stays as it is, whatever the comparison now
    # says: plugins were built on it, and a disagreement is for a person to
    # look at, not for a tool to settle.
    notes = [note for note in db.notes if note[1] != key]
    others = [k for k in db.columns if k != key]
    if key not in db.columns:
        db.columns.append(key)
    # The build each ID was first seen in, before this reading fills any.
    origin = {
        number: next(k for k in db.columns if k in row.addresses)
        for number, row in db.rows.items()
        if row.addresses
    }

    for other in others:
        there = exemap.Side(image_path(db.build(other)))
        functions_there = exemap.inventory(there)[0]
        m = exemap.build(there, side, (functions_there, functions))
        print(
            f"{key}: {m.leftovers_paired} functions nothing calls paired with {other}'s by what they are"
        )
        changed = m.changed_functions()
        ambiguous = {
            a: [b for same, _, _, b in options if same]
            for a, options in m.ambiguous
            if m.kind.get(a) == "function"
        }
        found = disagree = 0
        for number, row in db.rows.items():
            if other not in row.addresses:
                continue
            a = row.addresses[other]
            b, how = m.lookup(a)
            # A guess at a global by its neighbour is not written down: a
            # cell says the thing was seen there.
            if b is None or how.startswith("near"):
                continue
            if key not in row.addresses:
                row.addresses[key] = b
                found += 1
            elif row.addresses[key] != b:
                disagree += 1
                if disagree <= 10:
                    print(
                        f"  ID {number}: the table has {row.addresses[key]:#010x}, "
                        f"comparing with {other} now gives {b:#010x}; left as it is",
                        file=sys.stderr,
                    )
                continue
            # What differs from the build the ID came from is worth a note;
            # in that build itself there is nothing to differ from.
            if origin.get(number) != other:
                continue
            if a in changed:
                notes.append(
                    (
                        number,
                        key,
                        "changed",
                        f"{len(changed[a])} instructions differ from {other}'s",
                    )
                )
            if len(ambiguous.get(a, ())) > 1:
                rest = ", ".join(f"{x:#010x}" for x in sorted(ambiguous[a]) if x != b)
                notes.append(
                    (number, key, "ambiguous", f"the same code is also at {rest}")
                )
        print(
            f"{key}: {found} IDs found by comparing with {other}, {disagree} cells it would now put elsewhere"
        )

        # The same comparison the other way round reaches a few things the
        # first did not, since what each starts from and follows is its own
        # build's. Where it puts something of this build's that has no ID
        # on something of the other's that has one, and that ID has no
        # place here yet, they are the same thing: one ID, not two.
        back = exemap.build(side, there, (functions, functions_there))
        taken = db.by_address(key)
        by_other = db.by_address(other)
        twins = 0
        for address in sorted(kind_of):
            if address in taken:
                continue
            a, how = back.lookup(address)
            if a is None or how.startswith("near"):
                continue
            for number in by_other.get(a, ()):
                if key not in db.rows[number].addresses:
                    db.rows[number].addresses[key] = address
                    taken[address].append(number)
                    twins += 1
                    break
        print(
            f"{key}: {twins} more found by comparing it with {other} the other way round"
        )

    # What is left is this build's alone: new IDs, in address order.
    taken = db.by_address(key)
    names = names_in(side)
    new = 0
    number = db.next_id()
    for address in sorted(kind_of):
        if address not in taken:
            db.rows[number] = Row(
                kind_of[address], names.get(address, ""), {key: address}
            )
            number += 1
            new += 1
    print(f"{key}: {new} new IDs for what only it has")

    for numbers in db.by_address(key).values():
        if len(numbers) > 1:
            for number in numbers:
                rest = ", ".join(str(n) for n in numbers if n != number)
                notes.append((number, key, "shared", f"one address for IDs {rest} too"))
    db.notes = notes
    db.save()
    return 0


# -- asking --


def describe(db, number):
    row = db.rows[number]
    cells = "  ".join(
        f"{key} {row.addresses[key]:#010x}" if key in row.addresses else f"{key} -"
        for key in db.columns
    )
    lines = [f"{number:>6}  {row.kind:<8}  {cells}  {row.name}"]
    for noted, key, flag, detail in db.notes:
        if noted == number:
            lines.append(f"            {key}: {flag}: {detail}")
    return "\n".join(lines)


def nearest(db, key, address):
    """(id, offset) of the ID at or below an address in one build, or None."""
    table = sorted((a, min(ids)) for a, ids in db.by_address(key).items())
    i = bisect.bisect_right(table, (address, sys.maxsize)) - 1
    return (table[i][1], address - table[i][0]) if i >= 0 else None


def lookup(db, what, only=None):
    keys = [only] if only else db.columns
    if what.lower().startswith("0x"):
        address = int(what, 16)
        hit = False
        for key in keys:
            for number in db.by_address(key).get(address, ()):
                print(describe(db, number))
                hit = True
        if not hit:
            for key in keys:
                near = nearest(db, key, address)
                if near:
                    print(f"in {key}, {address:#010x} is ID {near[0]} + {near[1]:#x}:")
                    print(describe(db, near[0]))
        return 0
    if what.isdigit():
        if int(what) not in db.rows:
            print(f"no ID {what}", file=sys.stderr)
            return 1
        print(describe(db, int(what)))
        return 0
    shown = 0
    for number, row in db.rows.items():
        if what.lower() in row.name.lower():
            print(describe(db, number))
            shown += 1
            if shown == 50:
                print("... and more; narrow the name", file=sys.stderr)
                break
    return 0 if shown else 1


def pack_build(db, build):
    """One build's runtime file, as bytes."""
    key = build["key"]
    base = int(build["image_base"], 16)
    flags = collections.defaultdict(int)
    for number, noted_key, flag, _ in db.notes:
        if noted_key == key:
            flags[number] |= NOTE_FLAGS[flag]
    count = max(db.rows, default=0) + 1
    words = [NONE] * count
    for number, row in db.rows.items():
        if key in row.addresses:
            rva = row.addresses[key] - base
            if not 0 <= rva < 1 << 24:
                raise ValueError(
                    f"ID {number}: {row.addresses[key]:#x} is outside a 16 MB image"
                )
            words[number] = (
                flags[number] | (FLAG_DATA if row.kind == "data" else 0)
            ) << 24 | rva
    header = MAGIC + struct.pack(
        "<IIIIIII",
        FORMAT,
        int(build["link_stamp"], 16),
        int(build["size_of_image"], 16),
        int(build["entry_point_rva"], 16),
        base,
        count,
        0,
    )
    return header + struct.pack(f"<{count}I", *words)


def file_name(build):
    """A build's runtime file is named by its link stamp, which is what a
    reader has of the game it is in."""
    return f"daoaddresses-{int(build['link_stamp'], 16):08x}.bin"


def pack(db, folder):
    os.makedirs(folder, exist_ok=True)
    for build in db.builds:
        if build["key"] in db.columns:
            data = pack_build(db, build)
            with open(os.path.join(folder, file_name(build)), "wb") as f:
                f.write(data)
            print(f"{file_name(build)}: {len(data)} bytes, the {build['key']} build")
    return 0


def check(db):
    """Whether the table is one a reader can trust. Each line is a fault."""
    faults = []
    keys = [b["key"] for b in db.builds]
    if len(set(keys)) != len(keys):
        faults.append("data/builds.csv names a build twice")
    faults += [
        f"the table has a column {column!r} that data/builds.csv does not name"
        for column in db.columns
        if column not in keys
    ]
    if list(db.rows) != list(range(1, len(db.rows) + 1)):
        faults.append(
            "the IDs are not 1, 2, 3 and on with none missing: an ID is never taken out, only retired"
        )
    bounds = {
        b["key"]: (
            int(b["image_base"], 16),
            int(b["image_base"], 16) + int(b["size_of_image"], 16),
        )
        for b in db.builds
    }
    for number, row in db.rows.items():
        if row.kind not in KINDS:
            faults.append(f"ID {number}: kind {row.kind!r}")
        if not row.addresses and row.kind != "retired":
            faults.append(f"ID {number}: in no build, and not retired")
        for key, address in row.addresses.items():
            low, high = bounds.get(key, (0, 0))
            if not low <= address < high:
                faults.append(
                    f"ID {number}: {address:#010x} is outside the {key} image"
                )
    for number, key, flag, _ in db.notes:
        if number not in db.rows or key not in db.columns or flag not in NOTE_FLAGS:
            faults.append(
                f"a note for ID {number}, build {key!r}, flag {flag!r} fits nothing"
            )
        elif key not in db.rows[number].addresses:
            faults.append(f"a note for ID {number} in {key}, where it has no address")
    for fault in faults[:40]:
        print(fault, file=sys.stderr)
    print(
        f"{len(db.rows)} IDs, {len(db.columns)} builds, {len(db.notes)} notes: {len(faults)} faults"
    )
    return 1 if faults else 0


def stats(db):
    kinds = collections.Counter(row.kind for row in db.rows.values())
    print(
        f"{len(db.rows)} IDs: "
        + ", ".join(f"{n} {kind}" for kind, n in kinds.most_common())
    )
    for key in db.columns:
        have = [row for row in db.rows.values() if key in row.addresses]
        first = sum(
            1
            for row in have
            if next(k for k in db.columns if k in row.addresses) == key
        )
        flags = collections.Counter(flag for _, k, flag, _ in db.notes if k == key)
        noted = (
            ", ".join(f"{n} {flag}" for flag, n in sorted(flags.items())) or "no notes"
        )
        print(f"  {key}: {len(have)} of them, {first} first seen in it; {noted}")
    return 0


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    db = Database.load()
    command, rest = argv[0], argv[1:]
    if command == "add" and rest:
        return add(db, rest[0])
    if command == "lookup" and rest:
        only = rest[rest.index("--build") + 1] if "--build" in rest else None
        return lookup(db, rest[0], only)
    if command == "pack" and rest:
        return pack(db, rest[0])
    if command == "check":
        return check(db)
    if command == "stats":
        return stats(db)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
