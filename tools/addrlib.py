"""The address library: a number for every function and global of Dragon
Age: Origins, and where each is in every build of DAOrigins.exe.

    python tools/addrlib.py add KEY              read a build (data/builds.csv) into the table
    python tools/addrlib.py lookup 0x005D6740    what is at an address, in any build
    python tools/addrlib.py lookup 23456         an ID's row
    python tools/addrlib.py lookup SetPaused     rows by name
    python tools/addrlib.py lookup 0x5D6740 --build gog-1.05
    python tools/addrlib.py name 10547 CClientExoApp::SetPaused      name an ID
    python tools/addrlib.py name 0x005D6740 CClientExoApp::SetPaused --build gog-1.05
    python tools/addrlib.py names FILE [--build KEY]   many: `ID or 0xADDRESS<TAB>name` lines
    python tools/addrlib.py pack DIR             write each build's runtime file into DIR
    python tools/addrlib.py check                the table is sound (no game needed)
    python tools/addrlib.py kept [REV]           no ID or address of REV's table (HEAD's) has changed
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

The `name` column is the one place a thing's name is written down. A build's
own names are there from its reading (its exports and imports, its RTTI
classes' vftables and type descriptors); the rest are given by whoever
worked out what a function or a global is, with `name`. A name can be given
to any ID and changed; it is the ID that does not change. Nothing a program
reads at run time holds names, so naming one rebuilds nothing.

Reading a build needs its executable, under game/ (ignored by git); the
table, lookup, name, pack, check and kept do not.
"""

import bisect
import collections
import csv
import io
import os
import struct
import subprocess
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


def write_if_changed(path, text):
    """Writes a file of the table's unless it already says this. A checkout
    with its line ends turned to CR LF says the same thing, and writing over
    it would show git a file changed in which nothing was: naming one ID is
    then one changed file, the table, and not the notes too."""
    if os.path.exists(path):
        with open(path, encoding="utf-8", newline="") as f:
            if f.read().replace("\r\n", "\n") == text:
                return False
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    return True


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
                db.read_table(f)
        if os.path.exists(NOTES):
            with open(NOTES, encoding="utf-8", newline="") as f:
                db.notes = [
                    (int(r["id"]), r["build"], r["flag"], r["detail"])
                    for r in csv.DictReader(f)
                ]
        return db

    def read_table(self, lines):
        """The table's rows, from data/addresses.csv's text."""
        reader = csv.reader(lines)
        header = next(reader)
        self.columns = header[3:]
        for line in reader:
            addresses = {
                key: int(cell, 16)
                for key, cell in zip(self.columns, line[3:], strict=True)
                if cell
            }
            self.rows[int(line[0])] = Row(line[1], line[2], addresses)

    def save(self):
        table = io.StringIO(newline="")
        writer = csv.writer(table, lineterminator="\n")
        writer.writerow(["id", "kind", "name", *self.columns])
        for number, row in self.rows.items():
            cells = [
                f"{row.addresses[key]:#010x}" if key in row.addresses else ""
                for key in self.columns
            ]
            writer.writerow([number, row.kind, row.name, *cells])
        notes = io.StringIO(newline="")
        writer = csv.writer(notes, lineterminator="\n")
        writer.writerow(["id", "build", "flag", "detail"])
        writer.writerows(sorted(self.notes))
        write_if_changed(ADDRESSES, table.getvalue())
        write_if_changed(NOTES, notes.getvalue())

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


# -- naming --


def resolve(db, what, only=None):
    """The one ID an ID or an address means, or a ValueError saying why
    there is not one. An address is a build's: with no build said, it must
    be an ID's address in one build alone, or the same ID's in each."""
    if what.lower().startswith("0x"):
        address = int(what, 16)
        keys = [only] if only else db.columns
        found = {n for key in keys for n in db.by_address(key).get(address, ())}
        if len(found) != 1:
            where = only or "any build"
            raise ValueError(
                f"{address:#010x} is the address of {len(found)} IDs in {where}"
                + (": say which by its ID" if found else "")
            )
        return found.pop()
    if not what.isdigit() or int(what) not in db.rows:
        raise ValueError(f"no ID {what}")
    return int(what)


def set_name(db, number, name):
    """Names an ID; what it was named before. A name is one line with
    nothing around it, and a retired ID is nothing to name."""
    if name != name.strip() or not name or "\n" in name or "\t" in name:
        raise ValueError(f"ID {number}: {name!r} is not a name")
    row = db.rows[number]
    if row.kind == "retired":
        raise ValueError(f"ID {number} is retired")
    before, row.name = row.name, name
    return before


def name_many(db, pairs, only=None):
    """Names each (ID or address, name); the count named anew, the count
    renamed, and a line for each that could not be."""
    new = renamed = 0
    faults = []
    for what, name in pairs:
        try:
            before = set_name(db, resolve(db, what, only), name)
        except ValueError as fault:
            faults.append(str(fault))
            continue
        if not before:
            new += 1
        elif before != name:
            renamed += 1
    return new, renamed, faults


def name(db, pairs, only=None):
    """The `name` and `names` commands: names them and saves the table."""
    new, renamed, faults = name_many(db, pairs, only)
    for fault in faults[:40]:
        print(fault, file=sys.stderr)
    if len(pairs) == 1 and not faults:
        print(describe(db, resolve(db, pairs[0][0], only)))
    else:
        print(f"{new} named, {renamed} renamed, {len(faults)} not")
    # Not a fault: overloads share a name. But worth a look.
    uses = collections.Counter(row.name for row in db.rows.values() if row.name)
    for given in sorted({given for _, given in pairs if uses[given] > 1})[:20]:
        ids = [n for n, row in db.rows.items() if row.name == given]
        print(f"{given} is the name of IDs {', '.join(map(str, ids))}")
    if new or renamed:
        db.save()
    return 1 if faults else 0


def pairs_in(path):
    """(ID or address, name) for each line of a file of them, tab between;
    blank lines and lines starting with # are not any."""
    with open(path, encoding="utf-8") as f:
        lines = [
            line.rstrip("\n") for line in f if line.strip() and not line.startswith("#")
        ]
    for line in lines:
        if "\t" not in line:
            raise ValueError(f"{path}: a line with no tab: {line!r}")
    return [tuple(line.split("\t", 1)) for line in lines]


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
    """Steam and GOG share a link stamp: all four PE fields identify a file."""
    fields = ("link_stamp", "size_of_image", "entry_point_rva", "image_base")
    return (
        "daoaddresses-" + "-".join(f"{int(build[k], 16):08x}" for k in fields) + ".bin"
    )


def output_names(build):
    names = [file_name(build)]
    # Explicit legacy aliases preserve existing GOG/EA consumers. Never
    # assign a timestamp alias to a new build just because it was read first.
    if build.get("legacy") == "1":
        names.append(f"daoaddresses-{int(build['link_stamp'], 16):08x}.bin")
    return names


def pack(db, folder):
    if check(db):
        return 1
    os.makedirs(folder, exist_ok=True)
    for build in db.builds:
        if build["key"] in db.columns:
            data = pack_build(db, build)
            for name in output_names(build):
                with open(os.path.join(folder, name), "wb") as f:
                    f.write(data)
                print(f"{name}: {len(data)} bytes, the {build['key']} build")
    return 0


def check(db):
    """Whether the table is one a reader can trust. Each line is a fault."""
    faults = []
    keys = [b["key"] for b in db.builds]
    if len(set(keys)) != len(keys):
        faults.append("data/builds.csv names a build twice")
    outputs = {}
    for build in db.builds:
        if build.get("legacy", "") not in ("", "1"):
            faults.append(f"{build['key']}: legacy must be empty or 1")
        for name in output_names(build):
            if name in outputs:
                faults.append(
                    f"{name}: {outputs[name]} and {build['key']} would overwrite each other"
                )
            outputs[name] = build["key"]
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


def changes(before, after):
    """What an ID's promise forbids, between a table as it was and as it is:
    each line is a fault. An ID that is gone, one that became another kind
    of thing (other than retired), and an address that moved or was taken
    out. Builds are matched by all four PE fields, so a build's key may change;
    names may too, and new IDs, builds and addresses are what a table is
    for."""
    faults = []
    fingerprint = {b["key"]: file_name(b) for b in before.builds}
    key_now = {file_name(b): b["key"] for b in after.builds}
    for number, was in before.rows.items():
        now = after.rows.get(number)
        if now is None:
            faults.append(f"ID {number} is gone")
            continue
        if now.kind not in (was.kind, "retired"):
            faults.append(f"ID {number} was a {was.kind} and is a {now.kind}")
        for key, address in was.addresses.items():
            there = now.addresses.get(key_now.get(fingerprint.get(key)))
            if there != address and now.kind != "retired":
                faults.append(
                    f"ID {number} in {key} was at {address:#010x} and is "
                    + (f"at {there:#010x}" if there is not None else "nowhere")
                )
    return faults


def at_revision(revision):
    """The table and the builds as git has them at a revision; None if git
    has none (no git, no repository, or the files are newer than it)."""
    db = Database()
    for path, read in (
        ("data/builds.csv", lambda f: setattr(db, "builds", list(csv.DictReader(f)))),
        ("data/addresses.csv", db.read_table),
    ):
        try:
            text = subprocess.run(
                ["git", "show", f"{revision}:{path}"],
                cwd=REPO,
                capture_output=True,
                check=True,
            ).stdout.decode("utf-8")
        except (OSError, subprocess.CalledProcessError):
            return None
        read(io.StringIO(text, newline=""))
    return db


def kept(db, revision):
    """Whether every ID and address of a committed table is still as it was:
    what is run before a change to the table is committed. A cell put right
    on purpose fails it once, which is the point: say so in the commit."""
    before = at_revision(revision)
    if before is None:
        print(f"no table at {revision} to compare with")
        return 0
    faults = changes(before, db)
    for fault in faults[:40]:
        print(fault, file=sys.stderr)
    print(
        f"{len(before.rows)} IDs at {revision}, {len(db.rows)} now: {len(faults)} changed"
    )
    return 1 if faults else 0


def stats(db):
    kinds = collections.Counter(row.kind for row in db.rows.values())
    named = sum(1 for row in db.rows.values() if row.name)
    print(
        f"{len(db.rows)} IDs: "
        + ", ".join(f"{n} {kind}" for kind, n in kinds.most_common())
        + f"; {named} named"
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
    only = rest[rest.index("--build") + 1] if "--build" in rest[:-1] else None
    if only:
        at = rest.index("--build")
        rest = rest[:at] + rest[at + 2 :]
    if command == "lookup" and rest:
        return lookup(db, rest[0], only)
    if command == "name" and len(rest) == 2:
        return name(db, [tuple(rest)], only)
    if command == "names" and len(rest) == 1:
        try:
            return name(db, pairs_in(rest[0]), only)
        except (OSError, ValueError) as fault:
            print(fault, file=sys.stderr)
            return 1
    if command == "pack" and rest:
        return pack(db, rest[0])
    if command == "check":
        return check(db)
    if command == "kept":
        return kept(db, rest[0] if rest else "HEAD")
    if command == "stats":
        return stats(db)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
