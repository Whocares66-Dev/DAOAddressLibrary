"""Names for the build's library functions, from the libraries themselves.

    python tools/libmatch.py LIB [LIB ...]     what the GOG build has of these .lib files
    python tools/libmatch.py --names LIB ...   the same, as `ID<TAB>name` lines for addrlib.py names
    python tools/libmatch.py --write LIB ...   write data/libmatch.csv: what was matched, and from where

decomp-agent, 2026-11-20, on the user's word: bring the third-party code to
the engine's standard before anyone reads it. The build links its C runtime
statically, and the toolset that made it (Visual C++ 2005 SP1) has those
libraries; the open-source ones (zlib 1.2.3, libjpeg 6b, expat, TinyXML) are
compiled again from their sources with the build's compiler and flags.

A .lib is an archive of COFF objects. Each function's bytes are taken with
the places its relocations fill left out, and the build is searched for the
functions that are those bytes and that length. One function of the build
for one of the library: a name. Then what the matched pairs call: where the
library's function calls symbol S at a relocation and the build's calls
address A at the same place, A is S. That is tools/exemap.py's rule (two
instructions otherwise the same hold them), and nothing is named by
resemblance: code shorter than 16 bytes, and code two differently named
library functions share, names nothing by itself.

It needs game/ and the libraries, which are in no repository; what it finds
goes into the table with addrlib.py names, so nothing reads it at run time.

data/libmatch.csv records each function matched: its ID and address, the
library and the object file its code is from, the symbol, and how it was
matched. `bytes` is the library's own code, byte for byte but for what the
linker fills in: a rebuild of the game can link the library for it and
needs no one to read it (decomp-agent asked for the list for that,
2026-11-20). `called` is a name only, the function a matched one calls
there; its bytes were not compared (it is short, or shared, or of another
length in the table), so it says what the function is and not that the
library's object is it.
"""

import collections
import csv
import os
import re
import struct
import sys

import daoexe
import subsystems

ROOT = subsystems.REPO

FILE = os.path.join(subsystems.REPO, "data", "libmatch.csv")
MIN = 16  # bytes: shorter code is not one function's alone
REL32 = 0x14  # IMAGE_REL_I386_REL32: a call or jump's target


def members(path):
    with open(path, "rb") as f:
        data = f.read()
    assert data[:8] == b"!<arch>\n", path
    at, longnames = 8, b""
    while at + 60 <= len(data):
        head = data[at : at + 60]
        name, size = head[:16].decode("latin1").strip(), int(head[48:58])
        body = data[at + 60 : at + 60 + size]
        at += 60 + size + (size & 1)
        if name == "//":
            longnames = body
        elif name in ("/", ""):
            continue
        else:
            if name.startswith("/") and name[1:].isdigit():
                start = int(name[1:])
                name = longnames[start : longnames.index(b"\0", start)].decode("latin1")
            yield name.rstrip("/"), body


def functions(obj):
    """[(symbol, bytes, {offset in it: (kind, target symbol)})] of a COFF object's code."""
    if len(obj) < 20:
        return []
    machine, nsect, _, symptr, nsym, opt, _ = struct.unpack_from("<HHIIIHH", obj, 0)
    if machine != 0x14C or symptr == 0 or symptr + nsym * 18 > len(obj):
        return []
    strtab = symptr + nsym * 18

    def sym_name(raw):
        if raw[:4] == b"\0\0\0\0":
            start = strtab + struct.unpack_from("<I", raw, 4)[0]
            return obj[start : obj.index(b"\0", start)].decode("latin1")
        return raw.rstrip(b"\0").decode("latin1")

    symbols, i = [], 0
    while i < nsym:
        raw = obj[symptr + i * 18 : symptr + i * 18 + 18]
        value, sect, kind, storage, aux = struct.unpack_from("<IhHBB", raw, 8)
        symbols.append((i, sym_name(raw[:8]), value, sect, kind, storage))
        symbols += [None] * aux
        i += 1 + aux
    out = []
    for s in range(nsect):
        base = 20 + opt + s * 40
        _, _, _, rawsize, rawptr, relptr, _, nrel, _, flags = struct.unpack_from(
            "<8sIIIIIIHHI", obj, base
        )
        if not flags & 0x20 or rawsize == 0 or rawptr == 0:
            continue
        code = obj[rawptr : rawptr + rawsize]
        relocs = {}
        for r in range(nrel):
            off, symi, kind = struct.unpack_from("<IIH", obj, relptr + r * 10)
            target = symbols[symi] if symi < len(symbols) and symbols[symi] else None
            relocs[off] = (kind, target[1] if target else None)
        here = sorted(
            (x[2], x[1])
            for x in symbols
            if x
            and x[3] == s + 1
            and x[5] in (2, 3)
            and (x[4] == 0x20 or x[5] == 2)
            and not x[1].startswith((".", "$"))
        )
        for n, (start, name) in enumerate(here):
            end = here[n + 1][0] if n + 1 < len(here) else len(code)
            if end <= start:
                continue
            body = code[start:end].rstrip(b"\xcc\x90")
            out.append(
                (
                    name,
                    body,
                    {
                        o - start: v
                        for o, v in relocs.items()
                        if start <= o < start + len(body)
                    },
                )
            )
    return out


SPECIAL = {
    "2": "operator new",
    "3": "operator delete",
    "_U": "operator new[]",
    "_V": "operator delete[]",
    "4": "operator=",
    "8": "operator==",
    "9": "operator!=",
    "A": "operator[]",
    "6": "operator<<",
    "5": "operator>>",
    "_G": "`scalar deleting destructor'",
    "_E": "`vector deleting destructor'",
    "R": "operator()",
    "C": "operator->",
}


def plain(symbol):
    """A symbol's name as the table writes one, or None where this cannot tell."""
    if symbol.startswith("__imp_"):
        return None
    if symbol.startswith("?"):
        m = re.match(r"^\?\?([01])((?:\w+@)+)@", symbol)
        if m:
            parts = [p for p in m.group(2).split("@") if p][::-1]
            return "::".join(parts + [("~" if m.group(1) == "1" else "") + parts[-1]])
        m = re.match(r"^\?\?(_[A-Z]|[2-9A-Z])((?:\w+@)*)@", symbol)
        if m and m.group(1) in SPECIAL:
            return "::".join(
                [p for p in m.group(2).split("@") if p][::-1] + [SPECIAL[m.group(1)]]
            )
        m = re.match(r"^\?(\w+)@((?:\w+@)*)@", symbol)
        if m and "?" not in symbol[1:].split("@@")[0]:
            return "::".join(
                [p for p in m.group(2).split("@") if p][::-1] + [m.group(1)]
            )
        return None
    m = re.match(r"^[_@](\w+)@\d+$", symbol)
    if m:
        return m.group(1)
    return symbol[1:] if symbol.startswith("_") else symbol


def shape(code, relocs):
    """A function's bytes with what its relocations fill left out, and where."""
    masked = bytearray(code)
    for off in relocs:
        masked[off : off + 4] = b"\0\0\0\0"
    return bytes(masked), tuple(sorted(relocs))


def pattern_of(code, relocs):
    """A regular expression that is the function's bytes, any four at each
    relocation, and nothing after."""
    parts, i = [], 0
    while i < len(code):
        if i in relocs:
            parts.append(b".{4}")
            i += 4
        else:
            j = i
            while j < len(code) and j not in relocs:
                j += 1
            parts.append(re.escape(code[i:j]))
            i = j
    return re.compile(b"".join(parts) + b"$", re.S)


def build_functions(img, starts):
    """{address: a table function's bytes to the next one, its padding off}."""
    _, text_end, _ = img.section(".text")
    body = {}
    for i, va in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else text_end
        body[va] = img.bytes_at(va, min(end - va, 0x4000)).rstrip(b"\xcc\x90")
    return body


def by_bytes(lib, body):
    """({address: (symbol, its relocations, its place in lib)}, how many
    library functions shared their bytes with another of another name)."""
    by_length = collections.defaultdict(list)
    for va, code in body.items():
        by_length[len(code)].append(va)
    seen = collections.defaultdict(set)
    for name, code, relocs in lib:
        seen[shape(code, relocs)].add(name)
    found, shared = {}, 0
    for n, (name, code, relocs) in enumerate(lib):
        if len(seen[shape(code, relocs)]) > 1:
            shared += 1
            continue
        pattern = pattern_of(code, relocs)
        hits = [va for va in by_length.get(len(code), ()) if pattern.match(body[va])]
        if len(hits) != 1:
            continue
        va = hits[0]
        found[va] = None if va in found and found[va][0] != name else (name, relocs, n)
    return {va: v for va, v in found.items() if v}, shared


def by_calls(direct, body, known):
    """({address: symbol} for what the matched functions call and bytes did
    not name, the calls that disagree with a match)."""
    called = collections.defaultdict(collections.Counter)
    for va, (_, relocs, *_) in direct.items():
        code = body[va]
        for off, (kind, target) in relocs.items():
            if kind == REL32 and target and off + 4 <= len(code):
                to = va + off + 4 + struct.unpack_from("<i", code, off)[0]
                called[to][target] += 1
    extra = {
        to: next(iter(names))
        for to, names in called.items()
        if to not in direct and to in known and len(names) == 1
    }
    clash = [
        (to, dict(names))
        for to, names in called.items()
        if to in direct and set(names) != {direct[to][0]}
    ]
    return extra, clash


def main(argv):
    names_only, write = "--names" in argv, "--write" in argv
    libs = [a for a in argv if a not in ("--names", "--write")]
    if not libs:
        print(__doc__)
        return 2
    img = daoexe.Image(daoexe.default_exe(os.path.dirname(os.path.abspath(__file__))))
    with open(
        os.path.join(ROOT, "data", "addresses.csv"), encoding="utf-8", newline=""
    ) as f:
        rows = {
            int(r["gog-1.05"], 16): r
            for r in csv.DictReader(f)
            if r["kind"] == "function" and r["gog-1.05"]
        }
    body = build_functions(img, sorted(rows))
    lib, origin, defined = [], [], {}
    for path in libs:
        for member, obj in members(path):
            found = functions(obj)
            long = [f for f in found if len(f[1]) >= MIN]
            lib += long
            origin += [(os.path.basename(path), member)] * len(long)
            for name, _, _ in found:
                defined.setdefault(name, (os.path.basename(path), member))
    direct, shared = by_bytes(lib, body)
    extra, clash = by_calls(direct, body, rows)
    print(
        f"{len(lib)} library functions of {MIN} bytes or more; {len(direct)} functions "
        f"of the build are one's bytes ({shared} library functions shared theirs with "
        f"another name); {len(extra)} more by what those call; {len(clash)} calls "
        "disagree with a match",
        file=sys.stderr,
    )
    for to, names in clash:
        print(
            f"  0x{to:08X} is {direct[to][0]} by its bytes, called as {names}",
            file=sys.stderr,
        )
    if write:
        with open(FILE, "w", newline="", encoding="utf-8") as f:
            out = csv.writer(f, lineterminator="\n")
            out.writerow(("id", "address", "library", "object", "symbol", "how"))
            for va in sorted(set(direct) | set(extra)):
                symbol = direct[va][0] if va in direct else extra[va]
                library, member = (
                    origin[direct[va][2]]
                    if va in direct
                    else defined.get(symbol, ("", ""))
                )
                how = "bytes" if va in direct else "called"
                out.writerow(
                    (rows[va]["id"], f"0x{va:08X}", library, member, symbol, how)
                )
        return 0
    for va in sorted(set(direct) | set(extra)):
        symbol = direct[va][0] if va in direct else extra[va]
        name, row = plain(symbol), rows[va]
        how = "bytes" if va in direct else "called"
        if name is None:
            continue
        if names_only:
            if not row["name"]:
                print(f"{row['id']}\t{name}")
        elif row["name"] != name:
            print(
                f"{row['id']}\t0x{va:08X}\t{row['name'] or '-'}\t{name}\t{symbol}\t{how}"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
