"""Names for the build's standard-library template code, by its bytes.

    python tools/stlmatch.py generate DIR            write C++ files of instantiations into DIR
    python tools/stlmatch.py build DIR TOOLSET       compile them with Visual C++ 2005 (TOOLSET is
                                                     its root, holding VC\\ and SDK\\) into DIR\\stl.lib
    python tools/stlmatch.py match LIB [--names] [--elements FILE] [--agree FILE]
                                                     what the build has of LIB's functions

The user, 2026-11-20: name the standard library deterministically where it can
be. Its containers are templates, and the build's copies of vector<T>::insert
and the rest were made from VC8's headers for the game's own types; no library
holds them, so tools/libmatch.py has nothing to compare (it found the 41 of
libcpmt.lib that are not templates). So this makes such a library:
explicit instantiations of vector, list, deque, map, set and stdext::hash_map
over elements of every size from 4 to 128 bytes and of four kinds (plain data;
default constructor, copy and destructor out of line; and the two mixes), the
scalars, std::wstring and std::string, compiled with the build's compiler and
flags (dev/BUILDS.md, "The compiler"; /GL left out, its objects are not code).
A member defined out of line is only declared, so calls to it are relocations,
which the comparison leaves out: one kind stands for every class whose such
members are not inline.

Then libmatch's comparison, but kept per shape: the bytes of a function with
its relocations left out, and its length. Where every instantiation that
compiled to that shape is one member of one template, the build's functions
of that shape and length are that member, an argument written where all of
them agree on it and ? where they do not (std::vector<?>::_Insert_n). Where
two members share a shape (end and rbegin can), nothing is named. Code under
48 bytes names nothing: an engine function can be the same few instructions.
Only unnamed IDs are named; --agree writes how the named ones compare.

--elements writes what each match says of its element: the sizes and kinds of
the generated types whose code it is. DAODecomp's stl_bruteforce.py starts
from it to find the real type (decomp-agent asked, 2026-11-20).

It needs game/ and the compiler, which are in no repository; what it finds goes
into the table with addrlib.py names.
"""

import collections
import csv
import ctypes
import os
import re
import subprocess
import sys

import daoexe
import libmatch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIN = 48
FLAGS = "/nologo /c /O2 /Ob1 /Oy /GS /EHsc /Gy /GF /MT /GR".split()
SIZES = list(range(4, 129, 4))
MAP_SIZES = list(range(4, 65, 4))
SCALAR_ELEMENTS = ["char", "short", "int", "unsigned int", "__int64", "float", "double"]
REAL = [
    "std::wstring",
    "std::string",
    "std::pair<std::wstring,std::wstring>",
    "std::vector<int>",
]
KIND = {
    "P": "plain",
    "D": "out-of-line ctor/copy/dtor",
    "A": "out-of-line ctor/dtor, trivial copy",
    "C": "out-of-line ctor/copy, trivial dtor",
}
SYNTHETIC = re.compile(r"^[PDAC]_\d+$")
# A scalar argument says too much: a map over unsigned int is the same code
# as one over any pointer or unsigned type.
SCALARS = {
    "int", "unsigned int", "char", "unsigned char", "short", "unsigned short",
    "__int64", "unsigned __int64", "float", "double", "bool", "long", "unsigned long",
}  # fmt: skip
PIECE = re.compile(r"^_*(catch|unwind|ehhandler|unwindfunclet|tryblocktable)\$", re.I)


# --- generating ---


def element_types(sizes):
    return ["%s_%d" % (k, n) for n in sizes for k in KIND]


def declarations():
    lines = [
        "#include <%s>" % h
        for h in (
            "vector",
            "list",
            "deque",
            "map",
            "set",
            "string",
            "hash_map",
            "utility",
        )
    ]
    for n in SIZES:
        a = "int a[%d];" % (n // 4)
        lines += [
            "struct P_%d { %s };" % (n, a),
            "struct D_{0} {{ {1} D_{0}(); D_{0}(const D_{0} &); D_{0} &operator=(const D_{0} &); ~D_{0}(); }};".format(n, a),
            "struct A_{0} {{ {1} A_{0}(); ~A_{0}(); }};".format(n, a),
            "struct C_{0} {{ {1} C_{0}(); C_{0}(const C_{0} &); C_{0} &operator=(const C_{0} &); }};".format(n, a),
        ]  # fmt: skip
        for t in ("%s_%d" % (k, n) for k in KIND):
            lines.append("bool operator==(const %s &, const %s &);" % (t, t))
            lines.append("bool operator<(const %s &, const %s &);" % (t, t))
    return "\n".join(lines) + "\n"


def instantiations():
    """{file stem: [explicit instantiation lines]}."""
    out = {}
    elements = element_types(SIZES) + SCALAR_ELEMENTS + REAL
    for cont in ("vector", "list", "deque"):
        out[cont] = ["template class std::%s<%s >;" % (cont, t) for t in elements]
    values = element_types(MAP_SIZES) + SCALAR_ELEMENTS + REAL[:2]
    for i, key in enumerate(("int", "unsigned int", "std::wstring")):
        out["map%d" % i] = [
            "template class std::map<%s,%s >;" % (key, v) for v in values
        ]
        out["map%d" % i].append("template class std::set<%s >;" % key)
    for i, key in enumerate(("unsigned int", "std::wstring")):
        out["hash%d" % i] = [
            "template class stdext::hash_map<%s,%s >;" % (key, v) for v in values
        ]
    out["strings"] = [
        "template class std::basic_string<wchar_t>;",
        "template class std::basic_string<char>;",
        "template struct std::pair<std::wstring,std::wstring>;",
    ]
    return out


def generate(folder, per=12):
    """C++ files of at most `per` instantiations each: a plain COFF object holds
    under 65,536 sections, and /bigobj's objects are another format."""
    os.makedirs(folder, exist_ok=True)
    head, written = declarations(), []
    for stem, lines in instantiations().items():
        for i in range(0, len(lines), per):
            path = os.path.join(folder, "%s_%02d.cpp" % (stem, i // per))
            with open(path, "w", encoding="ascii", newline="\n") as f:
                f.write(head + "\n".join(lines[i : i + per]) + "\n")
            written.append(path)
    return written


def build(folder, toolset, jobs=8):
    env = dict(os.environ)
    env["INCLUDE"] = (
        os.path.join(toolset, "VC", "INCLUDE")
        + ";"
        + os.path.join(toolset, "SDK", "Include")
    )
    env["PATH"] = os.path.join(toolset, "VC", "Bin") + ";" + env["PATH"]
    cl, lib = (os.path.join(toolset, "VC", "Bin", x) for x in ("cl.exe", "lib.exe"))
    sources = sorted(f for f in os.listdir(folder) if f.endswith(".cpp"))
    for i in range(0, len(sources), jobs):
        runs = [
            subprocess.Popen(
                [cl, *FLAGS, s], cwd=folder, env=env, stdout=subprocess.PIPE, text=True
            )
            for s in sources[i : i + jobs]
        ]
        for s, p in zip(sources[i : i + jobs], runs, strict=True):
            out = p.communicate()[0]
            if p.returncode:
                sys.exit("%s did not compile:\n%s" % (s, out[-2000:]))
    objects = [s[:-4] + ".obj" for s in sources]
    subprocess.run(
        [lib, "/nologo", "/OUT:stl.lib", *objects], cwd=folder, env=env, check=True
    )
    return os.path.join(folder, "stl.lib")


# --- naming ---


def undecorate(symbol):
    buf = ctypes.create_string_buffer(4096)
    n = ctypes.WinDLL("dbghelp").UnDecorateSymbolName(
        symbol.encode("latin1"), buf, 4096, 0x1000
    )
    return buf.value.decode("latin1") if n else None


def split_args(text):
    out, depth, cur = [], 0, ""
    for ch in text:
        depth += (ch == "<") - (ch == ">")
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    out.append(cur)
    return [a.strip() for a in out]


def strip_args(text):
    out, depth = "", 0
    for ch in text:
        if ch in "<>":
            depth += 1 if ch == "<" else -1
        elif depth == 0:
            out += ch
    return out


def traits(args, prefix, kind):
    """std::_Tree<std::_Tmap_traits<K,V,...,0> > as the map it is, stdext::_Hash likewise."""
    inner = re.match(
        r"^(?:struct |class )?%s_[TH](map|set)_traits<(.*)>$" % prefix, args[0]
    )
    if not inner:
        return None
    ia = split_args(inner.group(2))
    multi = "multi" if ia[-1].strip() == "1" else ""
    if inner.group(1) == "map":
        return "%s%smap<%s,%s>" % (kind, multi, norm_type(ia[0]), norm_type(ia[1]))
    return "%s%sset<%s>" % (kind, multi, norm_type(ia[0]))


def norm_type(t):
    """A type as the table writes it, the generated ones and scalars as ?."""
    t = re.sub(r"\b(struct|class|enum) ", "", t).strip()
    t = t.replace(" const", "").replace("const ", "")
    if SYNTHETIC.match(t) or t in SCALARS:
        return "?"
    m = re.match(r"^(.*?)\s*(\*+)$", t)
    if m and "<" not in m.group(1):
        return norm_type(m.group(1)) + m.group(2)
    m = re.match(r"^([\w:]+)<(.*)>(\s*\*+)?$", t)
    if not m:
        return t.replace(" *", "*")
    base, args = m.group(1), split_args(m.group(2))
    ptr = (m.group(3) or "").replace(" ", "")
    if base == "std::basic_string" and args[0] in ("wchar_t", "char"):
        return ("std::wstring" if args[0] == "wchar_t" else "std::string") + ptr
    if base == "std::_Tree":
        return (traits(args, "std::", "std::") or norm_type(args[0])) + ptr
    if base == "stdext::_Hash":
        return (traits(args, "stdext::", "stdext::hash_") or norm_type(args[0])) + ptr
    keep = {"std::map": 2, "std::multimap": 2, "stdext::hash_map": 2}.get(
        base, len(args)
    )
    if base in (
        "std::vector",
        "std::list",
        "std::deque",
        "std::set",
        "std::allocator",
        "std::less",
    ):
        keep = 1
    return "%s<%s>%s" % (base, ",".join(norm_type(a) for a in args[:keep]), ptr)


def norm_name(full):
    """An undecorated name as the table writes it:
    std::vector<struct P_8,class std::allocator<struct P_8> >::_Insert_n is std::vector<?>::_Insert_n."""
    if full is None:
        return None
    full = re.sub(r"\b(struct|class|enum) ", "", full)
    depth, cut = 0, -1
    for i, ch in enumerate(full):
        depth += (ch == "<") - (ch == ">")
        if depth == 0 and full[i : i + 2] == "::":
            cut = i
    if cut < 0:
        return norm_type(full)
    owner, member = full[:cut], full[cut + 2 :]
    owner_n = norm_type(owner)
    if member.lstrip("~").split("<")[0] == owner.split("<")[0].split("::")[-1]:
        # A constructor or destructor: written with the owner's own leaf name.
        tilde = "~" if member.startswith("~") else ""
        return owner_n + "::" + tilde + strip_args(owner_n).split("::")[-1]
    m = re.match(r"^(~?\w+)<.*>$", member)
    if m and not member.startswith("operator"):
        member = m.group(1)  # a member template: the table writes the member alone
    return owner_n + "::" + member


def element_of(full):
    """(size, kind) of the element a generated instantiation was made for."""
    if full is None:
        return None
    m = re.search(r"\b([PDAC])_(\d+)\b", full)
    if m:
        return (int(m.group(2)), KIND[m.group(1)])
    if "std::basic_string<" in full:
        return (28, "string")
    for t, size in (("__int64", 8), ("double", 8), ("float", 4), ("unsigned int", 4), ("int", 4), ("short", 2), ("char", 1)):  # fmt: skip
        if re.search(r"<%s\b" % re.escape(t), full):
            return (size, "scalar " + t)
    return None


def pieces(name):
    """[text, [args], text, ...]: a name with its top-level argument lists split out."""
    out, depth, cur = [], 0, ""
    for ch in name:
        if ch == "<" and depth == 0:
            out.append(cur)
            cur, depth = "", 1
            continue
        if ch == ">" and depth == 1:
            out.append(split_args(cur))
            cur, depth = "", 0
            continue
        depth += (ch == "<") - (ch == ">")
        cur += ch
    out.append(cur)
    return out


def merge(names):
    """One name for code several instantiations share: an argument kept where
    all agree and ? where not; None where they are different members."""
    split = [pieces(n) for n in names]
    if len({len(p) for p in split}) != 1:
        return None
    out = ""
    for parts in zip(*split, strict=True):
        if isinstance(parts[0], str):
            if len(set(parts)) != 1:
                return None
            out += parts[0]
            continue
        if len({len(a) for a in parts}) != 1:
            return None
        out += (
            "<"
            + ",".join(
                a[0] if len(set(a)) == 1 else "?" for a in zip(*parts, strict=True)
            )
            + ">"
        )
    return out


def bare(name):
    """Owner and member without template arguments, to compare a name with the table's."""
    return "::".join(strip_args(name).split("::")[-2:])


def load(paths):
    """{shape: (names, code, relocations, element types)} of the libraries' functions."""
    shapes = {}
    for path in paths:
        for _, obj in libmatch.members(path):
            for symbol, code, relocs in libmatch.functions(obj):
                if len(code) < MIN or not symbol.startswith("?") or PIECE.match(symbol):
                    continue
                full = undecorate(symbol)
                name = norm_name(full)
                if not name or "<" not in name or name.startswith("?::"):
                    continue
                k = libmatch.shape(code, relocs)
                entry = shapes.setdefault(k, (set(), code, relocs, set()))
                entry[0].add(name)
                if element_of(full):
                    entry[3].add(element_of(full))
    return shapes


def match(shapes, body):
    """[(address, name, elements)] and how many build functions' shapes were two members'."""
    by_len = collections.defaultdict(list)
    for va, code in body.items():
        by_len[len(code)].append(va)
    found, ambiguous = [], 0
    for names, code, relocs, elements in shapes.values():
        pattern = libmatch.pattern_of(code, relocs)
        hits = [va for va in by_len.get(len(code), ()) if pattern.match(body[va])]
        name = merge(sorted(names))
        if name is None:
            ambiguous += len(hits)
            continue
        found += [(va, name, sorted(elements)) for va in hits]
    return found, ambiguous


def write_tsv(path, header, lines):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\t".join(header) + "\n")
        for line in lines:
            f.write("\t".join(line) + "\n")


def run_match(argv):
    def option(flag):
        return argv[argv.index(flag) + 1] if flag in argv else None

    elements_file, agree_file = option("--elements"), option("--agree")
    libs = [
        a
        for i, a in enumerate(argv)
        if not a.startswith("--") and argv[i - 1] not in ("--elements", "--agree")
    ]
    img = daoexe.Image(daoexe.default_exe(os.path.dirname(os.path.abspath(__file__))))
    with open(
        os.path.join(ROOT, "data", "addresses.csv"), encoding="utf-8", newline=""
    ) as f:
        rows = {
            int(r["gog-1.05"], 16): r
            for r in csv.DictReader(f)
            if r["kind"] == "function" and r["gog-1.05"]
        }
    found, ambiguous = match(load(libs), libmatch.build_functions(img, sorted(rows)))
    new = [(va, n, e) for va, n, e in found if not rows[va]["name"]]
    named = [(va, n) for va, n, _ in found if rows[va]["name"]]
    same = sum(1 for va, n in named if bare(rows[va]["name"]) == bare(n))
    print(
        f"{len(found)} functions of the build are generated code by their bytes: {len(new)} unnamed, "
        f"{same} named the same member, {len(named) - same} named otherwise; "
        f"{ambiguous} more whose bytes two members share",
        file=sys.stderr,
    )
    if elements_file:
        write_tsv(elements_file, ("address", "id", "name", "elements"), [
            (f"0x{va:08X}", rows[va]["id"], n, "; ".join("%d %s" % x for x in e)) for va, n, e in sorted(new)
        ])  # fmt: skip
    if agree_file:
        write_tsv(agree_file, ("address", "table", "bytes", "member"), [
            (f"0x{va:08X}", rows[va]["name"], n, "same" if bare(rows[va]["name"]) == bare(n) else "other")
            for va, n in sorted(named)
        ])  # fmt: skip
    if "--names" in argv:
        for va, n, _ in sorted(new):
            print(f"{rows[va]['id']}\t{n}")
    return 0


def main(argv):
    if len(argv) >= 2 and argv[0] == "generate":
        print(len(generate(argv[1])), "files")
        return 0
    if len(argv) >= 3 and argv[0] == "build":
        print(build(argv[1], argv[2]))
        return 0
    if len(argv) >= 2 and argv[0] == "match":
        return run_match(argv[1:])
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
