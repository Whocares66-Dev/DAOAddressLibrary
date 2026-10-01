"""Read a build of DAOrigins.exe without Ghidra: what the file is, its
classes and their vtables, the script commands, and disassembly of any
address. The default is the GOG build, game/gog/DAOrigins.exe.

    python tools/daoexe.py --check              which build of data/builds.csv the file is
    python tools/daoexe.py --rtti [text]        classes (undecorated), those containing text
    python tools/daoexe.py --vtables [text]     vftables: address, slot count, class
    python tools/daoexe.py --class-of 0xVA      the class of the vftable at an address
    python tools/daoexe.py --bases Class        a class's bases, each at its offset in the object
    python tools/daoexe.py --refs 0xVA          code holding the address as a 32-bit immediate
    python tools/daoexe.py --disasm 0xVA [n]    n instructions from an address (default: to ret)
    python tools/daoexe.py --commands [text]    the engine's COMMAND_* script command names
    python tools/daoexe.py --strings text       printable strings containing text, with addresses
    python tools/daoexe.py --imports            DLLs imported and the functions from each

    python tools/daoexe.py --exe PATH ...       any of the above over another file: another
                                                build (dev/BUILDS.md), whose addresses are its own

Addresses are virtual addresses at the preferred base, as Ghidra shows them
and data/addresses.csv holds them. --disasm needs capstone (pip install
capstone); the rest needs nothing beyond Python.
"""

import csv
import hashlib
import os
import re
import struct
import sys
from functools import cached_property

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import msvc_names  # noqa: E402

EXE = os.path.join(HERE, "..", "game", "gog", "DAOrigins.exe")
# The builds the address library knows, each with what identifies its file.
BUILDS = os.path.join(HERE, "..", "data", "builds.csv")


class Image:
    """The exe as bytes, with the PE structure needed to walk it."""

    def __init__(self, path=EXE):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        d = self.data
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        self.machine, nsec, self.time_date_stamp = struct.unpack_from("<HHI", d, pe + 4)
        optsz = struct.unpack_from("<H", d, pe + 20)[0]
        opt = pe + 24
        self.magic = struct.unpack_from("<H", d, opt)[0]
        self.entry_point_rva = struct.unpack_from("<I", d, opt + 16)[0]
        self.image_base = struct.unpack_from("<I", d, opt + 28)[0]
        self.size_of_image = struct.unpack_from("<I", d, opt + 56)[0]
        self.dirs = [struct.unpack_from("<II", d, opt + 96 + 8 * i) for i in range(16)]
        s = opt + optsz
        self.sections = []
        for i in range(nsec):
            name = d[s + 40 * i : s + 40 * i + 8].rstrip(b"\0").decode()
            vsize, va, rawsize, raw = struct.unpack_from("<IIII", d, s + 40 * i + 8)
            self.sections.append((name, va, max(vsize, rawsize), raw))

    # -- addresses --
    def offset(self, rva):
        for _, va, size, raw in self.sections:
            if va <= rva < va + size:
                return rva - va + raw
        return None

    def section(self, name):
        """(first va, end va, file offset) of a section."""
        for n, va, size, raw in self.sections:
            if n == name:
                return va + self.image_base, va + size + self.image_base, raw
        raise KeyError(name)

    def in_section(self, va, name):
        start, end, _ = self.section(name)
        return start <= va < end

    def va_of_offset(self, off):
        for _, va, size, raw in self.sections:
            if raw <= off < raw + size:
                return off - raw + va + self.image_base
        return None

    def u32(self, va):
        o = self.offset(va - self.image_base)
        return None if o is None else struct.unpack_from("<I", self.data, o)[0]

    def bytes_at(self, va, n):
        o = self.offset(va - self.image_base)
        return b"" if o is None else self.data[o : o + n]

    def cstring(self, rva, limit=1024):
        o = self.offset(rva)
        if o is None:
            return None
        end = self.data.find(b"\0", o, o + limit)
        return self.data[o : end if end >= 0 else o + limit].decode(errors="replace")

    def code_refs(self, value):
        """Addresses in .text where the 32-bit value appears (immediates, displacements)."""
        start, end, raw = self.section(".text")
        needle = struct.pack("<I", value)
        out = []
        i = self.data.find(needle, raw, raw + end - start)
        while i != -1:
            out.append(i - raw + start)
            i = self.data.find(needle, i + 1, raw + end - start)
        return out

    # -- RTTI (32-bit MSVC: every pointer absolute) --
    @cached_property
    def type_descriptors(self):
        """{TypeDescriptor va: decorated name}. A descriptor is type_info's
        vftable, a spare word, then the name; the vftable is read from
        type_info's own descriptor."""
        at = self.data.find(b".?AVtype_info@@\0")
        type_info_vftable = self.u32(self.va_of_offset(at) - 8)
        out = {}
        for m in re.finditer(rb"\.\?A[VUTW][^\0]{1,1000}?@@\0", self.data):
            va = self.va_of_offset(m.start())
            if va is not None and self.u32(va - 8) == type_info_vftable:
                out[va - 8] = m.group()[:-1].decode(errors="replace")
        return out

    @cached_property
    def vtables(self):
        """[(vftable va, decorated class, offset in the complete object, [slot vas])].
        The word before a vftable points at its complete object locator:
        signature 0, offset, constructor-displacement offset, type descriptor,
        class hierarchy descriptor."""
        tds = self.type_descriptors
        start, end, raw = self.section(".rdata")
        d = self.data
        locators = {}
        for off in range(raw, raw + end - start - 20, 4):
            sig, offset, _, td, chd = struct.unpack_from("<IIIII", d, off)
            if sig == 0 and td in tds and start <= chd < end:
                locators[off - raw + start] = (td, offset)
        text = self.section(".text")
        out = []
        for off in range(raw, raw + end - start - 8, 4):
            col, first = struct.unpack_from("<II", d, off)
            if col not in locators or not text[0] <= first < text[1]:
                continue
            va = off - raw + start + 4
            slots = []
            p = va
            while True:
                f = self.u32(p)
                if f is None or not text[0] <= f < text[1]:
                    break
                if slots and p in self._locator_slots(locators):
                    break
                slots.append(f)
                p += 4
            td, offset = locators[col]
            out.append((va, tds[td], offset, slots))
        return out

    def _locator_slots(self, locators):
        # The word before another vftable, which ends this one.
        if not hasattr(self, "_before_vftables"):
            start, end, raw = self.section(".rdata")
            self._before_vftables = set()
            for off in range(raw, raw + end - start - 4, 4):
                if struct.unpack_from("<I", self.data, off)[0] in locators:
                    self._before_vftables.add(off - raw + start)
        return self._before_vftables

    def bases(self, decorated):
        """[(decorated base, offset in the object, bases it contains)] from the
        class hierarchy descriptor of the class's primary vftable, the class
        itself first. A base descriptor is the base's type descriptor, the
        number of bases below it, then its displacement (mdisp, pdisp, vdisp);
        pdisp is -1 unless the base is virtual, which this does not resolve."""
        for va, name, offset, _ in self.vtables:
            if name != decorated or offset != 0:
                continue
            hierarchy = self.u32(self.u32(va - 4) + 16)
            count, array = self.u32(hierarchy + 8), self.u32(hierarchy + 12)
            out = []
            for i in range(count):
                descriptor = self.u32(array + 4 * i)
                contained = self.u32(descriptor + 4)
                mdisp = struct.unpack("<i", self.bytes_at(descriptor + 8, 4))[0]
                out.append(
                    (
                        self.type_descriptors.get(self.u32(descriptor), "?"),
                        mdisp,
                        contained,
                    )
                )
            return out
        return None

    def class_of_vftable(self, va):
        for v, name, offset, slots in self.vtables:
            if v == va:
                return name, offset, slots
        return None

    def rtti_names(self):
        return sorted(set(self.type_descriptors.values()))

    def commands(self):
        return sorted(
            set(m.decode() for m in re.findall(rb"COMMAND_[A-Z0-9_]+", self.data))
        )

    def imports(self):
        rva, _ = self.dirs[1]
        o = self.offset(rva)
        out = []
        while True:
            ilt, _, _, name, iat = struct.unpack_from("<IIIII", self.data, o)
            if name == 0:
                break
            funcs = []
            p = self.offset(ilt or iat)
            while True:
                e = struct.unpack_from("<I", self.data, p)[0]
                if e == 0:
                    break
                funcs.append(
                    f"ordinal {e & 0xFFFF}" if e & 0x80000000 else self.cstring(e + 2)
                )
                p += 4
            out.append((self.cstring(name), funcs))
            o += 20
        return out

    # -- code --
    def disasm(self, va, count=None, limit=0x2000):
        """Instructions from va, linearly: count of them, or to the first ret."""
        import capstone

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        out = []
        for ins in md.disasm(self.bytes_at(va, limit), va):
            out.append(ins)
            if count is not None and len(out) >= count:
                break
            if count is None and ins.mnemonic == "ret":
                break
        return out

    def function_start(self, va, reach=0x4000):
        """The start of the function holding va, by the int3 padding MSVC puts
        between functions: the first byte after a run of two or more 0xCC."""
        o = self.offset(va - self.image_base)
        k = o
        while k > o - reach:
            if self.data[k - 2 : k] == b"\xcc\xcc" and self.data[k] != 0xCC:
                return va - (o - k)
            k -= 1
        return None


def undecorate(name):
    return msvc_names.undecorate(name)


def check(img):
    """Which build of data/builds.csv a file is. A build's row is of the exe
    as installed, so a file that matches one in every header field and in
    its hash is that build, untouched; one that matches in its link stamp
    alone is an image made from it (the EA build as tools/ea_dump.py writes
    it, its entry point put back)."""
    sha = hashlib.sha256(img.data).hexdigest()
    have = {
        "sha256": sha,
        "link_stamp": img.time_date_stamp,
        "size_of_image": img.size_of_image,
        "entry_point_rva": img.entry_point_rva,
        "image_base": img.image_base,
    }
    for what, value in have.items():
        print(f"  {what:<16} {value if isinstance(value, str) else f'{value:#x}'}")
    with open(BUILDS, encoding="utf-8", newline="") as f:
        builds = list(csv.DictReader(f))
    for build in builds:
        want = {k: (build[k] if k == "sha256" else int(build[k], 16)) for k in have}
        if want == have:
            print(f"the {build['key']} build, as installed: {build['name']}")
            return 0
    for build in builds:
        if int(build["link_stamp"], 16) == img.time_date_stamp:
            print(
                f"the {build['key']} build ({build['name']}), but not the file as installed"
            )
            return 0
    print("NOT a build data/builds.csv knows: the address library has no column for it")
    return 1


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    exe = EXE
    if argv[0] == "--exe":
        if len(argv) < 3:
            print("--exe needs a path and then what to do with it", file=sys.stderr)
            return 2
        exe, argv = argv[1], argv[2:]
    if not os.path.exists(exe):
        print(
            f"no {os.path.normpath(exe)}; copy the game's bin_ship\\DAOrigins.exe there",
            file=sys.stderr,
        )
        return 2
    img = Image(exe)
    mode, rest = argv[0], argv[1:]
    want = rest[0].lower() if rest else ""
    if mode == "--check":
        return check(img)
    if mode == "--rtti":
        for name in sorted(undecorate(n) for n in img.rtti_names()):
            if want in name.lower():
                print(name)
        return 0
    if mode == "--vtables":
        rows = [
            (va, undecorate(name), offset, slots)
            for va, name, offset, slots in img.vtables
        ]
        for va, name, offset, slots in sorted(rows, key=lambda r: r[1]):
            if want in name.lower():
                at = f" (at +{offset:#x})" if offset else ""
                print(f"{va:#010x}  {len(slots):3d} slots  {name}{at}")
        return 0
    if mode == "--class-of":
        found = img.class_of_vftable(int(rest[0], 16))
        if not found:
            print(f"no vftable at {rest[0]}")
            return 1
        name, offset, slots = found
        print(f"{undecorate(name)}  (offset {offset:#x}, {len(slots)} slots)")
        for i, f in enumerate(slots):
            print(f"    [{i:2d}] {f:#010x}")
        return 0
    if mode == "--bases":
        if not rest:
            print("--bases needs a class name, as --rtti prints it", file=sys.stderr)
            return 2
        decorated = next(
            (n for n in img.rtti_names() if undecorate(n) == rest[0]), None
        )
        found = img.bases(decorated) if decorated else None
        if not found:
            print(f"no class {rest[0]} with a vftable of its own")
            return 1
        for name, offset, contained in found:
            print(f"{offset:#06x}  {undecorate(name)}  ({contained} below)")
        return 0
    if mode == "--refs":
        for r in img.code_refs(int(rest[0], 16)):
            print(f"{r:#010x}")
        return 0
    if mode == "--disasm":
        count = int(rest[1]) if len(rest) > 1 else None
        for ins in img.disasm(int(rest[0], 16), count):
            print(f"{ins.address:#010x}  {ins.mnemonic} {ins.op_str}")
        return 0
    if mode == "--commands":
        names = [c for c in img.commands() if want in c.lower()]
        for c in names:
            print(c)
        print(f"{len(names)} commands", file=sys.stderr)
        return 0
    if mode == "--strings":
        if not want:
            print("--strings needs text to look for", file=sys.stderr)
            return 2
        pattern = re.compile(rb"[\x20-\x7e]{4,}")
        for m in pattern.finditer(img.data):
            s = m.group().decode()
            if want in s.lower():
                va = img.va_of_offset(m.start())
                print(f"{va if va else 0:#010x}  {s}")
        return 0
    if mode == "--imports":
        for dll, funcs in img.imports():
            print(f"{dll}: {len(funcs)}")
            for f in funcs:
                print(f"    {f}")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
