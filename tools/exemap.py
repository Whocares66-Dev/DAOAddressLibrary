"""Where everything in one build of DAOrigins.exe is in another: the
comparison tools/addrlib.py carries an ID from build to build with.

    python tools/exemap.py ONE.exe OTHER.exe                    build the map, say how much it covers
    python tools/exemap.py ONE.exe OTHER.exe --lookup 0xVA...   single addresses of ONE's, in OTHER
    python tools/exemap.py ONE.exe OTHER.exe --changes          the functions that are not the same code
    python tools/exemap.py ONE.exe OTHER.exe --ranges FILE      write the whole map: start, length, other start
    python tools/exemap.py ONE.exe --inventory                  count what ONE holds that something refers to

Two builds of the game (dev/BUILDS.md) are the same engine linked in another
order: a function is byte for byte what it is in the other, apart from the
addresses inside it, and sits somewhere else. So no offset maps one to the
other, but the code itself does. Starting from what has a name in both (the
entry point, the exports, the imports, the RTTI classes and their vftables),
two functions known to be the same are read side by side, one instruction
each. They agree in everything but addresses, and where they hold an
address, the two addresses are the same thing in the two builds: a call's
target is a pair of functions to read next, a global's address a pair of
globals, a vftable's a pair of tables whose slots pair up in turn.

A build read against itself pairs everything with itself, and what the
reading reaches is the build's inventory: every function and every global
something refers to. That is what gets an ID (inventory).

Which bytes are addresses is not guessed. The relocation table of each
build lists every absolute address in the image, and a call or jump's
relative target is the instruction's own. Nothing here needs Ghidra;
capstone decodes (pip install capstone).

Where the source changed between the builds the instructions do not agree,
and that is the other thing this finds: an operand that differs (a field
that moved, a size, a line number in an assert) is noted and read past, and
where the instructions themselves part ways that path stops.

An address is mapped one of these ways, most trustworthy first:
  exact    both builds were seen to refer to it, by the same reference
  changed  the same, and the function there is not the same code in both
  range    inside a run of instructions or bytes compared one to one
  near     data nothing refers to directly, taken to be as far past the last
           exact address below it as in the first build: a field of a global
"""

import bisect
import collections
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import daoexe  # noqa: E402

CHUNK = 0x400
ENDS = {"ret", "retf", "jmp", "int3", "iretd", "hlt", "ud2"}
# How near a paired function must be to vouch for the layout around it.
NEIGHBOUR = 0x1000


class Side:
    """One build, laid out as it is in memory, with what its relocation
    table says: which words are addresses, and which addresses are pointed at."""

    def __init__(self, path):
        import capstone

        self.img = img = daoexe.Image(path)
        self.base = img.image_base
        d = img.data
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        nsec, optsz = (
            struct.unpack_from("<H", d, pe + 6)[0],
            struct.unpack_from("<H", d, pe + 20)[0],
        )
        at = pe + 24 + optsz
        mem = bytearray(img.size_of_image + 0x1000)
        self.sections = []
        for i in range(nsec):
            name = d[at + 40 * i : at + 40 * i + 8].rstrip(b"\0").decode()
            vsize, rva, rawsize, raw = struct.unpack_from("<IIII", d, at + 40 * i + 8)
            held = min(vsize, rawsize)
            mem[rva : rva + held] = d[raw : raw + held]
            self.sections.append(
                (name, self.base + rva, self.base + rva + vsize, self.base + rva + held)
            )
        self.mem = bytes(mem)
        self.text = next((s, e) for n, s, e, _ in self.sections if n == ".text")

        # Every HIGHLOW entry is the address of a 32-bit absolute address.
        self.is_reloc = bytearray(len(mem))
        self.is_target = bytearray(len(mem))
        # What the relocated words point at, by where the word is: data
        # pointing into .text holds a function's address (a vftable's slot,
        # a callback in a table), and anything pointed at outside .text is a
        # global.
        self.code_pointers = set()
        self.data_targets = set()
        rva, size = img.dirs[5]
        o, end = img.offset(rva), img.offset(rva) + size
        while o < end:
            page, block = struct.unpack_from("<II", d, o)
            if block == 0:
                break
            for i in range((block - 8) // 2):
                entry = struct.unpack_from("<H", d, o + 8 + 2 * i)[0]
                if entry >> 12 == 3:
                    where = page + (entry & 0xFFF)
                    self.is_reloc[where] = 1
                    value = struct.unpack_from("<I", self.mem, where)[0]
                    target = value - self.base
                    if 0 <= target < len(mem):
                        self.is_target[target] = 1
                    if self.in_text(value):
                        if not self.in_text(self.base + where):
                            self.code_pointers.add(value)
                    elif self.section(value)[0]:
                        self.data_targets.add(value)
            o += block
        # The word before a vftable points at its RTTI and nothing points at
        # the word, so it is marked as the start of something by hand: a walk
        # down one table must not run on into the next.
        for va, _, _, _ in img.vtables:
            self.is_target[va - 4 - self.base] = 1

        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    def in_text(self, va):
        return self.text[0] <= va < self.text[1]

    def section(self, va):
        """(name, end of the section, end of what the file holds of it)."""
        for name, start, end, held in self.sections:
            if start <= va < end:
                return name, end, held
        return None, 0, 0

    def u32(self, va):
        return struct.unpack_from("<I", self.mem, va - self.base)[0]

    def starts_function(self, va):
        """Whether code a jump goes to is where a function starts, by what
        MSVC puts before one: functions are aligned to 16 bytes, after int3
        padding or straight after the return that ends the one before. A
        jump to another function (a tail call, a thunk) lands so; a jump
        within a function, to a loop the compiler aligned with nops, does
        not."""
        at = va - self.base
        if va % 16 != 0 or not self.in_text(va - 3):
            return False
        return self.mem[at - 1] in (0xCC, 0xC3) or self.mem[at - 3] == 0xC2

    def relocs_in(self, va, size):
        """Offsets within [va, va+size) where a relocated word starts."""
        out = []
        i = self.is_reloc.find(1, va - self.base, va - self.base + size)
        while i != -1:
            out.append(i - (va - self.base))
            i = self.is_reloc.find(1, i + 1, va - self.base + size)
        return out

    def exports(self):
        rva, _ = self.img.dirs[0]
        o = self.img.offset(rva)
        d = self.img.data
        _, _, _, _, _, _, _, count, functions, names, ordinals = struct.unpack_from(
            "<IIHHIIIIIII", d, o
        )
        out = {}
        for i in range(count):
            name = self.img.cstring(
                struct.unpack_from("<I", d, self.img.offset(names) + 4 * i)[0]
            )
            ordinal = struct.unpack_from("<H", d, self.img.offset(ordinals) + 2 * i)[0]
            out[name] = (
                self.base
                + struct.unpack_from("<I", d, self.img.offset(functions) + 4 * ordinal)[
                    0
                ]
            )
        return out

    def import_slots(self):
        """{(dll, function): the IAT slot's address}."""
        rva, _ = self.img.dirs[1]
        o = self.img.offset(rva)
        d = self.img.data
        out = {}
        while True:
            ilt, _, _, name, iat = struct.unpack_from("<IIIII", d, o)
            if name == 0:
                break
            dll = self.img.cstring(name).lower()
            p = self.img.offset(ilt or iat)
            n = 0
            while True:
                e = struct.unpack_from("<I", d, p + 4 * n)[0]
                if e == 0:
                    break
                what = e & 0xFFFF if e & 0x80000000 else self.img.cstring(e + 2)
                out[(dll, what)] = self.base + iat + 4 * n
                n += 1
            o += 20
        return out


class Walk:
    """Two stretches of code read side by side: how far they agreed."""

    def __init__(self, runs, matched, operands, breaks):
        self.runs = runs  # [(a start, length, b start)]
        self.matched = matched
        self.operands = (
            operands  # [(a, b, a's text, b's text)] where only an operand differs
        )
        self.breaks = (
            breaks  # [(a, b, why)] where the two stop being the same instructions
        )
        self.same = not operands and not breaks


class Map:
    # A pair that code or a vftable gave is believed even where the two
    # functions differ: it is the same function, changed. A pair that only
    # the position in some other table gave has to show it, by this many
    # instructions agreeing before the first that does not.
    ENOUGH = 8

    def __init__(self, a, b, unordered=()):
        self.a, self.b = a, b
        self.unordered = set(unordered)  # tables in a whose order is not b's
        self.strong = collections.defaultdict(
            collections.Counter
        )  # a -> {b: references from code}
        self.weak = collections.defaultdict(
            collections.Counter
        )  # a -> {b: references from tables}
        self.kind = {}  # a -> "function" | "code" | "data" | "table"
        self.queue = collections.deque()
        self.queued = set()
        self.at = {}  # an instruction in a -> the same instruction in b, once compared
        self.walks = {}  # (a, b) -> Walk, for code that was accepted
        self.data_runs = {}  # (a, b) -> (a start, length, b start)
        self.rejected = []  # (a, b, where in a, where in b, why)
        self.children = collections.defaultdict(
            list
        )  # a table in a -> [(a, b)] functions it gave
        self.differing_data = []
        self.vftables = {va for va, _, _, _ in a.img.vtables}
        self.vftables_b = {va for va, _, _, _ in b.img.vtables}
        self.seeds = 0

    # -- pairs --
    def pair(self, a, b, kind, strong=True):
        (self.strong if strong else self.weak)[a][b] += 1
        if kind == "function" or a not in self.kind:
            self.kind[a] = kind
        if (a, b) not in self.queued:
            self.queued.add((a, b))
            self.queue.append((a, b, kind, strong))
            # The word before a vftable points at its RTTI: the locator,
            # and from it the class's hierarchy and bases. Nothing in code
            # refers to that word, so a pair of vftables is the way to it.
            if kind == "data" and a in self.vftables and b in self.vftables_b:
                self.pair(a - 4, b - 4, "data", strong)

    def seed(self):
        A, B = self.a, self.b
        self.pair(
            A.base + A.img.entry_point_rva, B.base + B.img.entry_point_rva, "function"
        )
        ea, eb = A.exports(), B.exports()
        for name in ea.keys() & eb.keys():
            self.pair(ea[name], eb[name], "function" if A.in_text(ea[name]) else "data")
        ia, ib = A.import_slots(), B.import_slots()
        for key in ia.keys() & ib.keys():
            self.pair(ia[key], ib[key], "data")
        da = {name: va for va, name in A.img.type_descriptors.items()}
        db = {name: va for va, name in B.img.type_descriptors.items()}
        for name in da.keys() & db.keys():
            self.pair(da[name], db[name], "data")
        # A class with one vftable at an offset names it; a class with
        # several there is left to its constructors.
        va, vb = collections.defaultdict(list), collections.defaultdict(list)
        for v, name, offset, _ in A.img.vtables:
            va[(name, offset)].append(v)
        for v, name, offset, _ in B.img.vtables:
            vb[(name, offset)].append(v)
        for key in va.keys() & vb.keys():
            if len(va[key]) == 1 and len(vb[key]) == 1:
                self.pair(va[key][0], vb[key][0], "data")
        # The TLS and load-configuration directories, which the headers
        # point at by RVA and which hold addresses of their own: the TLS
        # template's start and end, the security cookie.
        for directory in (9, 10):
            rva_a, rva_b = A.img.dirs[directory][0], B.img.dirs[directory][0]
            if rva_a and rva_b:
                self.pair(A.base + rva_a, B.base + rva_b, "data")
        self.seeds = len(self.queue)

    # -- code --
    def walk_code(self, start_a, start_b, strong):
        """Read two functions side by side from a pair of addresses, following
        the short jumps within them. Addresses apart, the instructions are
        expected to be the same. One that differs in an operand alone is
        noted and read past. Where the two stop being the same instructions,
        one build has code the other lacks, and reading goes on from where
        they next agree (resume). What agreeing instructions refer to is
        paired."""
        A, B = self.a, self.b
        local = [(start_a, start_b)]
        seen = {}
        found, runs, operands, breaks = [], [], [], []
        while local:
            a, b = local.pop()
            if not (A.in_text(a) and B.in_text(b)):
                breaks.append((a, b, "leaves .text"))
                continue
            run_a, run_b = a, b
            going = True
            while going:
                if a in seen or self.at.get(a) == b:
                    break
                ga = A.md.disasm_lite(A.mem[a - A.base : a - A.base + CHUNK], a)
                gb = B.md.disasm_lite(B.mem[b - B.base : b - B.base + CHUNK], b)
                progressed = False
                # Not strict: either side may run out of bytes that decode first.
                for (ia, size, mnemonic, ops), (ib, size_b, mnemonic_b, ops_b) in zip(
                    ga, gb, strict=False
                ):
                    if ia in seen or self.at.get(ia) == ib:
                        going = False
                        break
                    problem = None
                    differs = False
                    bytes_a = A.mem[ia - A.base : ia - A.base + size]
                    bytes_b = B.mem[ib - B.base : ib - B.base + size_b]
                    direct = ops.startswith("0x") and (
                        mnemonic == "call"
                        or mnemonic[0] == "j"
                        or mnemonic[:4] == "loop"
                    )
                    if size != size_b or mnemonic != mnemonic_b:
                        problem = f"{mnemonic} {ops} | {mnemonic_b} {ops_b}"
                    elif direct:
                        # The displacement is the instruction's last one or four bytes.
                        width = 4 if bytes_a[0] in (0xE8, 0xE9, 0x0F) else 1
                        if bytes_a[:-width] != bytes_b[:-width]:
                            problem = f"{mnemonic} {ops} | {mnemonic_b} {ops_b}"
                        elif width == 1:
                            local.append((int(ops, 16), int(ops_b, 16)))
                        else:
                            kind = "function" if mnemonic == "call" else "code"
                            found.append((int(ops, 16), int(ops_b, 16), kind))
                    else:
                        ra, rb = A.relocs_in(ia, size), B.relocs_in(ib, size)
                        # An address that runs past the instruction's end is
                        # in no instruction: this is data that sits in .text.
                        if ra and ra[-1] + 4 > size:
                            problem = "not code"
                        elif ra != rb:
                            problem = f"{mnemonic} {ops} | {mnemonic_b} {ops_b}"
                        else:
                            last = 0
                            pairs = []
                            for n, r in enumerate(ra):
                                differs |= bytes_a[last:r] != bytes_b[last:r]
                                last = r + 4
                                value_a = struct.unpack_from("<I", bytes_a, r)[0]
                                value_b = struct.unpack_from("<I", bytes_b, r)[0]
                                if A.section(value_a)[0] != B.section(value_b)[0]:
                                    problem = f"{mnemonic} {ops} | {mnemonic_b} {ops_b}"
                                    break
                                # An address in .text inside a memory operand is a jump
                                # table or a byte table, which MSVC puts after the
                                # function; anywhere else it is a function's address. A
                                # displacement comes before an immediate, so of two
                                # addresses the first is the memory operand's; one alone
                                # is, if it is written inside the brackets.
                                bracket = ops[ops.find("[") : ops.rfind("]") + 1]
                                in_memory = (len(ra) == 2 and n == 0) or (
                                    len(ra) == 1 and f"{value_a:#x}" in bracket
                                )
                                kind = (
                                    "data"
                                    if not A.in_text(value_a)
                                    else "table"
                                    if in_memory
                                    else "function"
                                )
                                pairs.append((value_a, value_b, kind))
                            if not problem:
                                differs |= bytes_a[last:] != bytes_b[last:]
                                found += pairs
                    if problem:
                        breaks.append((ia, ib, problem))
                        # Two builds that differ here may agree again further
                        # on; bytes that are not code have nothing further on.
                        again = self.resume(ia, ib) if problem != "not code" else None
                        if again:
                            local.append(again)
                        a, b = ia, ib
                        going = False
                        break
                    if differs:
                        operands.append(
                            (ia, ib, f"{mnemonic} {ops}", f"{mnemonic_b} {ops_b}")
                        )
                    seen[ia] = ib
                    progressed = True
                    a, b = ia + size, ib + size
                    if mnemonic in ENDS:
                        going = False
                        break
                if not progressed and going:
                    breaks.append((a, b, "does not decode"))
                    break
            if a > run_a:
                runs.append((run_a, a - run_a, run_b))

        if breaks and not strong and len(seen) < self.ENOUGH:
            self.rejected.append((start_a, start_b, *breaks[0]))
            return False
        for ia, ib in seen.items():
            self.at.setdefault(ia, ib)
        self.walks[(start_a, start_b)] = Walk(runs, len(seen), operands, breaks)
        for a, b, kind in found:
            self.pair(a, b, kind)
        return True

    def masked(self, side, va, size, mnemonic, ops):
        """An instruction's bytes with its addresses blanked."""
        raw = bytearray(side.mem[va - side.base : va - side.base + size])
        for r in side.relocs_in(va, size):
            raw[r : r + 4] = bytes(4)
        if ops.startswith("0x") and (
            mnemonic == "call" or mnemonic[0] == "j" or mnemonic[:4] == "loop"
        ):
            width = 4 if raw[0] in (0xE8, 0xE9, 0x0F) else 1
            raw[-width:] = bytes(width)
        return bytes(raw)

    # How far past a difference to look for the two agreeing again, and how
    # many instructions in a row must agree for it to count.
    AHEAD = 96
    AGREE = 5

    def resume(self, a, b):
        """The nearest (a, b) past a difference from which the next
        instructions are the same again, addresses apart."""
        A, B = self.a, self.b

        def ahead(side, va):
            out = []
            code = side.mem[va - side.base : va - side.base + 16 * self.AHEAD]
            for at, size, mnemonic, ops in side.md.disasm_lite(code, va):
                if mnemonic == "int3" or len(out) == self.AHEAD:
                    break
                out.append((at, self.masked(side, at, size, mnemonic, ops)))
            return out

        sa, sb = ahead(A, a), ahead(B, b)
        best = None
        for i in range(len(sa) - self.AGREE + 1):
            for j in range(len(sb) - self.AGREE + 1):
                if best and i + j >= best[0]:
                    break
                # Not where it stopped: the two already differ there, however
                # alike their bytes, and to resume there is to stop again.
                if i + j > 0 and all(
                    sa[i + k][1] == sb[j + k][1] for k in range(self.AGREE)
                ):
                    best = (i + j, sa[i][0], sb[j][0])
        return best and best[1:]

    # -- data --
    def walk_data(self, a, b, table):
        """Two globals side by side until something else starts in either
        build: the words that are addresses pair up, the rest must be equal.
        A jump table (in .text) is addresses only."""
        A, B = self.a, self.b
        name, end_a, held_a = A.section(a)
        _, end_b, held_b = B.section(b)
        if not table and name not in (".rdata", ".data"):
            return
        # Past what the file holds the section is zero in both, and equal
        # zeroes say nothing about being the same thing.
        end_a, end_b = min(end_a, held_a), min(end_b, held_b)
        start_a, start_b = a, b
        found = []
        while a < end_a and b < end_b:
            if a != start_a and (A.is_target[a - A.base] or B.is_target[b - B.base]):
                break
            ra, rb = A.is_reloc[a - A.base], B.is_reloc[b - B.base]
            if ra and rb:
                value_a, value_b = A.u32(a), B.u32(b)
                if table and not (A.in_text(value_a) and B.in_text(value_b)):
                    break
                if not table and A.section(value_a)[0] != B.section(value_b)[0]:
                    break
                kind = "code" if table else "function" if A.in_text(value_a) else "data"
                found.append((value_a, value_b, kind))
                a, b = a + 4, b + 4
            elif ra or rb or table:
                break
            elif A.mem[a - A.base] != B.mem[b - B.base]:
                self.differing_data.append((a, b))
                break
            else:
                a, b = a + 1, b + 1
        if a > start_a:
            self.data_runs[(start_a, start_b)] = (start_a, a - start_a, start_b)
        if start_a in self.unordered:
            return
        # A vftable's slots and a jump table's cases are in the order the
        # source gives them. Any other table of functions may not be.
        sure = table or start_a in self.vftables
        for value_a, value_b, kind in found:
            self.pair(value_a, value_b, kind, sure)
            if not sure and kind == "function":
                self.children[start_a].append((value_a, value_b))

    def run(self):
        while self.queue:
            a, b, kind, strong = self.queue.popleft()
            if kind in ("function", "code"):
                self.walk_code(a, b, strong)
            else:
                self.walk_data(a, b, kind == "table")

    def out_of_order(self):
        """Tables of functions whose entries did not pair up: tables the
        linker fills, like the C runtime's list of initializers, are in link
        order, which the two builds do not share."""
        bad = {(a, b) for a, b, _, _, _ in self.rejected}
        return {
            table
            for table, pairs in self.children.items()
            if any(p in bad for p in pairs)
        }

    # -- the result --
    def finish(self):
        """exact: {a: b}, the candidate with the most references, one whose
        code is unchanged before one whose code differs.
        ranges: sorted (a start, length, b start), no two overlapping."""
        A = self.a
        bad = {(a, b) for a, b, _, _, _ in self.rejected}
        self.exact = {}
        self.ambiguous = []
        for a in self.strong.keys() | self.weak.keys():
            options = []
            for b in self.strong[a].keys() | self.weak[a].keys():
                if (a, b) in bad:
                    continue
                walk = self.walks.get((a, b))
                options.append(
                    (walk is None or walk.same, self.strong[a][b], self.weak[a][b], b)
                )
            if not options:
                continue
            options.sort(reverse=True)
            if len(options) > 1:
                self.ambiguous.append((a, options))
            self.exact[a] = options[0][3]

        owned = bytearray(len(A.mem))
        ranges = []
        chosen, others = [], []
        for (a, b), walk in self.walks.items():
            (chosen if self.exact.get(a) == b else others).extend(walk.runs)
        for (a, b), run in self.data_runs.items():
            (chosen if self.exact.get(a) == b else others).append(run)
        for runs in (chosen, others):
            for start, length, other in sorted(set(runs)):
                at = start - A.base
                if owned.find(1, at, at + length) != -1:
                    continue
                owned[at : at + length] = b"\x01" * length
                ranges.append((start, length, other))
        ranges.sort()
        merged = []
        for start, length, other in ranges:
            if merged:
                s, n, o = merged[-1]
                if start == s + n and other - start == o - s:
                    merged[-1] = (s, n + length, o)
                    continue
            merged.append((start, length, other))
        self.ranges = merged
        self.starts = [s for s, _, _ in merged]
        self.exact_data = sorted(a for a in self.exact if not A.in_text(a))
        self.exact_code = sorted(
            a for a in self.exact if self.kind.get(a) == "function"
        )

    def function_of(self, a):
        """The paired function at or before a code address."""
        i = bisect.bisect_right(self.exact_code, a) - 1
        return self.exact_code[i] if i >= 0 else None

    def changed_functions(self):
        """{function in a: [(instruction in a, in b, a's text, b's text)]},
        the operand differences and the places the code parts ways."""
        out = collections.defaultdict(set)
        for (a, b), walk in self.walks.items():
            if self.exact.get(a) != b or walk.same:
                continue
            rows = out[self.function_of(a)]
            rows.update(walk.operands)
            for ia, ib, why in walk.breaks:
                text_a, _, text_b = why.partition(" | ")
                rows.add((ia, ib, text_a + "  <- parts ways", text_b))
        return {f: sorted(rows) for f, rows in out.items()}

    def lookup(self, a):
        """(b, how) or (None, why not)."""
        if a in self.exact:
            walk = self.walks.get((a, self.exact[a]))
            return self.exact[a], "changed" if walk and not walk.same else "exact"
        i = bisect.bisect_right(self.starts, a) - 1
        if i >= 0:
            s, n, o = self.ranges[i]
            if a < s + n:
                return o + a - s, "range"
        if not self.a.in_text(a) and self.a.section(a)[0]:
            i = bisect.bisect_right(self.exact_data, a) - 1
            if i >= 0:
                below = self.exact_data[i]
                if self.a.section(below)[0] == self.a.section(a)[0]:
                    return self.exact[
                        below
                    ] + a - below, f"near {below:#010x}+{a - below:#x}"
        return None, "not reached"

    def coverage(self):
        A = self.a
        start, end = A.text
        covered = bytearray(end - start)
        for s, n, _ in self.ranges:
            if A.in_text(s):
                covered[s - start : s - start + n] = b"\x01" * n
        code = A.mem[start - A.base : end - A.base]
        padding = sum(1 for i in range(len(code)) if code[i] == 0xCC and not covered[i])
        return sum(covered), len(code), padding


def shape(side, start, limit=4000):
    """One function read on its own: (its instructions' bytes in address
    order with every address blanked, the addresses in the same order), or
    None for bytes that are not a function. Short jumps are followed; a call
    or a far jump's target is one of the addresses."""
    blocks = [start]
    seen = {}
    while blocks:
        at = blocks.pop()
        going = True
        while going:
            if at in seen or not side.in_text(at):
                break
            code = side.mem[at - side.base : at - side.base + CHUNK]
            progressed = False
            for va, size, mnemonic, ops in side.md.disasm_lite(code, at):
                if va in seen:
                    going = False
                    break
                raw = bytearray(side.mem[va - side.base : va - side.base + size])
                refs = []
                direct = ops.startswith("0x") and (
                    mnemonic == "call" or mnemonic[0] == "j" or mnemonic[:4] == "loop"
                )
                if direct:
                    width = 4 if raw[0] in (0xE8, 0xE9, 0x0F) else 1
                    raw[-width:] = bytes(width)
                    if width == 1:
                        blocks.append(int(ops, 16))
                    else:
                        refs.append(int(ops, 16))
                else:
                    for r in side.relocs_in(va, size):
                        if r + 4 > size:
                            return None
                        refs.append(struct.unpack_from("<I", raw, r)[0])
                        raw[r : r + 4] = bytes(4)
                seen[va] = (bytes(raw), refs)
                progressed = True
                at = va + size
                if len(seen) > limit:
                    return None
                if mnemonic in ENDS:
                    going = False
                    break
            if not progressed and going:
                return None
    if not seen:
        return None
    order = sorted(seen)
    return (
        b"".join(seen[va][0] for va in order),
        tuple(ref for va in order for ref in seen[va][1]),
    )


def clusters(addresses, apart=0x400):
    """Sorted addresses as runs, a new run wherever two are far apart."""
    out = []
    for address in sorted(addresses):
        if out and address - out[-1][-1] <= apart:
            out[-1].append(address)
        else:
            out.append([address])
    return out


def match_leftovers(m, functions_a, functions_b):
    """Pair the functions the reading did not reach, by what they are: the
    same instructions, referring to the same things. A static initializer or
    an unwind stub is called by nothing the reading follows (the C runtime
    walks a table of them in link order, which two builds do not share), but
    it names the global it constructs and the constructor it calls. Two
    functions pair only if no other function on either side looks the same,
    with what each refers to counted where that is already paired; what they
    refer to that was not paired then pairs too, in step. How many pairs it
    made; the map is run on and finished again, so they are read and
    checked like any other."""
    A, B = m.a, m.b
    shapes_a = {f: shape(A, f) for f in functions_a if m.lookup(f)[0] is None}
    images = set(m.exact.values())
    shapes_b = {f: shape(B, f) for f in functions_b if f not in images}
    made = 0
    while True:
        known = m.exact
        images = set(known.values())
        by_key_b = collections.defaultdict(list)
        for f, s in shapes_b.items():
            if s and f not in images:
                key = (s[0], tuple(r if r in images else None for r in s[1]))
                by_key_b[key].append(f)
        by_key_a = collections.defaultdict(list)
        for f, s in shapes_a.items():
            if s and f not in known:
                by_key_a[(s[0], tuple(known.get(r) for r in s[1]))].append(f)
        pairs = [
            (fa[0], by_key_b[key][0])
            for key, fa in by_key_a.items()
            if len(fa) == 1 and len(by_key_b.get(key, ())) == 1
        ]
        if not pairs:
            # Functions that look the same on both sides, several of them:
            # the initializers of one class's globals, the unwind stubs of
            # one function. What one object file contributes keeps its
            # layout whatever the link order, so a run of them standing at
            # the same distances from each other in both builds, and no
            # other run so spaced, is the same run, in order.
            for key, fa in by_key_a.items():
                ca, cb = clusters(fa), clusters(by_key_b.get(key, ()))
                spaced_a = collections.defaultdict(list)
                spaced_b = collections.defaultdict(list)
                for c in ca:
                    spaced_a[tuple(x - c[0] for x in c)].append(c)
                for c in cb:
                    spaced_b[tuple(x - c[0] for x in c)].append(c)
                for spacing, runs in spaced_a.items():
                    if len(runs) == 1 and len(spaced_b.get(spacing, ())) == 1:
                        pairs += zip(runs[0], spaced_b[spacing][0], strict=True)
        if not pairs:
            # One of several alike, standing between two paired functions at
            # the same distance from each in both builds: the same argument,
            # with neighbours for the layout. Both neighbours, since the one
            # below alone may be the end of another object file, after
            # which the builds differ.
            paired = sorted(f for f in known if A.in_text(f))
            for key, fa in by_key_a.items():
                candidates = set(by_key_b.get(key, ()))
                for f in fa:
                    i = bisect.bisect_left(paired, f)
                    if i == 0 or i == len(paired):
                        continue
                    below, above = paired[i - 1], paired[i]
                    if f - below > NEIGHBOUR or above - f > NEIGHBOUR:
                        continue
                    there = known[below] + (f - below)
                    if there == known[above] - (above - f) and there in candidates:
                        pairs.append((f, there))
        if not pairs:
            return made
        for fa, fb in pairs:
            m.pair(fa, fb, "function")
        made += len(pairs)
        m.run()
        m.finish()


def build(a, b, inventories=None):
    """The map from one build to another (each a Side, or a path), made
    twice: the first pass finds the tables whose order the builds do not
    share, the second leaves what they would pair alone. With the two
    builds' inventories of functions, what the reading did not reach is
    then paired by what it is (match_leftovers)."""
    a = a if isinstance(a, Side) else Side(a)
    b = b if isinstance(b, Side) else Side(b)
    first = Map(a, b)
    first.seed()
    first.run()
    m = Map(a, b, first.out_of_order())
    m.seed()
    m.run()
    m.finish()
    m.leftovers_paired = match_leftovers(m, *inventories) if inventories else 0
    return m


def functions_of(m):
    """The addresses in a map's first build where a function starts: what is
    called or pointed at, and what is only jumped to but starts as a
    function does in both builds (a tail call's target)."""
    out = set(m.exact_code)
    for a, kind in m.kind.items():
        if (
            kind == "code"
            and a in m.exact
            and m.a.starts_function(a)
            and m.b.starts_function(m.exact[a])
        ):
            out.add(a)
    return out


def inventory(side):
    """What one build holds that something refers to: (its functions, its
    globals), each a sorted list of addresses. The build is read against
    itself, from the same named things a comparison starts from and from
    every function's address held in data, so whatever the reading reaches
    is there; a global is anything outside .text a relocated word points at,
    which needs no reading."""
    side = side if isinstance(side, Side) else Side(side)
    m = Map(side, side)
    m.seed()
    for pointer in sorted(side.code_pointers):
        m.pair(pointer, pointer, "function")
    m.run()
    m.finish()
    return sorted(functions_of(m)), sorted(side.data_targets)


def main(argv):
    if not argv or argv[0] in ("-h", "--help") or len(argv) < 2:
        print(__doc__)
        return 0
    if argv[1] == "--inventory":
        functions, data = inventory(argv[0])
        print(f"{len(functions)} functions and {len(data)} globals referred to")
        return 0
    one, other, rest = argv[0], argv[1], argv[2:]
    m = build(one, other)

    if rest and rest[0] == "--lookup":
        for text in rest[1:]:
            a = int(text, 16)
            b, how = m.lookup(a)
            print(f"{a:#010x}  {f'{b:#010x}' if b else '-':>10}  {how}")
        return 0

    covered, size, padding = m.coverage()
    functions = len(m.exact_code)
    changed = m.changed_functions()
    print(
        f"{m.seeds} named pairs to start from, {len(m.unordered)} tables left alone as out of order"
    )
    print(
        f"{functions} functions and {len(m.exact_data)} data addresses paired, {len(m.ranges)} ranges"
    )
    print(
        f".text: {covered:#x} of {size:#x} bytes compared one to one ({100 * covered / size:.1f}%), "
        f"{padding:#x} more are padding"
    )
    print(
        f"{len(changed)} functions differ, in {sum(len(rows) for rows in changed.values())} instructions"
    )
    print(
        f"{len(m.rejected)} pairs rejected, {len(m.ambiguous)} addresses with more than one candidate"
    )

    if rest and rest[0] == "--changes":
        for function in sorted(changed, key=lambda f: f or 0):
            b, _ = m.lookup(function) if function else (None, "")
            print(f"{function or 0:#010x} -> {b or 0:#010x}")
            for ia, ib, text_a, text_b in changed[function]:
                print(f"    {ia:#010x} {text_a:<44} | {ib:#010x} {text_b}")
    if rest and rest[0] == "--ranges":
        with open(rest[1], "w", newline="\n") as f:
            f.write("one,length,other\n")
            for s, n, o in m.ranges:
                f.write(f"{s:#010x},{n:#x},{o:#010x}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
