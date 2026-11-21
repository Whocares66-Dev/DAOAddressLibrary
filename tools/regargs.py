"""The registers each function takes its arguments in, where whole-program
optimisation gave it a convention of its own.

    python tools/regargs.py 0xVA ...            what each reads before it writes, and its callers
    python tools/regargs.py --write [FILE]      `registers` rows in data/ghidra_fixes.csv, for every
                                                function, or those of FILE's first column (0xVA)

The build was compiled /GL and linked /LTCG (dev/BUILDS.md, "The
compiler"), and the linker may then give a function whose every caller it
can see a convention of its own: an argument in eax, edx or esi, a this
in ecx for a free function. A decompile that does not know shows the
caller's setup as dead stores and the callee's reads as unaff_ and in_
registers, and a matching rebuild needs the real arguments (decomp-agent,
2026-11-20: 641 of its functions set aside so, its largest group).

A register is an argument when both sides say so:
- the function reads it before it writes it, on some path from its start
  (pushing ebx, esi, edi or ebp to save them is no read; a register handed
  on unwritten to a direct callee or tail jump that reads it is read here),
  read from its own instructions with capstone, branch by branch;
- every caller whose setup can be read loads it just before the call: the
  straight line back from the call, ended by another call, a return or an
  unconditional jump (code after a return is reached from elsewhere, and
  that caller says nothing). A register the function reads and some caller
  does not set is not taken: agents had read a leftover register as an
  argument.

A `registers` row gives the registers in the order the function first
reads them, then `|N` for N bytes of stack arguments it pops itself (its
ret N) or `|Nc` for N its callers pop, where they all agree (eax,edx|8).
tools/ghidra_sync.py makes them its parameters, in custom storage: Ghidra
stores none for most functions and infers them in each decompile, so the
stack ones are said too, or they would be lost. Not written: a member
(Class::) that reads only ecx, which __thiscall already says, and a
function nothing readable calls.
"""

import collections
import csv
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

ARGS = ("eax", "ecx", "edx", "ebx", "esi", "edi")
SAVED = ("ebx", "esi", "edi", "ebp")
FULL = {}
for _full, _parts in {
    "eax": ("eax", "ax", "al", "ah"),
    "ecx": ("ecx", "cx", "cl", "ch"),
    "edx": ("edx", "dx", "dl", "dh"),
    "ebx": ("ebx", "bx", "bl", "bh"),
    "esi": ("esi", "si"),
    "edi": ("edi", "di"),
    "ebp": ("ebp", "bp"),
}.items():
    for _p in _parts:
        FULL[_p] = _full
FIXES = os.path.join(ROOT, "data", "ghidra_fixes.csv")


class Reader:
    """Register arguments of the functions of one image.

    image: has bytes_at(va, n) and code_callers(va); body: {start: its bytes};
    names: {start: name}."""

    def __init__(self, image, body, names):
        import capstone

        self.img, self.body, self.names = image, body, names
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.md.detail = True
        self.memo = {}

    def regs(self, ins, ids):
        return {FULL[ins.reg_name(r)] for r in ids if ins.reg_name(r) in FULL}

    def live_in(self, va, depth=0):
        """{register: the first instruction that reads it} of va's arguments in registers."""
        if va in self.memo:
            return self.memo[va]
        if depth > 6:
            return {}
        self.memo[va] = {}
        self.memo[va] = found = self._live_in(va, depth)
        return found

    def _live_in(self, va, depth):
        from capstone import x86_const as X

        code = {ins.address: ins for ins in self.md.disasm(self.body.get(va, b""), va)}
        order = sorted(code)
        after = {
            a: order[i + 1] if i + 1 < len(order) else None for i, a in enumerate(order)
        }
        found, seen = {}, set()
        work = [(va, frozenset())]
        steps = 0
        while work and steps < 20000:
            steps += 1
            a, written = work.pop()
            if a not in code or (a, written) in seen:
                continue
            seen.add((a, written))
            ins = code[a]
            m, ops = ins.mnemonic, ins.operands
            read, wrote = ins.regs_access()
            reads, writes = self.regs(ins, read), self.regs(ins, wrote)
            same = (
                len(ops) == 2
                and ops[0].type == ops[1].type == X.X86_OP_REG
                and ops[0].reg == ops[1].reg
            )
            if m in ("xor", "sub") and same:
                reads = set()  # xor r, r writes r and reads nothing
            if m == "push" and len(ops) == 1 and ops[0].type == X.X86_OP_REG:
                pushed = FULL.get(ins.reg_name(ops[0].reg))
                if pushed in SAVED:
                    reads = set()  # saved, not used; a later read still is a use
                elif a == va:
                    # MSVC's way to reserve a stack slot is a push of a scratch
                    # register first thing (FindParameterRec's push ecx,
                    # 0x00504660, read as an argument 2026-11-20).
                    reads = set()
            for r in reads:
                if r in ARGS and r not in written:
                    found.setdefault(r, a)
            written = written | (writes & set(ARGS))
            direct = ops[0].imm if ops and ops[0].type == X.X86_OP_IMM else None
            if m in ("call", "jmp") and direct in self.body and direct not in code:
                for r in self.live_in(direct, depth + 1):
                    if r not in written:
                        found.setdefault(r, a)
            if m in ("ret", "retn") or (m == "jmp" and direct not in code):
                continue
            if m == "call":
                written = written | {"eax", "ecx", "edx"}
            if ins.group(X.X86_GRP_JUMP) and direct is not None:
                nexts = [direct] if m == "jmp" else [direct, after[a]]
            else:
                nexts = [after[a]]
            work += [(t, written) for t in nexts if t is not None]
        return found

    def callers_set(self, va, reg):
        """(callers that load reg in the straight line before the call, callers
        whose straight line could be read)."""
        good = told = 0
        for c in self.img.code_callers(va):
            if self.img.bytes_at(c, 1)[:1] != b"\xe8":
                continue
            line = self.line_before(c)
            used = False
            for ins in reversed(line):
                read, wrote = ins.regs_access()
                if reg in self.regs(ins, wrote):
                    # A register loaded and then read again before the call
                    # was a temporary (lea ecx, [esp+x]; push ecx): no load
                    # for the call.
                    good += not used
                    told += 1
                    break
                # Pushed, it went to the stack; tested or compared, it stays the
                # call's (mov ecx, [g]; test ecx, ecx; jz; ... call).
                if ins.mnemonic == "push" and reg in self.regs(ins, read):
                    used = True
                if ins.mnemonic == "call":
                    told += 1
                    break
                if ins.mnemonic in ("ret", "jmp"):
                    break
        return good, told

    def line_before(self, call):
        """Up to 24 instructions that end just before the call at an address."""
        code = self.img.bytes_at(call - 96, 101)
        for s in range(80):
            line = list(self.md.disasm(code[s:], call - 96 + s))
            if line and line[-1].address == call:
                return line[:-1][-24:]
        return []

    def arguments(self, va):
        """([registers every readable caller loads, in the order va reads them], {register: (loaded, readable)})."""
        found = self.live_in(va)
        told = {r: self.callers_set(va, r) for r in found}
        taken = [
            r
            for r in sorted(found, key=found.get)
            if told[r][1] and told[r][0] == told[r][1]
        ]
        return taken, told

    def starts(self):
        if not hasattr(self, "_starts"):
            self._starts = sorted(self.body)
        return self._starts

    def stack(self, va):
        """("|N", why) for N bytes of stack arguments the function pops (its
        ret N), ("|Nc", why) for N its callers pop (every caller's add esp, N
        straight after the call, all agreeing), or ("", why) where neither
        says: a function with no stored parameters has none of the stack ones
        the decompiler infers once it is given registers, so they are said."""
        pops = {
            ins.operands[0].imm
            for ins in self.md.disasm(self.body.get(va, b""), va)
            if ins.mnemonic == "ret" and ins.operands
        }
        if len(pops) == 1:
            n = pops.pop()
            return "|%d" % n, "ret %d" % n
        if pops:
            return "", "rets disagree"
        # The callers pop, but often later, several calls' arguments at once
        # (FindIndexRange16's, 0x0057F6D0): what they push since the call
        # before is the count.
        # An add esp straight after the call says it outright; else the
        # pushes back to the call before, inside the caller (a push before
        # any call may save the caller's own register).
        import bisect

        starts = self.starts()
        pushed = []
        for c in self.img.code_callers(va):
            if self.img.bytes_at(c, 1)[:1] != b"\xe8":
                continue
            after = list(self.md.disasm(self.img.bytes_at(c + 5, 8), c + 5))
            if (
                after
                and after[0].mnemonic == "add"
                and after[0].op_str.startswith("esp, ")
            ):
                pushed.append(int(after[0].op_str[5:], 0))
                continue
            own = starts[bisect.bisect_right(starts, c) - 1] if starts else 0
            n, ended = 0, False
            for ins in reversed(self.line_before(c)):
                if ins.address < own:
                    break
                if ins.mnemonic == "call":
                    ended = True
                    break
                if ins.mnemonic in ("ret", "jmp"):
                    break
                n += ins.mnemonic == "push"
            if not ended:
                return "", "plain ret, a caller's pushes cannot be counted"
            pushed.append(4 * n)
        if pushed and len(set(pushed)) == 1:
            n = pushed[0]
            return "|%dc" % n, "plain ret, its %d callers push %d bytes" % (
                len(pushed),
                n,
            )
        return "", "plain ret, its callers push different amounts"


def owner_of(name):
    """What a name puts its function in: Class of Class::Method, without arguments."""
    import msvc_names

    parts = msvc_names.split_top(name.split("(")[0])
    return "::".join(parts[:-1])


def classes():
    """The classes the build and the table know: RTTI's, and data/structs.csv's.
    An owner not among them is a namespace, and its function free."""
    import daoexe

    img = daoexe.Image(daoexe.default_exe(HERE))
    out = {daoexe.undecorate(d) for _, d, _, _ in img.vtables}
    with open(
        os.path.join(ROOT, "data", "structs.csv"), encoding="utf-8", newline=""
    ) as f:
        out |= {r["struct"] for r in csv.DictReader(f)}
    return out


def rows_for(reader, starts, signatures, known=frozenset()):
    """[(address, "eax,edx", why)] for each function given."""
    out = []
    for va in starts:
        taken, told = reader.arguments(va)
        if not taken:
            continue
        name = reader.names.get(va, "")
        thiscall = "__thiscall" in signatures.get(va, "")
        owner = owner_of(name)
        # A template's owner (std::vector<T>) is a class: the STL has no RTTI.
        member = (
            owner in known or "<" in owner or owner.startswith(("std::", "stdext::"))
        )
        if taken == ["ecx"] and (thiscall or member):
            continue
        found = reader.live_in(va)
        why = "; ".join(
            "%s read at 0x%08X before written, loaded by %d of %d callers whose setup can be read"
            % (r, found[r], told[r][0], told[r][1])
            for r in taken
        )
        stack, stack_why = reader.stack(va)
        out.append(
            (
                va,
                ",".join(taken) + stack,
                "%s; %s (tools/regargs.py)" % (why, stack_why),
            )
        )
    return out


def load():
    import daoexe
    import libmatch

    img = daoexe.Image(daoexe.default_exe(HERE))
    with open(
        os.path.join(ROOT, "data", "addresses.csv"), encoding="utf-8", newline=""
    ) as f:
        names = {
            int(r["gog-1.05"], 16): r["name"]
            for r in csv.DictReader(f)
            if r["kind"] == "function" and r["gog-1.05"]
        }
    return Reader(img, libmatch.build_functions(img, sorted(names)), names)


def write(rows):
    """Replace the file's `registers` rows for these addresses, append the rest."""
    with open(FIXES, encoding="utf-8", newline="") as f:
        table = list(csv.reader(f))
    new = {"0x%08X" % va: (regs, why) for va, regs, why in rows}
    kept = [r for r in table if not (r[1] == "registers" and r[0] in new)]
    kept += [[a, "registers", regs, why] for a, (regs, why) in sorted(new.items())]
    with open(FIXES, "w", encoding="utf-8", newline="") as f:
        csv.writer(f, lineterminator="\n").writerows(kept)
    return len(new)


def main(argv):
    reader = load()
    with open(FIXES, encoding="utf-8", newline="") as f:
        signatures = {
            int(r["address"], 16): r["value"]
            for r in csv.DictReader(f)
            if r["what"] in ("signature", "convention")
        }
    if "--write" in argv:
        rest = [a for a in argv if a != "--write"]
        if rest:
            with open(rest[0], encoding="utf-8") as f:
                starts = sorted(
                    {
                        int(line.split("\t")[0], 16)
                        for line in f
                        if line.startswith("0x")
                    }
                )
        else:
            starts = sorted(reader.names)
        rows = rows_for(
            reader, [s for s in starts if s in reader.body], signatures, classes()
        )
        print(
            write(rows),
            "registers rows written",
            collections.Counter(r for _, r, _ in rows).most_common(8),
        )
        return 0
    if not argv:
        print(__doc__)
        return 2
    for a in argv:
        va = int(a, 16)
        taken, told = reader.arguments(va)
        print(
            "0x%08X %-40s takes %s; read: %s"
            % (va, reader.names.get(va, "")[:40], ",".join(taken) or "-", told)
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
