"""Brings DAOLib's Ghidra database of the GOG build (`ghidra-dao`) into line
with data/addresses.csv and data/ghidra_fixes.csv.

    python tools/ghidra_sync.py              apply everything, then save the program
    python tools/ghidra_sync.py --dry-run    count what would change, change nothing
    python tools/ghidra_sync.py --limit N    only the first N rows of the table (a trial)
    python tools/ghidra_sync.py --only types,eh    only these parts (rows, fixes, types, eh, comments, params, getters)
    python tools/ghidra_sync.py --no-save    apply and leave it unsaved, to look at before keeping it
    python tools/ghidra_sync.py --discard    drop everything done since the last save

The user, 2026-10-31, relayed by paragon-agent: "If we know something that
ghidra gets wrong, we should fix the ghidra database. As we apply more
fixes, ghidra should get fewer things wrong", and asked that the keeper of
this repository be its one writer, every other session reading it only.
Readers had been misled by it: it defined 33,364 functions to the table's
59,743, kept names the table had since put right, and gave every function
no parameters.

So the database is a copy, never a source. A name is written in the
table's name column as ever, and a Ghidra fix that is not a name (a
calling convention, a signature, an auto-label to clear) is a line of
data/ghidra_fixes.csv. This tool writes both into whatever Ghidra project
the server has open, the live one or a fresh import of the GOG exe, so the
database can be made again from anyone's copy of the game. The database
itself (DAOLib's game/ghidra, about 740 MB with the exe's bytes in it) is
in no repository.

What a run does, on the GOG build's addresses:

- every function row: defines the function where Ghidra has none
  (disassembling first if need be, Ghidra's flow finding the body), and,
  if the table names it, gives it that name in its namespaces, made as
  needed. A name the table does not have is left as Ghidra has it.
- every data row with a name: makes that name the address's primary label.
- every line of data/ghidra_fixes.csv (`address,what,value,why`):
  `convention` sets the calling convention (`__thiscall`, `__stdcall`,
  `__cdecl`, `__fastcall`); `signature` sets the prototype from C
  (`bool __thiscall f(void *this, int *key)`, in types Ghidra knows, the
  first parameter of a __thiscall being this and the name ignored: the
  table names);
  `clear` removes a misleading label at the address (`value` the label,
  as Ghidra holds it, with or without its namespaces,
  or empty for every non-primary one); `nofunction` removes a function
  Ghidra defined where the table has none (a start inside another
  function's instruction), so the body goes back to its function;
  `returns` (value empty) marks a function Ghidra took for one that never
  returns as returning; `callfixup` gives a function one of the compiler
  spec's call fixups by name; `datatype` types a global and `returntype`
  a function's return, in the types a struct's field is written in
  (`CCParty *`).
- what tools/receivers.py reads from the code of what a global holds and
  what a getter returns, as `datatype` and `returntype` rows nobody wrote,
  and which methods are called with this inside their object and how far
  in (`thisat`, Class+0xN): its head says what counts.
- every struct in data/structs.csv: its fields onto the type Ghidra's
  decompiler uses for that class, with their types, and each vftable's
  slots named and typed for the functions in them. tools/ghidra_types.py
  is this half and its head says how.
- every function that is a piece of another's exception handling (an
  unwind funclet, a catch block, an __ehhandler stub) and that the table
  neither names nor comments: named Unwind@, Catch@ or EhHandler@ and its
  address, as Ghidra's own analysis names them, with the function it
  belongs to in its plate comment.
- every comment in the table's comment column: the plate comment at its
  address. One the table takes out stays in Ghidra.

A run that leaves a class type shorter than it was, or without a vftable
pointer or a nested class it had, has damaged it: such a run is discarded
whole and nothing saved (2026-11-16: writing by offset into types Ghidra
lays out itself did both, and was seen only because the run was not saved).
A change to how types are written is tried with --no-save and looked at
through tools/facts_dump.py on a sample before it is kept.

It talks to the server over MCP's plain HTTP (initialize, then
`eval_python` with the work as JSON, a few thousand rows a call, then
`save_program`), the way DAOLib's `.mcp.json` names it. It refuses a
program whose SHA-256 is not the GOG build's in data/builds.csv.

The server is headless (DAOLib's tools/ghidra-mcp.ps1), and its waiting
script holds the program's transaction for its whole run, so save_program
saves only with the user's GhidrAssistMCP fork at agentic-switch 4dc7768
or later, where that script ends its transaction, saves and opens another
on request. With an older one the changes stay in memory until the
server's -Stop.
"""

import csv
import re
import json
import sys
import time
import urllib.request
from pathlib import Path

import ghidra_types
import structs
from msvc_names import split_top

ROOT = Path(__file__).resolve().parent.parent
SERVER = "http://127.0.0.1:8090/mcp"
BUILD = "gog-1.05"
CHUNK = 4000

# Runs inside Ghidra (pyghidra, Python 3). PAYLOAD is the JSON of the work.
GHIDRA_SCRIPT = r"""
import json
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.symbol import SymbolUtilities
from ghidra.app.util.cparser.C import CParserUtils
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.app.cmd.function import CreateFunctionCmd
W = json.loads(PAYLOAD)
TYPE_WORDS = {"void", "int", "bool", "char", "short", "long", "float", "double",
              "unsigned", "signed", "uint", "ushort", "uchar"}
program = currentProgram
if program.getExecutableSHA256().lower() != W["sha256"]:
    raise Exception("not the " + W["build"] + " build: " + program.getExecutableSHA256())
dry = W["dry"]
fm = program.getFunctionManager()
st = program.getSymbolTable()
listing = program.getListing()
SOURCE = SourceType.IMPORTED
done = {"created": 0, "named": 0, "same": 0, "labels": 0, "fixes": 0, "structs": 0,
        "comments": 0, "classfields": 0}
faults = []
spaces = {}

def namespace(path):
    key = "::".join(path)
    if key in spaces:
        return spaces[key]
    parent = program.getGlobalNamespace()
    for part in path:
        found = st.getNamespace(part, parent)
        parent = found if found is not None else st.createNameSpace(parent, part, SOURCE)
    spaces[key] = parent
    return parent

for kind, address, parts in W["rows"]:
    a = toAddr(address)
    name = "::".join(parts) if parts else ""
    try:
        if parts:
            parts = parts[:-1] + [SymbolUtilities.replaceInvalidChars(parts[-1], True)]
        if kind == "function":
            f = fm.getFunctionAt(a)
            if f is None:
                done["created"] += 1
                if dry:
                    continue
                if listing.getInstructionAt(a) is None:
                    disassemble(a)
                f = createFunction(a, None)
                if f is None:
                    done["created"] -= 1
                    faults.append("no function at 0x%08x" % address)
                    continue
            if not parts:
                continue
            # The whole path, not the leaf: on the leaf alone a class's rename
            # (Vector::Zero to Vector3::Zero, 2026-11-02) never reached Ghidra.
            # A namespace Ghidra's class recovery made has the same path.
            if f.getSymbol().getName(True) == "::".join(parts):
                done["same"] += 1
                continue
            done["named"] += 1
            if not dry:
                space = namespace(parts[:-1])
                # An export's decorated name may already be a label here, which
                # the function cannot then take; the entry point is the
                # address's, not the label's, so the label goes.
                for other in list(st.getSymbols(a)):
                    if other != f.getSymbol() and other.getName() == parts[-1] \
                            and other.getParentNamespace() == space:
                        other.delete()
                f.getSymbol().setNameAndNamespace(parts[-1], space, SOURCE)
        else:
            primary = st.getPrimarySymbol(a)
            if primary is not None and primary.getName(True) == "::".join(parts):
                done["same"] += 1
                continue
            done["labels"] += 1
            if dry:
                continue
            # The right leaf in another namespace (a name the table has moved
            # into a class) is moved; else a new label, made primary.
            if primary is not None and primary.getName() == parts[-1]:
                primary.setNameAndNamespace(parts[-1], namespace(parts[:-1]), SOURCE)
            else:
                label = st.createLabel(a, parts[-1], namespace(parts[:-1]), SOURCE)
                label.setPrimary()
    except Exception as e:
        faults.append("0x%08x %s: %s" % (address, name, e))

for address, what, value in W["fixes"]:
    a = toAddr(address)
    try:
        done["fixes"] += 1
        if dry:
            continue
        if what == "convention":
            fm.getFunctionAt(a).setCallingConvention(value)
        elif what == "signature":
            f = fm.getFunctionAt(a)
            symbol = f.getSymbol()
            kept = (symbol.getName(), symbol.getParentNamespace(), symbol.getSource())
            # Ghidra's C parser has no __thiscall: the prototype goes in
            # without it and without its first (this) parameter, and the
            # convention then makes this ECX's auto-parameter.
            text, thiscall = value, "__thiscall" in value
            if thiscall:
                head, rest = text.replace("__thiscall", "").split("(", 1)
                params = rest.rsplit(")", 1)[0].split(",")[1:]
                text = head + "(" + (",".join(params) if params else "void") + ")"
            # A prototype written without a name (void * __thiscall(...))
            # gets one, which the parser needs and the table replaces.
            head, rest = text.split("(", 1)
            last = head.split()[-1] if head.split() else ""
            if head.rstrip().endswith("*") or last in TYPE_WORDS:
                text = head.rstrip() + " f(" + rest
            sig = CParserUtils.parseSignature(None, program, text, False)
            if sig is None:
                raise Exception("Ghidra cannot parse " + text)
            ApplyFunctionSignatureCmd(a, sig, SOURCE, True, False).applyTo(program)
            if thiscall:
                f.setCallingConvention("__thiscall")
            # Applying a signature renames the function after it; the table
            # names the function, not the signature.
            if (symbol.getName(), symbol.getParentNamespace()) != kept[:2]:
                symbol.setNameAndNamespace(kept[0], kept[1], kept[2])
        elif what == "clear":
            # A function's own symbol is never a label to clear: deleting it
            # deletes the function, as a thunk's inherited name did 2026-11-01.
            for s in list(st.getSymbols(a)):
                named = value in (s.getName(), s.getName(True))
                if s.getSymbolType() != SymbolType.FUNCTION and (
                    (value and named) or (not value and not s.isPrimary())
                ):
                    s.delete()
        elif what == "nofunction":
            # A function Ghidra made that is not one, such as a start inside
            # another function's instruction: its body goes back to the
            # function around it.
            f = fm.getFunctionAt(a)
            if f is not None:
                fm.removeFunction(a)
                around = fm.getFunctionContaining(a.subtract(1))
                if around is not None:
                    CreateFunctionCmd.fixupFunctionBody(program, around, monitor)
        elif what == "returns":
            # Ghidra took it for one that never returns (operator new), which
            # ends every caller's body at the call.
            fm.getFunctionAt(a).setNoReturn(False)
        elif what == "callfixup":
            # One of the compiler spec's call fixups, which Ghidra's analysis
            # gives by name and so missed where the name came later, from
            # the table: __security_check_cookie's callers each kept an
            # extraout_EAX for the value it was thought to clobber.
            f = fm.getFunctionAt(a)
            if f.getCallFixup() != value:
                f.setCallFixup(value)
        else:
            raise Exception("unknown fix " + what)
    except Exception as e:
        faults.append("fix 0x%08x %s: %s" % (address, what, e))

# A switch Ghidra did not follow: `jmp [reg*4 + table]` with no reference to
# where it goes. Its function then ends at the jump, the cases are code in no
# function, and the decompile stops at "Could not recover jumptable". Six of
# the build's 615 (2026-11-16): the script interpreter's two, whose cases run
# to 0x00942A5B, MovementController::GetSpeed's, three in libraries. The
# decompiler gives up where a path reaches the jump without passing the test
# of its index, so it cannot tell the cases' numbers either: the cases are
# given by address, and a comment at the jump says which entries go to each.
# The table is the words at its address that point into the code, up to the
# first that does not or the first something else refers to (checked against
# the six jumps' own bounds).
done["switches"] = 0
if W.get("switches"):
    import re as _re
    from java.util import ArrayList
    from ghidra.program.model.listing import CodeUnit
    from ghidra.program.model.pcode import JumpTable
    from ghidra.program.model.symbol import RefType
    _text = program.getMemory().getBlock(".text")
    _refs = program.getReferenceManager()
    for ins in listing.getInstructions(_text.getStart(), True):
        if ins.getMnemonicString() != "JMP":
            continue
        found = _re.match(r"JMP dword ptr \[\w+\*0x4 \+ (0x[0-9a-f]+)\]$", str(ins))
        if not found or any(r.getReferenceType().isFlow() for r in ins.getReferencesFrom()):
            continue
        a = ins.getAddress()
        try:
            f = fm.getFunctionContaining(a)
            if f is None:
                raise Exception("in no function")
            table = toAddr(int(found.group(1), 16))
            goes = []
            while True:
                at = table.add(4 * len(goes))
                to = table.getNewAddress(program.getMemory().getInt(at) & 0xFFFFFFFF)
                if not _text.contains(to) or (goes and _refs.hasReferencesTo(at)):
                    break
                goes.append(to)
            if not goes:
                raise Exception("no table at %s" % table)
            done["switches"] += 1
            if dry:
                continue
            for to in goes:
                _refs.addMemoryReference(a, to, RefType.COMPUTED_JUMP, SOURCE, 0)
            JumpTable(a, ArrayList(goes), True, len(goes)).writeOverride(f)
            CreateFunctionCmd.fixupFunctionBody(program, f, monitor)
            by = {}
            for i, to in enumerate(goes):
                by.setdefault(to, []).append(str(i))
            listing.setComment(a, CodeUnit.PRE_COMMENT, "A switch through the %d entries at %s, which Ghidra did not "
                               "follow; its case labels here are not the entries' numbers. Entries: %s" % (
                                   len(goes), table, "; ".join(
                                       "%s -> %s" % (", ".join(n), to) for to, n in sorted(by.items()))))
        except Exception as e:
            faults.append("switch at %s: %s" % (a, e))

dtm = program.getDataTypeManager()
@TYPES@
from ghidra.program.model.listing import CodeUnit
for address, text in W.get("comments", []):
    a = toAddr(address)
    try:
        unit = listing.getCodeUnitAt(a)
        if unit is None or unit.getComment(CodeUnit.PLATE_COMMENT) == text:
            continue
        done["comments"] += 1
        if not dry:
            unit.setComment(CodeUnit.PLATE_COMMENT, text)
    except Exception as e:
        faults.append("comment 0x%08x: %s" % (address, e))

print("RESULT " + json.dumps({"done": done, "faults": faults[:50], "nfaults": len(faults)}))
""".replace("@TYPES@", ghidra_types.GHIDRA_TYPES)


class Server:
    """Just enough MCP over HTTP: a session, a tool call, a task's wait."""

    def __init__(self, url=SERVER):
        self.url, self.session, self.next = url, None, 0
        self.post(
            "initialize",
            {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "ghidra_sync", "version": "1"},
            },
        )
        self.post("notifications/initialized", None, note=True)

    def post(self, method, params, note=False):
        body = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            body["params"] = params
        if not note:
            self.next += 1
            body["id"] = self.next
        head = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.session:
            head["Mcp-Session-Id"] = self.session
        request = urllib.request.Request(self.url, json.dumps(body).encode(), head)
        with urllib.request.urlopen(request, timeout=3700) as answer:
            self.session = answer.headers.get("Mcp-Session-Id") or self.session
            text = answer.read().decode("utf-8")
        if "data:" in text:
            text = [line[5:] for line in text.splitlines() if line.startswith("data:")][
                -1
            ]
        return json.loads(text) if text.strip() else None

    def call(self, tool, arguments):
        reply = self.post("tools/call", {"name": tool, "arguments": arguments})
        if "error" in reply:
            raise RuntimeError(f"{tool}: {reply['error']}")
        return "\n".join(part.get("text", "") for part in reply["result"]["content"])

    def run(self, script, timeout=1800):
        """eval_python, waiting for its task; the script's printed output."""
        text = self.call("eval_python", {"script": script, "timeout_seconds": timeout})
        task = next(
            (
                line.split(":", 1)[1].strip()
                for line in text.splitlines()
                if line.startswith("Task ID:")
            ),
            None,
        )
        if task is None:
            return text
        while True:
            time.sleep(3)
            status = self.call("get_task_status", {"task_id": task})
            if "RUNNING" not in status[:400] and "PENDING" not in status[:400]:
                return status


def struct_rows():
    """data/structs.csv as the script wants it: (name, its parts in Ghidra,
    size, fields), a struct with no sizeof row being as long as its last
    field, and a field (offset, size, its type as ghidra_types.field_type
    reads it, name)."""
    fields, whole = {}, {}
    for row in ghidra_types.with_instances(structs.read()):
        offset, size = int(row["offset"], 16), int(row["size"], 16)
        if row["field"] == structs.SIZEOF:
            whole[row["struct"]] = size
        else:
            fields.setdefault(row["struct"], []).append(
                (offset, size, ghidra_types.field_type(row["type"]), row["field"])
            )
    return [
        (
            name,
            ghidra_parts(name),
            max(whole.get(name, 0), *(o + s for o, s, _, _ in held)),
            sorted(held, key=lambda field: field[0]),
        )
        for name, held in sorted(fields.items())
    ]


def comment_rows():
    """(address, comment) of every ID the table comments, in this build:
    each becomes the plate comment at its address. A comment taken out of
    the table is left in Ghidra, as a name the table drops is."""
    with open(ROOT / "data" / "addresses.csv", newline="", encoding="utf-8") as f:
        return [
            (int(row[BUILD], 16), row["comment"])
            for row in csv.DictReader(f)
            if row.get("comment") and row[BUILD]
        ]


def slot_names():
    """{table address: {slot: (method, its overrides)}} for the vftable slots
    that take their name from their overrides (tools/vtables_dump.py,
    inherited_names), as JSON keys. Nothing if the build's image is not
    here."""
    import vtables_dump

    try:
        found = vtables_dump.inherited_names(*vtables_dump.read())
    except FileNotFoundError:
        return {}
    return {
        f"0x{va:08X}": {str(slot): said for slot, said in slots.items()}
        for va, slots in found.items()
    }


TYPED = ("datatype", "returntype", "thisat")


def typed_fixes(fixes):
    """The fixes that give a type (a global's, a function's return), with it
    read as ghidra_types.field_type reads a struct's: they are applied after
    the types, which they name. With them what tools/receivers.py reads
    from the build's code, where the file has no row of its own for the
    address and the build's image is here."""
    typed = [(address, what, value) for address, what, value in fixes if what in TYPED]
    held = {(address, what) for address, what, _ in typed}
    try:
        import receivers

        settled, _ = receivers.rows(*receivers.read())
    except FileNotFoundError:
        settled = []
    typed += [
        (address, what, value)
        for address, what, value, _why in settled
        if (address, what) not in held
    ]
    return [
        (
            address,
            what,
            # `thisat`'s value is Class+0xN: the class is the type.
            ghidra_types.field_type(
                value.rsplit("+", 1)[0] if what == "thisat" else value
            ),
            value,
        )
        for address, what, value in typed
    ]


EH_TEXT = {
    "Unwind": "Unwind funclet of {owner}: the compiler's cleanup of one of its locals when an "
    "exception passes through. It runs in that function's frame, so EBP here is that "
    "function's and unaff_EBP is expected.",
    "Catch": "Catch block of {owner}: it runs in that function's frame, so EBP here is that "
    "function's and unaff_EBP is expected.",
    "EhHandler": "Exception handler stub of {owner}: loads that function's FuncInfo and jumps "
    "to the C++ frame handler.",
}


def eh_rows():
    """(address, label, plate comment) of each function that is part of
    another's exception handling and that the table neither names nor
    comments: 18,727 of the GOG build's functions are such pieces, a third
    of what Ghidra decompiles, each read as a function of its own with an
    unexplained unaff_EBP. tools/subsystems.py finds them (`owner`); this
    says which kind each is, from the same FuncInfo. Nothing if the build's
    image is not here."""
    import addrlib
    import daoexe
    import subsystems

    db = addrlib.Database.load()
    build = next(b for b in db.builds if b["key"] == BUILD)
    image = ROOT / build["image"]
    if not image.exists():
        return []
    functions = subsystems.gog_functions(db)
    reading = subsystems.read_build(str(image), sorted(functions))
    img = daoexe.Image(str(image))
    commented = {row.addresses.get(BUILD) for row in db.rows.values() if row.comment}
    kinds = {}
    for piece in reading.owned:
        info = subsystems.handler_info(img, piece)
        if info is None:
            continue
        kinds[piece] = "EhHandler"
        for kind, address in subsystems.eh_kinds(img, info):
            kinds.setdefault(address, kind)
    out = []
    for piece, owner in sorted(reading.owned.items()):
        if functions[piece][1] or piece in commented or piece not in kinds:
            continue
        name = functions[owner][1] or f"FUN_{owner:08x}"
        out.append(
            (
                piece,
                f"{kinds[piece]}@{piece:08x}",
                EH_TEXT[kinds[piece]].format(owner=f"{name} (0x{owner:08X})"),
            )
        )
    return out


def work(limit=None):
    """The table's rows and the fixes, as the script wants them."""
    rows, ours = [], {}
    with open(ROOT / "data" / "addresses.csv", newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            cell = row[BUILD]
            if not cell or row["kind"] not in ("function", "data"):
                continue
            if row["kind"] == "data" and not row["name"]:
                continue
            parts = ghidra_parts(row["name"])
            rows.append((row["kind"], int(cell, 16), parts))
            if parts:
                ours.setdefault(int(cell, 16), set()).update(
                    {row["name"], "::".join(parts), parts[-1]}
                )
    path = ROOT / "data" / "ghidra_fixes.csv"
    with open(path, newline="", encoding="utf-8") as f:
        fixes = [
            (
                int(row["address"], 16),
                row["what"],
                ghidra_c(row["value"]) if row["what"] == "signature" else row["value"],
            )
            for row in csv.DictReader(f)
        ]
    # A clear of a label the table itself gives the address (an export's
    # decorated name such as ?OnExit@GThread@@UAEXXZ, which readers asked to
    # clear more than once) would be undone by the next run's names: such a
    # line is dropped, not fought over.
    starts = {address for kind, address, _ in rows if kind == "function"}
    fixes = [
        (a, what, value)
        for a, what, value in fixes
        if (what != "clear" or value not in ours.get(a, ()))
        and (what != "nofunction" or a not in starts)
    ]
    return rows[:limit] if limit else rows, fixes


def ghidra_c(prototype):
    """A prototype in the C Ghidra's parser reads: a C++ type (a namespace, a
    template, a reference, a name with a backtick) becomes void * (a pointer
    or reference to one) or the word it stands for, as readers write an
    unknown class by hand. Its stack layout is kept: a reference is a
    pointer, and a class passed by value is left to the reader, who gives
    it as words."""
    head, sep, rest = prototype.partition("(")
    if not sep:
        return prototype
    inner, close, tail = rest.rpartition(")")

    def simplify(decl):
        decl = decl.strip()
        # A pointer to a class with no C++ mark (ECString *) is unknown to
        # the parser too; Windows' types are all capitals (HWND), which it knows.
        plain_class = "*" in decl and re.match(
            r"(const\s+)?[A-Z]\w*[a-z]\w*\s*\*", decl
        )
        if not plain_class and not re.search(r"::|<|>|`|&", decl):
            return decl
        name = re.search(r"([A-Za-z_]\w*)\s*$", decl)
        pointer = "*" in decl or "&" in decl
        word = name.group(1) if name and pointer else ""
        return (
            ("void *" + word)
            if pointer
            else "void * " + (name.group(1) if name else "")
        )

    def simplify_head(text):
        # The return type and the name (which the table replaces). Only the
        # name went before 2026-11-05, and with it every return type but a
        # pointer: 352 bool, int and float functions read as void in Ghidra.
        if not re.search(r"::|<|>|`|&", text):
            return text
        conv = re.search(r"__(thiscall|stdcall|cdecl|fastcall)", text)
        if conv:
            returns = text[: conv.start()].strip()
        else:
            depth, cut = 0, -1
            for i, ch in enumerate(text.rstrip()):
                depth += ch == "<"
                depth -= ch == ">"
                if ch == " " and depth == 0:
                    cut = i
            returns = text[:cut].strip() if cut >= 0 else ""
        if re.search(r"::|<|>|`|&", returns) or "*" in returns:
            returns = "void *" if "*" in returns or "&" in returns else "void"
        return (returns or "void") + (" " + conv.group(0) if conv else "") + " f"

    params = [simplify(p) for p in split_params(inner)] if inner.strip() else []
    return f"{simplify_head(head)}({', '.join(params) if params else 'void'}){tail}"


def split_params(inner):
    """A parameter list's parameters, not splitting inside template brackets."""
    out, depth, cur = [], 0, ""
    for ch in inner:
        depth += ch == "<"
        depth -= ch == ">"
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    out.append(cur)
    return out


def ghidra_parts(name):
    """A name's namespaces and leaf as Ghidra holds them, the way DAOLib's
    tools/names.py writes them for its ImportNames.java (so the two agree
    and neither undoes the other): split at `::` outside template brackets,
    and inside a part `::` written `.` and a space `_`. A parameter list
    (`X::X(const N::X&)`, how the table tells overloads apart) stays whole
    on the leaf: split with the rest, its `::` made namespaces of
    `wstring(const_std` (2026-11-20)."""
    if not name:
        return None
    head, params = name, ""
    if name.endswith(")") and not name.endswith("operator()"):
        depth = 0
        for i in range(len(name) - 1, -1, -1):
            depth += name[i] == ")"
            depth -= name[i] == "("
            if depth == 0:
                head, params = name[:i], name[i:]
                break
    parts = split_top(head)
    parts[-1] += params
    return [part.replace("::", ".").replace(" ", "_") for part in parts]


def sha256():
    with open(ROOT / "data" / "builds.csv", newline="", encoding="utf-8") as f:
        return next(
            row["sha256"] for row in csv.DictReader(f) if row["key"] == BUILD
        ).lower()


def discard(server):
    """Drops everything done since the last save. The server has no undo,
    and its script holds one transaction from save to save; a transaction
    inside it that ends uncommitted makes the whole of it roll back when it
    ends, which the save does (tried on a copy of the project, 2026-11-16:
    a renamed type was back under its name and the program unchanged)."""
    server.run(
        "discarding = currentProgram.startTransaction('discard unsaved changes')\n"
        "currentProgram.endTransaction(discarding, False)\n"
    )
    return server.call("save_program", {}).splitlines()[-1]


PARTS = ("rows", "fixes", "types", "eh", "comments", "params", "getters")


def getter_calls(server, dry):
    """Runs the `getters` part, a script of its own since it decompiles every
    caller of the functions tools/receivers.py finds to be a getter every
    class shares (shared_getters): (its counts, its faults), or None if the
    script did not answer. Nothing to do if the build's image is not here."""
    import receivers

    try:
        _, _, functions, _, img = receivers.read()
    except FileNotFoundError:
        return {}, []
    return own_part(
        server,
        ghidra_types.GHIDRA_GETTERS,
        dry,
        getters=receivers.shared_getters(img, functions),
    )


def stored_parameters(server, fixes, dry):
    """Runs the `params` part, a script of its own since it decompiles every
    function it gives parameters to (tools/ghidra_types.py, GHIDRA_PARAMS):
    (its counts, its faults), or None. A function with a signature row is
    the row's."""
    return own_part(
        server,
        ghidra_types.GHIDRA_PARAMS,
        dry,
        rows=sorted({a for a, what, _ in fixes if what == "signature"}),
    )


def own_part(server, script, dry, **work):
    """Runs a part that is a script of its own: (its counts, its faults), or
    None if it did not answer."""
    payload = {"build": BUILD, "sha256": sha256(), "dry": dry, **work}
    output = server.run(
        f"PAYLOAD = {json.dumps(json.dumps(payload))}\n" + script, timeout=3600
    )
    result = next(
        (line[7:] for line in output.splitlines() if line.startswith("RESULT ")), None
    )
    if result is None:
        print(output[-2000:], file=sys.stderr)
        return None
    result = json.loads(result)
    return result["done"], result["faults"]


OPTIONS = ("--dry-run", "--limit", "--only", "--no-save", "--discard")


def main(argv):
    # A word this does not know must not read as "apply everything": --help
    # ran a whole sync and saved it, twice, on 2026-11-16.
    values = {i + 1 for i, word in enumerate(argv) if word in ("--limit", "--only")}
    if len(argv) in values or any(
        w not in OPTIONS and i not in values for i, w in enumerate(argv)
    ):
        print(__doc__.split("\n\nThe user, ")[0])
        return 2
    if "--discard" in argv:
        print(discard(Server()))
        return 0
    dry = "--dry-run" in argv
    limit = int(argv[argv.index("--limit") + 1]) if "--limit" in argv else None
    only = argv[argv.index("--only") + 1].split(",") if "--only" in argv else PARTS
    if unknown := set(only) - set(PARTS):
        print(f"--only takes {', '.join(PARTS)}: not {', '.join(sorted(unknown))}")
        return 2
    rows, fixes = work(limit)
    if "rows" not in only:
        rows = []
    server = Server()
    totals, faults, notes = {}, [], {}
    chunks = [rows[i : i + CHUNK] for i in range(0, len(rows), CHUNK)] or [[]]
    for n, chunk in enumerate(chunks):
        last = n == len(chunks) - 1
        payload = {
            "build": BUILD,
            "sha256": sha256(),
            "dry": dry,
            "rows": chunk,
            "fixes": [f for f in fixes if f[1] not in TYPED]
            if last and "fixes" in only
            else [],
            "typed": typed_fixes(fixes) if last and "fixes" in only else [],
            "switches": last and "fixes" in only,
            "eh": eh_rows() if last and "eh" in only else [],
            "types": last and "types" in only,
            "structs": struct_rows() if last and "types" in only else [],
            "slotnames": slot_names() if last and "types" in only else {},
            "comments": comment_rows() if last and "comments" in only else [],
        }
        output = server.run(
            f"PAYLOAD = {json.dumps(json.dumps(payload))}\n" + GHIDRA_SCRIPT
        )
        result = next(
            (line[7:] for line in output.splitlines() if line.startswith("RESULT ")),
            None,
        )
        if result is None:
            print(output[-2000:], file=sys.stderr)
            return 1
        result = json.loads(result)
        for key, value in result["done"].items():
            if isinstance(value, int):
                totals[key] = totals.get(key, 0) + value
            else:
                notes[key] = value
        faults += result["faults"]
        counts = {k: v for k, v in result["done"].items() if isinstance(v, int)}
        print(
            f"rows {n * CHUNK + len(chunk):>6} of {len(rows)}: {counts}, {result['nfaults']} faults"
        )
    if "params" in only and not totals.get("damage"):
        # After the fixes, whose rows say which functions are not its to
        # touch, and before the getters, which read callers' decompiles.
        answer = stored_parameters(server, fixes, dry)
        if answer is None:
            return 1
        totals.update(answer[0])
        faults += answer[1]
    if "getters" in only and not totals.get("damage"):
        # After the types and the prototypes: it reads what each caller's
        # decompile makes of them.
        answer = getter_calls(server, dry)
        if answer is None:
            return 1
        totals.update(answer[0])
        faults += answer[1]
    if totals.get("damage"):
        # A class type shrank or lost a vftable pointer or a nested class:
        # nothing of this run is kept.
        discard(server)
        print("DAMAGE to class types: the run was discarded, nothing saved")
    elif not dry and "--no-save" not in argv:
        print(server.call("save_program", {}).splitlines()[-1])
    verb = "would change" if dry else "changed"
    print(
        f"{verb}: {totals['created']} functions defined, {totals['named']} renamed, "
        f"{totals['labels']} labels, {totals['fixes']} fix rows applied, "
        f"{totals.get('comments', 0)} comments; {totals['same']} already right"
    )
    if "types" in only:
        print(
            f"types: {totals['structs']} structs, {totals['built']} built whole, "
            f"{totals['classfields']} fields written onto class types, "
            f"{totals['typed']} fields typed and {totals['untyped']} left undefined bytes, "
            f"{totals['grown']} class types grown to a field, {totals['beyond']} past a nested type's end, {totals['blocked']} on a vftable "
            f"pointer or nested class, {totals['placeholders']} placeholders replaced ({totals['byvalue']} by-value uses made bytes), "
            f"{totals['classes']} namespaces made classes, {totals['unpacked']} types unpacked, "
            f"{totals['renamed']} offset_0xN renamed, {totals['dropped']} fields the table no longer has cleared, "
            f"{totals['restored']} nested classes given back their own name, "
            f"{totals['filled']} undefined bytes of a class's data named for their place, "
            f"{totals.get('slots', 0)} vftable slots named or typed"
        )
        if notes.get("unresolved"):
            print(
                "  types not found, or not the field's size: "
                + ", ".join(f"{name} ({count})" for name, count in notes["unresolved"])
            )
    if "fixes" in only:
        print(
            f"typed fixes: {totals['typedfixes']} applied, {totals['notype']} whose class "
            f"Ghidra has no type for, {totals['noroom']} objects with no room or no layout, "
            f"{totals['nothis']} methods whose this is not in ECX"
        )
        print(f"switches: {totals.get('switches', 0)} given the cases of their tables")
    if "eh" in only:
        print(f"exception handling: {totals['eh']} labels and comments")
    if "params" in only:
        print(
            f"parameters: {totals.get('params', 0)} functions given the parameters their "
            f"decompile finds, {totals.get('paramsfailed', 0)} it found none for"
        )
    if "getters" in only:
        print(
            f"shared getters: {totals.get('getters', 0)} calls given their receiver's "
            f"field's type, {totals.get('gettersame', 0)} that had it, "
            f"{totals.get('getterdropped', 0)} that lost it, "
            f"{totals.get('getterfailed', 0)} callers not decompiled"
        )
    for fault in faults[:40]:
        print("  " + fault, file=sys.stderr)
    return 1 if faults else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
