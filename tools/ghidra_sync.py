"""Brings DAOLib's Ghidra database of the GOG build (`ghidra-dao`) into line
with data/addresses.csv and data/ghidra_fixes.csv.

    python tools/ghidra_sync.py              apply everything, then save the program
    python tools/ghidra_sync.py --dry-run    count what would change, change nothing
    python tools/ghidra_sync.py --limit N    only the first N rows of the table (a trial)

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
  returns as returning.
- every struct in data/structs.csv: made or replaced under /DAOAddressLibrary.
- every comment in the table's comment column: the plate comment at its
  address. One the table takes out stays in Ghidra.

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
from ghidra.program.model.data import (
    CategoryPath,
    DataTypeConflictHandler,
    DoubleDataType,
    FloatDataType,
    PointerDataType,
    StructureDataType,
    Undefined,
)

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
        "comments": 0}
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
        else:
            raise Exception("unknown fix " + what)
    except Exception as e:
        faults.append("fix 0x%08x %s: %s" % (address, what, e))

dtm = program.getDataTypeManager()
for name, size, fields in W.get("structs", []):
    try:
        done["structs"] += 1
        if dry:
            continue
        shape = StructureDataType(
            CategoryPath("/DAOAddressLibrary"),
            name.replace("::", ".").replace("<", "(").replace(">", ")").replace(" ", "_"),
            size,
            dtm,
        )
        for offset, length, kind, field in fields:
            if kind == "float":
                word = FloatDataType()
            elif kind == "double":
                word = DoubleDataType()
            elif kind.endswith("*"):
                word = PointerDataType()
            else:
                word = Undefined.getUndefinedDataType(length)
            shape.replaceAtOffset(offset, word, length, field, None)
        dtm.addDataType(shape, DataTypeConflictHandler.REPLACE_HANDLER)
    except Exception as e:
        faults.append("struct %s: %s" % (name, e))

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
"""


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
    """data/structs.csv as the script wants it: (name, size, fields), a struct
    with no sizeof row being as long as its last field."""
    fields, whole = {}, {}
    for row in structs.read():
        offset, size = int(row["offset"], 16), int(row["size"], 16)
        if row["field"] == structs.SIZEOF:
            whole[row["struct"]] = size
        else:
            fields.setdefault(row["struct"], []).append(
                (offset, size, row["type"], row["field"])
            )
    return [
        (name, whole.get(name, max(o + s for o, s, _, _ in held)), sorted(held))
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
        # The return type and the name (which the table replaces).
        if not re.search(r"::|<|>|`|&", text):
            return text
        conv = re.search(r"__(thiscall|stdcall|cdecl|fastcall)", text)
        pointer = "*" in text.split(conv.group(0))[0] if conv else "*" in text
        returns = "void *" if pointer else "void"
        return returns + (" " + conv.group(0) if conv else "") + " f"

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
    and inside a part `::` written `.` and a space `_`."""
    if not name:
        return None
    return [part.replace("::", ".").replace(" ", "_") for part in split_top(name)]


def sha256():
    with open(ROOT / "data" / "builds.csv", newline="", encoding="utf-8") as f:
        return next(
            row["sha256"] for row in csv.DictReader(f) if row["key"] == BUILD
        ).lower()


def main(argv):
    dry = "--dry-run" in argv
    limit = int(argv[argv.index("--limit") + 1]) if "--limit" in argv else None
    rows, fixes = work(limit)
    server = Server()
    totals, faults = {}, []
    chunks = [rows[i : i + CHUNK] for i in range(0, len(rows), CHUNK)] or [[]]
    for n, chunk in enumerate(chunks):
        payload = {
            "build": BUILD,
            "sha256": sha256(),
            "dry": dry,
            "rows": chunk,
            "fixes": fixes if n == len(chunks) - 1 else [],
            "structs": struct_rows() if n == len(chunks) - 1 else [],
            "comments": comment_rows() if n == len(chunks) - 1 else [],
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
            totals[key] = totals.get(key, 0) + value
        faults += result["faults"]
        print(
            f"rows {n * CHUNK + len(chunk):>6} of {len(rows)}: {result['done']}, {result['nfaults']} faults"
        )
    if not dry:
        print(server.call("save_program", {}).splitlines()[-1])
    verb = "would change" if dry else "changed"
    print(
        f"{verb}: {totals['created']} functions defined, {totals['named']} renamed, "
        f"{totals['labels']} labels, {totals['fixes']} fix rows applied, "
        f"{totals['structs']} structs, {totals.get('comments', 0)} comments; "
        f"{totals['same']} already right"
    )
    for fault in faults[:40]:
        print("  " + fault, file=sys.stderr)
    return 1 if faults else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
