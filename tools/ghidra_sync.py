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
  (`int f(void *this, int key)`, the name in it ignored: the table names);
  `clear` removes a misleading label at the address (`value` the label,
  or empty for every non-primary one).

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
import json
import sys
import time
import urllib.request
from pathlib import Path

from msvc_names import split_top

ROOT = Path(__file__).resolve().parent.parent
SERVER = "http://127.0.0.1:8090/mcp"
BUILD = "gog-1.05"
CHUNK = 4000

# Runs inside Ghidra (pyghidra, Python 3). PAYLOAD is the JSON of the work.
GHIDRA_SCRIPT = r"""
import json
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.symbol import SymbolUtilities
from ghidra.app.util.cparser.C import CParserUtils

W = json.loads(PAYLOAD)
program = currentProgram
if program.getExecutableSHA256().lower() != W["sha256"]:
    raise Exception("not the " + W["build"] + " build: " + program.getExecutableSHA256())
dry = W["dry"]
fm = program.getFunctionManager()
st = program.getSymbolTable()
listing = program.getListing()
SOURCE = SourceType.IMPORTED
done = {"created": 0, "named": 0, "same": 0, "labels": 0, "fixes": 0}
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
            # The leaf already right is right: Ghidra's class recovery may have
            # put it in its class, a better place than a namespace of that name.
            if f.getName() == parts[-1]:
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
            if primary is not None and primary.getName() == parts[-1]:
                done["same"] += 1
                continue
            done["labels"] += 1
            if not dry:
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
            sig = CParserUtils.parseSignature(None, program, value, True)
            from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
            ApplyFunctionSignatureCmd(a, sig, SOURCE, True, False).applyTo(program)
            # The table names the function, not the signature.
        elif what == "clear":
            for s in list(st.getSymbols(a)):
                if (value and s.getName() == value) or (not value and not s.isPrimary()):
                    s.delete()
        else:
            raise Exception("unknown fix " + what)
    except Exception as e:
        faults.append("fix 0x%08x %s: %s" % (address, what, e))

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


def work(limit=None):
    """The table's rows and the fixes, as the script wants them."""
    rows = []
    with open(ROOT / "data" / "addresses.csv", newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            cell = row[BUILD]
            if not cell or row["kind"] not in ("function", "data"):
                continue
            if row["kind"] == "data" and not row["name"]:
                continue
            rows.append((row["kind"], int(cell, 16), ghidra_parts(row["name"])))
    path = ROOT / "data" / "ghidra_fixes.csv"
    with open(path, newline="", encoding="utf-8") as f:
        fixes = [
            (int(row["address"], 16), row["what"], row["value"])
            for row in csv.DictReader(f)
        ]
    return rows[:limit] if limit else rows, fixes


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
        f"{totals['labels']} labels, {totals['fixes']} fixes; {totals['same']} already right"
    )
    for fault in faults[:40]:
        print("  " + fault, file=sys.stderr)
    return 1 if faults else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
