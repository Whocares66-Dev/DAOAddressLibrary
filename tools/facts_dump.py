"""Writes the facts store from DAOLib's Ghidra database of the GOG build
(`ghidra-dao`): one JSON file per function, what Ghidra knows of it.

    python tools/facts_dump.py --changed       functions whose record is missing or no longer what Ghidra holds
    python tools/facts_dump.py --missing       functions with no record
    python tools/facts_dump.py --all           every function the database defines
    python tools/facts_dump.py 0x004C0E50 ...  these addresses ({} where no function begins)
    python tools/facts_dump.py --from FILE     the addresses in FILE, one a line
    python tools/facts_dump.py --check N       N records made here against the server's own get_code, byte for byte
    python tools/facts_dump.py --all --workers 4   decompile on four threads

The store is `$CHAIN_CACHE\\facts`, else `%LOCALAPPDATA%\\paragon-chain\\facts`,
a file `0x%08X.json` an address. Paragon's port pipeline reads it
(`tools/chain/packet.py`) and so does the overseer; neither touches Ghidra.
Paragon's own client dumped it on about 2026-11-07 and was removed on
2026-11-14 (Paragon 440ceac0); paragon-agent asked on 2026-11-15, at the
user's word (dev/FACTS_DUMP.md), that the database's one writer keep the
store too, since it trailed every sync: holes where ghidra_sync had since
defined functions, and old names in every decompile.

A record is `{"version": 3, "value": {...}, "source": "<sha1>", "types":
[...]}`. `value` is what the old client wrote, field for field: its FACTS
script is below unchanged but for running over a batch, and `decompile` and
`disassembly` are the text the server's get_code tool gives (GhidrAssistMCP's
GetCodeTool: the same DecompInterface on the program's options, the same
listing walk, the same "[Context] Operating on" head), made here in the same
pass rather than in two more calls a function. `--check` holds this to
that. An address where no function begins has `{}` as its value, as before.

`types` is the structures, unions and function types the decompile went
through (the type of every value in it), and `source` a hash, taken in
Ghidra, of what the record is made from: the function's name, prototype,
convention and comments, its body, the names and types of what its
instructions refer to, the names and prototypes of its callees and callers,
and the layout of each of those types. `--changed` takes that hash again
for every function, without decompiling, and redoes the records whose hash
differs or that were written before `types` was kept. So a struct's new
field or a vftable's renamed slot redoes the functions that go through that
type and no others (renaming one field of CCArea marked the 18 of a sample
of 743 that use it, 2026-11-16), and `--all` is for a change to this tool.

`--workers N` decompiles a batch on N threads, each with a decompiler
process of its own; one, the default, is what every run so far has used.
Sending batches at once from here gains nothing (4 at once took 0.30 s a
function for 0.20 s alone).

Run it after each ghidra_sync.py run, `--changed`, and never while one is
running; only this repository writes the store, as only it writes the
database. Records are written as each batch comes back, each atomically, so
a run stopped part way loses nothing it wrote.
"""

import json
import os
import sys
import time
from pathlib import Path

from ghidra_sync import Server, sha256

FACTS_VERSION = 3
BATCH = 150  # functions an eval_python call: about 40 s of decompiling
HASHED = 3000  # functions a call that only hashes
STORE = (
    Path(
        os.environ.get("CHAIN_CACHE")
        or os.path.join(
            os.environ.get("LOCALAPPDATA")
            or os.path.join(os.path.expanduser("~"), ".cache"),
            "paragon-chain",
        )
    )
    / "facts"
)

# Runs inside Ghidra (pyghidra). The part from COMMON to the end of facts() is
# Paragon's old client (440ceac0^:tools/chain/ghidra_mcp.py) as it was, so the
# records keep their form, but for one thing. For a thunk (a function that is
# one jump to another) it described the function jumped to, under the thunk's
# address: the record at 0x00A084B0 said it was operator_new at 0x00413660
# with six instructions, beside the thunk's own one-line disassembly (a
# reader of paragon's, 2026-11-16: "holds operator_new's record"). A thunk's
# record is now its own, with what it jumps to as its one callee.
COMMON = r"""
import json
from ghidra.util.task import TaskMonitor
from ghidra.program.model.scalar import Scalar
prog = currentProgram
fm = prog.getFunctionManager(); L = prog.getListing(); mem = prog.getMemory(); st = prog.getSymbolTable()

def hx(a):
    return '0x%08X' % a.getOffset()

def real(f):
    if f is not None and f.isThunk():
        t = f.getThunkedFunction(True)
        if t is not None:
            return t
    return f

def pointer(a):
    try:
        return toAddr(mem.getInt(a) & 0xFFFFFFFF)
    except Exception:
        return None

def label(a):
    s = st.getPrimarySymbol(a)
    return s.getName(True) if s is not None else ''

def in_body(f, a):
    return a is not None and f.getBody().contains(a)

def flow_targets(ins):
    out = []
    for r in ins.getReferencesFrom():
        to = r.getToAddress()
        if to.isExternalAddress():
            s = st.getPrimarySymbol(to)
            out.append(('external', None, s.getName(True) if s else str(to)))
            continue
        g = fm.getFunctionAt(to)
        if g is not None:
            g = real(g)
            out.append(('external', None, g.getName(True)) if g.isExternal() else ('function', hx(g.getEntryPoint()), g.getName(True)))
            continue
        p = pointer(to) if r.getReferenceType().isData() else None
        g = real(fm.getFunctionAt(p)) if p is not None else None
        if g is not None:
            out.append(('external', None, g.getName(True)) if g.isExternal() else ('function', hx(g.getEntryPoint()), g.getName(True)))
        elif p is not None and p.isExternalAddress():
            out.append(('external', None, label(p)))
        else:
            out.append(('address', hx(to), label(to)))
    return out

def stats(f):
    f = real(f)
    if f.isExternal():
        return {'address': None, 'name': f.getName(True), 'external': True}
    n = cond = ind = 0
    lines = []
    for ins in L.getInstructions(f.getBody(), True):
        n += 1
        ft = ins.getFlowType()
        if ft.isConditional():
            cond += 1
        if ft.isComputed() and (ft.isCall() or ft.isJump()):
            t = flow_targets(ins)
            if not t or not all(k in ('function', 'external') or in_body(f, toAddr(a)) for k, a, _ in t):
                ind += 1
        if len(lines) < 17:
            lines.append('%s  %s' % (hx(ins.getAddress()), ins))
    calls = sorted(set(real(c).getName(True) for c in f.getCalledFunctions(TaskMonitor.DUMMY)))
    return {'address': hx(f.getEntryPoint()), 'name': f.getName(True), 'external': False, 'instructions': n,
            'conditional': cond, 'indirect': ind, 'calls': calls, 'listing': lines if n <= 16 else [],
            'callers': len(list(f.getCallingFunctions(TaskMonitor.DUMMY)))}

def facts(addr):
    f = fm.getFunctionAt(toAddr(addr))
    if f is None:
        return None
    b = f.getBody()
    out = {'address': hx(f.getEntryPoint()), 'name': f.getName(True),
           'ranges': [[hx(r.getMinAddress()), hx(r.getMaxAddress())] for r in b.getAddressRanges()],
           'callees': [], 'callers': [], 'branches': [], 'indirect': [], 'instructions': 0}
    called = set(f.getCalledFunctions(TaskMonitor.DUMMY))
    if f.isThunk() and f.getThunkedFunction(False) is not None:
        called.add(f.getThunkedFunction(False))
    for c in sorted(called, key=lambda x: x.getEntryPoint().getOffset()):
        s = stats(c)
        if c.isThunk():
            s['via_thunk'] = hx(c.getEntryPoint())
        if s.get('address') is None:
            s['address'] = hx(c.getEntryPoint()) if not c.isExternal() else c.getName(True)
        out['callees'].append(s)
    for c in sorted(f.getCallingFunctions(TaskMonitor.DUMMY), key=lambda x: x.getEntryPoint().getOffset()):
        out['callers'].append({'address': hx(c.getEntryPoint()), 'name': c.getName(True)})
    from ghidra.program.model.block import BasicBlockModel
    blocks = BasicBlockModel(prog).getCodeBlocksContaining(b, TaskMonitor.DUMMY)
    out['blocks'] = []
    while blocks.hasNext():
        out['blocks'].append(hx(blocks.next().getMinAddress()))
    out['blocks'].sort()
    for ins in L.getInstructions(b, True):
        out['instructions'] += 1
        ft = ins.getFlowType()
        if ft.isConditional():
            out['branches'].append({'address': hx(ins.getAddress()), 'ins': str(ins), 'kind': 'conditional'})
        if ft.isComputed() and (ft.isCall() or ft.isJump()):
            t = flow_targets(ins)
            internal = [x for x in t if x[0] == 'address' and in_body(f, toAddr(x[1]))]
            if ft.isJump() and internal:
                out['branches'].append({'address': hx(ins.getAddress()), 'ins': str(ins), 'kind': 'switch'})
                continue
            prev, p = [], ins
            for i in range(8):
                p = p.getPrevious()
                if p is None or not in_body(f, p.getAddress()):
                    break
                prev.append(str(p))
            out['indirect'].append({'site': hx(ins.getAddress()), 'ins': str(ins), 'kind': 'call' if ft.isCall() else 'jump',
                                    'prev': prev, 'known': [list(x) for x in t]})
    return out
"""

# What the server's get_code gives, made here (GhidrAssistMCP's GetCodeTool,
# DecompilerService and the backend's context head, read 2026-11-16), and what
# a record is made from.
TEXT = r"""
import threading
from concurrent.futures import ThreadPoolExecutor
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.data import Array, Composite, FunctionDefinition, Pointer, TypeDef
from ghidra.program.model.listing import CodeUnit
from java.security import MessageDigest
from java.lang import String as JString

HEAD = '[Context] Operating on: ' + prog.getDomainFile().getName() + '\n\n'
dtm = prog.getDataTypeManager()
_local = threading.local()
_made = []

def decompiler():
    # One a thread: a DecompInterface is one decompiler process.
    if getattr(_local, 'dec', None) is None:
        o = DecompileOptions()
        o.grabFromProgram(prog)
        d = DecompInterface()
        d.setOptions(o)
        d.openProgram(prog)
        _local.dec = (d, o)
        _made.append(d)
    return _local.dec

def touched(high):
    # The structures, unions and function types the decompile went through:
    # the type of every value in it, with its pointers and arrays taken off.
    out = set()
    ops = high.getPcodeOps()
    while ops.hasNext():
        op = ops.next()
        for v in [op.getOutput()] + list(op.getInputs()):
            h = v.getHigh() if v is not None else None
            t = h.getDataType() if h is not None else None
            while isinstance(t, (Pointer, Array, TypeDef)):
                t = t.getBaseDataType() if isinstance(t, TypeDef) else t.getDataType()
            if isinstance(t, (Composite, FunctionDefinition)):
                out.add(t.getPathName())
    return sorted(out)

def decompile_text(f):
    # (get_code's text, the types it went through)
    n = f.getName(True)
    try:
        d, o = decompiler()
        r = d.decompileFunction(f, o.getDefaultTimeout(), TaskMonitor.DUMMY)
        if r.isTimedOut():
            return HEAD + 'Decompilation timed out for function: ' + n, []
        if not r.decompileCompleted():
            return HEAD + 'Decompilation error for function ' + n + ': ' + str(r.getErrorMessage()), []
        c = r.getDecompiledFunction().getC()
        if c is None or not c.strip():
            return HEAD + 'No decompiled code available for function: ' + n, []
        high = r.getHighFunction()
        return HEAD + 'Decompiled function ' + n + ':\n\n' + c, touched(high) if high is not None else []
    except Exception as e:
        _local.dec = None
        return HEAD + 'Error decompiling function ' + n + ': ' + str(e), []

def disassembly_text(f):
    out = ['Disassembly of function: ', f.getName(True), '\n', 'Entry Point: ', str(f.getEntryPoint()), '\n\n']
    n = 0
    for ins in L.getInstructions(f.getBody(), True):
        out.append(str(ins.getAddress()) + ': ' + ins.getMnemonicString())
        for i in range(ins.getNumOperands()):
            out.append((' ' if i == 0 else ', ') + ins.getDefaultOperandRepresentation(i))
        c = ins.getComment(CodeUnit.EOL_COMMENT)
        if c is not None and c.strip():
            out.append(' ; ' + c.strip())
        out.append('\n')
        n += 1
    out.append('\nTotal instructions: %d' % n)
    return HEAD + ''.join(out)

def proto(g):
    return '%s|%s' % (g.getSignature().getPrototypeString(), g.getCallingConventionName())

_layouts = {}

def layout(path):
    # What of a type shows in a decompile: its fields' places, names and types.
    if path not in _layouts:
        t = dtm.getDataType(path)
        if t is None:
            text = 'gone'
        elif isinstance(t, FunctionDefinition):
            text = t.getPrototypeString(True)
        else:
            text = '%d{%s}' % (t.getLength(), ';'.join(
                '%d:%d:%s:%s' % (c.getOffset(), c.getLength(), c.getFieldName(), c.getDataType().getName())
                for c in t.getDefinedComponents()))
        _layouts[path] = text
    return _layouts[path]

def source(f, types):
    # A hash of what the record is made from; see facts_dump.py's head.
    # Java's digest: the server's Python cannot import hashlib (KeyError, 2026-11-16).
    h = MessageDigest.getInstance('SHA-1')
    def add(s):
        h.update(JString(s if s is not None else '-').getBytes('UTF-8'))
        h.update(0)
    t = real(f)
    for g in (f, t) if t is not f else (f,):
        add(g.getName(True)); add(proto(g))
        add(g.getComment())
        add(L.getCodeUnitAt(g.getEntryPoint()).getComment(CodeUnit.PLATE_COMMENT))
        for r in g.getBody().getAddressRanges():
            add(str(r))
        for ins in L.getInstructions(g.getBody(), True):
            add(str(ins))
            add(ins.getComment(CodeUnit.EOL_COMMENT))
            for to in sorted((r.getToAddress() for r in ins.getReferencesFrom()), key=str):
                add(label(to))
                d = L.getDataAt(to) if to.isMemoryAddress() else None
                add(d.getDataType().getName() if d is not None else None)
        for c in sorted(g.getCalledFunctions(TaskMonitor.DUMMY), key=lambda x: x.getEntryPoint().getOffset()):
            add(c.getName(True)); add(proto(c)); add(proto(real(c))); add(c.getCallFixup())
        for c in sorted(g.getCallingFunctions(TaskMonitor.DUMMY), key=lambda x: x.getEntryPoint().getOffset()):
            add(c.getName(True))
    for path in sorted(types):
        add(path); add(layout(path))
    return ''.join('%02x' % (b & 0xFF) for b in h.digest())

def check_build(sha):
    if prog.getExecutableSHA256().lower() != sha:
        raise Exception('not the GOG build: ' + prog.getExecutableSHA256())
"""

DUMP = (
    COMMON
    + TEXT
    + r"""
W = json.loads(PAYLOAD)
check_build(W['sha256'])

def record(a):
    f = fm.getFunctionAt(toAddr(a))
    if f is None:
        return a, [{}, None, []]
    v = facts(a)
    v['decompile'], types = decompile_text(f)
    v['disassembly'] = disassembly_text(f)
    return a, [v, source(f, types), types]

# A thread each worker, which with one is this run in order: the decompiler
# is a process of its own and Java gives up Python's lock while it waits.
with ThreadPoolExecutor(max_workers=max(1, W['workers'])) as pool:
    res = dict(pool.map(record, W['addrs']))
for d in _made:
    d.dispose()
print('RESULT ' + json.dumps(res))
"""
)

LIST = (
    COMMON
    + TEXT
    + r"""
W = json.loads(PAYLOAD)
check_build(W['sha256'])
if W['hash'] is None:
    res = [hx(f.getEntryPoint()) for f in fm.getFunctions(True) if not f.isExternal()]
else:
    res = {}
    for a, types in W['hash'].items():
        f = fm.getFunctionAt(toAddr(a))
        res[a] = source(f, types) if f is not None else None
print('RESULT ' + json.dumps(res))
"""
)


def result(output):
    line = next((x[7:] for x in output.splitlines() if x.startswith("RESULT ")), None)
    if line is None:
        raise RuntimeError("Ghidra gave no result:\n" + output[-3000:])
    return json.loads(line)


def path(addr):
    return STORE / ("0x%08X.json" % int(addr, 16))


def stored(addr):
    try:
        with open(path(addr), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def store(addr, value, src, types):
    p = path(addr)
    tmp = p.with_name(p.name + ".%d.tmp" % os.getpid())
    record = {"version": FACTS_VERSION, "value": value}
    if src is not None:
        record["source"] = src
        record["types"] = types
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(record, f)
    os.replace(tmp, p)


def run(server, script, payload):
    payload = dict(payload, sha256=sha256())
    return result(
        server.run(
            f"PAYLOAD = {json.dumps(json.dumps(payload))}\n" + script, timeout=3600
        )
    )


def functions(server):
    """Every function the database defines, by entry."""
    return sorted(run(server, LIST, {"hash": None}))


def changed(server):
    """The functions whose record is missing, of another version, or no
    longer what Ghidra holds: each record's `source` against the hash taken
    now of the function and of the types the record says it went through."""
    todo, held = [], {}
    for addr in functions(server):
        record = stored(addr)
        if (
            record is None
            or record.get("version") != FACTS_VERSION
            or "types" not in record
        ):
            todo.append(addr)
        else:
            held[addr] = (record.get("source"), record["types"])
    addrs = sorted(held)
    for i in range(0, len(addrs), HASHED):
        part = {a: held[a][1] for a in addrs[i : i + HASHED]}
        todo += [
            a for a, h in run(server, LIST, {"hash": part}).items() if h != held[a][0]
        ]
        print(f"hashed {min(i + HASHED, len(addrs))} of {len(addrs)}", flush=True)
    return sorted(todo)


def dump(server, addrs, workers=1):
    STORE.mkdir(parents=True, exist_ok=True)
    began, done = time.time(), 0
    for i in range(0, len(addrs), BATCH):
        part = addrs[i : i + BATCH]
        made = run(server, DUMP, {"addrs": part, "workers": workers})
        for a, (value, src, types) in made.items():
            store(a, value, src, types)
        done += len(part)
        rate = (time.time() - began) / done
        print(
            f"{done} of {len(addrs)} written, {rate:.2f} s each, "
            f"{(len(addrs) - done) * rate / 60:.0f} min left",
            flush=True,
        )
    return done


def answer(server, tool, arguments):
    """A tool's text, waiting for it when the server runs it as a task."""
    text = server.call(tool, arguments)
    task = next(
        (
            x.split(":", 1)[1].strip()
            for x in text.splitlines()
            if x.startswith("Task ID:")
        ),
        None,
    )
    while task is not None:
        time.sleep(1)
        text = server.call("get_task_status", {"task_id": task})
        if "RUNNING" not in text[:400] and "PENDING" not in text[:400]:
            return text
    return text


def check(server, n):
    """Holds records made here to the server's own get_code, byte for byte."""
    every = functions(server)
    step = max(1, len(every) // n)
    sample = every[::step][:n]
    made = run(server, DUMP, {"addrs": sample, "workers": 1})
    bad = 0
    for a in sample:
        value = made[a][0]
        for field, form in (
            ("decompile", "decompiler"),
            ("disassembly", "disassembly"),
        ):
            theirs = answer(server, "get_code", {"function": a, "format": form})
            if theirs != value[field]:
                bad += 1
                print(
                    f"{a} {field} differs:\n--- get_code\n{theirs[:600]}\n--- here\n{value[field][:600]}"
                )
    print(f"{len(sample)} functions checked, {bad} texts differ")
    return 1 if bad else 0


def addresses(argv):
    out = [a for a in argv if a.lower().startswith("0x")]
    if "--from" in argv:
        with open(argv[argv.index("--from") + 1], encoding="utf-8") as f:
            out += [x.split()[0] for x in f if x.strip()]
    return sorted({"0x%08X" % int(a, 16) for a in out})


def main(argv):
    if not argv or "--help" in argv or "-h" in argv:
        print(__doc__)
        return 0
    server = Server()
    if "--check" in argv:
        return check(server, int(argv[argv.index("--check") + 1]))
    workers = int(argv[argv.index("--workers") + 1]) if "--workers" in argv else 1
    if "--all" in argv:
        todo = functions(server)
    elif "--missing" in argv:
        todo = [a for a in functions(server) if not path(a).exists()]
    elif "--changed" in argv:
        todo = changed(server)
    else:
        todo = addresses(argv)
    print(f"{len(todo)} to write into {STORE}", flush=True)
    dump(server, todo, workers)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
