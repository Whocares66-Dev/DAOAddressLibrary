"""Writes the facts store from DAOLib's Ghidra database of the GOG build
(`ghidra-dao`): one JSON file per function, what Ghidra knows of it.

    python tools/facts_dump.py --changed       functions whose record is missing or no longer what Ghidra holds
    python tools/facts_dump.py --missing       functions with no record
    python tools/facts_dump.py --all           every function the database defines
    python tools/facts_dump.py 0x004C0E50 ...  these addresses ({} where no function begins)
    python tools/facts_dump.py --from FILE     the addresses in FILE, one a line
    python tools/facts_dump.py --check N       N records made here against the server's own get_code, byte for byte

The store is `$CHAIN_CACHE\\facts`, else `%LOCALAPPDATA%\\paragon-chain\\facts`,
a file `0x%08X.json` an address. Paragon's port pipeline reads it
(`tools/chain/packet.py`) and so does the overseer; neither touches Ghidra.
Paragon's own client dumped it on about 2026-11-07 and was removed on
2026-11-14 (Paragon 440ceac0); paragon-agent asked on 2026-11-15, at the
user's word (dev/FACTS_DUMP.md), that the database's one writer keep the
store too, since it trailed every sync: holes where ghidra_sync had since
defined functions, and old names in every decompile.

A record is `{"version": 3, "value": {...}, "source": "<sha1>"}`. `value`
is what the old client wrote, field for field: its FACTS script is below
unchanged but for running over a batch, and `decompile` and `disassembly`
are the text the server's get_code tool gives (GhidrAssistMCP's
GetCodeTool: the same DecompInterface on the program's options, the same
listing walk, the same "[Context] Operating on" head), made here in the same
pass rather than in two more calls a function. `--check` holds this to
that. An address where no function begins has `{}` as its value, as before.

`source` is a hash, taken in Ghidra, of what a record is made from and
cheap to read without decompiling: the function's name, prototype and
calling convention, its body and bytes, its comments, the names and
prototypes of its callees and callers, the labels its instructions refer
to, and the layout of each type in its prototype. `--changed` recomputes it
for every function and redoes the records whose hash differs, and the ones
written before it (no `source`). What it does not see is a type used only
inside a body (a local's struct); after a struct is changed that no
signature carries, run `--all`.

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
# records keep their form.
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
    f = real(f)
    b = f.getBody()
    out = {'address': hx(f.getEntryPoint()), 'name': f.getName(True),
           'ranges': [[hx(r.getMinAddress()), hx(r.getMaxAddress())] for r in b.getAddressRanges()],
           'callees': [], 'callers': [], 'branches': [], 'indirect': [], 'instructions': 0}
    for c in sorted(f.getCalledFunctions(TaskMonitor.DUMMY), key=lambda x: x.getEntryPoint().getOffset()):
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
# DecompilerService and the backend's context head, read 2026-11-16).
TEXT = r"""
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.listing import CodeUnit
from java.security import MessageDigest
from java.lang import String as JString

HEAD = '[Context] Operating on: ' + prog.getDomainFile().getName() + '\n\n'
_dec = [None]

def decompiler():
    if _dec[0] is None:
        o = DecompileOptions()
        o.grabFromProgram(prog)
        d = DecompInterface()
        d.setOptions(o)
        d.openProgram(prog)
        _dec[0] = (d, o)
    return _dec[0]

def decompile_text(f):
    n = f.getName(True)
    try:
        d, o = decompiler()
        r = d.decompileFunction(f, o.getDefaultTimeout(), TaskMonitor.DUMMY)
        if r.isTimedOut():
            return HEAD + 'Decompilation timed out for function: ' + n
        if not r.decompileCompleted():
            return HEAD + 'Decompilation error for function ' + n + ': ' + str(r.getErrorMessage())
        c = r.getDecompiledFunction().getC()
        if c is None or not c.strip():
            return HEAD + 'No decompiled code available for function: ' + n
        return HEAD + 'Decompiled function ' + n + ':\n\n' + c
    except Exception as e:
        _dec[0] = None
        return HEAD + 'Error decompiling function ' + n + ': ' + str(e)

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

def type_layout(t):
    while hasattr(t, 'getDataType') and t.getDataType() is not None and t.getDataType() is not t:
        t = t.getDataType()
    if hasattr(t, 'getComponents'):
        return t.getPathName() + '{' + ';'.join('%d:%s:%s' % (c.getOffset(), c.getFieldName(), c.getDataType().getName())
                                                 for c in t.getComponents()) + '}'
    return t.getPathName()

def source(f):
    # A hash of what the record is made from; see facts_dump.py's head.
    # Java's digest: the server's Python cannot import hashlib (KeyError, 2026-11-16).
    h = MessageDigest.getInstance('SHA-1')
    def add(s):
        h.update(JString(s if s is not None else '-').getBytes('UTF-8'))
        h.update(0)
    t = real(f)
    for g in (f, t) if t is not f else (f,):
        add(g.getName(True)); add(proto(g))
        add(type_layout(g.getReturnType()))
        for p in g.getParameters():
            add(type_layout(p.getDataType()))
        add(g.getComment())
        for r in g.getBody().getAddressRanges():
            add(str(r))
        for ins in L.getInstructions(g.getBody(), True):
            add(str(ins))
            add(ins.getComment(CodeUnit.EOL_COMMENT))
            for to in sorted((r.getToAddress() for r in ins.getReferencesFrom()), key=str):
                add(label(to))
        for c in sorted(g.getCalledFunctions(TaskMonitor.DUMMY), key=lambda x: x.getEntryPoint().getOffset()):
            add(c.getName(True)); add(proto(c)); add(proto(real(c)))
        for c in sorted(g.getCallingFunctions(TaskMonitor.DUMMY), key=lambda x: x.getEntryPoint().getOffset()):
            add(c.getName(True))
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
res = {}
for a in W['addrs']:
    f = fm.getFunctionAt(toAddr(a))
    if f is None:
        res[a] = [{}, None]
        continue
    v = facts(a)
    v['decompile'] = decompile_text(f)
    v['disassembly'] = disassembly_text(f)
    res[a] = [v, source(f)]
if _dec[0] is not None:
    _dec[0][0].dispose()
print('RESULT ' + json.dumps(res))
"""
)

LIST = (
    COMMON
    + TEXT
    + r"""
W = json.loads(PAYLOAD)
check_build(W['sha256'])
res = {}
for f in fm.getFunctions(True):
    if f.isExternal():
        continue
    a = hx(f.getEntryPoint())
    if W['hash'] and a >= W['from']:
        if len(res) >= W['count']:
            break
        res[a] = source(f)
    elif not W['hash']:
        res[a] = None
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


def store(addr, value, src):
    p = path(addr)
    tmp = p.with_name(p.name + ".%d.tmp" % os.getpid())
    record = {"version": FACTS_VERSION, "value": value}
    if src is not None:
        record["source"] = src
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
    return sorted(run(server, LIST, {"hash": False, "from": "", "count": 0}))


def hashes(server):
    """Every function's source hash, a few thousand a call."""
    out, start = {}, ""
    while True:
        got = run(server, LIST, {"hash": True, "from": start, "count": 3000})
        got = {a: h for a, h in got.items() if a not in out}
        if not got:
            return out
        out.update(got)
        start = max(got)
        print(f"hashed {len(out)}", flush=True)


def dump(server, addrs):
    STORE.mkdir(parents=True, exist_ok=True)
    began, done = time.time(), 0
    for i in range(0, len(addrs), BATCH):
        part = addrs[i : i + BATCH]
        for a, (value, src) in run(server, DUMP, {"addrs": part}).items():
            store(a, value, src)
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
    made = run(server, DUMP, {"addrs": sample})
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
    if "--all" in argv:
        todo = functions(server)
    elif "--missing" in argv:
        todo = [a for a in functions(server) if not path(a).exists()]
    elif "--changed" in argv:
        todo = []
        for a, h in hashes(server).items():
            r = stored(a)
            if r is None or r.get("version") != FACTS_VERSION or r.get("source") != h:
                todo.append(a)
        todo.sort()
    else:
        todo = addresses(argv)
    print(f"{len(todo)} to write into {STORE}", flush=True)
    dump(server, todo)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
