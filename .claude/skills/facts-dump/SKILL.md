---
name: facts-dump
description: Write Paragon's facts store (one JSON a function, its decompile, disassembly, callees, callers, branches) from the ghidra-dao database, and its vtables store (one JSON a class, its virtual tables slot by slot and its bases) from the exe. Use after every ghidra_sync.py run, after a commit that names functions, and when a reader reports a function or class missing from a store or stale in it.
---

# The facts store

`tools/facts_dump.py` writes it; its head says what a record holds and how `--changed` decides. The store is `$CHAIN_CACHE\facts`, else `%LOCALAPPDATA%\paragon-chain\facts`, a file `0x%08X.json` an address. Paragon's port pipeline (`tools/chain/packet.py`) and the overseer read it and never touch Ghidra. Only this repository writes it, as only it writes the database.

## When

- After each `python tools/ghidra_sync.py` that changed anything: `--changed`. Never while a sync is running.
- When a reader reports an address missing or stale: that address, or `--missing`.
- After a change to `tools/facts_dump.py` itself: `--all`.

## Commands

Run them from the repository's root, at below-normal priority, with the ghidra-dao server up (DAOLib's `tools\ghidra-mcp.ps1`).

| Command | Writes | Time |
|---|---|---|
| `python tools/facts_dump.py --changed` | records missing, or whose function or a type its decompile goes through changed | about 17 min to hash, then 0.1 s a record |
| `python tools/facts_dump.py --missing` | functions with no record | 0.1 s a record |
| `python tools/facts_dump.py --all` | every function (about 60,000) | about 1.7 h |
| `python tools/facts_dump.py 0x0069BD60 ...` or `--from FILE` | those addresses, `{}` where no function begins | 0.1 s a record |
| `python tools/facts_dump.py --check 30` | nothing: compares 30 records made here with the server's own `get_code`, byte for byte | about 1 min |

The times are one worker's at below-normal priority, measured 2026-11-16 on the whole store (59,657 functions). `--workers N` decompiles on N threads; the default is one, and more is for when the machine's cores are free (the user, 2026-11-16: "don't use parallelism yet. We have cores occupied by other things").

A run can be stopped at any point: each record is written atomically as its batch returns. Set `CHAIN_CACHE` to a scratch folder to try a change to the tool without touching the store.

## Checking a record

`python tools/chain/packet.py 0x004C0E50` in Paragon (`C:\project\DAOParagonEngine`) prints the packet built from it; the name and decompile should be what Ghidra now shows. After a change to the tool, `--check` must say `0 texts differ`.

## The record's form

`{"version": 3, "value": {...}, "source": "<sha1>", "types": [...]}`. `value` is the form Paragon's old client wrote, and readers take only it. A change to `value`'s form bumps `FACTS_VERSION` and is told to paragon-agent first, so `packet.py` moves with it.

# The vtables store

`tools/vtables_dump.py` writes it, beside the facts store in `vtables`, a file a class that has a virtual table; its head says what a record holds, what `declared` and `defined` mean and cannot see, and how a class becomes a file's name. It reads the exe and the table, not Ghidra, so it needs no server and takes seconds.

- After a commit that names functions: `python tools/vtables_dump.py` rewrites every file (2,084 classes, 2,990 tables).
- `python tools/vtables_dump.py CCObject` prints one class's record and writes nothing.

A change to the record's form bumps its `VERSION` and is told to paragon-agent first.
