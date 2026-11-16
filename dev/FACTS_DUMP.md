# A request from Paragon: the decompile store, dumped from the Ghidra database

From paragon-agent, 2026-11-15, at the user's word: this is to be worked out with addr-lib-agent, with a skill in this repository holding clear, short instructions for the tool. Nothing in this repository is changed by Paragon; this note is the request.

## What it is

Paragon's port pipeline and the overseer's checks read every exe function's decompile and disassembly from a store of JSON files, one per function: `%LOCALAPPDATA%\paragon-chain\facts\<0xADDR>.json` (or `$CHAIN_CACHE\facts`). Paragon's `tools/chain/packet.py` reads it and never touches Ghidra. The store was dumped on about 2026-11-07 from the `ghidra-dao` server by Paragon's own client, `tools/chain/ghidra_mcp.py`. That client was removed on 2026-11-14 (Paragon 440ceac0) with the lint rules it served; it is at Paragon `440ceac0^:tools/chain/ghidra_mcp.py`.

Two faults showed on 2026-11-15:
- **Holes.** 3,154 of the ledger's 19,478 functions had no record, among them real functions an audit needed (0x0069BD60 `ECDynArray<std.wstring>::GetOrDefault`, 0x004C31A0 `ECString::Right`). They were functions Ghidra did not define when the store was dumped; `ghidra_sync.py` has defined many since. Paragon is filling them tonight with the old client, kept as `scratch/helpers/ghidra_mcp_old.py` and driven by `scratch/helpers/fill_facts.py` (both in Paragon), at about 1.8 s a function.
- **Staleness.** Every fix ghidra_sync has applied since the dump (names, signatures, calling conventions, cleared labels) is missing from the store's names and decompiles: 0x00401210 is still `FUN_00401210` there.

The store is a product of the database, and this repository is the database's one writer, so the dump belongs here, run after each sync.

## What Paragon asks for

1. **A tool** (name and form yours; `tools/facts_dump.py` say) that writes the store from the database:
   - `--all`: every function the database defines.
   - `--missing`: only the addresses with no record.
   - `--changed`: only functions whose name, signature or body changed since their record was written. A hash of what the record was made from, kept in the record, would do.
   - The output path is `$CHAIN_CACHE\facts`, else `%LOCALAPPDATA%\paragon-chain\facts`, so every reader keeps working.
2. **The record's form, unchanged:** `{"version": 3, "value": {...}}` with `address`, `name` (namespaced), `ranges` (`[[min, max], ...]`), `callees` (each with its own address, name and size facts, `via_thunk` where called through one), `callers`, `blocks` (basic-block starts), `branches` (conditional, and switch jumps), `indirect` (computed calls and jumps, with the 8 instructions before and the known targets), `instructions` (count), `decompile`, `disassembly`. The `FACTS` script in the old client defines each field exactly. An address Ghidra has no function at is stored as `{}`, as before. If the form must change, bump `version` and tell Paragon, so `packet.py` moves with it.
3. **When it runs:** after each `ghidra_sync.py` run, `--changed` at least, so the store never trails the database. Running it from inside the sync's own pass may be cheaper than the MCP round trips (three calls a function today); that's your call.
4. **A skill** in `.claude/skills/` (say `facts-dump/SKILL.md`) with short, clear instructions:
   - what the store is and who reads it
   - when to run the tool (after a sync; when a reader finds a hole)
   - the commands, where the output goes, how long each mode takes
   - how to check a record (Paragon's `python tools/chain/packet.py <addr>` prints one)
   - that only this repository writes the store

## For reference

- The old client's facts code: Paragon `440ceac0^:tools/chain/ghidra_mcp.py`, functions `facts`, `stats`, `flow_targets`, and the `FACTS` script.
- The fill running tonight: Paragon `scratch/helpers/fill_facts.py`, log `C:\project\scratch-tools\fill-facts.log`. When your tool exists, Paragon stops using these and deletes them.
- The store's readers: Paragon `tools/chain/packet.py`; the overseer's not-needed screen (`%TEMP%\overseer_nn_screen.py`).
