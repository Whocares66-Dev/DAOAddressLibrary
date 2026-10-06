# DAOAddressLibrary -- project context

A number (an ID) for every function and global of Dragon Age: Origins, and where each is in every build of `DAOrigins.exe`: Skyrim's Address Library, for this game. Read `README.md` first, then `dev/BUILDS.md`: what the builds are, how they differ, and how the comparison that carries an ID from one build to another works.

It is a sibling of `C:\project\DAOLib` (the loader and library for native plugins, which reads this at run time) and `C:\project\DAOTurnBased` (a plugin). It knows nothing of either: no names of theirs, no code of theirs. DAOLib holds the names and the IDs it uses; this holds the IDs and the addresses.

Markdown here is not hard-wrapped: one line per paragraph or list item.

## What must not change

**An ID is forever.** `data/addresses.csv` is the source of truth, and its `id` column is a promise to every plugin built against it. Never renumber, never reuse, never delete a row. A thing that turns out to be nothing, or the same as another ID, has its kind set to `retired` and its cells emptied. `python tools\addrlib.py check` (a ctest) fails on a gap, and `python tools\addrlib.py kept` (a ctest too) fails if any ID or address the last commit's table has is gone or changed in the working copy's; it takes another revision to compare with. A cell put right on purpose fails it once: say so in the commit.

So the table is not regenerated from scratch. `tools\addrlib.py add <key>` fills a build's column and appends: run on a build already there, it re-fills that build's cells and adds IDs for what an improved reading newly finds. An improvement to `tools\exemap.py` therefore shows up as cells filled, never as IDs moved. If a change to the comparison would empty or move cells that plugins use, that is a regression: `tests\test_library.cpp` pins a few, and DAOLib's own tests pin every ID it names.

**A name is in one place.** The table's `name` column: a build's own names from its reading (exports, imports, RTTI), and the rest given with `python tools\addrlib.py name`. Projects that use the IDs (DAOLib) hold numbers and read the names here; do not keep a second list of them anywhere. Unlike an ID a name may be changed, and two IDs may share one (overloads). A name goes straight to `master`, ahead of the code that uses it if need be: it changes no ID and no address, nothing read at run time holds it, and `kept` answers for the rest. A commit that only names things says which (`A name: Class::Method (ID n)`).

**One session keeps this repository.** The user's rule, 2026-10-01: "Communicate changes to addr lib agent & let it decide to makes changes & commit. This cleanly separates responsibilities." A session working in DAOLib or a plugin does not commit or push here, in this checkout or in a submodule copy of it. It sends what it needs: for a name, the ID, function or data, the name, the GOG address and what the thing is (DAOLib's `tools\address_ids.py` prints the line); for a fault in the table, the tools or the docs, what went wrong. The session that keeps the repository decides, commits to `master`, and says which commit, which the asker then holds its submodule at.

The same holds the other way, for every repository: "each agent is responsible for one repo. don't directly manipulate other repos, otherwise there'll be a big mess", and "can read other repos but don't write to them, except for new /dev notes that they can read". So the keeper of this one reads DAOLib and the plugins freely and changes nothing in them: DAOLib is lib-agent's, branches, tools and docs. What may be written in another's repository is a new file under its `dev\`, a note for its owner, who decides whether it stays; and another session may leave one under `dev\` here.

The runtime file's format (`src/daoaddr/Library.cpp`'s head, `tools/addrlib.py`'s `pack_build`) is versioned by its `format` word. Readers refuse a format they do not know, so a change to it is a new number and an old reader failing safe, not a silent misread.

## The builds -- verified 2026-10-01

| key | | exe | image the tools read |
|---|---|---|---|
| `gog-1.05` | GOG Ultimate Edition 1.05.13263.0, link stamp 0x4eb19d53 | `C:\Program Files (x86)\GOG Galaxy\Games\Dragon Age Origins\bin_ship\DAOrigins.exe` | `game\gog\DAOrigins.exe`, the file itself |
| `ea-1.05` | EA app Ultimate Edition 1.05.13263.0, link stamp 0x52164c37, wrapped | `C:\Program Files\EA Games\Dragon Age\bin_ship\daorigins.exe` | `game\ea\DAOrigins.dump.exe`, decrypted (`tools\ea_dump.py`); `game\ea\DAOrigins.exe` is the file as installed |
| `steam-1.05` | Steam Ultimate Edition 1.05.13263.0, link stamp 0x4eb19d53, wrapped | `E:\SteamLibrary\steamapps\common\Dragon Age Ultimate Edition\bin_ship\DAOrigins.exe` | `game\steam\DAOrigins.unpacked.exe`, Steamless 3.1.0.5; stock copy is `game\steam\DAOrigins.exe` |

A key is a label for a build, `<store>-<version>`, with something more only if a store sells two builds of one version. The runtime identity is the full PE fingerprint: link stamp, image size, entry RVA and preferred image base. Steam and GOG share a link stamp, so a timestamp alone cannot identify the build. Runtime files are named by all four fields and by nothing else: the timestamp-only names GOG's and EA's first files had were dropped on 2026-10-02. A store's next version is a new row and column, and an identical executable sold by two stores needs only one row.

`game\` is ignored by git: the executables are BioWare's and EA's. Steam is read from `game\steam\DAOrigins.unpacked.exe`, produced by Steamless 3.1.0.5 from the installed copy at `E:\SteamLibrary\steamapps\common\Dragon Age Ultimate Edition\bin_ship\DAOrigins.exe`. See `dev/STEAM.md`; the installation itself is unchanged.

**`tools\ea_dump.py` starts the game through the EA app.** Say so before running it, check that no `DAOrigins.exe` is running (the game runs one at a time, and other sessions play-test in it), and do not run it for no reason: the dump in `game\ea\` is good until EA ships another file.

## Layout

```
data/           addresses.csv (the table), builds.csv (the builds and their fingerprints), notes.csv (changed, shared, ambiguous)
src/daoaddr/    the reader: Library (a build's file), Index (an address back to an ID). C++20, standard library only, no <Windows.h>
tests/          Catch2 over the reader, and the packed files against the table; ctest also runs tools/test_*.py and addrlib.py check
tools/          addrlib.py (the table: add, lookup, pack, check, stats), exemap.py (one build compared with another, and a
                build's inventory), daoexe.py (a PE read without Ghidra: RTTI, vftables, imports, disassembly), msvc_names.py,
                ea_dump.py (the EA build decrypted, from the running game), build.ps1, check-powershell.ps1, console.ps1
dev/            BUILDS.md
game/           the executables (ignored)
```

`daoexe.py` and `msvc_names.py` came from DAOLib, which has copies its other tools use. This is the lower layer, so a fix belongs here first.

## Building

```powershell
.\tools\build.ps1 -Preset debug -Test           # the reader, the files, the tests
.\tools\build.ps1 -Preset debug -Format -Lint   # rewrite with the formatters, then clang-tidy, ruff, PSScriptAnalyzer
.\tools\build.ps1 -Preset debug-asan -Test      # the tests under AddressSanitizer
.\tools\build.ps1 -Preset debug-analyze         # under MSVC's /analyze
```

The tooling is DAOLib's, which is the Skyrim repos': VS 2022 `cl.exe` targeting x86, vcpkg at `C:\vcpkg`, LLVM 22 for clang-format and clang-tidy, ruff, gersemi, PSScriptAnalyzer. Each fails the run on a finding. Run all four before a commit that touches code; a commit that only fills the table needs `python tools\addrlib.py check` and the tests.

The build packs the table into `build\<preset>\daolib\addresses\daoaddresses-<stamp>-<size>-<entry>-<base>.bin`, one per build. They are not in git: they are the table in another form, attached to a release.

## Working on the comparison

`tools\exemap.py` is the part with judgement in it. What it may do: pair two addresses because two instructions that are otherwise the same hold them, or because two tables of the same class hold them at the same slot, or because two functions are the same code referring to the same things and nothing else on either side is. What it may not do: pair by position in a table the linker orders, by nearness alone, or by a guess. A wrong pair is worse than a missing one: a missing cell fails loudly in a plugin, a wrong one hooks the wrong function.

Check a change against what is known: `python tools\exemap.py game\gog\DAOrigins.exe game\ea\DAOrigins.dump.exe` should still say `0 pairs rejected`, and the script commands, which each build registers by name, must map to each other (DAOLib's `tools\script_commands.py` reads the registrations; 692 of 692 on 2026-10-01).

## Style

DAOLib's: clang-format's stock Microsoft style. Lint is for correctness and, since 2026-10-05 (the user: "style & readability also matter. We want to write good clean code, avoid complexity"), for readability: clang-tidy's `readability-*` and `modernize-*` less the checks that are taste alone, which `.clang-tidy` lists with why, and a function past a cognitive complexity of 25 is split. Comments say why and what was read, with dates, not what the code does. A file's head says what the file is for and how it fits.
