# Steam executable, read 2026-10-01

For [DAOLib issue 1](https://github.com/Whocares66-Dev/DAOLib/issues/1), the installed file is `E:\SteamLibrary\steamapps\common\Dragon Age Ultimate Edition\bin_ship\DAOrigins.exe`. Analysis uses a copy under the ignored `game/steam/`; the installed file is unchanged.

[Steamless 3.1.0.5](https://github.com/atom0s/Steamless/releases/tag/v3.1.0.5), its official release archive, recognizes SteamStub Variant 2.1 (x86). Running `game\steamless\Steamless.CLI.exe game\steam\DAOrigins.exe` with default options decrypts `.text`, removes `.bind` and restores the engine entry point. Copy its output `DAOrigins.exe.unpacked.exe` to `DAOrigins.unpacked.exe` for the mapping tools. Neither the game nor Steam was launched.

| | Installed | Unpacked |
|---|---|---|
| File size | 10,594,144 | 10,217,312 |
| SHA-256 | `400c2c9e97bb1a534121553be66f202429ef6f7320c93c86f9b7a491864647bd` | `df7af15798f71d72b9927a35f9e87e7736bc60196e8d7524470d58214116e186` |
| Link stamp | `0x4eb19d53` | `0x4eb19d53` |
| SizeOfImage | `0x00a49000` | `0x009ed000` |
| Entry RVA | `0x009ed2ee` | `0x004e3024` |
| Preferred base | `0x00400000` | `0x00400000` |

Steam shares GOG's link stamp and section virtual addresses. The entire virtual `.text` (0x6d86aa bytes) is identical to GOG's: SHA-256 `1b44f297bf864264e0138f7d3ec15cc5780fcbe3643db42101e61815f814e3f3`. The raw `.data`, `.tls`, `.rsrc` and `.reloc` sections are also identical. Both images have 2,375 RTTI classes and 2,990 vftables.

The files differ in 165 bytes: header/stub bytes, sixteen bytes beyond `.text`'s virtual size, and six bytes in `.rdata`'s load configuration. Steam retains a SafeSEH table at `0x00b8ec30` with `0x110e` entries; GOG's load configuration disables it. These differences do not move the engine code.

The initial instruction comparison (`tools/exemap.py ... --changes`) reported 58,929 functions and 46,136 data addresses paired, zero rejected pairs and zero ambiguous addresses. Its one reported changed function at `0x009092f0` was a traversal stopping at embedded data at `0x00909b0f` (`not code`), not a byte difference. The verified identical-layout path now covers the full code section without that false change or duplicate IDs for identical initializers. It checks every virtual section byte and relocation location, allowing only the three documented PE load-configuration fields to differ; it does not identify binaries by timestamp or code hash alone.

The installed and unpacked headers differ from GOG's despite the shared timestamp. Timestamp-only file names cannot distinguish them. `daoexe.py --check` now recognizes the installed and analysis images by their recorded hashes, or reports a full-header match with an unverified hash; it no longer calls an unknown file GOG on timestamp alone.

## Final mapping

`python tools\addrlib.py add steam-1.05` records 103,528 IDs without allocating new IDs:

- All 103,293 GOG IDs have exactly their GOG addresses in Steam, including all 59,851 code IDs.
- Another 235 IDs first seen in EA map into Steam. Many are aliases of GOG IDs because EA folded identical functions differently. There are 103,297 distinct mapped addresses.
- Steam's full inventory, 59,851 functions and 43,443 globals, is covered. The extra global compared with GOG is the SafeSEH table at `0x00b8ec30`, already ID 103960 from EA.
- The Steam column has 461 shared-ID notes, 18 ambiguous-ID notes and one changed-function note (ID 103449, relative to EA). No GOG-origin function has a changed note.
- Comparing through EA offers 373 alternate cells for already mapped IDs, which `add` reports and leaves alone. These do not override the direct GOG/Steam identity proof. GOG and EA's committed cells and every existing ID remain unchanged.

An independent read of Steam's command registrations gives the same 827 entries as GOG; all 692 implemented script commands agree with the Steam column. This check uses the command names/numbers in the executable, not the comparison's seeds. The installed executable's SHA-256 was checked again after extraction and is unchanged.

## Runtime files and DAOLib handoff

The Steam runtime file is `daoaddresses-4eb19d53-00a49000-009ed2ee-00400000.bin`. `daoaddr::FileName(BuildInfo)` uses all four fields, and the reader's binary format remains version 1. The packer also writes full-fingerprint GOG/EA files and their original timestamp-only aliases, explicitly reserved by `legacy=1` in `builds.csv`. Steam never overwrites GOG's `daoaddresses-4eb19d53.bin`. Duplicate fingerprints or legacy names fail `check` and `pack` before any files are written. The ID-preservation check also matches builds by all four fields.

DAOLib's owner needs to migrate `Module.cpp` from `FileName(have->timeDateStamp)` to the `BuildInfo` overload, still compare the loaded file's four fields with the running executable, and arrange plugin initialization after SteamStub has decrypted `.text`. GOG's address layout can be used for Steam, but the stock wrapper entry point is not the engine entry point. This repository does not change DAOLib or deploy to the Steam installation.

**Done in DAOLib, 2026-10-01** (lib-agent, DAOLib master `5b17dbe`, the submodule at `b434b45`): the module looks its file up by all four fields and checks the header inside, GOG's listing file the same way, and `deploy.ps1 -Install steam` copies the files. The loader's test for a wrapped exe (the entry point's ID against the header's entry point) already takes Steam's down the same path as EA's: plugins load at the first call from the game's own `.text`. Seen in the Steam game, as lib-agent quoted its `loader.log` of 2026-10-01 23:18:59, from a DAOLib worktree's build: link stamp 0x4eb19d53, image size 0xa49000, entry rva 0x9ed2ee; 103,528 IDs from `daoaddresses-4eb19d53-00a49000-009ed2ee-00400000.bin`; "the game's code is wrapped"; 0.3 s later "running, decrypted (the clock read from 0x8e21bb)"; three plugins loaded and the game started.

**Played by hand, 2026-10-02 01:13** (computer-use-agent, DAOLib master `5b17dbe` deployed with `-Install steam`; results in DAOLib's `build\playtest-2026-10-02-steam\RESULTS.md`, recorded in its commit `c0ae959`). The same save and steps as GOG's and EA's the day before, and all eight passed with nothing differing from GOG's but what the build is: Steam's file found by its four fields, the stub waited out (plugins 0.33 s after start), seven plugins loaded, the probe's census on 871 of 872 functions with none refused, the world on the screen the same to the pixel, a plugin's keys and its options section, the preview's ring, the journal, a walk and a pause; no warning, error or crash. The save at first needed content the Steam install lacked (the promotional items, each for Origins and for Awakening); the user installed it, and the save then loaded with no Force Load.

**The timestamp-only names stay for now.** DAOLib's master no longer reads them, but plugins built against DAOLib before `5b17dbe` (the turn-based mod and Eluvian, deployed in the GOG folder) carry a loader that asks for `daoaddresses-4eb19d53.bin`. lib-agent will say when both have moved past it; until then `pack` keeps writing the two aliases.

The catalog's runtime fingerprint is the **stock installed** Steam file. The unpacked executable is the analysis input, identified separately by `image_sha256`; no runtime file for an installed Steamless-modified executable is claimed here. Runtime header behavior, loader timing and play testing remain to be verified in the Steam process. Static mapping and address-library tests do not establish that the existing DAOLib loader supports Steam yet.

## Validation

The debug build/tests and lint, AddressSanitizer build/tests, and MSVC static-analysis build all pass. CTest runs 14 checks, including the 49 Python unit tests, the packed-library integration test over every GOG ID, table validation and ID preservation. The GOG/EA regression comparison still reports zero rejected pairs and 98 changed functions in 578 instructions. `addrlib.py kept 6531a22` verifies the mapping against the pre-Steam table, with zero changed IDs or existing addresses.
