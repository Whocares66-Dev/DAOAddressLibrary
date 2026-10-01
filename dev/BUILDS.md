# Builds

Dragon Age: Origins Ultimate Edition is sold by GOG, EA and Steam, and all say 1.05.13263.0. This is what each executable is, how they differ, and how an ID is carried from one to another. Read 2026-10-01 ([DAOLib issue 1](https://github.com/Whocares66-Dev/DAOLib/issues/1)).

| Key | Build | In the table |
|---|---|---|
| `gog` | GOG Ultimate Edition | 103,293 IDs: everything it holds. The first build read, so its things have the low numbers. |
| `ea` | EA app Ultimate Edition | 103,567 IDs: 102,463 of GOG's, and 1,104 of its own. |
| | Steam | Not read: no copy yet. |

## The two files

`gog`: `C:\Program Files (x86)\GOG Galaxy\Games\Dragon Age Origins\bin_ship\DAOrigins.exe`. `ea`: `C:\Program Files\EA Games\Dragon Age\bin_ship\daorigins.exe`. EA's is not GOG's file: the same engine at the same version, rebuilt in 2013 with a few source changes, linked in another order, and shipped encrypted.

| | GOG | EA |
|---|---|---|
| Version resource | 1.05.13263.0 | 1.05.13263.0 |
| Size | 10,217,312 | 9,686,120 |
| SHA-256 | `7e719cac…859c` | `da168d42…e1b3` |
| Link stamp | 0x4eb19d53, 2011-11-02 | 0x52164c37, 2013-08-22 |
| SizeOfImage | 0x9ec0a2 | 0x96b000 |
| Entry point | 0x008E3024, the CRT's | 0x00401000, `jmp [Core/Activation.dll #100]` |
| `.text` | 0x6d86aa bytes, plain | 0x6d2f4a bytes, encrypted |
| `.data` | plain | encrypted |
| Imports on disk | 22 DLLs | `Core/Activation.dll` only |
| SafeSEH table | none | 0x1115 handlers |
| PDB path | `…\perforce\tag\main\build\bin_Ship\DragonAge.pdb` | `c:\program files (x86)\origin games\dragon age\bin_ship\DragonAge.pdb` |
| Signed | no | Electronic Arts |

`data\builds.csv` has these, and `python tools\daoexe.py --exe <file> --check` says which a file is.

### EA's wrapper

`.text` and `.data` are encrypted on disk. The entry point is one jump into `Core\Activation.dll`, ordinal 100, which checks the licence (cached in `ProgramData\Electronic Arts\EA Services\License\70377.dlf`), decrypts both sections in place, resolves the game's imports itself and goes on to the game's own entry point. The wrapper's import table sits in the first bytes of `.data` on disk. `.rdata`, `.rsrc` and `.reloc` are the same in memory as on disk, the game's own import directory still in `.rdata`. The headers in memory are the file's: the link stamp, and the wrapper's entry point (seen in play through DAOLib's loader, 2026-10-01). So a program that reads the running exe's headers finds EA's build by them, and the build's row and its runtime file carry the wrapper's entry point, 0x1000, not the game's.

Two runs, not one. `daorigins.exe` started by anything but the EA app decrypts nothing: it asks the EA app to start the game and exits with 0, and the EA app, opened if it was not open, starts the exe again. That second run decrypts.

### Reading it

The encryption was not attacked. `tools\ea_dump.py` starts the installed, licensed game, lets it decrypt itself, freezes the run the EA app starts as soon as the sections in memory differ from the file (about a second and a half in, before a window opens), copies the image out and ends the process. **It starts the game through the EA app**, so say so before running it and do not run it while a game is in use; it leaves an `ActivationUI.exe` behind to end by hand.

It writes `game\ea\DAOrigins.dump.exe`: the file on disk with the two sections from memory and the header pointed back at the game's own entry point (0x008B9584), import directory, IAT and relocations. That is the image the tools read for `ea`.

### The same engine

- 2,375 RTTI classes and 2,990 vftables in both, the same names.
- 827 script commands in both, the same names and numbers, 692 implemented.
- The same imports, plus one in EA's: `KERNEL32!GetFileAttributesW`.
- A function is byte for byte what it is in GOG's build apart from the addresses inside it. But `CClientExoApp`'s code is at 0x5dc190 in GOG's and 0x4c7e70 in EA's, and the distance changes every few functions: the object files were linked in another order. No offset, and no short list of offsets, takes one build to the other.

### What EA changed

98 functions differ, in 578 instructions (`python tools\exemap.py game\gog\DAOrigins.exe game\ea\DAOrigins.dump.exe --changes`). Each has a `changed` note in `data\notes.csv`. It is the Origin re-release's change to the DLC: content that needed an online check is found on disk instead.

- Strings only in EA's build: `DlcEnabled`, `..\addins\`, `BioWare\Dragon Age\AddIns\`, `\manifest.xml`, `DAO_PRC_OCP_1`, `DAO_PRC_OCP_2`, `DAO_PRC_ONRX_1`, `Cider.bik`.
- The changed code is in `ContentManager`, `OnlineFeatures`, `CClientOptions`, `Store`, the start-up tasks (`UpdateSplashScreenTask`, `Eclipse::InitializeTask`) and `GUI::ScaleformManager`. Assert line numbers moved in four source files (by 15, 4, 30 and 26 lines), a few functions have bigger stack frames or some instructions more, and `SmartData::Attribute<int>` became `Attribute<bool>` in a few places.
- **Three class layouts differ.** No address table covers these: a field offset read from GOG's build is wrong in EA's for them.

| Class | GOG | EA |
|---|---|---|
| `ContentManager` | size 0x200 | 0x10 bytes inserted at +0x17C; fields from there are 0x10 higher; size 0x210 |
| `GUI::ScaleformManager` | size 0x204 | 0x10 bytes inserted at +0x190; fields from there are 0x10 higher; size 0x214 |
| `AnimBaseWield`, `AnimBaseParts`, `AnimBaseHead` | sizes 0x230, 0x240 | fields at +0x224 and up are 0x10 lower (where the shift starts was not read); sizes 0x220, 0x230 |

- **Identical functions are folded differently.** The linker makes one function of functions with the same bytes, and each build's linker chose differently. Where GOG has one function and EA several copies of it, the ID goes to the copy most referred to, with an `ambiguous` note naming the others (227 IDs), and the other copies are things only EA has, with IDs of their own. Where EA has one function for several of GOG's, their IDs share its address, with a `shared` note (653 IDs). Calling one is the same either way. A detour on one catches a different set of callers in each build.

## What gets an ID

A build's inventory, `python tools\exemap.py <exe> --inventory`: every address in its code that something calls or points at, and every address outside its code that a relocated word holds. GOG's is 59,851 code addresses and 43,442 globals; EA's 59,772 and 43,466.

- Code: the build is read against itself, by the same reading that compares two builds (below), from the entry point, the exports, and every function's address held in data (each vftable slot, each callback in a table, each unwind stub the exception tables name). What the reading reaches by a call, or by a jump to where a function starts, is in.
- Globals: every target of a relocation outside `.text`. The relocation table lists every absolute address in the image, so this is complete and needs no reading. It includes the vftables, the RTTI records, the strings code refers to, and each field of a global that code addresses directly.

The code addresses are more than what a disassembler calls functions: an unwind stub and a catch block are code something points at, and have IDs.

## Carrying an ID to another build

`python tools\addrlib.py add <key>` compares the new build with each build already in the table and writes down where each known ID is in it.

**Reading two builds side by side** (`tools\exemap.py`). It starts from what has a name in both: the entry point, the exports, the imports, the RTTI type descriptors and the vftables, 8,994 pairs between GOG and EA. Two functions known to be the same are compared one instruction each. They agree in everything but addresses, and where they hold an address, the two addresses are the same thing in the two builds: a call's target is a pair of functions to compare next, a global's address a pair of globals, a vftable's a pair of tables whose slots pair up in turn, and the word before a vftable the pair of its RTTI records. Which bytes are addresses is not guessed: each build's relocation table says, and a call's relative target is the instruction's own.

Where the source changed, the instructions do not agree. One that differs in an operand alone (a field that moved, a size, a line number) is noted and read past. Where the instructions themselves part ways, one build has code the other lacks, and the comparison resumes where five in a row agree again.

A table of functions the linker fills in link order (the C runtime's list of static initializers) would pair the wrong functions by position; its entries not matching gives it away, and it is left alone. A vftable's slots and a switch's jump table are in source order and are trusted.

**What nothing calls.** A static initializer or an unwind stub is reached through such a table or not at all, so the reading leaves them. They are paired by what they are (`match_leftovers`): the same instructions, referring to the same things, with what each refers to counted where that is already paired, and only if no other function on either side looks the same. What they refer to that was unpaired (the global an initializer constructs) then pairs with them. Several that look the same (the initializers of one class's globals) pair only by layout: what one object file contributes keeps its layout whatever the link order, so a run of them at the same distances from each other in both builds, or one standing at the same distance from a paired function on each side of it, is the same in both. 1,654 functions between GOG and EA.

**Both ways.** The comparison is run from each build to the other, since what each starts from and follows is its own build's; the second way found 25 more.

Between GOG and EA:

| | |
|---|---|
| GOG's code addresses found in EA | 59,514 of 59,851 (99.4%) |
| GOG's globals found in EA | 42,949 of 43,442 (98.9%) |
| GOG `.text` compared one to one by the reading | 94.6%, and 3.9% more is padding |
| Only GOG has | 830: 337 code, 493 globals |
| Only EA has | 1,104: 520 code, 584 globals |

What only one build has is, for the most part, what was not found in the other rather than what is not there: an unwind stub of a function whose code changed, an initializer that looks like fifty others and stands alone, and the globals only those refer to. Some of EA's 520 are the extra copies of folded functions, and some are its new DLC code.

Checked against something the comparison did not use: EA's own command table registers all 692 implemented script commands, by name, at exactly the address the table gives for the ID of GOG's function of that name. And every one of the 4,362 addresses DAOLib had a name for has an ID, with the EA address DAOLib had found for it and then seen in play.

## Adding a build

1. Copy its executable to `game\<key>\`. If it is wrapped as EA's is, get an image of it decrypted; the tools read that.
2. Add a row to `data\builds.csv`: its key, the header fields of the file as installed, its hash, and the path of the image to read.
3. `python tools\addrlib.py add <key>`, then `check`, then the tests.
4. `python tools\exemap.py <reference> <image> --changes` for what differs in it, and write that up here: a plugin author needs to know which classes moved.

`add` never moves a cell that is filled, and says where a comparison would now put one elsewhere.
