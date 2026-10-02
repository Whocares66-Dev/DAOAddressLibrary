# DAOAddressLibrary

A number for every function and global of Dragon Age: Origins, and where each one is in every build of `DAOrigins.exe`. What Address Library is for Skyrim.

The game is sold by GOG, EA and Steam. They all say version 1.05.13263.0, and they are not the same executable: EA's is the same engine linked in another order, so a function at `0x005D6740` in GOG's build is at `0x004C1770` in EA's, and no offset takes one to the other ([dev/BUILDS.md](dev/BUILDS.md)). Steam's decrypted engine code is identical to GOG's, so every GOG ID keeps its address in Steam; the wrapper and PE metadata still distinguish their executables. A plugin that holds IDs can resolve the addresses for each supported build:

| ID | | GOG | EA | Steam |
|---|---|---|---|---|
| 10547 | `CClientExoApp::SetPaused` | `0x005D6740` | `0x004C1770` | `0x005D6740` |
| 25795 | the entry point | `0x008E3024` | `0x008B9584` | `0x008E3024` |
| 100835 | `g_clientExoApp` | `0x00C327EC` | `0x00C1ADAC` | `0x00C327EC` |

## What is here

- **The table**, [data/addresses.csv](data/addresses.csv): a row per ID, with its name where it has one, and a column per build. 104,397 IDs as of 2026-10-01, some 7,400 of them named so far (`python tools\addrlib.py stats` counts both). [data/builds.csv](data/builds.csv) says what each build is and how to tell its file; [data/notes.csv](data/notes.csv) says what a cell alone cannot (a function whose code differs between builds, an address two IDs share).
- **The files a program reads at run time**, one per build, packed from the table: `daoaddresses-<stamp>-<size>-<entry>-<base>.bin`, about 420 KB each. The build writes them to `build\<preset>\daolib\addresses\`.
- **The reader**, `src/daoaddr`: a small C++20 library, standard library only, that loads a build's file and answers "where is this ID" and "what ID is at this address".
- **The tools** that make the table from the executables (`tools/`), which need the game. Nothing else does.

## Using it

A program holds IDs and, at start-up, loads the file for the game it is running in:

```cpp
#include "daoaddr/Library.h"

const daoaddr::BuildInfo build = /* the running executable's four PE header fields */;
const auto library = daoaddr::Library::Load(folder / daoaddr::FileName(build));
if (!library || library->Build() != build)
{
    // No file for this build of the game: touch nothing.
}
const auto setPaused = library->Rva(daoaddr::Id{10547}); // add the exe's base
```

A new executable with a new fingerprint needs a new data file. Existing consumers using `FileName(linkStamp)` must migrate to `FileName(BuildInfo)` to distinguish Steam from GOG. The old overload and GOG/EA files remain available. [DAOLib](https://github.com/Whocares66-Dev/DAOLib) consumes this library; its Steam loader integration and play testing are separate from this address map ([Steam findings](dev/STEAM.md)).

To find an ID:

```powershell
python tools\addrlib.py lookup 0x005D6740            # an address, in any build
python tools\addrlib.py lookup 0x004C978F --build ea-1.05 # inside a function: ID 10645 + 0x3f
python tools\addrlib.py lookup 10547                 # an ID
python tools\addrlib.py lookup CClientExoApp::SetPaused # a name, or part of one
```

## Names

The table's `name` column is the one place a function's or a global's name is written down. A build's own names are there from its reading: exports, imports, and each RTTI class's vftables and type descriptor. The rest are given by whoever worked out what a thing is:

```powershell
python tools\addrlib.py name 10547 CClientExoApp::SetPaused                       # by ID
python tools\addrlib.py name 0x005D6740 CClientExoApp::SetPaused --build gog-1.05 # by its address in a build
python tools\addrlib.py names found.tsv --build gog-1.05                          # many: address or ID, tab, name
```

A name can be given to any ID, and changed: it is the ID that is the promise. Nothing read at run time holds names, so naming something rebuilds nothing. A project that uses the IDs holds the numbers and looks the names up here, so that a thing has one name wherever it is spoken of.

## Rules

- **An ID is given once and never given again.** A thing a later build drops keeps its ID, with an empty cell.
- **An ID names a thing, not a place.** What gets one is every address in a build's code that something calls or points at, and every address outside its code that something refers to.
- **A cell says the thing was found there**, by comparing instructions or verifying identical loaded sections and relocations (allowing only documented PE load-configuration differences). Nothing is guessed, and an empty cell means "not found", which is not always "not there".
- **The executables are not here.** They are BioWare's and EA's. The table is addresses, which are facts about them.

## Building

```powershell
.\tools\build.ps1 -Preset debug -Test           # the reader, the files, the tests
.\tools\build.ps1 -Preset debug -Format -Lint   # formatters, then clang-tidy, ruff, PSScriptAnalyzer
```

The same toolchain as DAOLib: Visual Studio 2022, vcpkg, x86. In another project, `add_subdirectory` gives `DAOAddressLibrary::daoaddr` and the `daoaddr_data` target that writes the files.

## Adding a build

Put its executable under `game\`, add its row to `data\builds.csv` (a key for it, its header fields, where its executable is), and:

```powershell
python tools\addrlib.py add <key>
python tools\addrlib.py check
```

A key is a label for a build, `<store>-<version>`, with something more only if a store sells two builds of one version. The runtime identity is the full PE fingerprint: link stamp, image size, entry RVA and preferred image base. Steam and GOG share a link stamp, so a timestamp alone cannot identify the build. Runtime files use all four fields; the original timestamp-only GOG and EA files remain explicit legacy aliases. A store's next version is a new row and column, and an identical executable sold by two stores needs only one row.

Every ID is looked for in the new build, and what only it has gets new IDs. [dev/BUILDS.md](dev/BUILDS.md) explains the comparison and EA changes; [dev/STEAM.md](dev/STEAM.md) records Steamless extraction, Steam coverage and the loader handoff.

GPLv3 ([LICENSE](LICENSE)).
