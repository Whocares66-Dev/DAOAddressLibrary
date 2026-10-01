# DAOAddressLibrary

A number for every function and global of Dragon Age: Origins, and where each one is in every build of `DAOrigins.exe`. What Address Library is for Skyrim.

The game is sold by GOG, EA and Steam. They all say version 1.05.13263.0, and they are not the same executable: EA's is the same engine linked in another order, so a function at `0x005D6740` in GOG's build is at `0x004C1770` in EA's, and no offset takes one to the other ([dev/BUILDS.md](dev/BUILDS.md)). A plugin that holds addresses works in one build. A plugin that holds IDs works in all of them:

| ID | | GOG | EA |
|---|---|---|---|
| 10547 | `CClientExoApp::SetPaused` | `0x005D6740` | `0x004C1770` |
| 25795 | the entry point | `0x008E3024` | `0x008B9584` |
| 100835 | `g_clientExoApp` | `0x00C327EC` | `0x00C1ADAC` |

## What is here

- **The table**, [data/addresses.csv](data/addresses.csv): a row per ID, a column per build. 104,397 IDs as of 2026-10-01. [data/builds.csv](data/builds.csv) says what each build is and how to tell its file; [data/notes.csv](data/notes.csv) says what a cell alone cannot (a function whose code differs between builds, an address two IDs share).
- **The files a program reads at run time**, one per build, packed from the table: `daoaddresses-<link stamp>.bin`, about 420 KB each. The build writes them to `build\<preset>\daolib\addresses\`.
- **The reader**, `src/daoaddr`: a small C++20 library, standard library only, that loads a build's file and answers "where is this ID" and "what ID is at this address".
- **The tools** that make the table from the executables (`tools/`), which need the game. Nothing else does.

## Using it

A program holds IDs and, at start-up, loads the file for the game it is running in:

```cpp
#include "daoaddr/Library.h"

const auto library = daoaddr::Library::Load(folder / daoaddr::FileName(linkStampOfTheRunningExe));
if (!library)
{
    // No file for this build of the game: touch nothing.
}
const auto setPaused = library->Rva(daoaddr::Id{10547}); // add the exe's base
```

So a build of the game it has never seen needs a new file beside it, and nothing rebuilt. [DAOLib](https://github.com/Whocares66-Dev/DAOLib) does this for its plugins.

To find an ID:

```powershell
python tools\addrlib.py lookup 0x005D6740            # an address, in any build
python tools\addrlib.py lookup 0x004C978F --build ea # inside a function: ID 10645 + 0x3f
python tools\addrlib.py lookup 10547                 # an ID
python tools\addrlib.py lookup CClientExoApp::vftable # a name the exe itself gives
```

## Rules

- **An ID is given once and never given again.** A thing a later build drops keeps its ID, with an empty cell.
- **An ID names a thing, not a place.** What gets one is every address in a build's code that something calls or points at, and every address outside its code that something refers to.
- **A cell says the thing was found there**, by comparing the builds' code instruction for instruction. Nothing is guessed, and an empty cell means "not found", which is not always "not there".
- **The executables are not here.** They are BioWare's and EA's. The table is addresses, which are facts about them.

## Building

```powershell
.\tools\build.ps1 -Preset debug -Test           # the reader, the files, the tests
.\tools\build.ps1 -Preset debug -Format -Lint   # formatters, then clang-tidy, ruff, PSScriptAnalyzer
```

The same toolchain as DAOLib: Visual Studio 2022, vcpkg, x86. In another project, `add_subdirectory` gives `DAOAddressLibrary::daoaddr` and the `daoaddr_data` target that writes the files.

## Adding a build

Put its executable under `game\<key>\`, add its row to `data\builds.csv`, and:

```powershell
python tools\addrlib.py add <key>
python tools\addrlib.py check
```

Every ID is looked for in the new build, and what only it has gets new IDs. [dev/BUILDS.md](dev/BUILDS.md) says how, and what was found for the EA build.

GPLv3 ([LICENSE](LICENSE)).
