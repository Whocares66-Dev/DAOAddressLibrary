# DAOAddressLibrary

A number for every function and global of Dragon Age: Origins, and where each one is in every build of `DAOrigins.exe`. What [Address Library](https://www.nexusmods.com/skyrimspecialedition/mods/32444) is for Skyrim.

GOG, EA and Steam all sell version 1.05.13263.0, and they are not the same executable: a function at one address in GOG's build is somewhere else in EA's. A plugin that holds an ID gets the right address in each:

| ID | | GOG | EA | Steam |
|---|---|---|---|---|
| 10547 | `CClientExoApp::SetPaused` | `0x005D6740` | `0x004C1770` | `0x005D6740` |
| 25795 | the entry point | `0x008E3024` | `0x008B9584` | `0x008E3024` |
| 100835 | `g_clientExoApp` | `0x00C327EC` | `0x00C1ADAC` | `0x00C327EC` |

What the builds are and how they differ is in [dev/BUILDS.md](dev/BUILDS.md).

## What is here

- **The table**, [data/addresses.csv](data/addresses.csv): a row per ID, with its name where it has one, and a column per build. Over 100,000 IDs; `python tools\addrlib.py stats` counts them.
- **The run-time files**, one per build, packed from the table when the project is built.
- **The reader**, [src/daoaddr](src/daoaddr/Library.h): a small C++20 library, standard library only, that loads a build's file and answers "where is this ID" and "what ID is at this address".
- **The tools**, [tools/](tools): `addrlib.py` works on the table; the rest read the game's executables to fill it.

## Using it

A program holds IDs and, at start-up, loads the file for the game it is running in:

```cpp
#include "daoaddr/Library.h"

const daoaddr::BuildInfo build = /* the running executable's four PE header fields */;
const auto library = daoaddr::Library::Load(folder / daoaddr::FileName(build));
if (!library)
{
    // No file for this build of the game: touch nothing.
}
const auto setPaused = library->Rva(daoaddr::Id{10547}); // add the exe's base
```

[Library.h](src/daoaddr/Library.h) documents the rest. In a CMake project, `add_subdirectory` gives the `DAOAddressLibrary::daoaddr` target and `daoaddr_data`, which writes the files. [DAOLib](https://github.com/Whocares66-Dev/DAOLib) uses it this way.

## Looking things up and naming them

```powershell
python tools\addrlib.py lookup 0x005D6740                    # an address, in any build
python tools\addrlib.py lookup 10547                         # an ID
python tools\addrlib.py lookup SetPaused                     # a name, or part of one
python tools\addrlib.py name 10547 CClientExoApp::SetPaused  # name an ID
```

`python tools\addrlib.py --help` lists every command.

The table's `name` column is the one place a name is written down. A project that uses the IDs holds the numbers and looks the names up here.

## The promise

- **An ID is given once and never given again.** A thing a later build drops keeps its ID, with an empty cell.
- **An ID names a thing, not a place.** A name can change; the ID does not.
- **A filled cell means the thing was found there**, by comparing the builds' code. Nothing is guessed, and an empty cell means "not found".

How IDs are carried from one build to another is in [dev/BUILDS.md](dev/BUILDS.md). The rules for changing the table are in [CLAUDE.md](CLAUDE.md).

## Building

```powershell
.\tools\build.ps1 -Preset debug -Test           # the reader, the files, the tests
.\tools\build.ps1 -Preset debug -Format -Lint   # formatters and linters
.\tools\build.ps1 -Preset debug-asan -Test      # the tests under AddressSanitizer
.\tools\build.ps1 -Preset debug-analyze         # under MSVC's /analyze
```

Visual Studio 2022, vcpkg, x86. Only the tools that read the game's executables need the game; those files are BioWare's and EA's and are not in this repository.

## Adding a build

See [Adding a build](dev/BUILDS.md#adding-a-build). [dev/STEAM.md](dev/STEAM.md) records how the Steam build was read.

GPLv3 ([LICENSE](LICENSE)).
