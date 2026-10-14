# Changelog

## 0.2.0

- **A build found by its code:** an executable whose headers are no known build's but whose code is (Steamless' output, the Nexus "decrypted Steam" exe, a repack with its relocations stripped) reads the file of the build whose code it is. `data/builds.csv` has each build's `.text` range and SHA-256, `pack` writes `daoaddresses-code.index`, and `daoaddr::CodeIndex` reads it, and `daoaddr::Retarget` makes the file of the exe's own headers from the matched build's, for programs built before the index (DAOLib #110, #1).
- **The same addresses:** every ID has the address it had in 0.1.0 (103,293, 103,567 and 103,528 for GOG, EA and Steam), and the file format is unchanged, so a loader or mod built on 0.1.0 reads these files as it did.
- **More names:** 7,532 IDs are named, 65 more than in 0.1.0: the renderer's lights and frame-buffer effects, the allocator, the resource manager, area loading and input among them. `addrlib.py lookup` finds them.
- **The zip:** `bin_ship\daolib\addresses` now holds `daoaddresses-code.index` beside the three build files, the repository's `README.md` in place of a README.txt, and `VERSION.txt`, which says the release and how many IDs each file has.

## 0.1.0

The first release:

- **An ID for every function and global:** 104,397 numbers, one for each of the 60,371 functions and 44,026 globals of `DAOrigins.exe`. An ID is given once and never changes, so a mod built on one keeps working.
- **Three builds of the game:** where each ID is in the GOG, EA and Steam executables of 1.05.13263.0 (103,293, 103,567 and 103,528 IDs), found by comparing the builds' code. Nothing is guessed: an address is there or it is empty.
- **A file per build, and a reader:** each build's addresses packed into one 420 KB file, and `daoaddr`, a C++20 library of the standard library alone, which loads the running game's file and answers "where is this ID" and "what ID is at this address".
- **Names:** 7,467 IDs are named, from the game's exports, imports and RTTI and from reading its code. `addrlib.py lookup` finds a row by ID, address or part of a name.
- **Tools to add a build:** `exemap.py` compares two executables, and `addrlib.py add` fills the new build's column and gives new IDs to what only it has.
