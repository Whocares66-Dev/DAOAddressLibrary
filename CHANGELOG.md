# Changelog

## 0.1.0

The first release:

- **An ID for every function and global:** 104,397 numbers, one for each of the 60,371 functions and 44,026 globals of `DAOrigins.exe`. An ID is given once and never changes, so a mod built on one keeps working.
- **Three builds of the game:** where each ID is in the GOG, EA and Steam executables of 1.05.13263.0 (103,293, 103,567 and 103,528 IDs), found by comparing the builds' code. Nothing is guessed: an address is there or it is empty.
- **A file per build, and a reader:** each build's addresses packed into one 420 KB file, and `daoaddr`, a C++20 library of the standard library alone, which loads the running game's file and answers "where is this ID" and "what ID is at this address".
- **Names:** 7,467 IDs are named, from the game's exports, imports and RTTI and from reading its code. `addrlib.py lookup` finds a row by ID, address or part of a name.
- **Tools to add a build:** `exemap.py` compares two executables, and `addrlib.py add` fills the new build's column and gives new IDs to what only it has.
