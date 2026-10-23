# Changelog

## 0.6.0

- **106 IDs retired:** they were the cases of `switch` statements, which the comparison had taken for functions of their own (10101 among them). Each keeps its number, never given to anything else, with its kind `retired` and no address, so each build's file has 106 fewer addresses: 103,187, 103,461 and 103,422 for GOG, EA and Steam. No address of any other ID moved, and the file format is unchanged.
- **More names:** 8,804 IDs are named, 1,169 more than in 0.5.0: the engine's physics and the PhysX and NXU it uses, its FMOD layer, every command the UI's Scaleform movies can call, facial animation and FaceFX, script handlers put right, and, read for DAOParagonEngine, perception, melee rings, the party, pathfinding, effects, abilities, projectiles, loot, stores and items. `addrlib.py lookup` finds them.
- **Every function's subsystem:** `data/subsystems.csv` says which part of the engine, or which library, each GOG function belongs to, and `tools/subsystems.py` writes and checks it.
- **Kinder tools:** builds and the tools that read a whole executable run at below-normal priority, so the game and other work keep the machine.

## 0.5.0

- **The same files as 0.4.0:** every address, the code index and the file format are unchanged, byte for byte, so nothing needs installing again. This release gives DAOLib 0.5.0 a tag to build against.
- **More names:** 7,635 IDs are named, 67 more than in 0.4.0: the material system, an area's colour grade, tints, the pathfinding grid's coarse levels, animation keys and controllers, pausing an object's animation, movement speed and turning, and how a character's equipment and appearance become models. `addrlib.py lookup` finds them.

## 0.4.0

- **The same files as 0.3.0:** every address, the code index and the file format are unchanged, byte for byte, so nothing needs installing again. This release gives DAOLib a tag to build its flicker fix against.
- **More names:** 7,568 IDs are named, 17 more than in 0.3.0: the atmosphere and sky, SpeedTree's light, a light's colour, and how a model's point light flickers (`Animation::RandomWaveController<float>::Update` and what makes and drives it). `addrlib.py lookup` finds them.

## 0.3.0

- **The same files as 0.2.0:** every address, the code index and the file format are unchanged, byte for byte, so nothing needs installing again. This release gives DAOLib 0.3.0 a tag to build against.
- **More names:** 7,551 IDs are named, 19 more than in 0.2.0: the scene camera's position and orientation, quaternion yaw, pitch and roll, the input system and key bindings, and the GUI's movies (`GFxMovieRoot::Advance`, `SetBackgroundAlpha` and `GUI::MovieRecord::Step`). `addrlib.py lookup` finds them.

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
