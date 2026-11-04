# Changelog

## 0.10.0

- **The engine's functions are named:** 30,035 IDs are named, 592 more than in 0.9.0. The last of the engine's own functions, the D3D9 driver among them, have been read twice and named. What is left unnamed is the compiler's static destructors and a handful of rendering helpers. `addrlib.py lookup` finds them.
- **Names put right:** 292 renamed. Among them are the vector types (`Math::Vector4f` aligned, `Math::VectorUA4f` unaligned, `Vector3`), the game's record types behind 114 placeholder names, the draw batch's counts, and `MovementController::SlopeFactor` (was `CornerFactor`). An ID's number never changes, so a plugin built on an older name still calls the same function.
- **5 IDs retired:** pieces of other functions, not functions. Each keeps its number, with its kind `retired` and no address, so each build's file has 5 fewer addresses: 103,052, 103,324 and 103,285 for GOG, EA and Steam. No other address moved, and the file format is unchanged.
- **More class shapes:** `data/structs.csv` has 1,844 fields of 239 classes, 179 more fields than 0.9.0, among them the D3D state cache and a creature's movement controller (keyboard driving, the ground slope, the move target).
- **Tools:** `daoexe.py --callers` lists the direct calls and jumps to an address, and `daoexe.py` finds the game when this repository is a submodule. The Ghidra sync now catches a function whose class changed but whose name did not.

## 0.9.0

- **The engine is read:** 29,443 IDs are named, 20,099 more than in 0.8.0, and 96.5% of the engine's own functions: 19,410 less 685, nearly all of what is left being the D3D9 driver, which a port replaces, and plumbing. The engine's names come from two independent readings of the code, reconciled; the library names, by their public names, from one pass and a check, and the class records' by a rule across every class. Game, game modes, world, AI, scripting, conversation, animation, input, camera, audio and the interface are done but for a few each. `addrlib.py lookup` finds them.
- **132 IDs retired:** they were places inside functions, not functions: tails reached only by a jump, where a catch resumes, and a switch's case. Each keeps its number, never given to anything else, with its kind `retired` and no address, so each build's file has that many fewer: 103,057, 103,329 and 103,290 addresses for GOG, EA and Steam. No address of any other ID moved, and the file format is unchanged. DAOLib and the plugins here used none of them. `exemap.py` now knows such places, so a new reading will not number them again.
- **The shapes of the classes:** `data/structs.csv` is new: 1,665 fields of 194 classes, `CCCreature`, `CCObject`, `CCParty`, `CCArea` and `CRoom` among them, each with the address of an instruction that uses it. `tools/structs.py` checks them for overlaps. About 173 offsets DAOLib already held by hand were compared with these, and none disagreed.
- **Names put right, globals and library functions named:** one class had two names, or two classes one: `CameraRig` is the game's camera, apart from the renderer's `SceneCamera`; `CRules` was `GdaTables`; `GraphicsStructures::Array` is a 3-word array that shared `ECDynArray`'s name; `EC::ModelPlacement`, `Math::AABB` and `Math::Matrix4x4f` each absorbed another name. Globals named include the game state the code leans on most, and the library functions the engine calls most: `__security_check_cookie`, `rand`, zlib's, and those at the engine's edge in Scaleform, PhysX and FaceFX.
- **Ghidra:** `tools/ghidra_sync.py` writes all this into the database: 18,876 fixes to what its analysis got wrong (prototypes, conventions, labels, false functions), and the classes' shapes as structs. Only the session keeping this repository writes it.

## 0.8.0

- **The same files as 0.7.0:** every address, the code index and the file format are unchanged, byte for byte, so nothing needs installing again. This release gives DAOLib 0.8.0 a tag to build against.
- **More names:** 9,344 IDs are named, 87 more than in 0.7.0, read for DAOLib, DAOParagonEngine and DAOElgaraShaders: the engine's draw distances (terrain detail, SpeedTree LOD, effects' fade), a creature's root motion and ground placement, an area's creature k-d tree, areas of effect, the journal's plot-flag gate, the save list's heroes, Scaleform's scale9 grid and the GUI's per-frame mouse move, particle emitters and their random seeds, and a material's parameters. `addrlib.py lookup` finds them.

## 0.7.0

- **The same files as 0.6.0:** every address, the code index and the file format are unchanged, byte for byte, so nothing needs installing again. This release gives DAOLib 0.7.0 a tag to build against.
- **More names:** 9,257 IDs are named, 453 more than in 0.6.0, read for DAOLib and DAOParagonEngine: movement and pathfinding (a creature's `MovementController` and the `MovementPath` it walks), the melee ring, perception through rooms and doors, the commands' and sub-actions' handlers, the loading mode's area moves, stores, crafting, item requirements, tactics, the level-up screen, the Chanter's board, and a model's physics shapes. `addrlib.py lookup` finds them.
- **Names put right:** 16 renamed, among them the movement functions that belong to `MovementPath`, `Commands::AttackStart` (was `AttackStep`) and the recipe test, now `ECBase::ECDynArray::Contains`. An ID's number never changes, so a plugin built on an older name still calls the same function.

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
