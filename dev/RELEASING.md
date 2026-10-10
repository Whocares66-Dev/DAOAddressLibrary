# Releasing

A release is a tag, `v<version>`, and on GitHub the zip a player installs: the run-time files, one per build of the game, laid out as the game's folder (`bin_ship\daolib\addresses\`). The reader and the table are the tagged source, and nothing else is attached. The process is SkyrimFollowerTactics' (`C:\project\SkyrimFollowerTactics\dev\RELEASING.md`) without its documentation site. Written 2026-10-10, for 0.1.0.

## The version

`project(DAOAddressLibrary VERSION x.y.z)` in `CMakeLists.txt` is the one place it is written. A number says what a loader and the mods a player already has can do with the new files:

- **patch**: the same files knowing more. IDs added, cells filled or put right.
- **minor**: a file for another build of the game, or something added to the reader.
- **major**: a new `format` word, which every reader built before it refuses (`src/daoaddr/Library.cpp`'s head), or a change to the reader that breaks its callers. Its notes say which DAOLib reads the files.

A name needs no release: no file holds one, and a project that wants it holds its submodule at the commit.

## Cutting one

1. Set the version, and add `## x.y.z` at the top of `CHANGELOG.md`: about five entries, the most important first, in a player's and a mod author's words. The section is the GitHub release's notes, word for word, so no link in it is relative.
2. Run the four commands of the README's "Building" and commit to `master`. `.\tools\package.ps1` alone writes `dist\DAOAddressLibrary-x.y.z.zip`, to look at.
3. Publishing waits for the user's word, as in SkyrimFollowerTactics: a request to prepare a release is not one to publish it.
4. `.\tools\release.ps1 none -DryRun`, then `.\tools\release.ps1 none`. It runs the debug preset's tests, writes the zip, makes the annotated tag, pushes `master` and the tag, and creates the release with the zip attached, a prerelease below 1.0. `patch`, `minor` or `major` in place of `none` bumps and commits the version first.
5. Check the release's tag, notes, prerelease flag and one zip, and the zip's hash against `dist\`. Tell lib-agent the tag. A tag is never moved: a correction is the next patch.

If the tests or the zip fail, nothing was tagged or pushed. If `gh release create` fails after the push, run it alone on the tag that is there: `gh release create vX.Y.Z --repo Whocares66-Dev/DAOAddressLibrary --verify-tag --title "DAOAddressLibrary X.Y.Z" --notes-file build\release-notes-X.Y.Z.md dist\DAOAddressLibrary-X.Y.Z.zip` (`--prerelease` below 1.0).

## With DAOLib's release

What is so, read in DAOLib 2026-10-10 (its master `1c64ab4`):

- **One folder.** The loader and every plugin, each with its own copy of the reader, read the running build's file from `bin_ship\daolib\addresses` (`src\dao\Module.cpp`). The folder's files are whichever were written there last.
- **DAOLib's zip has the files too.** Its `tools\package.ps1` puts in the ones its build packed from the submodule, so a player with DAOLib alone has a working set. `pack` writes no date, so at one commit of this repository they are this release's files byte for byte.
- **Newer files serve older code, not the other way.** `kept` holds every ID and address the last table had, so a loader or plugin built on an older table finds all it asks for in a newer file. A plugin built on a newer table than the files in the folder gets no address for the IDs they lack: `dao::Module::Address` gives 0 and `Detour::Attach` false.

So the two releases fit this way:

- **This zip is for the gap between DAOLib releases:** a plugin built on a newer table than the player's DAOLib shipped, or another build of the game supported before DAOLib's next release. Such a plugin's page says "Address Library x.y.z or later" and links here. A player with DAOLib alone needs nothing from here.
- **A DAOLib release holds its submodule at a tag of this repository,** and its notes and README.txt name it ("address files: DAOAddressLibrary 0.1.0"). Between releases it holds whatever commit it needs, as now.
- **An older zip extracted over newer files puts the older ones back.** DAOLib's `deploy.ps1` keeps a file that knows more IDs; extracting a zip cannot. The remedy is to extract the newest Address Library again, and which one is there is told by a count, not by a text file a zip left: the loader's log says how many IDs the file it read has, and this zip's `VERSION.txt` says how many each of its files has (0.1.0's zip has it in a `README.txt`; from the next release the zip's readme is the repository's `README.md`).
- **A major version here breaks the fit once:** a loader built before a new `format` refuses the new files and loads nothing. That release goes out with a DAOLib release that reads it, and neither before the other.

**Taken up in DAOLib, 2026-10-10** (lib-agent, DAOLib master `11c1f7e`, its issue 54, the submodule at `v0.1.0`): its `tools\package.ps1` reads the tag the submodule is at and names it in the zip's README.txt, or the commit with a warning where there is no tag, and the README.txt says that the archive replaces the address files, newer or not, and to extract a newer Address Library again after it. Its `dev\BUILDS.md`, "The files", holds its side of this. lib-agent built a zip at the tag and found its three files the same, by SHA-256, as this release's.

**DAOLib 0.1.0, 2026-10-10** (its tag `v0.1.0` at `41cf56c`, a prerelease, one zip, `DAOLib-0.1.0.zip`): released with the submodule at this repository's `v0.1.0`, which its zip's README.txt and its notes name. Its `tools\release.ps1` refuses when the submodule is at no `v*` tag here, so a DAOLib release always ships a released set of address files.
