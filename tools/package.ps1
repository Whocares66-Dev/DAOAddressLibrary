<#
.SYNOPSIS
    Make the release zip a player installs the address files from.

.DESCRIPTION
    Writes dist\DAOAddressLibrary-<version>.zip, laid out as the game's install folder,
    so a player extracts it there (beside bin_ship) as DAOLib's own zip is extracted:
    bin_ship\daolib\addresses\daoaddresses-*.bin, one per build of the game, with
    README.md, LICENSE.txt and VERSION.txt beside them. They are in that folder and not
    at the zip's root, which is the game's folder and where DAOLib's zip has a
    README.txt of its own.

    README.md is the repository's, the same file, as SkyrimFollowerTactics' zip has its
    own (the user asked for it 2026-10-10, after 0.1.0, whose zip had a README.txt
    written here instead): what it says of installing is written once, there. Its links
    to other files of the repository lead nowhere from a game folder.

    The files are packed here from the table (tools\addrlib.py pack), not taken from a
    build tree: packing needs Python alone, and it writes no date, so the same table
    gives the same bytes and these are the files any build of this commit makes, a
    loader's included (seen 2026-10-10: DAOLib's build\release files, hash for hash).

    VERSION.txt is what the README cannot say: the release, and how many IDs each of its
    files has an address for. A loader's log says the same of the file it read, which is
    how to tell which release is in a game folder: a text left by one zip says nothing
    of files another zip has since written.

    The version is the project's (CMakeLists.txt). Nothing is copied into the game.

.EXAMPLE
    .\tools\package.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'console.ps1')
$repo = Split-Path -Parent $PSScriptRoot

$cmake = Get-Content -Raw (Join-Path $repo 'CMakeLists.txt')
if ($cmake -notmatch 'project\(DAOAddressLibrary VERSION (\d+\.\d+\.\d+)') { throw 'No version in CMakeLists.txt' }
$version = $Matches[1]
$name = "DAOAddressLibrary-$version"

$stage = Join-Path $repo "build\package\$name"
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
$addresses = Join-Path $stage 'bin_ship\daolib\addresses'
New-Item -ItemType Directory -Force $addresses | Out-Null

python (Join-Path $repo 'tools\addrlib.py') pack $addresses
if ($LASTEXITCODE -ne 0) { throw "tools\addrlib.py pack failed ($LASTEXITCODE)" }

# How many IDs a file has an address for: the words after its 0x24-byte header
# (src/daoaddr/Library.cpp's head) that are not 0xFFFFFFFF, and the build it
# is for from the header's four fields, which data\builds.csv names.
$builds = Import-Csv (Join-Path $repo 'data\builds.csv')
$lines = foreach ($file in Get-ChildItem -Path $addresses -Filter 'daoaddresses-*.bin' | Sort-Object Name) {
    $bytes = [IO.File]::ReadAllBytes($file.FullName)
    $fields = 0x0C, 0x10, 0x14, 0x18 | ForEach-Object { [BitConverter]::ToUInt32($bytes, $_) }
    $build = $builds | Where-Object {
        [uint32]$_.link_stamp -eq $fields[0] -and [uint32]$_.size_of_image -eq $fields[1] -and
        [uint32]$_.entry_point_rva -eq $fields[2] -and [uint32]$_.image_base -eq $fields[3]
    }
    if (@($build).Count -ne 1) { throw "$($file.Name) is not the file of one build in data\builds.csv" }
    $known = 0
    for ($at = 0x24; $at + 4 -le $bytes.Length; $at += 4) {
        if ([BitConverter]::ToUInt32($bytes, $at) -ne [uint32]::MaxValue) { $known++ }
    }
    '  {0,-38} {1,7} IDs  {2}' -f $build.name, $known, $file.Name
}
if (@($lines).Count -eq 0) { throw 'tools\addrlib.py pack wrote no file' }

$versionText = @"
DAOAddressLibrary $version
https://github.com/Whocares66-Dev/DAOAddressLibrary/releases

$($lines -join "`n")

DAOLib's zip has address files too, and whichever zip was extracted last wrote the
ones in this folder. Documents\BioWare\Dragon Age\daolib\loader.log says at each start
how many IDs the file it read has for the game's build, and the numbers above are
this release's.
"@
Set-Content -Path (Join-Path $addresses 'VERSION.txt') -Value $versionText -Encoding utf8
Copy-Item -Force (Join-Path $repo 'README.md') $addresses
Copy-Item -Force (Join-Path $repo 'LICENSE') (Join-Path $addresses 'LICENSE.txt')

$dist = Join-Path $repo 'dist'
New-Item -ItemType Directory -Force $dist | Out-Null
$zip = Join-Path $dist "$name.zip"
if (Test-Path $zip) { Remove-Item -Force $zip }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip
Remove-Item -Recurse -Force $stage
$lines | ForEach-Object { Show-Info $_.Trim() }
Show-Ok "package -> $zip"
