<#
.SYNOPSIS
    Cut a release: tag the version, and put the zip of address files on a GitHub release.

.DESCRIPTION
    SkyrimFollowerTactics' tools\release.ps1, for this repository (dev/RELEASING.md):

        .\tools\release.ps1 none       the version CMakeLists.txt already names
        .\tools\release.ps1 patch      0.1.0 -> 0.1.1
        .\tools\release.ps1 minor      0.1.0 -> 0.2.0
        .\tools\release.ps1 major      0.1.0 -> 1.0.0
        .\tools\release.ps1 none -DryRun     say what it would do, change nothing

    A tag is git's: a name for one commit, pushed like a branch. A release is GitHub's,
    on top of a tag: a title, notes and uploaded files. The tag is what a repository
    that holds this as a submodule is held at; the release carries the zip a player
    extracts into the game (tools\package.ps1).

    The version is in one place, project(DAOAddressLibrary VERSION ...) in
    CMakeLists.txt, and the notes are that version's section of CHANGELOG.md, so the
    release page says what the repository says.

    What can fail without leaving a mark goes first: the tests and the zip come before
    the commit and the tag, and nothing is pushed until the zip exists. The tests are
    the debug preset's, which hold the table to its promise (check, kept) and read the
    packed files back. The formatters and linters are not run here: they belong to the
    commits that got to master.

.PARAMETER Draft
    Make the release a draft: on GitHub with its file, unseen until published by hand.

.PARAMETER DryRun
    Say what would happen. Builds nothing, writes nothing, pushes nothing.

.PARAMETER Force
    Skip the clean-tree and ancestry checks. Not the master check: nothing is released
    off another branch.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateSet('major', 'minor', 'patch', 'none')]
    [string] $Bump,
    [switch] $Draft,
    [switch] $DryRun,
    [switch] $Force
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'console.ps1')
$repo = Split-Path -Parent $PSScriptRoot

# --- where this would go ----------------------------------------------------

$remote = (git -C $repo remote get-url origin).Trim()
# The remote is an SSH host alias (git@github.com-someone:Owner/Repo.git),
# which gh does not read as a GitHub remote, so every gh call names the
# repository.
if ($remote -notmatch '[:/]([^:/]+/[^/]+?)(\.git)?$') { throw "Cannot read an owner/repo out of the origin remote: $remote" }
$github = $Matches[1]

# --- checks -----------------------------------------------------------------

$branch = (git -C $repo rev-parse --abbrev-ref HEAD).Trim()
if ($branch -ne 'master') { throw "On branch '$branch'. A release is cut from master." }

if (-not $Force) {
    # Tracked changes only: dist\ and build\ are ignored and no reason to refuse.
    $dirty = git -C $repo status --porcelain --untracked-files=no
    if ($dirty) { throw "The working tree has changes:`n$($dirty -join "`n")" }

    git -C $repo fetch --quiet origin
    if ($LASTEXITCODE -ne 0) { throw 'Could not fetch origin; cannot verify master before release.' }
    $upstream = (git -C $repo rev-parse origin/master).Trim()
    git -C $repo merge-base --is-ancestor $upstream HEAD
    if ($LASTEXITCODE -ne 0) { throw 'origin/master is not an ancestor of master. Fetch and merge first (or pass -Force).' }
}

# A dry run reports a missing gh as a warning and goes on, so one run says
# everything that is not ready.
$ghProblem = $null
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    $ghProblem = 'The GitHub CLI (gh) is not installed: https://cli.github.com'
}
else {
    gh auth status *> $null
    if ($LASTEXITCODE -ne 0) { $ghProblem = 'gh is not logged in. Run: gh auth login' }
}
if ($ghProblem) {
    if (-not $DryRun) { throw $ghProblem }
    Show-Warn $ghProblem
}

# --- the version ------------------------------------------------------------

$cmake = Join-Path $repo 'CMakeLists.txt'
$text = Get-Content $cmake -Raw
if ($text -notmatch 'project\((\w+) VERSION (\d+)\.(\d+)\.(\d+)') { throw 'No project(<name> VERSION x.y.z) in CMakeLists.txt' }
$name = $Matches[1]
[int] $major, [int] $minor, [int] $patch = $Matches[2], $Matches[3], $Matches[4]
$from = "$major.$minor.$patch"
switch ($Bump) {
    'major' { $major++; $minor = 0; $patch = 0 }
    'minor' { $minor++; $patch = 0 }
    'patch' { $patch++ }
    'none' { }
}
$version = "$major.$minor.$patch"
$tag = "v$version"

if (git -C $repo tag --list $tag) { throw "Tag $tag already exists here." }
git -C $repo ls-remote --exit-code --tags origin "refs/tags/$tag" *> $null
if ($LASTEXITCODE -eq 0) { throw "Tag $tag already exists on origin." }
if ($LASTEXITCODE -ne 2) { throw "Could not check whether tag $tag exists on origin." }

$notesMatch = [regex]::Match((Get-Content (Join-Path $repo 'CHANGELOG.md') -Raw),
    "(?ms)^## $([regex]::Escape($version))\s*\r?\n(?<notes>.*?)(?=^## |\z)")
if (-not $notesMatch.Success -or -not $notesMatch.Groups['notes'].Value.Trim()) {
    throw "CHANGELOG.md needs a nonempty ## $version section before release."
}
$notes = $notesMatch.Groups['notes'].Value.Trim()
$notesFile = Join-Path $repo "build\release-notes-$version.md"
$zip = Join-Path $repo "dist\$name-$version.zip"

# Below 1.0 is GitHub's prerelease, as SkyrimFollowerTactics' releases are.
$prerelease = $major -eq 0

Show-Line "release $github  $from -> $version  (tag $tag)" -Colour Cyan
if ($prerelease) { Show-Info 'marked prerelease (0.x)' }
if ($Draft) { Show-Info 'draft: published by hand' }

if ($DryRun) {
    Show-Line "`n-DryRun, so this is where it stops. It would:" -Colour Yellow
    $steps = @()
    if ($Bump -ne 'none') { $steps += "set $name VERSION to $version in CMakeLists.txt" }
    $steps += @('run the debug preset''s tests', "run tools\package.ps1 -> $zip")
    if ($Bump -ne 'none') { $steps += "commit CMakeLists.txt as `"$name $version`"" }
    $steps += @("tag $tag, push master and the tag",
        "gh release create $tag on $github, CHANGELOG.md's $version section its notes, the zip attached")
    $steps | ForEach-Object { Show-Info "- $_" }
    # Not return: ls-remote's 2, its "no such tag", would be left as the
    # script's exit code, and a dry run that found nothing wrong read as failed.
    exit 0
}

# --- bump, then prove it builds --------------------------------------------

if ($Bump -ne 'none') {
    $bumped = $text -replace "project\($name VERSION $([regex]::Escape($from))", "project($name VERSION $version"
    if ($bumped -eq $text) { throw 'The version line did not change: CMakeLists.txt is not what was read.' }
    Set-Content -Path $cmake -Value $bumped -NoNewline
}

try {
    & (Join-Path $PSScriptRoot 'build.ps1') -Preset debug -Test
    & (Join-Path $PSScriptRoot 'package.ps1')
    if (-not (Test-Path $zip)) { throw "Packaging did not write $zip." }
}
catch {
    Show-Bad 'failed before anything was committed or tagged. To undo a bump: git checkout CMakeLists.txt'
    throw
}

# --- commit, tag, push, release --------------------------------------------

if ($Bump -ne 'none') {
    git -C $repo add $cmake
    if ($LASTEXITCODE -ne 0) { throw 'Could not stage the version bump.' }
    git -C $repo commit --quiet -m "$name $version"
    if ($LASTEXITCODE -ne 0) { throw 'Could not commit the version bump.' }
}
New-Item -ItemType Directory -Force (Split-Path -Parent $notesFile) | Out-Null
[IO.File]::WriteAllText($notesFile, "$notes`n", [Text.UTF8Encoding]::new($false))
git -C $repo tag -a $tag -m "$name $version"
if ($LASTEXITCODE -ne 0) { throw "Could not create tag $tag." }
git -C $repo push --quiet origin HEAD
if ($LASTEXITCODE -ne 0) { throw "Could not push master; tag $tag exists here and nothing was published." }
git -C $repo push --quiet origin $tag
if ($LASTEXITCODE -ne 0) { throw "Master was pushed, but tag $tag was not; push the tag before creating the release." }

$arguments = @('release', 'create', $tag, '--repo', $github, '--title', "$name $version",
    '--notes-file', $notesFile, '--verify-tag')
if ($prerelease) { $arguments += '--prerelease' }
if ($Draft) { $arguments += '--draft' }
$arguments += $zip

gh @arguments
if ($LASTEXITCODE -ne 0) {
    throw "The tag and the push went through; gh release create did not. Run it alone, with --notes-file $notesFile and $zip (dev/RELEASING.md)."
}

Show-Ok "released $name $version"
Show-Info "https://github.com/$github/releases/tag/$tag"
