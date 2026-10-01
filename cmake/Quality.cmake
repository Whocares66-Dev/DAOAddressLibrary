# The format and lint targets, over every language of ours in the repository:
#
#   cmake --build --preset debug --target format         rewrite files in place
#   cmake --build --preset debug --target format-check    fail if anything is unformatted
#   cmake --build --preset debug --target tidy            static analysis
#
#   C++         clang-format, clang-tidy
#   Python      ruff format, ruff check
#   PowerShell  PSScriptAnalyzer's Invoke-Formatter and Invoke-ScriptAnalyzer
#   CMake       gersemi, a formatter only
#
# Each formatter runs its stock style, and each linter the checks that find
# bugs and costs, nothing stylistic: .clang-format, .clang-tidy, ruff.toml and
# .gersemirc say which; PSScriptAnalyzer runs its defaults.
#
# clang-format and clang-tidy are LLVM's own release, 22 or later
# (`winget install LLVM.LLVM`, into Program Files\LLVM, or where LLVM_ROOT
# says), not the older one Visual Studio bundles, which is searched nowhere:
# clang-tidy 22 walks none of a system header's declarations, which is most
# of a file's cost. ruff and gersemi are `pip install --user`, and
# PSScriptAnalyzer `Install-Module PSScriptAnalyzer -Scope CurrentUser`. A
# tool that is missing is said at configure time, and its language skipped.

set(_llvm_hints "$ENV{LLVM_ROOT}/bin" "$ENV{ProgramFiles}/LLVM/bin")

find_program(
    DAOADDR_CLANG_FORMAT
    NAMES clang-format
    HINTS ${_llvm_hints}
    NO_DEFAULT_PATH
)
find_program(
    DAOADDR_CLANG_TIDY
    NAMES clang-tidy
    HINTS ${_llvm_hints}
    NO_DEFAULT_PATH
)

# ruff by `python -m`: pip's --user install puts ruff.exe in a Scripts folder
# that is not on PATH, so find_program would miss it.
set(DAOADDR_RUFF "")
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
    execute_process(
        COMMAND "${Python3_EXECUTABLE}" -m ruff --version
        RESULT_VARIABLE _ruff_result
        OUTPUT_VARIABLE _ruff_version
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(_ruff_result EQUAL 0)
        set(DAOADDR_RUFF "${Python3_EXECUTABLE}" -m ruff)
        message(STATUS "ruff: ${_ruff_version} (${Python3_EXECUTABLE})")
    endif()
endif()
if(NOT DAOADDR_RUFF)
    message(
        STATUS
        "ruff: NOT FOUND -- Python is not formatted or linted; pip install --user ruff"
    )
endif()

# gersemi the same way. It walks into build/ if given a folder, so it is
# given git's list instead.
set(DAOADDR_GERSEMI "")
if(Python3_Interpreter_FOUND)
    execute_process(
        COMMAND "${Python3_EXECUTABLE}" -m gersemi --version
        RESULT_VARIABLE _gersemi_result
        OUTPUT_VARIABLE _gersemi_version
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(_gersemi_result EQUAL 0)
        set(DAOADDR_GERSEMI "${Python3_EXECUTABLE}" -m gersemi)
        message(STATUS "gersemi: ${_gersemi_version}")
    endif()
endif()
if(DAOADDR_GERSEMI)
    execute_process(
        COMMAND
            git ls-files --cached --others --exclude-standard -- "*.cmake"
            "*CMakeLists.txt"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        RESULT_VARIABLE _git_result
        OUTPUT_VARIABLE DAOADDR_CMAKE_FILES
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(NOT _git_result EQUAL 0 OR NOT DAOADDR_CMAKE_FILES)
        message(
            STATUS
            "gersemi: no CMake files from git -- CMake is not formatted"
        )
        set(DAOADDR_GERSEMI "")
    else()
        string(REPLACE "\n" ";" DAOADDR_CMAKE_FILES "${DAOADDR_CMAKE_FILES}")
    endif()
else()
    message(
        STATUS
        "gersemi: NOT FOUND -- CMake is not formatted; pip install --user gersemi"
    )
endif()
unset(_gersemi_result)
unset(_gersemi_version)
unset(_git_result)

set(DAOADDR_PSCHECK "")
find_program(DAOADDR_PWSH NAMES pwsh)
if(DAOADDR_PWSH)
    execute_process(
        COMMAND
            "${DAOADDR_PWSH}" -NoProfile -NonInteractive -Command
            "if (-not (Get-Module -ListAvailable PSScriptAnalyzer)) { exit 1 }"
        RESULT_VARIABLE _pssa_result
        OUTPUT_QUIET
        ERROR_QUIET
    )
    if(_pssa_result EQUAL 0)
        set(DAOADDR_PSCHECK
            "${DAOADDR_PWSH}"
            -NoProfile
            -NonInteractive
            -File
            "${CMAKE_SOURCE_DIR}/tools/check-powershell.ps1"
        )
        message(STATUS "PSScriptAnalyzer: found (${DAOADDR_PWSH})")
    endif()
endif()
if(NOT DAOADDR_PSCHECK)
    message(
        STATUS
        "PSScriptAnalyzer: NOT FOUND -- PowerShell is not formatted or linted; "
        "Install-Module PSScriptAnalyzer -Scope CurrentUser, under pwsh 7"
    )
endif()
unset(_ruff_result)
unset(_ruff_version)
unset(_pssa_result)

# Our own sources only. Never glob the build tree: it holds vcpkg headers,
# and reformatting those would be both wrong and enormous.
file(
    GLOB_RECURSE DAOADDR_SOURCES
    CONFIGURE_DEPENDS
    "${CMAKE_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_SOURCE_DIR}/src/*.h"
    "${CMAKE_SOURCE_DIR}/tests/*.cpp"
    "${CMAKE_SOURCE_DIR}/tests/*.h"
    "${CMAKE_SOURCE_DIR}/examples/*.cpp"
    "${CMAKE_SOURCE_DIR}/examples/*.h"
)

set(DAOADDR_FORMAT_COMMANDS "")
set(DAOADDR_FORMAT_CHECK_COMMANDS "")
if(DAOADDR_CLANG_FORMAT)
    message(STATUS "clang-format: ${DAOADDR_CLANG_FORMAT}")
    list(
        APPEND DAOADDR_FORMAT_COMMANDS
        COMMAND
        "${DAOADDR_CLANG_FORMAT}"
        -i
        --style=file
        ${DAOADDR_SOURCES}
    )
    # -Werror turns "would reformat" into a non-zero exit, which is what makes
    # this usable as a gate rather than a report.
    list(
        APPEND DAOADDR_FORMAT_CHECK_COMMANDS
        COMMAND
        "${DAOADDR_CLANG_FORMAT}"
        --dry-run
        -Werror
        --style=file
        ${DAOADDR_SOURCES}
    )
else()
    message(STATUS "clang-format: NOT FOUND -- C++ is not formatted")
endif()
if(DAOADDR_RUFF)
    list(APPEND DAOADDR_FORMAT_COMMANDS COMMAND ${DAOADDR_RUFF} format --quiet)
    list(
        APPEND DAOADDR_FORMAT_CHECK_COMMANDS
        COMMAND
        ${DAOADDR_RUFF}
        format
        --check
    )
endif()
if(DAOADDR_GERSEMI)
    list(
        APPEND DAOADDR_FORMAT_COMMANDS
        COMMAND
        ${DAOADDR_GERSEMI}
        --in-place
        --quiet
        ${DAOADDR_CMAKE_FILES}
    )
    list(
        APPEND DAOADDR_FORMAT_CHECK_COMMANDS
        COMMAND
        ${DAOADDR_GERSEMI}
        --check
        ${DAOADDR_CMAKE_FILES}
    )
endif()
if(DAOADDR_PSCHECK)
    list(APPEND DAOADDR_FORMAT_COMMANDS COMMAND ${DAOADDR_PSCHECK} -Mode Format)
    list(
        APPEND DAOADDR_FORMAT_CHECK_COMMANDS
        COMMAND
        ${DAOADDR_PSCHECK}
        -Mode
        FormatCheck
    )
endif()
if(DAOADDR_FORMAT_COMMANDS)
    add_custom_target(
        format
        ${DAOADDR_FORMAT_COMMANDS}
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        COMMENT "Formatting C++, Python, PowerShell and CMake"
        VERBATIM
    )
    add_custom_target(
        format-check
        ${DAOADDR_FORMAT_CHECK_COMMANDS}
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        COMMENT "Checking the formatting of C++, Python, PowerShell and CMake"
        VERBATIM
    )
endif()

if(DAOADDR_CLANG_TIDY)
    message(STATUS "clang-tidy: ${DAOADDR_CLANG_TIDY}")

    # One custom command per file, not one command over all of them: the
    # files run in parallel across cores, and a stamp per file means an
    # unchanged file is not checked again. The stamps deliberately do NOT
    # depend on the compile database, which is rewritten on every configure.
    # Delete build/<preset>/tidy to force a full pass.
    file(
        GLOB_RECURSE DAOADDR_TIDY_SOURCES
        CONFIGURE_DEPENDS
        "${CMAKE_SOURCE_DIR}/src/*.cpp"
    )
    if(DAOADDR_BUILD_TESTS)
        file(
            GLOB_RECURSE DAOADDR_TIDY_TESTS
            CONFIGURE_DEPENDS
            "${CMAKE_SOURCE_DIR}/tests/*.cpp"
        )
        list(APPEND DAOADDR_TIDY_SOURCES ${DAOADDR_TIDY_TESTS})
    endif()
    if(DAOADDR_BUILD_EXAMPLES)
        file(
            GLOB_RECURSE DAOADDR_TIDY_EXAMPLES
            CONFIGURE_DEPENDS
            "${CMAKE_SOURCE_DIR}/examples/*.cpp"
        )
        list(APPEND DAOADDR_TIDY_SOURCES ${DAOADDR_TIDY_EXAMPLES})
    endif()
    file(
        GLOB_RECURSE DAOADDR_TIDY_HEADERS
        CONFIGURE_DEPENDS
        "${CMAKE_SOURCE_DIR}/src/*.h"
        "${CMAKE_SOURCE_DIR}/tests/*.h"
        "${CMAKE_SOURCE_DIR}/examples/*.h"
    )

    # Reports from any header under this tree's src/, tests/ or examples/, by absolute
    # path, so a vendored library's src/ never matches. clang-tidy prints
    # mixed separators (src\dao/Log.h), hence either slash.
    set(DAOADDR_TIDY_HEADER_FILTER "${CMAKE_SOURCE_DIR}")
    foreach(
        _c
        .
        +
        *
        ?
        ^
        $
        "("
        ")"
        "|"
        "{"
        "}"
        "["
    )
        string(
            REPLACE "${_c}"
            "\\${_c}"
            DAOADDR_TIDY_HEADER_FILTER
            "${DAOADDR_TIDY_HEADER_FILTER}"
        )
    endforeach()
    string(APPEND DAOADDR_TIDY_HEADER_FILTER "/(src|tests|examples)/")
    string(
        REPLACE "/"
        "[/\\]"
        DAOADDR_TIDY_HEADER_FILTER
        "${DAOADDR_TIDY_HEADER_FILTER}"
    )
    unset(_c)

    set(DAOADDR_TIDY_STAMPS "")
    file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/tidy")
    foreach(_src IN LISTS DAOADDR_TIDY_SOURCES)
        file(RELATIVE_PATH _rel "${CMAKE_SOURCE_DIR}" "${_src}")
        string(REPLACE "/" "_" _stampname "${_rel}")
        set(_stamp "${CMAKE_BINARY_DIR}/tidy/${_stampname}.stamp")
        # The compile database is MSVC's; clang takes /Zc:preprocessor and
        # /external:anglebrackets without using them, and under
        # WarningsAsErrors that note would fail every file. And it is a
        # 32-bit build: cl.exe's command line does not say so (the x86
        # cl.exe is the whole of it), so clang would assume the host's
        # x86_64, which is not what the library is built for; the target is
        # named outright.
        add_custom_command(
            OUTPUT "${_stamp}"
            COMMAND
                "${DAOADDR_CLANG_TIDY}" -p "${CMAKE_BINARY_DIR}"
                "--header-filter=${DAOADDR_TIDY_HEADER_FILTER}"
                --extra-arg=--target=i386-pc-windows-msvc
                --extra-arg=-Wno-unused-command-line-argument "${_src}"
            COMMAND "${CMAKE_COMMAND}" -E touch "${_stamp}"
            DEPENDS
                "${_src}"
                ${DAOADDR_TIDY_HEADERS}
                "${CMAKE_SOURCE_DIR}/.clang-tidy"
                "${CMAKE_SOURCE_DIR}/tests/.clang-tidy"
            COMMENT "clang-tidy ${_rel}"
            VERBATIM
        )
        list(APPEND DAOADDR_TIDY_STAMPS "${_stamp}")
    endforeach()
    unset(_src)
    unset(_rel)
    unset(_stampname)
    unset(_stamp)
else()
    set(DAOADDR_TIDY_STAMPS "")
    message(STATUS "clang-tidy: NOT FOUND -- C++ is not linted")
endif()

# ruff check runs every time: it takes well under a second. PSScriptAnalyzer
# takes seconds to load, so its script keeps a stamp and returns at once while
# no script has changed.
set(DAOADDR_LINT_COMMANDS "")
if(DAOADDR_RUFF)
    list(APPEND DAOADDR_LINT_COMMANDS COMMAND ${DAOADDR_RUFF} check --quiet)
endif()
if(DAOADDR_PSCHECK)
    list(
        APPEND DAOADDR_LINT_COMMANDS
        COMMAND
        ${DAOADDR_PSCHECK}
        -Mode
        Lint
        -Stamp
        "${CMAKE_BINARY_DIR}/tidy/powershell.stamp"
    )
endif()
if(DAOADDR_TIDY_STAMPS OR DAOADDR_LINT_COMMANDS)
    file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/tidy")
    add_custom_target(
        tidy
        ${DAOADDR_LINT_COMMANDS}
        DEPENDS ${DAOADDR_TIDY_STAMPS}
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        VERBATIM
    )
endif()

unset(_llvm_hints)
