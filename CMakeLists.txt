cmake_minimum_required(VERSION 3.21)

project(DAOAddressLibrary VERSION 0.4.0 LANGUAGES CXX)

# Two things are built here. daoaddr is the reader a program compiles in:
# it loads one build's file and answers "where is this ID". The files are
# the other: data/addresses.csv packed into one per build of the game
# (tools/addrlib.py pack), which a program reads at run time, so a new
# build of the game is a new file and nothing rebuilt.
#
# DAOAddressLibrary is built on its own, or inside a repository that brings
# it in with add_subdirectory (DAOLib does). Inside another it gives the
# reader and the files and leaves its tests and quality targets out.
option(
    DAOADDR_BUILD_TESTS
    "Build the unit tests (no game required)"
    ${PROJECT_IS_TOP_LEVEL}
)
option(DAOADDR_SANITIZE "Build with AddressSanitizer" OFF)
# The debug-analyze preset; its own build tree, as clang-tidy reads the
# debug tree's compile database and clang rejects /analyze.
option(DAOADDR_ANALYZE "MSVC static analysis (/analyze) on our own targets" OFF)
# Where the files go: a folder that is a game folder's worth of files when
# this is built with a loader, which looks for them beside itself.
set(DAOADDR_DATA_DIR
    "${CMAKE_BINARY_DIR}/daolib/addresses"
    CACHE PATH
    "Where the per-build runtime files are written"
)

function(daoaddr_apply_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX /permissive- /utf-8)
        if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
            target_compile_options(${target} PRIVATE /Zc:preprocessor)
            target_compile_options(
                ${target}
                PRIVATE /external:anglebrackets /external:W0
            )
        endif()
        if(DAOADDR_ANALYZE AND CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
            target_compile_options(
                ${target}
                PRIVATE /analyze /analyze:external-
            )
        endif()
    else()
        target_compile_options(
            ${target}
            PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion
        )
    endif()
    target_compile_features(${target} PRIVATE cxx_std_20)
endfunction()

# AddressSanitizer has to cover every translation unit, so it is global and
# set before any target; only the top-level build asks for it.
if(DAOADDR_SANITIZE AND PROJECT_IS_TOP_LEVEL)
    if(MSVC)
        add_compile_options(/fsanitize=address /Oy-)
        # vcpkg's Catch2 is built without ASan, so the STL's container
        # annotations, on under /fsanitize=address, would differ between it
        # and us; Microsoft's advice for linking such libraries is to turn
        # them off.
        add_compile_definitions(
            _DISABLE_STRING_ANNOTATION
            _DISABLE_VECTOR_ANNOTATION
        )
        add_link_options(/INCREMENTAL:NO)
        string(
            REPLACE "/RTC1"
            ""
            CMAKE_CXX_FLAGS_DEBUG
            "${CMAKE_CXX_FLAGS_DEBUG}"
        )
    else()
        add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address)
    endif()
endif()

if(PROJECT_IS_TOP_LEVEL)
    list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
    include(Quality)
endif()

# ---------------------------------------------------------------------------
# daoaddr -- the reader. No dependency beyond the standard library, and no
# <Windows.h>: bytes in, answers out, which is what tests/ covers.
# ---------------------------------------------------------------------------
add_library(daoaddr STATIC src/daoaddr/Library.cpp src/daoaddr/CodeIndex.cpp)
daoaddr_apply_warnings(daoaddr)
target_compile_features(daoaddr PUBLIC cxx_std_20)
target_include_directories(daoaddr PUBLIC "${PROJECT_SOURCE_DIR}/src")
add_library(DAOAddressLibrary::daoaddr ALIAS daoaddr)

# ---------------------------------------------------------------------------
# The runtime files, one per build of the game, from the table.
# ---------------------------------------------------------------------------
find_package(Python3 COMPONENTS Interpreter REQUIRED)
set(DAOADDR_DATA_STAMP "${CMAKE_CURRENT_BINARY_DIR}/daoaddr_data.stamp")
add_custom_command(
    OUTPUT "${DAOADDR_DATA_STAMP}"
    COMMAND
        "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tools/addrlib.py" pack
        "${DAOADDR_DATA_DIR}"
    COMMAND "${CMAKE_COMMAND}" -E touch "${DAOADDR_DATA_STAMP}"
    DEPENDS
        "${PROJECT_SOURCE_DIR}/tools/addrlib.py"
        "${PROJECT_SOURCE_DIR}/data/addresses.csv"
        "${PROJECT_SOURCE_DIR}/data/builds.csv"
        "${PROJECT_SOURCE_DIR}/data/notes.csv"
    COMMENT "Packing data/addresses.csv into a file per build"
    VERBATIM
)
add_custom_target(daoaddr_data ALL DEPENDS "${DAOADDR_DATA_STAMP}")

if(DAOADDR_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
