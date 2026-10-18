find_package(Catch2 3 CONFIG REQUIRED)

add_executable(daoaddr_tests test_library.cpp test_codeindex.cpp)
daoaddr_apply_warnings(daoaddr_tests)
target_link_libraries(daoaddr_tests PRIVATE daoaddr Catch2::Catch2WithMain)
# The files the build packed from the table: the tests read them back.
target_compile_definitions(
    daoaddr_tests
    PRIVATE DAOADDR_DATA_DIR="${DAOADDR_DATA_DIR}"
)
add_dependencies(daoaddr_tests daoaddr_data)

include(Catch)
catch_discover_tests(daoaddr_tests)

# The Python tools' own tests (tools/test_*.py), and the table's soundness.
add_test(
    NAME python_tools
    COMMAND
        "${Python3_EXECUTABLE}" -m unittest discover -s
        "${PROJECT_SOURCE_DIR}/tools" -p "test_*.py"
)
add_test(
    NAME table
    COMMAND
        "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tools/addrlib.py" check
)
# The subsystems file: every ID in it a function of the table, every rule whole.
add_test(
    NAME subsystems
    COMMAND
        "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tools/subsystems.py"
        --check
)
# An ID's promise: nothing the last commit's table says has changed. Run
# before a change to the table is committed; it passes where there is no
# history to ask (a copy that is not a git checkout).
add_test(
    NAME table_ids_kept
    COMMAND
        "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tools/addrlib.py" kept
)
