# Workspace automation runner (`cmake -P cmake/xtask.cmake -- <ci|fmt|fmt-check|layers|lint|test>`).

get_filename_component(WORKSPACE_ROOT "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)

set(SUBCOMMAND "ci")
math(EXPR LAST_ARG_IDX "${CMAKE_ARGC} - 1")
set(AFTER_DASH FALSE)
foreach(idx RANGE 0 ${LAST_ARG_IDX})
    set(arg_val "${CMAKE_ARGV${idx}}")
    if(AFTER_DASH)
        set(SUBCOMMAND "${arg_val}")
        break()
    endif()
    if("${arg_val}" STREQUAL "--")
        set(AFTER_DASH TRUE)
    endif()
endforeach()

function(read_locked_version tool_key out_var out_min_var)
    set(lock_path "${WORKSPACE_ROOT}/TOOLS.lock")
    if(NOT EXISTS "${lock_path}")
        message(FATAL_ERROR "Missing TOOLS.lock at ${lock_path}")
    endif()
    file(STRINGS "${lock_path}" lock_lines)
    set(in_section FALSE)
    set(found_ver "")
    set(found_min "")
    foreach(line IN LISTS lock_lines)
        string(STRIP "${line}" stripped)
        if("${stripped}" STREQUAL "[${tool_key}]")
            set(in_section TRUE)
        elseif("${stripped}" MATCHES "^\\[.*\\]$")
            set(in_section FALSE)
        elseif(in_section AND "${stripped}" MATCHES "^version[ \t]*=[ \t]*\"([^\"]+)\"")
            set(found_ver "${CMAKE_MATCH_1}")
        elseif(in_section AND "${stripped}" MATCHES "^minimum[ \t]*=[ \t]*\"([^\"]+)\"")
            set(found_min "${CMAKE_MATCH_1}")
        endif()
    endforeach()
    if(NOT found_ver)
        message(FATAL_ERROR "TOOLS.lock missing version pin for [${tool_key}]")
    endif()
    set(${out_var} "${found_ver}" PARENT_SCOPE)
    set(${out_min_var} "${found_min}" PARENT_SCOPE)
endfunction()

function(resolve_and_verify_tool out_var lock_key)
    unset(FOUND_TOOL CACHE)
    find_program(FOUND_TOOL NAMES ${ARGN} PATHS ENV PATH NO_DEFAULT_PATH)
    if(NOT FOUND_TOOL)
        message(FATAL_ERROR
            "Required tool '${lock_key}' not found on PATH (searched: ${ARGN})"
        )
    endif()
    set(tool_bin "${FOUND_TOOL}")
    unset(FOUND_TOOL CACHE)

    read_locked_version("${lock_key}" expected_ver minimum_ver)
    execute_process(
        COMMAND "${tool_bin}" --version
        WORKING_DIRECTORY "${WORKSPACE_ROOT}"
        RESULT_VARIABLE ver_rc
        OUTPUT_VARIABLE ver_out
        ERROR_VARIABLE ver_err
    )
    if(NOT ver_rc EQUAL 0)
        message(FATAL_ERROR
            "Failed to probe version of '${lock_key}' (${tool_bin} --version exited ${ver_rc})"
        )
    endif()
    string(REGEX MATCH "[0-9]+\\.[0-9]+(\\.[0-9]+)?" actual_ver "${ver_out}\n${ver_err}")
    if(minimum_ver)
        # TOOLS.lock states a floor: any version at or above it builds this workspace
        # (CI runners and other machines need not match the version seeded locally).
        if("${actual_ver}" VERSION_LESS "${minimum_ver}")
            message(FATAL_ERROR
                "Tool version too old for '${lock_key}' (${tool_bin}): need >= ${minimum_ver} from TOOLS.lock, found '${actual_ver}'"
            )
        endif()
    elseif(NOT "${actual_ver}" STREQUAL "${expected_ver}")
        message(FATAL_ERROR
            "Tool version mismatch for '${lock_key}' (${tool_bin}): expected ${expected_ver} from TOOLS.lock, found '${actual_ver}'"
        )
    endif()
    set(${out_var} "${tool_bin}" PARENT_SCOPE)
endfunction()

function(collect_cpp_files out_all out_tu)
    set(all_list "")
    set(tu_list "")
    foreach(dir_name IN ITEMS foundation domain adapters apps tests)
        file(GLOB_RECURSE dir_hdrs
            RELATIVE "${WORKSPACE_ROOT}"
            "${WORKSPACE_ROOT}/${dir_name}/*.hpp"
            "${WORKSPACE_ROOT}/${dir_name}/*.h"
        )
        file(GLOB_RECURSE dir_srcs
            RELATIVE "${WORKSPACE_ROOT}"
            "${WORKSPACE_ROOT}/${dir_name}/*.cpp"
        )
        list(APPEND all_list ${dir_hdrs} ${dir_srcs})
        list(APPEND tu_list ${dir_srcs})
    endforeach()
    list(SORT all_list)
    list(SORT tu_list)
    set(${out_all} "${all_list}" PARENT_SCOPE)
    set(${out_tu} "${tu_list}" PARENT_SCOPE)
endfunction()

function(run_checked)
    execute_process(
        COMMAND ${ARGN}
        WORKING_DIRECTORY "${WORKSPACE_ROOT}"
        RESULT_VARIABLE cmd_rc
    )
    if(NOT cmd_rc EQUAL 0)
        string(JOIN " " cmd_str ${ARGN})
        message(FATAL_ERROR "Command failed (exit ${cmd_rc}): ${cmd_str}")
    endif()
endfunction()

function(cmd_fmt_check)
    resolve_and_verify_tool(CLANG_FORMAT_BIN "clang-format" "clang-format")
    collect_cpp_files(ALL_CPP_FILES TU_CPP_FILES)
    if(NOT ALL_CPP_FILES)
        message(FATAL_ERROR "No C++ files found in workspace")
    endif()
    run_checked("${CLANG_FORMAT_BIN}" --dry-run -Werror ${ALL_CPP_FILES})
endfunction()

function(cmd_fmt)
    resolve_and_verify_tool(CLANG_FORMAT_BIN "clang-format" "clang-format")
    collect_cpp_files(ALL_CPP_FILES TU_CPP_FILES)
    run_checked("${CLANG_FORMAT_BIN}" -i ${ALL_CPP_FILES})
endfunction()

function(check_file_for_forbidden rel_file layer_name)
    file(READ "${WORKSPACE_ROOT}/${rel_file}" file_txt)
    foreach(forbidden_pat IN LISTS ARGN)
        string(REGEX MATCH "${forbidden_pat}" hit "${file_txt}")
        if(hit)
            message(FATAL_ERROR
                "layer violation in ${rel_file} (layer ${layer_name}): forbidden dependency '${hit}'"
            )
        endif()
    endforeach()
endfunction()

function(check_cmake_layer_links rel_file layer_name forbidden_dir_regex)
    file(READ "${WORKSPACE_ROOT}/${rel_file}" file_txt)
    string(REGEX REPLACE "#[^\r\n]*" "" clean_txt "${file_txt}")
    if(NOT "${forbidden_dir_regex}" STREQUAL "")
        string(REGEX MATCH "${forbidden_dir_regex}" dir_hit "${clean_txt}")
        if(dir_hit)
            message(FATAL_ERROR
                "layer violation in ${rel_file} (layer ${layer_name}): forbidden path dependency '${dir_hit}'"
            )
        endif()
    endif()
    string(REGEX MATCHALL "target_link_libraries[ \t\r\n]*\\([^)]*\\)" link_calls "${clean_txt}")
    foreach(call_txt IN LISTS link_calls)
        string(REGEX REPLACE "^target_link_libraries[ \t\r\n]*\\(" "" args_txt "${call_txt}")
        string(REGEX REPLACE "\\)$" "" args_txt "${args_txt}")
        string(REGEX REPLACE "[ \t\r\n;\"]+" ";" tokens "${args_txt}")
        set(is_first TRUE)
        foreach(tok IN LISTS tokens)
            if("${tok}" STREQUAL "")
                continue()
            endif()
            if(is_first)
                set(is_first FALSE)
                continue()
            endif()
            if("${tok}" MATCHES "^(PUBLIC|PRIVATE|INTERFACE|LINK_PUBLIC|LINK_PRIVATE)$")
                continue()
            endif()
            foreach(forbidden_target IN LISTS ARGN)
                if("${tok}" STREQUAL "${forbidden_target}")
                    message(FATAL_ERROR
                        "layer violation in ${rel_file} (layer ${layer_name}): forbidden dependency '${tok}'"
                    )
                endif()
            endforeach()
        endforeach()
    endforeach()
endfunction()

function(cmd_layers)
    check_cmake_layer_links("foundation/CMakeLists.txt" "foundation"
        "(^|[ \t\r\n\"/])(domain|adapters|apps)/"
        "tmpl_prefix_domain" "tmpl_prefix::domain" "domain"
        "tmpl_prefix_adapters" "tmpl_prefix::adapters" "adapters"
        "tmpl_prefix_cli" "tmpl_prefix::cli" "cli"
    )
    check_cmake_layer_links("domain/CMakeLists.txt" "domain"
        "(^|[ \t\r\n\"/])(adapters|apps)/"
        "tmpl_prefix_adapters" "tmpl_prefix::adapters" "adapters"
        "tmpl_prefix_cli" "tmpl_prefix::cli" "cli"
    )
    check_cmake_layer_links("adapters/CMakeLists.txt" "adapters"
        "(^|[ \t\r\n\"/])apps/"
        "tmpl_prefix_cli" "tmpl_prefix::cli" "cli"
    )

    file(GLOB_RECURSE foundation_files
        RELATIVE "${WORKSPACE_ROOT}"
        "${WORKSPACE_ROOT}/foundation/*.hpp"
        "${WORKSPACE_ROOT}/foundation/*.h"
        "${WORKSPACE_ROOT}/foundation/*.cpp"
    )
    foreach(f IN LISTS foundation_files)
        check_file_for_forbidden("${f}" "foundation"
            "#include[ \t]+[\"<](domain|adapters|apps)/"
        )
    endforeach()

    file(GLOB_RECURSE domain_files
        RELATIVE "${WORKSPACE_ROOT}"
        "${WORKSPACE_ROOT}/domain/*.hpp"
        "${WORKSPACE_ROOT}/domain/*.h"
        "${WORKSPACE_ROOT}/domain/*.cpp"
    )
    foreach(f IN LISTS domain_files)
        check_file_for_forbidden("${f}" "domain"
            "#include[ \t]+[\"<](adapters|apps)/"
        )
    endforeach()

    file(GLOB_RECURSE adapters_files
        RELATIVE "${WORKSPACE_ROOT}"
        "${WORKSPACE_ROOT}/adapters/*.hpp"
        "${WORKSPACE_ROOT}/adapters/*.h"
        "${WORKSPACE_ROOT}/adapters/*.cpp"
    )
    foreach(f IN LISTS adapters_files)
        check_file_for_forbidden("${f}" "adapters"
            "#include[ \t]+[\"<]apps/"
        )
    endforeach()

    message(STATUS "layer check passed (foundation < domain < adapters < apps)")
endfunction()

function(configure_workspace)
    resolve_and_verify_tool(CMAKE_BIN "cmake" "cmake")
    resolve_and_verify_tool(NINJA_BIN "ninja" "ninja" "ninja-build")
    resolve_and_verify_tool(CLANG_BIN "clang" "clang")
    resolve_and_verify_tool(CLANGXX_BIN "clang" "clang++")

    run_checked("${CMAKE_BIN}"
        -B build
        -G Ninja
        "-DCMAKE_MAKE_PROGRAM=${NINJA_BIN}"
        "-DCMAKE_CXX_COMPILER=${CLANGXX_BIN}"
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
    )
endfunction()

function(cmd_test)
    resolve_and_verify_tool(CMAKE_BIN "cmake" "cmake")
    resolve_and_verify_tool(CTEST_BIN "cmake" "ctest")
    configure_workspace()
    run_checked("${CMAKE_BIN}" --build build)
    run_checked("${CTEST_BIN}" --test-dir build --output-on-failure)
endfunction()

function(cmd_lint)
    resolve_and_verify_tool(CLANG_TIDY_BIN "clang-tidy" "clang-tidy")
    run_checked("${CLANG_TIDY_BIN}" --verify-config "--config-file=${WORKSPACE_ROOT}/.clang-tidy")
    if(NOT EXISTS "${WORKSPACE_ROOT}/build/compile_commands.json")
        configure_workspace()
    endif()
    collect_cpp_files(ALL_CPP_FILES TU_CPP_FILES)
    run_checked("${CLANG_TIDY_BIN}" --quiet -p "${WORKSPACE_ROOT}/build" ${TU_CPP_FILES})
endfunction()

if("${SUBCOMMAND}" STREQUAL "ci")
    cmd_fmt_check()
    cmd_layers()
    cmd_test()
    cmd_lint()
elseif("${SUBCOMMAND}" STREQUAL "fmt")
    cmd_fmt()
elseif("${SUBCOMMAND}" STREQUAL "fmt-check")
    cmd_fmt_check()
elseif("${SUBCOMMAND}" STREQUAL "layers")
    cmd_layers()
elseif("${SUBCOMMAND}" STREQUAL "test")
    cmd_test()
elseif("${SUBCOMMAND}" STREQUAL "lint")
    cmd_lint()
else()
    message(FATAL_ERROR
        "Unknown xtask subcommand '${SUBCOMMAND}' (expected: ci, fmt, fmt-check, layers, lint, or test)"
    )
endif()
