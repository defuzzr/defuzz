add_executable(tmpl_prefix_tests
    workspace_test.cpp
)

target_link_libraries(tmpl_prefix_tests
    PRIVATE
        tmpl_prefix_foundation
        tmpl_prefix_domain
        tmpl_prefix_adapters
)

add_test(NAME tmpl_prefix_tests COMMAND tmpl_prefix_tests)
add_test(NAME tmpl_prefix_cli_smoke COMMAND tmpl_prefix_cli)
