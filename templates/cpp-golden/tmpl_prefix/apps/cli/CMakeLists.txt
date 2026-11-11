add_executable(tmpl_prefix_cli
    src/main.cpp
)

set_target_properties(tmpl_prefix_cli PROPERTIES
    OUTPUT_NAME "tmpl-prefix"
)

target_link_libraries(tmpl_prefix_cli
    PRIVATE
        tmpl_prefix_foundation
        tmpl_prefix_domain
        tmpl_prefix_adapters
)
