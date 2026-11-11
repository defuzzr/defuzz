add_library(tmpl_prefix_adapters STATIC
    src/memory_repo.cpp
)
add_library(tmpl_prefix::adapters ALIAS tmpl_prefix_adapters)

target_include_directories(tmpl_prefix_adapters
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(tmpl_prefix_adapters
    PUBLIC
        tmpl_prefix_foundation
        tmpl_prefix_domain
)
