add_library(tmpl_prefix_domain STATIC
    src/service.cpp
)
add_library(tmpl_prefix::domain ALIAS tmpl_prefix_domain)

target_include_directories(tmpl_prefix_domain
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(tmpl_prefix_domain
    PUBLIC
        tmpl_prefix_foundation
)
