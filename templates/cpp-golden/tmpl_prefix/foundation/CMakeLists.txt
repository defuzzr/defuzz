add_library(tmpl_prefix_foundation STATIC
    src/error.cpp
)
add_library(tmpl_prefix::foundation ALIAS tmpl_prefix_foundation)

target_include_directories(tmpl_prefix_foundation
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
