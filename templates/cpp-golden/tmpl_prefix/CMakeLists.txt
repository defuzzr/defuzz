cmake_minimum_required(VERSION 3.20...3.28)
project(tmpl_prefix VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_options(-Wall -Wextra -Wpedantic -Werror)

enable_testing()

add_subdirectory(foundation)
add_subdirectory(domain)
add_subdirectory(adapters)
add_subdirectory(apps/cli)
add_subdirectory(tests)
