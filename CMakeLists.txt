cmake_minimum_required(VERSION 3.0)
project(icmp-redir)

set(CMAKE_CXX_STANDARD 20)

add_compile_options(-Wall -Wextra -g -DDEBUG -O0)

# TODO: Add branch name, build date, cxx flags
execute_process(
        COMMAND git describe --dirty --always
        OUTPUT_VARIABLE HEAD_COMMIT
        OUTPUT_STRIP_TRAILING_WHITESPACE
)
add_compile_definitions(HEAD_COMMIT="${HEAD_COMMIT}")

add_executable(
        ${PROJECT_NAME}
        src/main.cpp
        src/config.cpp
        src/config.h
        src/client.cpp
        src/client.h
)
