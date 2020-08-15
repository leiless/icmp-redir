cmake_minimum_required(VERSION 3.0)
project(icmp-redir)

set(CMAKE_CXX_STANDARD 17)

add_compile_options(-Wall -Wextra -g -DDEBUG -O0)
#add_compile_options(-Wall -Wextra -O2 -DASSERTF_DISABLE)

# TODO: Stringify CMAKE_CXX_FLAGS

execute_process(
        COMMAND git describe --dirty --always
        OUTPUT_VARIABLE BUILD_HEAD_COMMIT
        OUTPUT_STRIP_TRAILING_WHITESPACE
)
add_compile_definitions(BUILD_HEAD_COMMIT="${BUILD_HEAD_COMMIT}")

execute_process(
        COMMAND date "+%Y/%m/%d %H:%M:%S %z"
        OUTPUT_VARIABLE BUILD_TIMESTAMP
        OUTPUT_STRIP_TRAILING_WHITESPACE
)
add_compile_definitions(BUILD_TIMESTAMP="${BUILD_TIMESTAMP}")

execute_process(
        COMMAND whoami
        OUTPUT_VARIABLE BUILD_USER
        OUTPUT_STRIP_TRAILING_WHITESPACE
)
add_compile_definitions(BUILD_USER="${BUILD_USER}")

add_executable(
        ${PROJECT_NAME}
        src/threadpool.hpp
        src/compile.h
        src/assertf.h
        src/formatter.h
        src/net.h
        src/net.cpp
        src/main.cpp
        src/config.cpp
        src/config.h
        src/icmp.cpp
        src/icmp.h
        src/utils.h
        src/utils.cpp
)

# see: https://stackoverflow.com/questions/1620918/cmake-and-libpthread
find_package(Threads REQUIRED)
if (THREADS_HAVE_PTHREAD_ARG)
    target_compile_options(${PROJECT_NAME} PUBLIC "-pthread")
endif()
if (CMAKE_THREAD_LIBS_INIT)
    target_link_libraries(${PROJECT_NAME} "${CMAKE_THREAD_LIBS_INIT}")
endif()

