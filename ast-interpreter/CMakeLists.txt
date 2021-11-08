cmake_minimum_required(VERSION 3.1.0)
project(assign1)

find_package(Clang REQUIRED CONFIG HINTS ${LLVM_DIR} ${LLVM_DIR}/lib/cmake/clang NO_DEFAULT_PATH)

include_directories(${LLVM_INCLUDE_DIRS} ${CLANG_INCLUDE_DIRS} SYSTEM)
link_directories(${LLVM_LIBRARY_DIRS})

file(GLOB SOURCE "./*.cpp")

add_executable(ast-interpreter ${SOURCE})

set(LLVM_LINK_COMPONENTS
        ${LLVM_TARGETS_TO_BUILD}
        Option
        Support
        )

# https://stackoverflow.com/questions/10851247/how-do-i-activate-c-11-in-cmake
set(
        CMAKE_CXX_FLAGS
        "-std=c++14 ${CMAKE_CXX_FLAGS} -g -fno-exceptions -fno-rtti"
        )

target_link_libraries(ast-interpreter
        clangAST
        clangBasic
        clangFrontend
        clangTooling
        )

install(TARGETS ast-interpreter
        RUNTIME DESTINATION bin)
