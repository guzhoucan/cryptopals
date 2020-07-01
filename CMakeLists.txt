cmake_minimum_required(VERSION 3.16)
project(cryptopals)

set(CMAKE_CXX_STANDARD 14)

add_subdirectory(lib/abseil-cpp)
add_subdirectory(lib/googletest)
add_subdirectory(set1)
