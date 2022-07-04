cmake_minimum_required(VERSION 3.16)
project(Project)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "-march=native")

add_executable(Project main.cpp aes_lib.h ecb_main.cpp)
