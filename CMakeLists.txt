cmake_minimum_required(VERSION 3.16)
project(OCB_AES_128 C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "-march=native")
add_executable(OCB_AES_128 main.c)
