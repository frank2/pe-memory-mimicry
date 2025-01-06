cmake_minimum_required(VERSION 3.15)

project(binobj C)
add_executable(binobj binobj.c)
# target_compile_options(binobj PUBLIC /O2 /GS- /D NDEBUG /W3 /D _CRT_SECURE_NO_WARNINGS /nologo)
