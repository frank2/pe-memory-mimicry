cmake_minimum_required(VERSION 3.15)

project(sheep_monitor CXX)
# the CMake way to set /MT and /MTd
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# remove runtime checks from the build flags
string(REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
string(REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")

add_executable(sheep_monitor WIN32 main.cpp)
target_compile_options(sheep_monitor PRIVATE "/GS-")
