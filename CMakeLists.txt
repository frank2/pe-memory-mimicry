cmake_minimum_required(VERSION 3.15)

project(memory_mimicry C)
add_executable(memory_mimicry main.c)

add_subdirectory(binobj)
add_subdirectory(sheep_monitor)
add_dependencies(memory_mimicry binobj sheep_monitor)
add_custom_command(TARGET memory_mimicry
  PRE_BUILD
  COMMAND powershell -ExecutionPolicy bypass -File "${CMAKE_CURRENT_SOURCE_DIR}/filesize.ps1" -Filename "$<TARGET_FILE:sheep_monitor>" -Label SHEEP_MONITOR_SIZE -Output "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/sheep_monitor.h"
  VERBATIM)
add_custom_command(TARGET memory_mimicry
  PRE_BUILD
  COMMAND "$<TARGET_FILE:binobj>" SHEEP_MONITOR 1 "$<TARGET_FILE:sheep_monitor>" "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/sheep_monitor.obj"
  VERBATIM)

target_include_directories(memory_mimicry PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>")
target_link_libraries(memory_mimicry "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/sheep_monitor.obj")
