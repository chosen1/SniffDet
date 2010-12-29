cmake_minimum_required (VERSION 2.6)

project (sniffdet)

set(sniffdet_VERSION_MAJOR 0)
set(sniffdet_VERSION_MINOR 9svn)

configure_file (
  "config.h.in"
  "${CMAKE_BINARY_DIR}/config.h"
)

include_directories("${CMAKE_BINARY_DIR}")

add_subdirectory(src)
