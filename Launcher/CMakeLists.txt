cmake_minimum_required (VERSION 3.8)

add_definitions(-DUNICODE)
add_definitions(-D_UNICODE)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)

add_executable (PacketLogger "PacketLogger.cpp")

