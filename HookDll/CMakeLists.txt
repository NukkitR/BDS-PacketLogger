
cmake_minimum_required (VERSION 3.8)
project("HookDll")

add_definitions(-DUNICODE)
add_definitions(-D_UNICODE)

add_library (HookDll SHARED 
"dllmain.cpp"
"minhook/src/buffer.c"
"minhook/src/hook.c"
"minhook/src/trampoline.c"
"minhook/src/hde/hde32.c"
"minhook/src/hde/hde64.c"
 "offset.h" "helper.h")

set(CMAKE_CXX_STANDARD 17)
set_property(TARGET HookDll PROPERTY CXX_STANDARD 17)

set_target_properties(HookDll PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
)