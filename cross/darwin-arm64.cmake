# CMake toolchain: aarch64-apple-darwin via osxcross (leviathan).
# Used by cross/build-mac-deps.sh for aom + libyuv; nothing else should need it.
set(CMAKE_SYSTEM_NAME Darwin)
set(CMAKE_SYSTEM_PROCESSOR arm64)
set(CMAKE_OSX_ARCHITECTURES arm64)

set(OSX /mnt/Octopus/Code/osxcross/target)
set(CMAKE_OSX_SYSROOT ${OSX}/SDK/MacOSX14.5.sdk)
set(CMAKE_OSX_DEPLOYMENT_TARGET 11.0)

set(CMAKE_C_COMPILER ${OSX}/bin/aarch64-apple-darwin-clang-wrapper)
set(CMAKE_CXX_COMPILER ${OSX}/bin/aarch64-apple-darwin-clangxx-wrapper)
set(CMAKE_AR ${OSX}/bin/aarch64-apple-darwin23.5-ar)
set(CMAKE_RANLIB ${OSX}/bin/aarch64-apple-darwin23.5-ranlib)
set(CMAKE_STRIP ${OSX}/bin/aarch64-apple-darwin23.5-strip)
set(CMAKE_INSTALL_NAME_TOOL ${OSX}/bin/aarch64-apple-darwin23.5-install_name_tool)
set(CMAKE_ASM_COMPILER ${OSX}/bin/aarch64-apple-darwin-clang-wrapper)

# Find libraries/headers only in the SDK; host tools (nasm, perl, python) from the host.
set(CMAKE_FIND_ROOT_PATH ${CMAKE_OSX_SYSROOT})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
