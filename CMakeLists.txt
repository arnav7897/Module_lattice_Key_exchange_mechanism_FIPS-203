cmake_minimum_required(VERSION 3.10)
project(mlkem_hash_demo C CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)

# Include directories
include_directories(
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/third_party/keccak
)

# Source files
add_executable(hash.exe
    src/hash.cpp
    third_party/keccak/simple_fips_202.c
)

