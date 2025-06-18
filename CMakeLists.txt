cmake_minimum_required(VERSION 3.10)
project(mlkem_hash_demo LANGUAGES C CXX)

# Use C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include headers
include_directories(
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/third_party/keccak
)

# Add source files
set(SOURCES
    src/hash.cpp
    include/ml-kem/base.cpp
    include/ml-kem/sampling.cpp
    include/ml-kem/ntt.cpp
    include/ml-kem/K_PKE.cpp
    third_party/keccak/simple_fips_202.c
)

# Create the executable
add_executable(hash.exe ${SOURCES})
