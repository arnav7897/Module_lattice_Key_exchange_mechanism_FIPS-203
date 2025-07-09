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
set(SOURCES
    include/ml-kem/base.cpp
    include/ml-kem/sampling.cpp
    include/ml-kem/ntt.cpp
    include/ml-kem/K_PKE.cpp
    include/ml-kem/ML-KEM.cpp
    third_party/keccak/simple_fips_202.c
)
# Main executable
add_executable(Test.exe src/test.cpp ${SOURCES})
add_executable(mlkem_keygen src/mlkem_keygen.cpp ${SOURCES})
add_executable(mlkem_encaps src/mlkem_encaps.cpp ${SOURCES})
add_executable(mlkem_decaps src/mlkem_decaps.cpp ${SOURCES})