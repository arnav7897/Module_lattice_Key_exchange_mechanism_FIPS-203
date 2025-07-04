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

# Main source files
set(SOURCES
    src/test.cpp
    include/ml-kem/base.cpp
    include/ml-kem/sampling.cpp
    include/ml-kem/ntt.cpp
    include/ml-kem/K_PKE.cpp
    include/ml-kem/ML-KEM.cpp
    third_party/keccak/simple_fips_202.c
)

# Main executable
add_executable(Test.exe ${SOURCES})

# ========================
# Unit test for base.cpp
# ========================
#add_executable(base_test.exe test/base_test.cpp third_party/keccak/simple_fips_202.c include/ml-kem/sampling.cpp include/ml-kem/base.cpp include/ml-kem/ntt.cpp)

add_executable(ntt_test.exe test/ntt_test.cpp third_party/keccak/simple_fips_202.c include/ml-kem/sampling.cpp include/ml-kem/base.cpp include/ml-kem/ntt.cpp )
# Optionally link additional libs if needed (e.g., crypto)
# target_link_libraries(base_test ...)

# Add test to CTest (optional but useful)
enable_testing()
add_test(NAME BaseTest COMMAND base_test)