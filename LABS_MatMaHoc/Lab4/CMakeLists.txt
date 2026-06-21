cmake_minimum_required(VERSION 3.10)
project(Lab4_Cryptography)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(${OPENSSL_INCLUDE_DIR})

# Task 1: Hashing Suite
add_executable(Lab4_Task1_HashSuite Lab4_Task1_HashSuite.cpp)
target_link_libraries(Lab4_Task1_HashSuite PRIVATE ${OPENSSL_CRYPTO_LIBRARY})

# Task 2: X509 Parsing
add_executable(Lab4_Task2_X509 Lab4_Task2_X509.cpp)
target_link_libraries(Lab4_Task2_X509 PRIVATE ${OPENSSL_CRYPTO_LIBRARY})

# Task 5: Performance Benchmark
add_executable(Lab4_Task5_Benchmark Lab4_Task5_Benchmark.cpp)
target_link_libraries(Lab4_Task5_Benchmark PRIVATE ${OPENSSL_CRYPTO_LIBRARY})

# Task 6A: Custom Length Extension
add_executable(Lab4_Task6A_LenExt Lab4_Task6A_LenExt.cpp)
# No OpenSSL dependency for this custom implementation
