cmake_minimum_required(VERSION 3.10)
project(Lab4_Cryptography)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

if(WIN32)
    set(OPENSSL_ROOT "D:/Labs_Crypto/openssl362" CACHE PATH "Path to OpenSSL")
    include_directories("${OPENSSL_ROOT}/include")
    
    # Do trong thư mục D:/Labs_Crypto/openssl362/lib64 chỉ có libcrypto.a và libcrypto.dll.a
    # Nên ta gán cứng file này luôn cho mọi compiler (MSVC/MinGW)
    # CẦN THÊM ws2_32 và crypt32 vì OpenSSL tĩnh trên Windows gọi API hệ thống
    set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT}/lib64/libcrypto.a" ws2_32 crypt32 advapi32 user32 gdi32)
else()
    find_package(OpenSSL REQUIRED)
    include_directories(${OPENSSL_INCLUDE_DIR})
endif()

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
