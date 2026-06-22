cmake_minimum_required(VERSION 3.10)
project(Lab6_PQC)

set(CMAKE_CXX_STANDARD 17)

# Point to OpenSSL 3.6.2 for ML-DSA and ML-KEM support
if(WIN32)
    set(OPENSSL_ROOT_DIR "C:/msys64/home/LONG/openssl-3.6.2")
    set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
    set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/libcrypto.dll.a")
else()
    # On Linux, assume OpenSSL 3.x is built and installed system-wide or via pkg-config
    find_package(OpenSSL REQUIRED)
    set(OPENSSL_INCLUDE_DIR ${OPENSSL_INCLUDE_DIR})
    set(OPENSSL_CRYPTO_LIBRARY ${OPENSSL_CRYPTO_LIBRARY})
endif()

include_directories(${OPENSSL_INCLUDE_DIR})

# pqtool
add_executable(pqtool pqtool.cpp)
target_link_libraries(pqtool PRIVATE ${OPENSSL_CRYPTO_LIBRARY})

# cert_demo
add_executable(cert_demo cert_demo.cpp)
target_link_libraries(cert_demo PRIVATE ${OPENSSL_CRYPTO_LIBRARY})

# benchmark
add_executable(benchmark Lab6_Benchmark.cpp)
target_link_libraries(benchmark PRIVATE ${OPENSSL_CRYPTO_LIBRARY})
