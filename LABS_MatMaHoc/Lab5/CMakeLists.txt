cmake_minimum_required(VERSION 3.10)
project(Lab5_Signatures)

set(CMAKE_CXX_STANDARD 17)

# OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Crypto++ 
if(WIN32)
    set(CRYPTOPP_INCLUDE_DIR "C:/msys64/home/LONG/cryptopp")
    set(CRYPTOPP_LIBRARIES "C:/msys64/home/LONG/cryptopp/libcryptopp.a")
    include_directories(${CRYPTOPP_INCLUDE_DIR})
endif()

add_executable(sigtool Lab5_SigTool.cpp)
if(WIN32)
    target_link_libraries(sigtool PRIVATE ${CRYPTOPP_LIBRARIES} ${OPENSSL_CRYPTO_LIBRARY})
    target_link_options(sigtool PRIVATE "-Wl,--allow-multiple-definition")
else()
    target_link_libraries(sigtool PRIVATE cryptopp ${OPENSSL_CRYPTO_LIBRARY})
endif()

add_executable(benchmark Lab5_Benchmark.cpp)
if(WIN32)
    target_link_libraries(benchmark PRIVATE ${CRYPTOPP_LIBRARIES} ${OPENSSL_CRYPTO_LIBRARY})
    target_link_options(benchmark PRIVATE "-Wl,--allow-multiple-definition")
else()
    target_link_libraries(benchmark PRIVATE cryptopp ${OPENSSL_CRYPTO_LIBRARY})
endif()
