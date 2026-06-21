cmake_minimum_required(VERSION 3.15)
project(Lab3_RSA_Hybrid CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(POLICY CMP0091)
  cmake_policy(SET CMP0091 NEW)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# Crypto++ paths (Cross-platform)
if(WIN32)
    set(CRYPTOPP_ROOT "D:/Labs_Crypto/cryptolibrary" CACHE PATH "Path to Crypto++")
    include_directories("${CRYPTOPP_ROOT}/include")
endif()

# JSON Library Path
include_directories("src")

# Source files
set(SOURCES
    src/utils.cpp
    src/rsa_keygen.cpp
    src/rsa_encrypt.cpp
    src/rsa_decrypt.cpp
    src/benchmarker.cpp
    src/rsatool.cpp
)

add_executable(rsatool ${SOURCES})

if(WIN32)
    if(MSVC)
        target_link_libraries(rsatool PRIVATE "${CRYPTOPP_ROOT}/libs/cryptopp/msvc/cryptlib.lib")
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        target_link_libraries(rsatool PRIVATE "${CRYPTOPP_ROOT}/libs/cryptopp/clang/libcryptopp.a")
    else() # Default to GCC/MinGW
        target_link_libraries(rsatool PRIVATE "${CRYPTOPP_ROOT}/libs/cryptopp/gcc/libcryptopp.a")
    endif()
else()
    # Link against system Crypto++ on Linux/macOS
    target_link_libraries(rsatool PRIVATE cryptopp)
endif()
