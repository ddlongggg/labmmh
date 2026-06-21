cmake_minimum_required(VERSION 3.15)
project(AESTool CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(POLICY CMP0091)
  cmake_policy(SET CMP0091 NEW)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()
if(WIN32)
    set(CRYPTOPP_ROOT "D:/Labs_Crypto/cryptolibrary" CACHE PATH "Path to Crypto++")
    include_directories("${CRYPTOPP_ROOT}/include")
endif()
set(SOURCES
    src/main.cpp
    src/AESUtils.cpp
    src/CipherCore.cpp
    src/KATRunner.cpp
    src/Benchmarker.cpp
)
add_executable(aestool ${SOURCES})
if(WIN32)
    if(MSVC)
        target_link_libraries(aestool PRIVATE "${CRYPTOPP_ROOT}/libs/cryptopp/msvc/cryptlib.lib")
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        target_link_libraries(aestool PRIVATE "${CRYPTOPP_ROOT}/libs/cryptopp/clang/libcryptopp.a")
    else() # Default to GCC/MinGW
        target_link_libraries(aestool PRIVATE "${CRYPTOPP_ROOT}/libs/cryptopp/gcc/libcryptopp.a")
    endif()
else()
    target_link_libraries(aestool PRIVATE cryptopp)
endif()
