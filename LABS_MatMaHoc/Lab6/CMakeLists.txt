cmake_minimum_required(VERSION 3.10)
project(Lab6_PQC)

set(CMAKE_CXX_STANDARD 17)

# ==========================================
# CẤU HÌNH OPENSSL 3.6.2 (Bắt buộc cho PQC)
# ==========================================
if(WIN32)
    set(OPENSSL_ROOT_DIR "C:/msys64/home/LONG/openssl-3.6.2")
    set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
    set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/libcrypto.dll.a")
else()
    set(OPENSSL_ROOT_DIR "/home/duclong2901/openssl-3.6.2")
    set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
    
    # Tự động dò tìm cả file .so (thư viện động) và .a (thư viện tĩnh)
    if(EXISTS "${OPENSSL_ROOT_DIR}/lib/libcrypto.so")
        set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/lib/libcrypto.so")
    elseif(EXISTS "${OPENSSL_ROOT_DIR}/lib/libcrypto.a")
        set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/lib/libcrypto.a")
    elseif(EXISTS "${OPENSSL_ROOT_DIR}/lib64/libcrypto.so")
        set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/lib64/libcrypto.so")
    elseif(EXISTS "${OPENSSL_ROOT_DIR}/lib64/libcrypto.a")
        set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/lib64/libcrypto.a")
    elseif(EXISTS "${OPENSSL_ROOT_DIR}/libcrypto.a")
        set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/libcrypto.a")
    else()
        # Nếu vẫn không thấy gì, ép về mặc định để báo lỗi rõ ràng
        set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/libcrypto.so")
    endif()
endif()

include_directories(${OPENSSL_INCLUDE_DIR})

# ==========================================
# CẤU HÌNH CÁC FILE THỰC THI (TARGETS)
# ==========================================

add_executable(pqtool pqtool.cpp)
target_link_libraries(pqtool PRIVATE ${OPENSSL_CRYPTO_LIBRARY})

add_executable(cert_demo cert_demo.cpp)
target_link_libraries(cert_demo PRIVATE ${OPENSSL_CRYPTO_LIBRARY})

add_executable(benchmark Lab6_Benchmark.cpp)
target_link_libraries(benchmark PRIVATE ${OPENSSL_CRYPTO_LIBRARY})
