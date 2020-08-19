cmake_minimum_required(VERSION 3.16)
project(cryptopals)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_IMPLICIT_INCLUDE_DIRECTORIES /usr/include)
set(OPENSSL_ROOT_DIR /usr/lib/x86_64-linux-gnu)
message("OPENSSL_ROOT_DIR is " ${OPENSSL_ROOT_DIR})
find_package(OpenSSL REQUIRED)
message("OPENSSL_FOUND is " ${OPENSSL_FOUND})
message("OPENSSL_INCLUDE_DIR is " ${OPENSSL_INCLUDE_DIR})
message("OPENSSL_CRYPTO_LIBRARY is " ${OPENSSL_CRYPTO_LIBRARY})
message("OPENSSL_SSL_LIBRARY is " ${OPENSSL_SSL_LIBRARY})
message("OPENSSL_LIBRARIES is " ${OPENSSL_LIBRARIES})
message("OPENSSL_VERSION is " ${OPENSSL_VERSION})

add_subdirectory(lib/abseil-cpp)
add_subdirectory(lib/googletest)
add_subdirectory(set1)
add_subdirectory(set2)

