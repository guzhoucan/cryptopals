add_library(base STATIC base.h base.cpp)
target_link_libraries(base PUBLIC)
add_executable(base_test base_test.cpp)
target_link_libraries(base_test PRIVATE gtest_main base)

add_library(key STATIC key.h key.cpp)
target_link_libraries(key PUBLIC base)
add_executable(key_test key_test.cpp)
target_link_libraries(key_test PRIVATE gtest_main key absl::strings OpenSSL::Crypto)

add_library(cipher STATIC cipher.h cipher.cpp)
target_link_libraries(cipher PUBLIC base key)
add_executable(cipher_test cipher_test.cpp)
target_link_libraries(cipher_test PRIVATE gtest_main cipher absl::strings OpenSSL::Crypto)