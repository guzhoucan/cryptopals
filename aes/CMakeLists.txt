add_library(base STATIC base.h base.cpp)
target_link_libraries(base PUBLIC)
add_executable(base_test base_test.cpp)
target_link_libraries(base_test PRIVATE gtest_main base)

add_library(key STATIC key.h key.cpp)
target_link_libraries(key PUBLIC base)
add_executable(key_test key_test.cpp)
target_link_libraries(key_test PRIVATE gtest_main key absl::strings OpenSSL::Crypto)