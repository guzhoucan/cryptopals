# Challenge 10
add_library(aes STATIC aes.h aes.cpp)
target_link_libraries(aes PUBLIC OpenSSL::Crypto fixed_xor)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cbc_ciphertext.txt
        ${CMAKE_CURRENT_BINARY_DIR}/cbc_ciphertext.txt COPYONLY)
add_executable(aes_test aes_test.cpp)
target_link_libraries(aes_test PRIVATE gtest_main absl::strings aes)