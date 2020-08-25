# Challenge 9
add_library(padding STATIC padding.h padding.cpp)
target_link_libraries(padding PUBLIC)
add_executable(padding_test padding_test.cpp)
target_link_libraries(padding_test PRIVATE gtest_main padding)

# Challenge 10
add_library(aes STATIC aes.h aes.cpp)
target_link_libraries(aes PUBLIC OpenSSL::Crypto fixed_xor)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cbc_ciphertext.txt
        ${CMAKE_CURRENT_BINARY_DIR}/cbc_ciphertext.txt COPYONLY)
add_executable(aes_test aes_test.cpp)
target_link_libraries(aes_test PRIVATE gtest_main absl::strings aes)

# Challenge 11
add_library(rand_util STATIC rand_util.h rand_util.cpp)
target_link_libraries(rand_util PUBLIC)
add_library(detection_oracle STATIC detection_oracle.h detection_oracle.cpp)
target_link_libraries(detection_oracle PUBLIC aes padding rand_util
        absl::flat_hash_set)
add_executable(detection_oracle_test detection_oracle_test.cpp)
target_link_libraries(detection_oracle_test PRIVATE gtest_main detection_oracle)