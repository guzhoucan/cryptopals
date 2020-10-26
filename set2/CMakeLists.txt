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
target_link_libraries(aes_test PRIVATE gtest_main absl::strings aes rand_util)

# Challenge 11
add_library(rand_util STATIC rand_util.h rand_util.cpp)
target_link_libraries(rand_util PUBLIC)
add_executable(mode_detection mode_detection.cpp)
target_link_libraries(mode_detection PRIVATE gtest_main aes padding rand_util
        absl::flat_hash_set)

# Challenge 12
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/unknown_str.txt
        ${CMAKE_CURRENT_BINARY_DIR}/unknown_str.txt COPYONLY)
add_executable(ecb_decryption ecb_decryption.cpp)
target_link_libraries(ecb_decryption PRIVATE gtest_main absl::strings aes
        padding rand_util)

# Challenge 13
add_executable(ecb_cut_and_paste ecb_cut_and_paste.cpp)
target_link_libraries(ecb_cut_and_paste PRIVATE gtest_main absl::strings aes
        padding rand_util)