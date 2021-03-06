# Challenge 1
add_executable(convert_hex_to_base64 convert_hex_to_base64.cpp)
target_link_libraries(convert_hex_to_base64 gtest_main absl::strings)

# Challenge 2
add_library(fixed_xor STATIC fixed_xor.h fixed_xor.cpp)
add_executable(fixed_xor_test fixed_xor_test.cpp)
target_link_libraries(fixed_xor_test PRIVATE gtest_main absl::strings fixed_xor)

# Challenge 3 & 4
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/1984.txt
        ${CMAKE_CURRENT_BINARY_DIR}/1984.txt COPYONLY)
add_library(letter_freq STATIC letter_frequency.h letter_frequency.cpp)
target_link_libraries(letter_freq PUBLIC absl::strings absl::flat_hash_map)

add_library(single_byte_xor_cipher STATIC single_byte_xor_cipher.h
        single_byte_xor_cipher.cpp)
target_link_libraries(single_byte_xor_cipher PUBLIC fixed_xor letter_freq)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/detect_single_byte_xor_cipher.txt
        ${CMAKE_CURRENT_BINARY_DIR}/detect_single_byte_xor_cipher.txt COPYONLY)
add_executable(single_byte_xor_cipher_test single_byte_xor_cipher_test.cpp)
target_link_libraries(single_byte_xor_cipher_test PRIVATE gtest_main
        letter_freq single_byte_xor_cipher)

# Challenge 5 & 6
add_library(repeat_key_xor STATIC repeat_key_xor.h repeat_key_xor.cpp)
target_link_libraries(repeat_key_xor PUBLIC single_byte_xor_cipher)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/break_repeat_key_xor.txt
        ${CMAKE_CURRENT_BINARY_DIR}/break_repeat_key_xor.txt COPYONLY)
add_executable(repeat_key_xor_test repeat_key_xor_test.cpp)
target_link_libraries(repeat_key_xor_test PRIVATE gtest_main absl::strings
        repeat_key_xor)

# Challenge 7 & 8
add_library(aes_in_ecb_mode STATIC aes_in_ecb_mode.h aes_in_ecb_mode.cpp)
target_link_libraries(aes_in_ecb_mode PUBLIC OpenSSL::Crypto absl::flat_hash_map)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/aes_in_ecb_mode.txt
        ${CMAKE_CURRENT_BINARY_DIR}/aes_in_ecb_mode.txt COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/detect_aes_in_ecb_mode.txt
        ${CMAKE_CURRENT_BINARY_DIR}/detect_aes_in_ecb_mode.txt COPYONLY)
add_executable(aes_in_ecb_mode_test aes_in_ecb_mode_test.cpp)
target_link_libraries(aes_in_ecb_mode_test PRIVATE gtest_main absl::strings
        aes_in_ecb_mode)