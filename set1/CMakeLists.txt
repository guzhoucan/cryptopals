add_executable(convert_hex_to_base64 convert_hex_to_base64.cpp)
target_link_libraries(convert_hex_to_base64 gtest_main absl::strings)

add_library(fixed_xor STATIC fixed_xor.h fixed_xor.cpp)
add_executable(fixed_xor_test fixed_xor_test.cpp)
target_link_libraries(fixed_xor_test PRIVATE gtest_main absl::strings fixed_xor)

add_library(letter_freq STATIC letter_frequency.h letter_frequency.cpp)
target_link_libraries(letter_freq PUBLIC absl::strings)

add_library(single_byte_xor_cipher STATIC single_byte_xor_cipher.h
        single_byte_xor_cipher.cpp)
target_link_libraries(single_byte_xor_cipher PUBLIC fixed_xor letter_freq)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/detect_single_byte_xor_cipher.txt
        ${CMAKE_CURRENT_BINARY_DIR}/detect_single_byte_xor_cipher.txt COPYONLY)
add_executable(single_byte_xor_cipher_test single_byte_xor_cipher_test.cpp)
target_link_libraries(single_byte_xor_cipher_test PRIVATE gtest_main
        letter_freq single_byte_xor_cipher)
