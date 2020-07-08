#include "single_byte_xor_cipher.h"

#include <fstream>

#include "absl/strings/escaping.h"
#include "gtest/gtest.h"

namespace cryptopals {
namespace {

TEST(DecodeSingleByteXorCipher, Test) {
  std::string cipher_text = absl::HexStringToBytes(
      "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
  SingleByteXorPlaintext result = DecodeSingleByteXorCipher(cipher_text);
  EXPECT_EQ("Cooking MC's like a pound of bacon", result.plain_text);
  EXPECT_EQ('X', result.key);
}

TEST(DetectSingleByteXorCipher, Test) {
  std::vector<std::string> cipher_tests;
  std::ifstream file("detect_single_byte_xor_cipher.txt");
  ASSERT_TRUE(file.is_open());
  std::string line;
  while (std::getline(file, line)) {
    cipher_tests.push_back(absl::HexStringToBytes(line));
  }
  file.close();
  SingleByteXorPlaintext result = DetectSingleByteXorCipher(cipher_tests);
  EXPECT_EQ("Now that the party is jumping\n", result.plain_text);
  EXPECT_EQ('5', result.key);
  EXPECT_EQ(170, result.pos);
}

}  // namespace
}  // namespace cryptopals