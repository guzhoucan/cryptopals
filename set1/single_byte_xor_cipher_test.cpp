#include "single_byte_xor_cipher.h"

#include <fstream>

#include "absl/strings/escaping.h"
#include "gtest/gtest.h"

namespace cryptopals {
namespace {

TEST(SingleByteXorCipherTest, DecodeSingleByteXorCipher) {
  std::string ciphertext = absl::HexStringToBytes(
      "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
  SingleByteXorPlaintext result = DecodeSingleByteXorCipher(ciphertext);
  EXPECT_EQ("Cooking MC's like a pound of bacon", result.plaintext);
  EXPECT_EQ('X', result.key);
}

TEST(SingleByteXorCipherTest, DetectSingleByteXorCipher) {
  std::vector<std::string> ciphertexts;
  std::ifstream file("detect_single_byte_xor_cipher.txt");
  ASSERT_TRUE(file.is_open());
  std::string line;
  while (std::getline(file, line)) {
    ciphertexts.push_back(absl::HexStringToBytes(line));
  }
  file.close();
  SingleByteXorPlaintext result = DetectSingleByteXorCipher(ciphertexts);
  EXPECT_EQ("Now that the party is jumping\n", result.plaintext);
  EXPECT_EQ('5', result.key);
  EXPECT_EQ(170, result.pos);
}

}  // namespace
}  // namespace cryptopals