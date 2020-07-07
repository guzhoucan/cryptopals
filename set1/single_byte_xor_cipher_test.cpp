#include "single_byte_xor_cipher.h"

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

}  // namespace
}  // namespace cryptopals