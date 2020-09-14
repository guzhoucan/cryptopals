#include "cipher.h"

#include "absl/strings/escaping.h"
#include "gtest/gtest.h"

namespace cryptopals::aes {
namespace {

// See FIPS-197 Appendix C – Example Vectors
TEST(CipherTest, Encrypt128) {
  std::string plaintext =
      absl::HexStringToBytes("00112233445566778899aabbccddeeff");
  std::string key = absl::HexStringToBytes("000102030405060708090a0b0c0d0e0f");
  auto aes = AesCipher::Create(key);
  std::string ciphertext = aes->Encrypt(plaintext);
  EXPECT_EQ(absl::HexStringToBytes("69c4e0d86a7b0430d8cdb78070b4c55a"),
            ciphertext);
}

TEST(CipherTest, Encrypt192) {
  std::string plaintext =
      absl::HexStringToBytes("00112233445566778899aabbccddeeff");
  std::string key = absl::HexStringToBytes(
      "000102030405060708090a0b0c0d0e0f1011121314151617");
  auto aes = AesCipher::Create(key);
  std::string ciphertext = aes->Encrypt(plaintext);
  EXPECT_EQ(absl::HexStringToBytes("dda97ca4864cdfe06eaf70a0ec0d7191"),
            ciphertext);
}

TEST(CipherTest, Encrypt256) {
  std::string plaintext =
      absl::HexStringToBytes("00112233445566778899aabbccddeeff");
  std::string key = absl::HexStringToBytes(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  auto aes = AesCipher::Create(key);
  std::string ciphertext = aes->Encrypt(plaintext);
  EXPECT_EQ(absl::HexStringToBytes("8ea2b7ca516745bfeafc49904b496089"),
            ciphertext);
}

}  // namespace
}  // namespace cryptopals::aes