#include "aes.h"

#include <openssl/rand.h>

#include <fstream>

#include "absl/strings/escaping.h"
#include "gtest/gtest.h"

namespace cryptopals {
namespace {

TEST(AesEcbTest, BlockCircling) {
  std::string key = "YELLOW SUBMARINE";  // 128-bit key
  std::string plaintext(32, 0);          // 256-bit, two blocks
  ASSERT_TRUE(RAND_bytes(reinterpret_cast<unsigned char*>(plaintext.data()),
                         plaintext.size()));

  std::string ciphertext = Aes::EcbEncrypt(plaintext, key);
  EXPECT_EQ(plaintext, Aes::EcbDecrypt(ciphertext, key));
}

TEST(AesCbcTest, BlockCircling) {
  std::string key = "YELLOW SUBMARINE";  // 128-bit key
  std::string plaintext(32, 0);          // 256-bit, two blocks
  ASSERT_TRUE(RAND_bytes(reinterpret_cast<unsigned char*>(plaintext.data()),
                         plaintext.size()));
  std::string iv(16, 0);

  std::string ciphertext = Aes::CbcEncrypt(plaintext, key, iv);
  EXPECT_EQ(plaintext, Aes::CbcDecrypt(ciphertext, key, iv));
}

TEST(AesCbcTest, Decrypt) {
  std::ifstream file("cbc_ciphertext.txt", std::ios::in | std::ios::binary);
  ASSERT_TRUE(file.is_open());
  std::stringstream ss;
  ss << file.rdbuf();
  std::string ciphertext_base64 = ss.str();
  file.close();
  std::string ciphertext;
  ASSERT_TRUE(absl::Base64Unescape(ciphertext_base64, &ciphertext));
  std::string key = "YELLOW SUBMARINE";
  std::string iv(16, 0);

  std::string plaintext = Aes::CbcDecrypt(ciphertext, key, iv);
  std::string expected_end = "Play that funky music \n\x04\x04\x04\x04";
  EXPECT_EQ(plaintext.substr(plaintext.size() - expected_end.size()),
            expected_end);
}

}  // namespace
}  // namespace cryptopals