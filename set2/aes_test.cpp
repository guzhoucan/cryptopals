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
  ASSERT_EQ(plaintext, Aes::EcbDecrypt(ciphertext, key));
}

// Beyond my wildest imagination, the real openssl impl works with partial
// block, even though crypto/aes/aes_core.c uses memcpy on 16-byte block.
// I tried to use raw c array for plaintext/ciphertext and they won't be
// overwritten by each other during debugging.
// Is AES a byte-wise mapping?
TEST(AesEcbTest, NonBlockCircling) {
  std::string key = "YELLOW SUBMARINE";  // 128-bit key
  std::string plaintext = "WTF";

  std::string ciphertext = Aes::EcbEncrypt(plaintext, key);
  ASSERT_EQ(plaintext, Aes::EcbDecrypt(ciphertext, key));
}

TEST(AesCbcTest, BlockCircling) {
  std::string key = "YELLOW SUBMARINE";  // 128-bit key
  std::string plaintext(32, 0);          // 256-bit, two blocks
  ASSERT_TRUE(RAND_bytes(reinterpret_cast<unsigned char*>(plaintext.data()),
                         plaintext.size()));
  std::string iv(16, 0);

  std::string ciphertext = Aes::CbcEncrypt(plaintext, key, iv);
  ASSERT_EQ(plaintext, Aes::CbcDecrypt(ciphertext, key, iv));
}

TEST(AesCbcTest, NonBlockCircling) {
  std::string key = "YELLOW SUBMARINE";  // 128-bit key
  std::string plaintext = "WTF";
  std::string iv(16, 'a');

  std::string ciphertext = Aes::CbcEncrypt(plaintext, key, iv);
  // There's a potential memory issue with the AES lib, causing the result to
  // be either "WTFaaaaaaaaaaaaa" or "WTFa\xE\aADaaaaaaaa", but it still
  // maintains the byte-wise mapping.
  ASSERT_EQ(plaintext, Aes::CbcDecrypt(ciphertext, key, iv).substr(0, 3));
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
  ASSERT_EQ(plaintext.substr(plaintext.size() - expected_end.size()),
            expected_end);
}

}  // namespace
}  // namespace cryptopals