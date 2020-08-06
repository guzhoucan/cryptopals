#include <openssl/aes.h>

#include <fstream>

#include "absl/strings/escaping.h"
#include "gtest/gtest.h"

namespace cryptopals {
namespace {

TEST(DecryptAesInEcbMode, UsingLib) {
  std::ifstream file("aes_in_ecb_mode.txt", std::ios::in | std::ios::binary);
  ASSERT_TRUE(file.is_open());
  std::stringstream ss;
  ss << file.rdbuf();
  std::string ciphertext_base64 = ss.str();
  file.close();
  std::string ciphertext;
  ASSERT_TRUE(absl::Base64Unescape(ciphertext_base64, &ciphertext));

  std::string key = "YELLOW SUBMARINE";
  AES_KEY aes_key;
  ASSERT_EQ(0, AES_set_decrypt_key(
                   reinterpret_cast<const unsigned char*>(key.c_str()),
                   key.size() * 8, &aes_key));

  std::string plaintext(ciphertext.size(), 0);

  for (size_t i = 0; i < ciphertext.size(); i += 16) {
    const auto* in = reinterpret_cast<const unsigned char*>(&ciphertext[i]);
    auto* out = reinterpret_cast<unsigned char*>(&plaintext[i]);
    AES_decrypt(in, out, &aes_key);
  }

  size_t padding_length = plaintext.back();
  plaintext.resize(plaintext.size() - padding_length);

  std::string expected_end = "Play that funky music \n";

  ASSERT_EQ(plaintext.substr(plaintext.size() - expected_end.size()),
            expected_end);
}

}  // namespace
}  // namespace cryptopals