#include "aes_in_ecb_mode.h"

#include <fstream>

#include "absl/strings/escaping.h"
#include "gtest/gtest.h"

namespace cryptopals {
namespace {

TEST(DecryptAesInEcbModeTest, DecryptUsingLib) {
  std::ifstream file("aes_in_ecb_mode.txt", std::ios::in | std::ios::binary);
  ASSERT_TRUE(file.is_open());
  std::stringstream ss;
  ss << file.rdbuf();
  std::string ciphertext_base64 = ss.str();
  file.close();
  std::string ciphertext;
  ASSERT_TRUE(absl::Base64Unescape(ciphertext_base64, &ciphertext));

  std::string key = "YELLOW SUBMARINE";
  auto plaintext = DecryptAesInEcbMode(ciphertext, key);

  std::string expected_end = "Play that funky music \n";
  ASSERT_EQ(plaintext.substr(plaintext.size() - expected_end.size()),
            expected_end);
}

}  // namespace
}  // namespace cryptopals