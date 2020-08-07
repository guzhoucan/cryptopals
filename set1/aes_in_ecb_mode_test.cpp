#include "aes_in_ecb_mode.h"

#include <fstream>

#include "absl/strings/escaping.h"
#include "gtest/gtest.h"

namespace cryptopals {
namespace {

TEST(AesInEcbModeTest, DecryptUsingLib) {
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

TEST(AesInEcbModeTest, DetectAesInEcbMode) {
  std::ifstream file("detect_aes_in_ecb_mode.txt",
                     std::ios::in | std::ios::binary);
  ASSERT_TRUE(file.is_open());

  std::vector<std::string> ciphertexts;
  std::string line;
  while (std::getline(file, line)) {
    ciphertexts.push_back(absl::HexStringToBytes(line));
  }

  EcbPattern best = {.ciphertext = "", .uniqueness = 0};
  int best_index = 0;
  for (int i = 0; i < ciphertexts.size(); i++) {
    EcbPattern pattern = GetEcbPattern(ciphertexts[i]);
    if (pattern.uniqueness > best.uniqueness) {
      best = pattern;
      best_index = i;
    }
  }

  ASSERT_EQ(132, best_index);  // Line 133 - not sure if it is correct.
  ASSERT_EQ(
      "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f"
      "6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d465"
      "97949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154"
      "789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0"
      "ab51b29933f2c123c58386b06fba186a",
      absl::BytesToHexString(best.ciphertext));
}

}  // namespace
}  // namespace cryptopals