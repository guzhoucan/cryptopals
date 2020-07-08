#include "repeat_key_xor.h"

#include <fstream>

#include "absl/strings/escaping.h"
#include "gtest/gtest.h"

namespace cryptopals {
namespace {

TEST(RepeatKeyXorEncode, Test) {
  std::string key = "ICE";
  std::string plain_text =
      "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a "
      "cymbal";
  std::string cipher_text = RepeatKeyXorEncode(plain_text, key);
  EXPECT_EQ(
      "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765"
      "272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27"
      "282f",
      absl::BytesToHexString(cipher_text));
}

TEST(GetHammingDistance, Test) {
  std::string str1 = "this is a test";
  std::string str2 = "wokka wokka!!!";
  EXPECT_EQ(37, GetHammingDistance(str1, str2));
}

TEST(BreakRepeatKeyXor, Test) {
  std::ifstream file("break_repeat_key_xor.txt",
                     std::ios::in | std::ios::binary);
  ASSERT_TRUE(file.is_open());
  std::stringstream ss;
  ss << file.rdbuf();
  std::string cipher_text_base64 = ss.str();
  file.close();
  std::string cipher_text;
  ASSERT_TRUE(absl::Base64Unescape(cipher_text_base64, &cipher_text));

  BreakRepeatKeyXorOutput output = BreakRepeatKeyXor(cipher_text);
  EXPECT_EQ("I'm back and I'm ringin' the bell ",
            output.plain_text.substr(0, output.plain_text.find('\n')));
  EXPECT_EQ("Terminator X: Bring the noise", output.key);
}

}  // namespace
}  // namespace cryptopals