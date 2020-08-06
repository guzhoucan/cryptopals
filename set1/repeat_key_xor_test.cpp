#include "repeat_key_xor.h"

#include <fstream>

#include "absl/strings/escaping.h"
#include "gtest/gtest.h"

namespace cryptopals {
namespace {

TEST(RepeatKeyXorTest, RepeatKeyXorEncode) {
  std::string key = "ICE";
  std::string plaintext =
      "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a "
      "cymbal";
  std::string ciphertext = RepeatKeyXorEncode(plaintext, key);
  EXPECT_EQ(
      "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765"
      "272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27"
      "282f",
      absl::BytesToHexString(ciphertext));
}

TEST(RepeatKeyXorTest, GetHammingDistance) {
  std::string str1 = "this is a test";
  std::string str2 = "wokka wokka!!!";
  EXPECT_EQ(37, GetHammingDistance(str1, str2));
}

TEST(RepeatKeyXorTest, BreakRepeatKeyXor) {
  std::ifstream file("break_repeat_key_xor.txt",
                     std::ios::in | std::ios::binary);
  ASSERT_TRUE(file.is_open());
  std::stringstream ss;
  ss << file.rdbuf();
  std::string ciphertext_base64 = ss.str();
  file.close();
  std::string ciphertext;
  ASSERT_TRUE(absl::Base64Unescape(ciphertext_base64, &ciphertext));

  BreakRepeatKeyXorOutput output = BreakRepeatKeyXor(ciphertext);
  EXPECT_EQ("I'm back and I'm ringin' the bell ",
            output.plaintext.substr(0, output.plaintext.find('\n')));
  EXPECT_EQ("Terminator X: Bring the noise", output.key);
}

}  // namespace
}  // namespace cryptopals