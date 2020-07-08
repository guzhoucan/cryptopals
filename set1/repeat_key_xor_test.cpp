#include "repeat_key_xor.h"

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

}  // namespace
}  // namespace cryptopals