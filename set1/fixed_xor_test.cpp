#include "fixed_xor.h"

#include "absl/strings/escaping.h"
#include "gtest/gtest.h"

namespace cryptopals {
namespace {

TEST(FixedXorTest, Test) {
  std::string str1 =
      absl::HexStringToBytes("1c0111001f010100061a024b53535009181c");
  std::string str2 =
      absl::HexStringToBytes("686974207468652062756c6c277320657965");
  std::string result =
      absl::HexStringToBytes("746865206b696420646f6e277420706c6179");
  EXPECT_EQ(result, FixedXor(str1, str2));
}

}  // namespace
}  // namespace cryptopals