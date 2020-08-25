#include "padding.h"

#include "gtest/gtest.h"

namespace cryptopals {
namespace {

TEST(Pkcs7Test, Encode) {
  std::string input = "YELLOW SUBMARINE";
  std::string expected = "YELLOW SUBMARINE\x04\x04\x04\x04";
  EXPECT_EQ(expected, Padding::Pkcs7Encode(input, expected.size()));
}

TEST(Pkcs7Test, Circling) {
  std::string input = "YELLOW SUBMARINE";
  for (uint32_t i = 2; i < 1u << 8u; i++) {
    EXPECT_EQ(input, Padding::Pkcs7Decode(Padding::Pkcs7Encode(input, i)));
  }
}

}  // namespace
}  // namespace cryptopals