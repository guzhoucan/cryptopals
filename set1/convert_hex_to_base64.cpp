#include "gtest/gtest.h"
#include "absl/strings/escaping.h"

namespace {
TEST(ConvertHexToBase64, Test) {
  std::string bytes = absl::HexStringToBytes("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
  std::string base64 = absl::Base64Escape(bytes);
  EXPECT_EQ(base64, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
}
}