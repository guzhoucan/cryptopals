#include "detection_oracle.h"

#include "gtest/gtest.h"

namespace cryptopals {
namespace {

TEST(DetectionOracleTest, DetectECB) {
  std::string input(43, 'a');  // 11 (worst prefix) + 32 (two blocks)
  for (int i = 0; i < 100; i++) {
    std::string ciphertext = EncryptionOracleWithMode(input, CipherMode::ECB);
    EXPECT_EQ(CipherMode::ECB, DetectMode(ciphertext));
  }
}

// If the random prefix is all 'a', this test will fail
TEST(DetectionOracleTest, DetectCBC) {
  std::string input(43, 'a');  // 11 (worst prefix) + 32 (two blocks)
  for (int i = 0; i < 100; i++) {
    std::string ciphertext = EncryptionOracleWithMode(input, CipherMode::CBC);
    EXPECT_EQ(CipherMode::CBC, DetectMode(ciphertext));
  }
}

// This is not guaranteed to pass every time, you'll be very lucky if it
// fails :P
// The process complies Binomial distribution with standard deviation:
// \sigma = sqrt(250) = 15.81
// I'm using normal approximation and I set confidence interval at mean +-
// 3\sigma, i.e. [453, 547]. The chance of failure is about 0.269% (1/370).
TEST(DetectionOracleTest, FreqAnalysis) {
  std::string input(43, 'a');  // 11 (worst prefix) + 32 (two blocks)
  int ecb_count = 0;
  for (int i = 0; i < 1000; i++) {
    std::string ciphertext = EncryptionOracle(input);
    if (DetectMode(ciphertext) == CipherMode::ECB) {
      ecb_count++;
    }
  }
  EXPECT_GT(ecb_count, 453);
  EXPECT_LT(ecb_count, 547);
}

}  // namespace
}  // namespace cryptopals