#include <functional>
#include <random>
#include <stdexcept>

#include "absl/container/flat_hash_set.h"
#include "aes.h"
#include "gtest/gtest.h"
#include "padding.h"
#include "rand_util.h"

namespace cryptopals {
namespace {

enum class CipherMode { ECB, CBC };

std::string RandPadding(std::string_view input, uint8_t prefix_len,
                        uint8_t suffix_len) {
  return util::RandStr(prefix_len) + std::string(input) +
         util::RandStr(suffix_len);
}

std::string EncryptionOracleWithMode(std::string_view input, CipherMode mode) {
  std::default_random_engine generator(std::random_device{}());
  auto random_length = [&generator]() {
    return std::uniform_int_distribution<uint8_t>(5, 10)(generator);
  };

  auto extended = RandPadding(input, random_length(), random_length());
  auto padded = Padding::Pkcs7Encode(extended, 16);
  auto key = util::RandStr(16);

  switch (mode) {
    case CipherMode::ECB:
      return Aes::EcbEncrypt(padded, key);
    case CipherMode::CBC:
      auto iv = util::RandStr(16);
      return Aes::CbcEncrypt(padded, key, iv);
  }
  throw std::runtime_error("Unexpected CipherMode");
}

std::string EncryptionOracle(std::string_view input) {
  std::default_random_engine generator(std::random_device{}());
  auto random_mode = [&generator]() {
    return std::uniform_int_distribution<uint8_t>(0, 1)(generator);
  };
  bool mode = random_mode();  // 0 - ECB, 1 - CBC
  if (!mode) {
    return EncryptionOracleWithMode(input, CipherMode::ECB);
  } else {
    return EncryptionOracleWithMode(input, CipherMode::CBC);
  }
}

CipherMode DetectMode(std::string_view ciphertext) {
  absl::flat_hash_set<std::string_view> encountered;
  for (int i = 0; i < ciphertext.size(); i += 16) {
    auto block = ciphertext.substr(i, 16);
    if (encountered.contains(block)) {
      return CipherMode::ECB;
    }
    encountered.insert(block);
  }
  return CipherMode::CBC;
}

TEST(ModeDetection, DetectECB) {
  std::string input(43, 'a');  // 11 (worst prefix) + 32 (two blocks)
  for (int i = 0; i < 100; i++) {
    std::string ciphertext = EncryptionOracleWithMode(input, CipherMode::ECB);
    EXPECT_EQ(CipherMode::ECB, DetectMode(ciphertext));
  }
}

// If the random prefix is all 'a', this test will fail
TEST(ModeDetection, DetectCBC) {
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
TEST(ModeDetection, FreqAnalysis) {
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