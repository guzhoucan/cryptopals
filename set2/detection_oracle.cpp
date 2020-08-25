#include "detection_oracle.h"

#include <functional>
#include <random>
#include <stdexcept>

#include "absl/container/flat_hash_set.h"
#include "aes.h"
#include "padding.h"
#include "rand_util.h"

namespace cryptopals {

namespace {

std::string RandPadding(std::string_view input, uint8_t prefix_len,
                        uint8_t suffix_len) {
  return util::RandStr(prefix_len) + std::string(input) +
         util::RandStr(suffix_len);
}

}  // namespace

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

}  // namespace cryptopals