#ifndef CRYPTOPALS_SET1_AES_IN_ECB_MODE_H_
#define CRYPTOPALS_SET1_AES_IN_ECB_MODE_H_

#include <string>

namespace cryptopals {

struct EcbPattern {
  std::string ciphertext;
  // Sum of (blob_count ^ 2) for all unique (16-byte) blobs in the ciphertext
  uint32_t uniqueness;
};

std::string DecryptAesInEcbMode(std::string_view ciphertext,
                                std::string_view key);

EcbPattern GetEcbPattern(std::string_view ciphertext);

}  // namespace cryptopals

#endif  // CRYPTOPALS_SET1_AES_IN_ECB_MODE_H_
