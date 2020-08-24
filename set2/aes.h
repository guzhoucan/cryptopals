#ifndef CRYPTOPALS_SET2_AES_H_
#define CRYPTOPALS_SET2_AES_H_

#include <string>

namespace cryptopals {

// Note for all methods:
// `key` should be 128/192/256 bits.
// `plaintext`/`ciphertext` needs to be aligned with 128-bit blocks.
// 'iv' needs to be 128-bit long.
class Aes {
 public:
  std::string static EcbEncrypt(std::string_view plaintext,
                                std::string_view key);
  std::string static EcbDecrypt(std::string_view ciphertext,
                                std::string_view key);

  std::string static CbcEncrypt(std::string_view plaintext,
                                std::string_view key, std::string_view iv);
  std::string static CbcDecrypt(std::string_view ciphertext,
                                std::string_view key, std::string_view iv);
};

}  // namespace cryptopals

#endif  // CRYPTOPALS_SET2_AES_H_
