#ifndef CRYPTOPALS_SET2_AES_H_
#define CRYPTOPALS_SET2_AES_H_

#include <string>

namespace cryptopals {

class Aes {
 public:
  // Note: `key` should be either 128/192/256 bits.
  // Ideally, `plaintext`/`ciphertext` should be aligned with 128-bit blocks.
  // But it seems that the actual openssl impl works with arbitrary input (see
  // UT).
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
