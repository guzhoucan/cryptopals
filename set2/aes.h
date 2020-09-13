#ifndef CRYPTOPALS_SET2_AES_H_
#define CRYPTOPALS_SET2_AES_H_

#include <string>

namespace cryptopals {

// all AES `key` should be 128/192/256 bits.
class Aes {
 public:
  // `plaintext`/`ciphertext` needs to be aligned with 128-bit blocks.
  std::string static EcbEncrypt(std::string_view plaintext,
                                std::string_view key);
  std::string static EcbDecrypt(std::string_view ciphertext,
                                std::string_view key);

  // `plaintext`/`ciphertext` needs to be aligned with 128-bit blocks.
  // `iv` needs to be 128-bit long.
  std::string static CbcEncrypt(std::string_view plaintext,
                                std::string_view key, std::string_view iv);
  std::string static CbcDecrypt(std::string_view ciphertext,
                                std::string_view key, std::string_view iv);

  // No size limit on `plaintext`/`ciphertext`.
  // `nonce` is 32-bit, `iv` is 64-bit.
  // Counter will start from 1, details see https://tools.ietf.org/html/rfc3686
  std::string static CtrEncrypt(std::string_view plaintext,
                                std::string_view key, std::string_view nonce,
                                std::string_view iv);
  std::string static CtrDecrypt(std::string_view ciphertext,
                                std::string_view key, std::string_view nonce,
                                std::string_view iv);
};

}  // namespace cryptopals

#endif  // CRYPTOPALS_SET2_AES_H_
