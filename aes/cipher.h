#ifndef CRYPTOPALS_AES_CIPHER_H_
#define CRYPTOPALS_AES_CIPHER_H_

#include <memory>
#include <string>
#include <string_view>

#include "key.h"

namespace cryptopals::aes {

class AesCipher {
 public:
  static std::unique_ptr<AesCipher> Create(std::string_view key);
  explicit AesCipher(std::unique_ptr<KeySchedule> key_schedule)
      : ks(std::move(key_schedule)) {}

  std::string Encrypt(std::string_view plaintext);
  std::string Decrypt(std::string_view ciphertext);
  std::string EquivDecrypt(std::string_view ciphertext);

 private:
  std::unique_ptr<KeySchedule> ks;
};

}  // namespace cryptopals::aes

#endif  // CRYPTOPALS_AES_CIPHER_H_
