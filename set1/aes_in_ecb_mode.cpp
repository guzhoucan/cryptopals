#include "aes_in_ecb_mode.h"

#include <openssl/aes.h>

#include <cstdlib>
#include <iostream>

namespace cryptopals {

std::string DecryptAesInEcbMode(std::string_view ciphertext,
                                std::string_view key) {
  AES_KEY aes_key;
  if (0 !=
      AES_set_decrypt_key(reinterpret_cast<const unsigned char*>(key.data()),
                          static_cast<int>(key.size()) * 8, &aes_key)) {
    std::cerr << "Invalid key: " << key << std::endl;
    std::abort();
  }

  std::string plaintext(ciphertext.size(), 0);

  for (size_t i = 0; i < ciphertext.size(); i += 16) {
    const auto* in = reinterpret_cast<const unsigned char*>(&ciphertext[i]);
    auto* out = reinterpret_cast<unsigned char*>(&plaintext[i]);
    AES_decrypt(in, out, &aes_key);
  }

  // PKCS5 padding
  auto padding_length = static_cast<uint8_t>(plaintext.back());
  plaintext.resize(plaintext.size() - padding_length);

  return plaintext;
}

}  // namespace cryptopals