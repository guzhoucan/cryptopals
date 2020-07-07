#ifndef CRYPTOPALS_SET1_SINGLE_BYTE_XOR_CIPHER_H_
#define CRYPTOPALS_SET1_SINGLE_BYTE_XOR_CIPHER_H_

#include <cstdlib>
#include <string>
#include <string_view>

namespace cryptopals {

struct SingleByteXorPlaintext {
  uint8_t key;
  std::string plain_text;
};

SingleByteXorPlaintext DecodeSingleByteXorCipher(std::string_view cipher_text);

}  // namespace cryptopals

#endif  // CRYPTOPALS_SET1_SINGLE_BYTE_XOR_CIPHER_H_
