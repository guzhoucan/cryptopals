#ifndef CRYPTOPALS_SET1_SINGLE_BYTE_XOR_CIPHER_H_
#define CRYPTOPALS_SET1_SINGLE_BYTE_XOR_CIPHER_H_

#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

namespace cryptopals {

struct SingleByteXorPlaintext {
  uint8_t key;
  std::string plain_text;
  double score;  // averaged score per character
  size_t pos;    // only used in DetectSingleByteXorCipher
};

SingleByteXorPlaintext DecodeSingleByteXorCipher(std::string_view cipher_text);

SingleByteXorPlaintext DetectSingleByteXorCipher(
    std::vector<std::string> cipher_texts);

}  // namespace cryptopals

#endif  // CRYPTOPALS_SET1_SINGLE_BYTE_XOR_CIPHER_H_
