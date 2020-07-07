#include "single_byte_xor_cipher.h"

#include "fixed_xor.h"
#include "letter_frequency.h"

namespace cryptopals {

SingleByteXorPlaintext DecodeSingleByteXorCipher(std::string_view cipher_text) {
  SingleByteXorPlaintext result;
  double best_score = -DBL_MAX;
  for (uint32_t k = 0; k <= 0xff; k++) {
    std::string candidate =
        FixedXor(cipher_text, std::string(cipher_text.size(), k));
    double score = MessageAvgFreq(candidate);
    if (score > best_score) {
      best_score = score;
      result.key = k;
      result.plain_text = candidate;
    }
  }
  return result;
}

}  // namespace cryptopals