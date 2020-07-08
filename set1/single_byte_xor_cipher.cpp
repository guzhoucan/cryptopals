#include "single_byte_xor_cipher.h"

#include "fixed_xor.h"
#include "letter_frequency.h"

namespace cryptopals {

SingleByteXorPlaintext DecodeSingleByteXorCipher(std::string_view cipher_text) {
  SingleByteXorPlaintext result;
  result.score = -DBL_MAX;
  for (uint32_t k = 0; k <= 0xff; k++) {
    std::string candidate =
        FixedXor(cipher_text, std::string(cipher_text.size(), k));
    double score = MessageAvgFreq(candidate);
    if (score > result.score) {
      result.score = score;
      result.key = k;
      result.plain_text = candidate;
    }
  }
  return result;
}

SingleByteXorPlaintext DetectSingleByteXorCipher(
    std::vector<std::string> cipher_texts) {
  SingleByteXorPlaintext best, current;
  best.score = -DBL_MAX;
  for (int i = 0; i < cipher_texts.size(); i++) {
    current = DecodeSingleByteXorCipher(cipher_texts[i]);
    if (current.score > best.score) {
      best = current;
      best.pos = i;
    }
  }
  return best;
}

}  // namespace cryptopals