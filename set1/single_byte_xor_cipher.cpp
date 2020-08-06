#include "single_byte_xor_cipher.h"

#include "fixed_xor.h"
#include "letter_frequency.h"

namespace cryptopals {

SingleByteXorPlaintext DecodeSingleByteXorCipher(std::string_view ciphertext) {
  SingleByteXorPlaintext result;
  result.score = std::numeric_limits<double>::lowest();
  for (uint32_t k = 0; k <= 0xff; k++) {
    std::string candidate =
        FixedXor(ciphertext, std::string(ciphertext.size(), k));
    double score = MessageAvgFreq(candidate);
    if (score > result.score) {
      result.score = score;
      result.key = k;
      result.plaintext = candidate;
    }
  }
  return result;
}

SingleByteXorPlaintext DetectSingleByteXorCipher(
    std::vector<std::string> ciphertexts) {
  SingleByteXorPlaintext best, current;
  best.score = std::numeric_limits<double>::lowest();
  for (int i = 0; i < ciphertexts.size(); i++) {
    current = DecodeSingleByteXorCipher(ciphertexts[i]);
    if (current.score > best.score) {
      best = current;
      best.pos = i;
    }
  }
  return best;
}

}  // namespace cryptopals