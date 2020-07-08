#include "repeat_key_xor.h"

namespace cryptopals {

std::string RepeatKeyXorEncode(std::string_view plain_text,
                               std::string_view key) {
  std::string output;
  output.resize(plain_text.size());
  for (int i = 0; i < plain_text.size(); i++) {
    output[i] = (uint8_t)plain_text[i] ^ (uint8_t)key[i % key.size()];
  }
  return output;
}

}  // namespace cryptopals
