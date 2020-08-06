#ifndef CRYPTOPALS_SET1_REPEAT_KEY_XOR_H_
#define CRYPTOPALS_SET1_REPEAT_KEY_XOR_H_

#include <string>
#include <string_view>

namespace cryptopals {

struct BreakRepeatKeyXorOutput {
  std::string key;
  std::string plaintext;
  double score;  // averaged score per character
};

uint32_t GetHammingDistance(std::string_view str1, std::string_view str2);

std::string RepeatKeyXorEncode(std::string_view plaintext,
                               std::string_view key);

std::string RepeatKeyXorDecode(std::string_view ciphertext,
                               std::string_view key);

BreakRepeatKeyXorOutput BreakRepeatKeyXor(std::string_view ciphertext);

}  // namespace cryptopals

#endif  // CRYPTOPALS_SET1_REPEAT_KEY_XOR_H_
