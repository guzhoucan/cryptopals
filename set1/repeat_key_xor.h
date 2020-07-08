#ifndef CRYPTOPALS_SET1_REPEAT_KEY_XOR_H_
#define CRYPTOPALS_SET1_REPEAT_KEY_XOR_H_

#include <string>
#include <string_view>

namespace cryptopals {

std::string RepeatKeyXorEncode(std::string_view plain_text,
                               std::string_view key);

}  // namespace cryptopals

#endif  // CRYPTOPALS_SET1_REPEAT_KEY_XOR_H_
