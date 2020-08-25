#ifndef CRYPTOPALS_SET2_PADDING_H_
#define CRYPTOPALS_SET2_PADDING_H_

#include <string>
#include <string_view>

namespace cryptopals {

class Padding {
 public:
  static std::string Pkcs7Encode(std::string_view input, uint8_t block_size);
  static std::string Pkcs7Decode(std::string_view input);
};

}  // namespace cryptopals

#endif  // CRYPTOPALS_SET2_PADDING_H_
