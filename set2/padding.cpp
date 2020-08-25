#include "padding.h"

#include <cassert>

namespace cryptopals {

// https://tools.ietf.org/html/rfc2315#section-10.3
std::string Padding::Pkcs7Encode(std::string_view input, uint8_t block_size) {
  assert(block_size > 1);
  uint8_t pad = block_size - input.size() % block_size;
  std::string tail(/*size=*/pad, /*char=*/pad);
  return std::string(input) + tail;
}

std::string Padding::Pkcs7Decode(std::string_view input) {
  auto padding_length = static_cast<uint8_t>(input.back());
  return std::string(input.substr(0, input.size() - padding_length));
}

}  // namespace cryptopals