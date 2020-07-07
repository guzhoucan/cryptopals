#include "fixed_xor.h"

#include <algorithm>

namespace cryptopals {

std::string FixedXor(std::string_view str1, std::string_view str2) {
  size_t size = std::min(str1.size(), str2.size());
  std::string output;
  for (size_t i = 0; i < size; i++) {
    output.push_back((unsigned char)str1.at(i) ^ (unsigned char)str2.at(i));
  }
  return output;
}

}  // namespace cryptopals