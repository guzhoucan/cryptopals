#ifndef CRYPTOPALS_SET1_FIXED_XOR_H_
#define CRYPTOPALS_SET1_FIXED_XOR_H_

#include <string>
#include <string_view>

namespace cryptopals {

// This method produces a XOR result of two binary strings (at the granularity
// of one byte). XOR result will only be calculated against the first min(str1
// .size(), str2.size()) bytes if str1 and str2 have different length.
std::string FixedXor(std::string_view str1, std::string_view str2);

}  // namespace cryptopals

#endif  // CRYPTOPALS_SET1_FIXED_XOR_H_