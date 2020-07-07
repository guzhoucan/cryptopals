#ifndef CRYPTOPALS_UTIL_LETTER_FREQUENCY_H_
#define CRYPTOPALS_UTIL_LETTER_FREQUENCY_H_

#include <string_view>

namespace cryptopals {

double CharFreq(char ch);

double MessageAvgFreq(std::string_view message);

}  // namespace cryptopals

#endif  // CRYPTOPALS_UTIL_LETTER_FREQUENCY_H_