#include "rand_util.h"

#include <algorithm>
#include <climits>
#include <random>

namespace cryptopals::util {

std::string RandStr(uint8_t length) {
  std::independent_bits_engine<std::default_random_engine, CHAR_BIT,
                               unsigned char>
      random_byte_engine(std::random_device{}());
  std::string str(length, 0);
  std::generate(str.begin(), str.end(), random_byte_engine);
  return str;
}

}  // namespace cryptopals::util