#include "letter_frequency.h"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>

#include "absl/container/flat_hash_map.h"

namespace cryptopals {
namespace {

constexpr double kInvalidCharPenalty = -0.1;

absl::flat_hash_map<unsigned char, double>* CreateCharFreqMap() {
  auto* map = new absl::flat_hash_map<unsigned char, double>();
  std::ifstream file("1984.txt", std::ios::in);
  if (!file.is_open()) {
    std::cerr << "Cannot open file 1984.txt\n";
    std::abort();
  }
  std::stringstream ss;
  ss << file.rdbuf();
  std::string text = ss.str();

  for (const unsigned char c : text) {
    (*map)[c] += 1.0;
  }
  for (auto& [character, freq] : *map) {
    freq /= text.size();
  }
  return map;
}

const absl::flat_hash_map<unsigned char, double>* GetCharFreqMap() {
  // Function static initialization is thread safe after c++11. No destructor
  // is ever run.
  static absl::flat_hash_map<unsigned char, double>* char_freq_map =
      CreateCharFreqMap();
  return char_freq_map;
}

}  // namespace

double CharFreq(unsigned char ch) {
  // Note: Be aware do NOT use `auto map = *GetCharFreqMap()`, it will create
  // a copy each time.
  const auto* freq_map = GetCharFreqMap();
  auto it = freq_map->find(ch);
  if (it != freq_map->end()) {
    return it->second;
  } else {
    return kInvalidCharPenalty;
  }
}

double MessageAvgFreq(std::string_view message) {
  double score = 0;
  for (const auto& ch : message) {
    score += CharFreq(ch);
  }
  return score / message.size();
}

}  // namespace cryptopals