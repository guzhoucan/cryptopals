#include "letter_frequency.h"

#include <unordered_map>

#include "absl/strings/escaping.h"

namespace cryptopals {
namespace {

constexpr double kInvalidCharPenalty = -10.0;
constexpr double kRareCharWeight = 0.01;

// https://en.wikipedia.org/wiki/Letter_frequency
std::unordered_map<char, double> char_freq_map = {
    {'a', 8.497}, {'b', 1.492}, {'c', 2.202}, {'d', 4.253}, {'e', 11.162},
    {'f', 2.228}, {'g', 2.015}, {'h', 6.094}, {'i', 7.546}, {'j', 0.153},
    {'k', 1.292}, {'l', 4.025}, {'m', 2.406}, {'n', 6.749}, {'o', 7.507},
    {'p', 1.929}, {'q', 0.095}, {'r', 7.587}, {'s', 6.327}, {'t', 9.356},
    {'u', 2.758}, {'v', 0.978}, {'w', 2.560}, {'x', 0.150}, {'y', 1.994},
    {'z', 0.077}};

// Special characters with higher weight comparing to least common
// char in alphabet (z). Weights are set arbitrarily (partially according to
// http://millikeys.sourceforge.net/freqanalysis.html)
std::unordered_map<char, double> special_freq_map = {
    {' ', 20},  {',', 1.5},  {'.', 1.5},  {'"', 0.8}, {'\'', 0.6},
    {'-', 0.3}, {'?', 0.15}, {';', 0.08}, {'!', 0.08}};

}  // namespace

double CharFreq(char ch) {
  if (!absl::ascii_isprint(ch)) {
    return kInvalidCharPenalty;
  }
  if (absl::ascii_isalpha(ch)) {
    return char_freq_map[absl::ascii_tolower(ch)];
  }
  auto it = special_freq_map.find(ch);
  if (it != special_freq_map.end()) {
    return it->second;
  }
  return kRareCharWeight;
}

double MessageAvgFreq(std::string_view message) {
  double score = 0;
  for (const auto& ch : message) {
    score += CharFreq(ch);
  }
  return score / message.size();
}

}  // namespace cryptopals