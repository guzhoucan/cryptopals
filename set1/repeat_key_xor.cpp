#include "repeat_key_xor.h"

#include <algorithm>
#include <functional>
#include <queue>
#include <vector>

#include "single_byte_xor_cipher.h"

namespace cryptopals {

namespace {

template <class T>
using min_heap = std::priority_queue<T, std::vector<T>, std::greater<T>>;

constexpr uint8_t kMinKeySize = 2;
constexpr uint8_t kMaxKeySize = 40;
constexpr uint8_t kMaxBlobsCount = 4;
constexpr uint8_t kKeySizeCandidateCount = 3;

uint8_t CountSetBits(uint8_t n) {
  uint8_t count = 0;
  while (n) {
    count += n & 1u;
    n >>= 1u;
  }
  return count;
}

struct KeySize {
  uint8_t size;
  double hamming_dist;  // average dist per key byte
  bool operator<(const KeySize& rhs) const {
    return hamming_dist != rhs.hamming_dist ? hamming_dist < rhs.hamming_dist
                                            : size < rhs.size;
  }
  bool operator>(const KeySize& rhs) const {
    return hamming_dist != rhs.hamming_dist ? hamming_dist > rhs.hamming_dist
                                            : size > rhs.size;
    ;
  }
};

// Return guesses for key size in a min-heap of Hamming distance.
min_heap<KeySize> GuessKeySize(std::string_view ciphertext) {
  min_heap<KeySize> output;
  for (uint8_t s = kMinKeySize; s <= kMaxKeySize; s++) {
    // if key size is longer than half of the `ciphertext`, we cannot make a
    // valid guess since we need at least 2 blobs to discover the repeating
    // pattern.
    if (ciphertext.size() / s < 2) {
      break;
    }
    // split the ciphertext into blobs of size `s`
    std::vector<std::string> blobs(
        std::max(static_cast<uint8_t>(ciphertext.size() / s), kMaxBlobsCount));
    for (int i = 0; i < blobs.size(); i++) {
      blobs.emplace_back(ciphertext.substr(i * s, s));
    }
    // calculate the average hamming dist between blobs
    uint64_t total_dist = 0;
    for (int i = 0; i < blobs.size() - 1; i++) {
      total_dist += GetHammingDistance(blobs[i], blobs[i + 1]);
    }
    // `avg_dist` is avg dist between two blobs, KeySize.hamming_dist is the
    // average of distance PER BYTE, so we need to divide by key size `s`
    // again.
    double avg_dist =
        static_cast<double>(total_dist) / static_cast<double>(blobs.size() - 1);
    output.emplace(KeySize{s, avg_dist / s});
  }
  return output;
}

}  // namespace

uint32_t GetHammingDistance(std::string_view str1, std::string_view str2) {
  uint32_t dist = 0;
  for (int i = 0; i < str1.size(); i++) {
    uint8_t xor_result =
        static_cast<uint8_t>(str1[i]) ^ static_cast<uint8_t>(str2[i]);
    dist += CountSetBits(xor_result);
  }
  return dist;
}

std::string RepeatKeyXorEncode(std::string_view plaintext,
                               std::string_view key) {
  std::string output;
  output.resize(plaintext.size());
  for (int i = 0; i < plaintext.size(); i++) {
    output[i] = static_cast<uint8_t>(plaintext[i]) ^
                static_cast<uint8_t>(key[i % key.size()]);
  }
  return output;
}

std::string RepeatKeyXorDecode(std::string_view ciphertext,
                               std::string_view key) {
  return RepeatKeyXorEncode(ciphertext, key);
}

BreakRepeatKeyXorOutput BreakRepeatKeyXor(std::string_view ciphertext) {
  BreakRepeatKeyXorOutput best;
  best.score = std::numeric_limits<double>::lowest();
  auto key_guesses = GuessKeySize(ciphertext);
  int max_tries = std::min(key_guesses.size(), (size_t)kKeySizeCandidateCount);
  for (int tries = 0; tries < max_tries; tries++, key_guesses.pop()) {
    double total_score = 0;
    std::string key;
    auto key_guess = key_guesses.top();
    std::vector<std::string> single_key_ciphertexts;
    single_key_ciphertexts.resize(key_guess.size);
    for (int i = 0; i < ciphertext.size(); i++) {
      single_key_ciphertexts[i % key_guess.size] += ciphertext[i];
    }
    for (const auto& single_key_ciphertext : single_key_ciphertexts) {
      SingleByteXorPlaintext plaintext =
          DecodeSingleByteXorCipher(single_key_ciphertext);
      key += plaintext.key;
      total_score += plaintext.score * plaintext.plaintext.size();
    }
    double avg_score = total_score / ciphertext.size();
    if (avg_score > best.score) {
      best.key = key;
      best.score = avg_score;
    }
  }
  best.plaintext = RepeatKeyXorDecode(ciphertext, best.key);
  return best;
}

}  // namespace cryptopals
