#include "cipher.h"

#include <stdexcept>

#include "base.h"

namespace cryptopals::aes {
namespace {

constexpr int kBlockSize = 16;  // 128-bit block

}  // namespace

std::unique_ptr<AesCipher> AesCipher::Create(std::string_view key) {
  return std::make_unique<AesCipher>(KeySchedule::ExpandKey(key));
}

// FIPS-197 Figure 5. Pseudo Code for the Cipher.
std::string AesCipher::Encrypt(std::string_view plaintext) {
  if (plaintext.size() != kBlockSize) {
    throw std::invalid_argument("invalid plaintext size");
  }
  const auto* in = (uint8_t*)plaintext.data();

  // FIPS-197 Figure 3. State array input and output.
  // s[n] is the n-th column

  // Initial AddRoundKey
  uint32_t s0 = GetU32(in) ^ ks->enc[0];
  uint32_t s1 = GetU32(in + 4) ^ ks->enc[1];
  uint32_t s2 = GetU32(in + 8) ^ ks->enc[2];
  uint32_t s3 = GetU32(in + 12) ^ ks->enc[3];

  for (uint round = 1; round < ks->nr; round++) {
    // SubBytes
    s0 = SubWord(s0);
    s1 = SubWord(s1);
    s2 = SubWord(s2);
    s3 = SubWord(s3);
    // ShiftRows
    auto t = ShiftRows({s0, s1, s2, s3});
    s0 = t[0];
    s1 = t[1];
    s2 = t[2];
    s3 = t[3];
    // MixColumns
    s0 = MixColumn(s0);
    s1 = MixColumn(s1);
    s2 = MixColumn(s2);
    s3 = MixColumn(s3);
    // AddRoundKey
    s0 ^= ks->enc[4 * round];
    s1 ^= ks->enc[4 * round + 1];
    s2 ^= ks->enc[4 * round + 2];
    s3 ^= ks->enc[4 * round + 3];
  }

  // Final round:
  // SubBytes
  s0 = SubWord(s0);
  s1 = SubWord(s1);
  s2 = SubWord(s2);
  s3 = SubWord(s3);
  // ShiftRows
  auto t = ShiftRows({s0, s1, s2, s3});
  s0 = t[0];
  s1 = t[1];
  s2 = t[2];
  s3 = t[3];
  // AddRoundKey
  s0 ^= ks->enc[4 * ks->nr];
  s1 ^= ks->enc[4 * ks->nr + 1];
  s2 ^= ks->enc[4 * ks->nr + 2];
  s3 ^= ks->enc[4 * ks->nr + 3];

  // Store state back to memory with big-endian
  uint8_t state[kBlockSize];
  PutU32(s0, state);
  PutU32(s1, state + 4);
  PutU32(s2, state + 8);
  PutU32(s3, state + 12);

  return std::string(reinterpret_cast<const char*>(state), kBlockSize);
}

// FIPS-197 Figure 12. Pseudo Code for the Inverse Cipher
std::string AesCipher::Decrypt(std::string_view ciphertext) {
  if (ciphertext.size() != kBlockSize) {
    throw std::invalid_argument("invalid plaintext size");
  }
  const auto* in = (uint8_t*)ciphertext.data();

  // FIPS-197 Figure 3. State array input and output.
  // s[n] is the n-th column

  // AddRoundKey
  uint32_t s0 = GetU32(in) ^ ks->enc[4 * ks->nr];
  uint32_t s1 = GetU32(in + 4) ^ ks->enc[4 * ks->nr + 1];
  uint32_t s2 = GetU32(in + 8) ^ ks->enc[4 * ks->nr + 2];
  uint32_t s3 = GetU32(in + 12) ^ ks->enc[4 * ks->nr + 3];

  for (uint round = ks->nr - 1; round > 0; round--) {
    // InvShiftRows
    auto t = InvShiftRows({s0, s1, s2, s3});
    s0 = t[0];
    s1 = t[1];
    s2 = t[2];
    s3 = t[3];
    // InvSubBytes
    s0 = InvSubWord(s0);
    s1 = InvSubWord(s1);
    s2 = InvSubWord(s2);
    s3 = InvSubWord(s3);
    // AddRoundKey
    s0 ^= ks->enc[4 * round];
    s1 ^= ks->enc[4 * round + 1];
    s2 ^= ks->enc[4 * round + 2];
    s3 ^= ks->enc[4 * round + 3];
    // InvMixColumns
    s0 = InvMixColumn(s0);
    s1 = InvMixColumn(s1);
    s2 = InvMixColumn(s2);
    s3 = InvMixColumn(s3);
  }

  // InvShiftRows
  auto t = InvShiftRows({s0, s1, s2, s3});
  s0 = t[0];
  s1 = t[1];
  s2 = t[2];
  s3 = t[3];
  // InvSubBytes
  s0 = InvSubWord(s0);
  s1 = InvSubWord(s1);
  s2 = InvSubWord(s2);
  s3 = InvSubWord(s3);
  // AddRoundKey
  s0 ^= ks->enc[0];
  s1 ^= ks->enc[1];
  s2 ^= ks->enc[2];
  s3 ^= ks->enc[3];

  // Store state back to memory with big-endian
  uint8_t state[kBlockSize];
  PutU32(s0, state);
  PutU32(s1, state + 4);
  PutU32(s2, state + 8);
  PutU32(s3, state + 12);

  return std::string(reinterpret_cast<const char*>(state), kBlockSize);
}

}  // namespace cryptopals::aes