#include "cipher.h"

#include <stdexcept>

#include "base.h"

namespace cryptopals::aes {
namespace {

constexpr int kBlockSize = 16;  // 128-bit block

// FIPS-197 5.1.3 MixColumns() Transformation
uint32_t MixColumn(uint32_t s) {
  uint8_t b0 = s >> 24u;
  uint8_t b1 = s >> 16u;
  uint8_t b2 = s >> 8u;
  uint8_t b3 = s;
  uint8_t t1 = Mul(0x02u, b0) ^ Mul(0x03u, b1) ^ b2 ^ b3;
  uint8_t t2 = b0 ^ Mul(0x02u, b1) ^ Mul(0x03u, b2) ^ b3;
  uint8_t t3 = b0 ^ b1 ^ Mul(0x02u, b2) ^ Mul(0x03u, b3);
  uint8_t t4 = Mul(0x03u, b0) ^ b1 ^ b2 ^ Mul(0x02u, b3);
  return (uint32_t)t1 << 24u | (uint32_t)t2 << 16u | (uint32_t)t3 << 8u |
         (uint32_t)t4;
}

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
  uint32_t t0, t1, t2, t3;

  for (uint round = 1; round < ks->nr; round++) {
    // SubBytes
    s0 = SubWord(s0);
    s1 = SubWord(s1);
    s2 = SubWord(s2);
    s3 = SubWord(s3);
    // ShiftRows
    // s0[0] s1[0] s2[0] s3[0] ---> s0[0] s1[0] s2[0] s3[0]
    // s0[1] s1[1] s2[1] s3[1] ---> s1[1] s2[1] s3[1] s0[1]
    // s0[2] s1[2] s2[2] s3[2] ---> s2[2] s3[2] s0[2] s1[2]
    // s0[3] s1[3] s2[3] s3[3] ---> s3[3] s0[3] s1[3] s2[3]
    //  s0    s1    s2    s3         t0    t1    t2    t3
    t0 = s0 & 0xff000000u | s1 & 0x00ff0000u | s2 & 0x0000ff00u |
         s3 & 0x000000ffu;
    t1 = s1 & 0xff000000u | s2 & 0x00ff0000u | s3 & 0x0000ff00u |
         s0 & 0x000000ffu;
    t2 = s2 & 0xff000000u | s3 & 0x00ff0000u | s0 & 0x0000ff00u |
         s1 & 0x000000ffu;
    t3 = s3 & 0xff000000u | s0 & 0x00ff0000u | s1 & 0x0000ff00u |
         s2 & 0x000000ffu;
    s0 = t0;
    s1 = t1;
    s2 = t2;
    s3 = t3;
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
  t0 =
      s0 & 0xff000000u | s1 & 0x00ff0000u | s2 & 0x0000ff00u | s3 & 0x000000ffu;
  t1 =
      s1 & 0xff000000u | s2 & 0x00ff0000u | s3 & 0x0000ff00u | s0 & 0x000000ffu;
  t2 =
      s2 & 0xff000000u | s3 & 0x00ff0000u | s0 & 0x0000ff00u | s1 & 0x000000ffu;
  t3 =
      s3 & 0xff000000u | s0 & 0x00ff0000u | s1 & 0x0000ff00u | s2 & 0x000000ffu;
  s0 = t0;
  s1 = t1;
  s2 = t2;
  s3 = t3;
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

// TODO: decrypt
std::string AesCipher::Decrypt(std::string_view ciphertext) { return ""; }

}  // namespace cryptopals::aes