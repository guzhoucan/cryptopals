#include "base.h"

namespace cryptopals::aes {

// See FIPS-197 4.2 Multiplication
// For example, {57} * {13} = {fe} because
// {57} * {02} = xtime({57}) = {ae}
// {57} * {04} = xtime({ae}) = {47}
// {57} * {08} = xtime({47}) = {8e}
// {57} * {10} = xtime({8e}) = {07},
// thus,
// {57} * {13} = {57} * ({01} + {02} + {10})
//             = {57} * {ae} * {07}
//             = {fe}
// imagine a = {57}, b = {13}, pow_a = {57}/{ae}/{07} in the following code
uint8_t Mul(uint8_t a, uint8_t b) {
  uint16_t product = 0;
  uint16_t pow_a = a;
  for (uint16_t bit = 0x01; bit < 0x100; bit <<= 1u) {
    // Invariant: bit == 1 << n, pow_a == a * x^n
    if (b & bit) {
      // if b has term x^n, result will contain a * x^n
      product ^= pow_a;
    }
    // pow_a *= x in GF(2^8) modulo kPoly
    pow_a <<= 1u;
    if (pow_a & 0x100u) {
      pow_a ^= kPoly;
      pow_a &= 0x00ffu;  // optional, higher 8-bit is never used.
    }
  }
  return product;
}

uint32_t GetU32(const uint8_t* addr) {
  return ((uint32_t)addr[0] << 24u) | ((uint32_t)addr[1] << 16u) |
         ((uint32_t)(addr)[2] << 8u) | ((uint32_t)(addr)[3]);
}
void PutU32(uint32_t val, uint8_t* addr) {
  addr[0] = (uint8_t)(val >> 24u);
  addr[1] = (uint8_t)(val >> 16u);
  addr[2] = (uint8_t)(val >> 8u);
  addr[3] = (uint8_t)val;
}

uint32_t SubWord(uint32_t word) {
  return ((uint32_t)kSBox0[(uint8_t)(word >> 24u)] << 24u) |
         ((uint32_t)kSBox0[(uint8_t)(word >> 16u)] << 16u) |
         ((uint32_t)kSBox0[(uint8_t)(word >> 8u)] << 8u) |
         ((uint32_t)kSBox0[(uint8_t)word]);
}

uint32_t InvSubWord(uint32_t word) {
  return ((uint32_t)kSBox1[(uint8_t)(word >> 24u)] << 24u) |
         ((uint32_t)kSBox1[(uint8_t)(word >> 16u)] << 16u) |
         ((uint32_t)kSBox1[(uint8_t)(word >> 8u)] << 8u) |
         ((uint32_t)kSBox1[(uint8_t)word]);
}

uint32_t RotWord(uint32_t word) { return word << 8u | word >> 24u; }

// FIPS-197 5.1.2 ShiftRows() Transformation
// s[0][0] s[1][0] s[2][0] s[3][0] ---> s[0][0] s[1][0] s[2][0] s[3][0]
// s[0][1] s[1][1] s[2][1] s[3][1] ---> s[1][1] s[2][1] s[3][1] s[0][1]
// s[0][2] s[1][2] s[2][2] s[3][2] ---> s[2][2] s[3][2] s[0][2] s[1][2]
// s[0][3] s[1][3] s[2][3] s[3][3] ---> s[3][3] s[0][3] s[1][3] s[2][3]
//    s0      s1      s2      s3          t0      t1      t2      t3
std::array<uint32_t, 4> ShiftRows(const std::array<uint32_t, 4> s) {
  uint32_t t0, t1, t2, t3;
  t0 = s[0] & 0xff000000u | s[1] & 0x00ff0000u | s[2] & 0x0000ff00u |
       s[3] & 0x000000ffu;
  t1 = s[1] & 0xff000000u | s[2] & 0x00ff0000u | s[3] & 0x0000ff00u |
       s[0] & 0x000000ffu;
  t2 = s[2] & 0xff000000u | s[3] & 0x00ff0000u | s[0] & 0x0000ff00u |
       s[1] & 0x000000ffu;
  t3 = s[3] & 0xff000000u | s[0] & 0x00ff0000u | s[1] & 0x0000ff00u |
       s[2] & 0x000000ffu;
  return std::array<uint32_t, 4>{t0, t1, t2, t3};
}

// FIPS-197 5.3.1 InvShiftRows() Transformation
// s[0][0] s[1][0] s[2][0] s[3][0] ---> s[0][0] s[1][0] s[2][0] s[3][0]
// s[0][1] s[1][1] s[2][1] s[3][1] ---> s[3][1] s[0][1] s[1][1] s[2][1]
// s[0][2] s[1][2] s[2][2] s[3][2] ---> s[2][2] s[3][2] s[0][2] s[1][2]
// s[0][3] s[1][3] s[2][3] s[3][3] ---> s[1][3] s[2][3] s[3][3] s[0][3]
//    s0      s1      s2      s3          t0      t1      t2      t3
std::array<uint32_t, 4> InvShiftRows(const std::array<uint32_t, 4> s) {
  uint32_t t0, t1, t2, t3;
  t0 = s[0] & 0xff000000u | s[3] & 0x00ff0000u | s[2] & 0x0000ff00u |
       s[1] & 0x000000ffu;
  t1 = s[1] & 0xff000000u | s[0] & 0x00ff0000u | s[3] & 0x0000ff00u |
       s[2] & 0x000000ffu;
  t2 = s[2] & 0xff000000u | s[1] & 0x00ff0000u | s[0] & 0x0000ff00u |
       s[3] & 0x000000ffu;
  t3 = s[3] & 0xff000000u | s[2] & 0x00ff0000u | s[1] & 0x0000ff00u |
       s[0] & 0x000000ffu;
  return std::array<uint32_t, 4>{t0, t1, t2, t3};
}

// FIPS-197 5.1.3 MixColumns() Transformation
// Equivalent in math to:
// a(x) = {03}x^3 + {01}x^2 + {01}x + {02}
// return a(x) * s(x)
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

// FIPS-197 5.3.3 InvMixColumns() Transformation
// Equivalent in math to:
// a^-1(x) = {0b}x^3 + {0d}x^2 + {09}x + {0e}
// return a^-1(x) * s(x)
uint32_t InvMixColumn(uint32_t s) {
  uint8_t b0 = s >> 24u;
  uint8_t b1 = s >> 16u;
  uint8_t b2 = s >> 8u;
  uint8_t b3 = s;
  uint8_t t1 =
      Mul(0x0eu, b0) ^ Mul(0x0bu, b1) ^ Mul(0x0du, b2) ^ Mul(0x09u, b3);
  uint8_t t2 =
      Mul(0x09u, b0) ^ Mul(0x0eu, b1) ^ Mul(0x0bu, b2) ^ Mul(0x0du, b3);
  uint8_t t3 =
      Mul(0x0du, b0) ^ Mul(0x09u, b1) ^ Mul(0x0eu, b2) ^ Mul(0x0bu, b3);
  uint8_t t4 =
      Mul(0x0bu, b0) ^ Mul(0x0du, b1) ^ Mul(0x09u, b2) ^ Mul(0x0eu, b3);
  return (uint32_t)t1 << 24u | (uint32_t)t2 << 16u | (uint32_t)t3 << 8u |
         (uint32_t)t4;
}

}  // namespace cryptopals::aes