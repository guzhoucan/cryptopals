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

}  // namespace cryptopals::aes