#include "base.h"

#include "gtest/gtest.h"

namespace cryptopals::aes {
namespace {

TEST(BaseTest, PowX) {
  uint16_t pow_x = 1;
  for (int i = 0; i < sizeof(kPowX); i++) {
    EXPECT_EQ(kPowX[i], pow_x & 0xffu);
    pow_x <<= 1u;
    // if pow_x has x^8 term, minus(XOR) kPoly to reduce the highest term
    // within x^7
    if (pow_x & 0x100u) {
      pow_x ^= kPoly;
      pow_x &= 0x00ffu;  // optional, higher 8-bit is never used in comparison.
    }
  }
}

TEST(BaseTest, Mul) {
  // Calculate multiplication for all the possible `a` and `b` input
  for (uint16_t a = 0; a < 0x100; a++) {
    for (uint16_t b = 0; b < 0x100; b++) {
      // Multiply a, b bit by bit
      uint8_t product = 0;
      for (uint j = 0; j < 8; j++) {
        for (uint k = 0; k < 8; k++) {
          // It's like a polynomial multiply expansion:
          // If a has term (1 *) x^j and b has term (1 *) x^k, then product
          // will contain term (1 *) x^(j+k).
          // Add (XOR) all temporary products together to get the final product.
          if ((a & 1u << j) && (b & 1u << k)) {
            product ^= kPowX[j + k];
          }
        }
      }
      // Verify the expected `product` can be returned from function `Mul`
      EXPECT_EQ(product, Mul(a, b));
    }
  }
}

}  // namespace
}  // namespace cryptopals::aes