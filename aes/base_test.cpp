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

// Check that S-boxes are inverses of each other.
TEST(BaseTest, SBoxes) {
  for (uint16_t i = 0; i < 0x100; i++) {
    EXPECT_EQ(i, kSBox1[kSBox0[i]]);
    EXPECT_EQ(i, kSBox0[kSBox1[i]]);
  }
}

TEST(BaseTest, PutU32) {
  uint8_t addr[4];
  PutU32(uint32_t(0x01020304), addr);
  EXPECT_EQ(0x01, addr[0]);
  EXPECT_EQ(0x02, addr[1]);
  EXPECT_EQ(0x03, addr[2]);
  EXPECT_EQ(0x04, addr[3]);
}

TEST(BaseTest, GetU32) {
  uint8_t addr[4];
  addr[0] = 0x01;
  addr[1] = 0x02;
  addr[2] = 0x03;
  addr[3] = 0x04;
  EXPECT_EQ(0x01020304u, GetU32(addr));
}

TEST(BaseTest, SubWord) { EXPECT_EQ(0x8a84eb01u, SubWord(0xcf4f3c09u)); }

TEST(BaseTest, InvSubWord) { EXPECT_EQ(0xcf4f3c09u, InvSubWord(0x8a84eb01u)); }

TEST(BaseTest, RotWord) { EXPECT_EQ(0x02030401u, RotWord(0x01020304u)); }

}  // namespace
}  // namespace cryptopals::aes