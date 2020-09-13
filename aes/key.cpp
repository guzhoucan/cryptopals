#include "key.h"

#include <stdexcept>

#include "base.h"

namespace cryptopals::aes {
namespace {

// FIPS-197 Figure 11. Pseudo Code for Key Expansion.
void ExpandEnc(std::vector<uint32_t>* enc, const uint8_t* key,
               uint nk,  // Key Length (Nk words)
               uint nr   // Number of Rounds(Nr)
) {
  for (uint i = 0; i < nk; i++) {
    (*enc)[i] = GetU32(key + i * 4);
  }
  uint32_t temp;
  for (uint i = nk; i < 4 * (nr + 1); i++) {
    temp = (*enc)[i - 1];
    if (i % nk == 0) {
      // Rcon[i] = kPowX[i - 1]
      temp = SubWord(RotWord(temp)) ^ ((uint32_t)kPowX[i / nk - 1]) << 24u;
    } else if (nk > 6 && i % nk == 4) {
      temp = SubWord(temp);
    }
    (*enc)[i] = (*enc)[i - nk] ^ temp;
  }
}

}  // namespace

std::unique_ptr<KeySchedule> KeySchedule::ExpandKey(std::string_view key) {
  auto ks = std::make_unique<KeySchedule>();
  // FIPS-197 Figure 4. Key-Block-Round Combinations.
  uint nk;  // Key Length (Nk words)
  uint nr;  // Number of Rounds(Nr)
  switch (key.size()) {
    case 16:  // 128 bit
      nk = 4;
      nr = 10;
      break;
    case 24:  // 192 bit
      nk = 6;
      nr = 12;
      break;
    case 32:  // 256 bit
      nk = 8;
      nr = 14;
      break;
    default:
      throw std::invalid_argument("invalid key size");
  }

  ks->enc.resize(4 * (nr + 1));
  ks->dec.resize(4 * (nr + 1));
  ExpandEnc(&ks->enc, reinterpret_cast<const uint8_t*>(key.data()), nk, nr);
  // TODO: populate dec

  return std::move(ks);
}

}  // namespace cryptopals::aes
