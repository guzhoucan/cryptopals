#ifndef CRYPTOPALS_AES_KEY_H_
#define CRYPTOPALS_AES_KEY_H_

#include <memory>
#include <string_view>
#include <utility>
#include <vector>

namespace cryptopals::aes {

// Terms see FIPS-197 5.2 Key Expansion
class KeySchedule {
 public:
  static std::unique_ptr<KeySchedule> ExpandKey(std::string_view key);

  std::vector<uint32_t> enc;
  std::vector<uint32_t> dec;  // FIPS-197 5.3.5 Equivalent Inverse Cipher
  uint nk;                    // Key Length (Nk words)
  uint nr;                    // Number of Rounds(Nr)
};

}  // namespace cryptopals::aes

#endif  // CRYPTOPALS_AES_KEY_H_
