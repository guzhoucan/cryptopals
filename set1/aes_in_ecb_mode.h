#ifndef CRYPTOPALS_SET1_AES_IN_ECB_MODE_H_
#define CRYPTOPALS_SET1_AES_IN_ECB_MODE_H_

#include <string>

namespace cryptopals {

std::string DecryptAesInEcbMode(std::string_view ciphertext,
                                std::string_view key);

}  // namespace cryptopals

#endif  // CRYPTOPALS_SET1_AES_IN_ECB_MODE_H_
