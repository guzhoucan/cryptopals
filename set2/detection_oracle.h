#ifndef CRYPTOPALS_SET2_DETECTION_ORACLE_H_
#define CRYPTOPALS_SET2_DETECTION_ORACLE_H_

#include <string>
#include <string_view>

namespace cryptopals {

enum class CipherMode { ECB, CBC };

std::string EncryptionOracle(std::string_view input);

// For testing
std::string EncryptionOracleWithMode(std::string_view input, CipherMode mode);

CipherMode DetectMode(std::string_view ciphertext);

}  // namespace cryptopals

#endif  // CRYPTOPALS_SET2_DETECTION_ORACLE_H_
