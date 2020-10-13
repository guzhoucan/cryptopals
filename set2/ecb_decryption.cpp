#include <absl/strings/escaping.h>
#include <gtest/gtest.h>

#include <fstream>

#include "aes.h"
#include "padding.h"
#include "rand_util.h"

namespace cryptopals {
namespace {

constexpr std::string_view kUnknownStrFilename = "unknown_str.txt";

std::string ReadBase64File(std::string_view filename) {
  std::ifstream file(filename.data(), std::ios::in | std::ios::binary);
  assert(file.is_open());
  std::stringstream ss;
  ss << file.rdbuf();
  std::string content_base64 = ss.str();
  file.close();
  std::string result;
  assert(absl::Base64Unescape(content_base64, &result));
  return result;
}

class EncryptionOracle {
 public:
  explicit EncryptionOracle(std::string_view unknown_str)
      : unknown_str_(unknown_str) {}

  std::string Encrypt(std::string_view input) {
    auto padded = Padding::Pkcs7Encode(absl::StrCat(input, unknown_str_), 16);
    return Aes::EcbEncrypt(padded, random_key_);
  }

 private:
  std::string unknown_str_;
  std::string random_key_ = util::RandStr(16);
};

TEST(EcbDecryption, DetectSize) {
  auto unknown_str = ReadBase64File(kUnknownStrFilename);
  EncryptionOracle oracle(unknown_str);
  size_t cur_size = oracle.Encrypt("").size();
  size_t next_size;
  std::string prefix;
  while (prefix.size() < 100) {
    prefix += 'A';
    next_size = oracle.Encrypt(prefix).size();
    if (next_size > cur_size) {
      break;  // Now absl::StrCat(prefix, unknown_str).size() % 16 == 0
    }
  }
  EXPECT_EQ(next_size - cur_size, 16);  // we know it's 128-bit AES :)
  EXPECT_EQ(cur_size - prefix.size(), unknown_str.size());
  std::cout << "unknown_str size is: " << cur_size - prefix.size() << std::endl;
}

TEST(EcbDecryption, DetectMode) {
  EncryptionOracle oracle(ReadBase64File(kUnknownStrFilename));
  std::string two_blocks(32, 'A');
  auto output = oracle.Encrypt(two_blocks);
  // Same first two blocks -> ECB mode
  EXPECT_EQ(output.substr(0, 16), output.substr(16, 16));
}

TEST(EcbDecryption, DecryptStr) {
  auto unknown_str = ReadBase64File(kUnknownStrFilename);
  EncryptionOracle oracle(unknown_str);

  // We know unknown_str.size() == 138 from EcbDecryption_DetectSize
  std::string guess(138, 'x');

  for (int i = 0; i < 138; i++) {
    // Use a prefix of size `15 - i % 16` to make sure the i-th char is
    // located at the last char in position `16 * (j + 1) - 1`, i.e. the
    // last char of the "j+1"-th block.
    int j = i / 16;
    std::string prefix(15 - i % 16, 'A');
    auto output = oracle.Encrypt(prefix).substr(16 * j, 16);

    std::string block(16, 'A');
    if (i < 16) {
      // When guessing the first block, `block` looks like:
      // "A" padding | chars before i (already guessed) | i-th char (to be
      // guessed)
      // e.g: AA..AA | Rollin | x
      block.replace(block.begin() + 15 - i, block.begin() + 15, guess.begin(),
                    guess.begin() + i);
    } else {
      // Later when guess.size() > 16, we can construct the `block` by
      // appending 15 chars prior to the i-th char to be guessed
      block.replace(block.begin(), block.begin() + 15, guess.begin() + i - 15,
                    guess.begin() + i);
    }
    // Brute-forcing - try all possible last char of `block`
    for (int c = 0; c < 256; c++) {
      auto ch = static_cast<unsigned char>(c);
      block[15] = ch;
      if (oracle.Encrypt(block).substr(0, 16) == output) {
        // Found that encryption of `block` is the same as the desired `output`
        guess[i] = ch;
        break;
      }
    }
  }
  EXPECT_EQ(guess, unknown_str);

  std::cout << "unknown_str content is:\n" << guess << std::endl;
}

}  // namespace
}  // namespace cryptopals
