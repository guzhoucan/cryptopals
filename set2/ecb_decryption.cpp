#include <absl/strings/escaping.h>
#include <gtest/gtest.h>

#include <cstdlib>
#include <ctime>
#include <exception>
#include <fstream>

#include "aes.h"
#include "padding.h"
#include "rand_util.h"

namespace cryptopals {
namespace {

constexpr size_t kBlockSize = 16;  // AES 128 bit block.
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
  virtual std::string Encrypt(std::string_view input) = 0;
};

class EncryptionOracleEasy : public EncryptionOracle {
 public:
  explicit EncryptionOracleEasy(std::string_view target_bytes)
      : target_bytes_(target_bytes) {}

  std::string Encrypt(std::string_view input) override {
    auto padded =
        Padding::Pkcs7Encode(absl::StrCat(input, target_bytes_), kBlockSize);
    return Aes::EcbEncrypt(padded, random_key_);
  }

 private:
  std::string target_bytes_;
  std::string random_key_ = util::RandStr(kBlockSize);
};

size_t GuessTargetBytesSize(EncryptionOracle* oracle, size_t prefix_size) {
  // Need (kBlockSize - prefix_size % kBlockSize) % kBlockSize chars to
  // complete the final block of prefix.
  std::string stimulus((kBlockSize - prefix_size % kBlockSize) % kBlockSize,
                       'x');
  size_t cur_size = oracle->Encrypt(stimulus).size();
  size_t next_size;
  for (int i = 0; i < kBlockSize; i++) {
    stimulus += 'x';
    next_size = oracle->Encrypt(stimulus).size();
    if (next_size > cur_size) {
      assert(next_size - cur_size ==
             kBlockSize);  // we know it's 128-bit AES :)
      // Now absl::StrCat(prefix, stimulus, target_bytes).size() % 16 == 0
      return cur_size - stimulus.size() - prefix_size;
    }
  }
  throw std::runtime_error("Should not reach here.");
}

TEST(EcbDecryptionEasy, DetectTargetBytesSize) {
  auto unknown_str = ReadBase64File(kUnknownStrFilename);
  EncryptionOracleEasy oracle(unknown_str);
  auto size = GuessTargetBytesSize(&oracle, 0);
  EXPECT_EQ(size, unknown_str.size());
  // unknown_str.size() == 138
  std::cout << "unknown_str size is: " << size << std::endl;
}

std::string DecryptTargetBytes(EncryptionOracle* oracle, size_t prefix_size,
                               size_t target_size) {
  // Complementary for prefix
  std::string prefix_comp((kBlockSize - prefix_size % kBlockSize) % kBlockSize,
                          'x');
  auto prefix_blk_size = prefix_size + prefix_comp.size();
  std::string target_bytes;
  for (size_t i = 0; i < target_size; i++) {
    // Use a stimulus of size `15 - i % 16` to make sure the i-th char is
    // located at the last char in position `16 * (j + 1) - 1`, i.e. the
    // last char of the "j+1"-th block.
    size_t j = i / kBlockSize;
    std::string stimulus(kBlockSize - 1 - i % kBlockSize, 'A');
    auto output = oracle->Encrypt(absl::StrCat(prefix_comp, stimulus))
                      .substr(prefix_blk_size + kBlockSize * j, kBlockSize);

    std::string block;
    if (i < kBlockSize) {
      // When guessing the first block of target_bytes, `block` looks like:
      // "A" padding | chars before i (already guessed) | i-th char (to be
      // guessed)
      // e.g: AA..AA | Rollin | x
      // Note that target_bytes.size() == i - 1
      block.assign(kBlockSize - target_bytes.size() - 1, 'A');
      block += target_bytes;
    } else {
      // Later when target_bytes.size() >= 15, we can construct the `block` by
      // appending 15 chars prior to the i-th char to be guessed
      block = target_bytes.substr(i - (kBlockSize - 1), kBlockSize - 1);
    }
    block.resize(kBlockSize);  // allocate block[15]
    // Brute-forcing - try all possible last char of `block`
    for (int c = 0; c < 256; c++) {
      auto ch = static_cast<unsigned char>(c);
      block[15] = ch;
      if (oracle->Encrypt(absl::StrCat(prefix_comp, block))
              .substr(prefix_blk_size, kBlockSize) == output) {
        // Found that encryption of `block` is the same as the desired `output`
        target_bytes += ch;
        break;
      }
    }
  }
  return target_bytes;
}

TEST(EcbDecryptionEasy, DecryptTargetBytes) {
  auto unknown_str = ReadBase64File(kUnknownStrFilename);
  EncryptionOracleEasy oracle(unknown_str);
  auto target_size = GuessTargetBytesSize(&oracle, 0);
  auto target_bytes = DecryptTargetBytes(&oracle, 0, target_size);
  EXPECT_EQ(target_bytes, unknown_str);
  std::cout << "unknown_str content is:\n" << target_bytes << std::endl;
}

// Quote from Internet:
// "At first I read the instructions understanding that the random-prefix should
// be changed at every call to the oracle, including its length.
//
// Looking at other people's solutions on the Internet, and reading the
// instructions again, it seems that it wasn't really what I was supposed to do:
// the random prefix should be generated once at the instantiation of the
// oracle, and stay the same across all calls to the oracle."
class EncryptionOracleHard : public EncryptionOracle {
 public:
  explicit EncryptionOracleHard(std::string_view target_bytes)
      : target_bytes_(target_bytes) {
    std::srand(std::time(nullptr));
    auto prefix_len_ = std::rand() % 32 + 1;  // Use prefix of length [1, 32]
    random_prefix_ = util::RandStr(prefix_len_);
    random_key_ = util::RandStr(kBlockSize);
  }

  std::string Encrypt(std::string_view input) override {
    auto padded = Padding::Pkcs7Encode(
        absl::StrCat(random_prefix_, input, target_bytes_), kBlockSize);
    return Aes::EcbEncrypt(padded, random_key_);
  }

  std::string random_prefix_;  // cheat for testing
 private:
  std::string target_bytes_;
  std::string random_key_;
};

// This would report wrong result if:
// a. There exist two consecutive blocks with same content (ignorable with
//    random prefix)
// b. The leading chars of the suffix contains `ch`
// Problem b is covered in GuessPrefixSize, and tailing `ch` in prefix won't
// affect the result. Details see tests.
//
// The impl looks (a little) complicated because duplicated blocks in suffix
// is considered.
size_t GuessPrefixSizeInternal(EncryptionOracle* oracle, char ch) {
  size_t dup_blk_pos;
  // 47 repeating chars will for sure produce two duplicated blocks no matter
  // what the prefix_size is.
  std::string stimulus(3 * kBlockSize - 1, ch);
  auto response = oracle->Encrypt(stimulus);
  for (int i = 0; i < response.size() - 2 * kBlockSize; i += kBlockSize) {
    auto cur_blk = response.substr(i, kBlockSize);
    auto nxt_blk = response.substr(i + kBlockSize, kBlockSize);
    if (cur_blk == nxt_blk) {
      dup_blk_pos = i;
      break;
    }
  }
  for (int i = 0; i < kBlockSize; i++) {
    stimulus.assign(2 * kBlockSize + i, ch);
    response = oracle->Encrypt(stimulus);
    auto cur_blk = response.substr(dup_blk_pos, kBlockSize);
    auto nxt_blk = response.substr(dup_blk_pos + kBlockSize, kBlockSize);
    if (cur_blk == nxt_blk) {
      // Found precise stimulus size, where `i` chars are used for complete the
      // last block of prefix
      return dup_blk_pos - i;
    }
  }
  throw std::runtime_error("Should not reach here.");
}

size_t GuessPrefixSize(EncryptionOracle* oracle) {
  size_t guess_a = GuessPrefixSizeInternal(oracle, 'A');
  size_t guess_b = GuessPrefixSizeInternal(oracle, 'B');
  if (guess_a == guess_b) {
    return guess_a;
  } else {
    // If we hit GuessPrefixSizeInternal situation (b), we have either
    // random_prefix | stimulus | A... or
    // random_prefix | stimulus | B...
    // Probing with 'C' will for sure give us the correct answer.
    return GuessPrefixSizeInternal(oracle, 'C');
  }
}

TEST(DetectPrefixSizeTest, DuplicatedBlockInTargetBytes) {
  std::string target_bytes(3 * kBlockSize, 'x');
  EncryptionOracleHard oracle(target_bytes);
  EXPECT_EQ(GuessPrefixSize(&oracle), oracle.random_prefix_.size());
}

TEST(DetectPrefixSizeTest, SameLeadingCharInTargetBytes) {
  std::string target_bytes = "Afoobar";
  EncryptionOracleHard oracle(target_bytes);
  EXPECT_EQ(GuessPrefixSize(&oracle), oracle.random_prefix_.size());
}

TEST(DetectPrefixSizeTest, SameTailingCharInPrefix) {
  EncryptionOracleHard oracle("foobar");
  oracle.random_prefix_ = "foobarA";
  EXPECT_EQ(GuessPrefixSize(&oracle), oracle.random_prefix_.size());
}

TEST(EcbDecryptionHard, DecryptTargetBytes) {
  auto unknown_str = ReadBase64File(kUnknownStrFilename);
  EncryptionOracleHard oracle(unknown_str);
  auto prefix_size = GuessPrefixSize(&oracle);
  EXPECT_EQ(prefix_size, oracle.random_prefix_.size());
  auto target_size = GuessTargetBytesSize(&oracle, prefix_size);
  EXPECT_EQ(target_size, unknown_str.size());
  auto target_bytes = DecryptTargetBytes(&oracle, prefix_size, target_size);
  EXPECT_EQ(target_bytes, unknown_str);
}

}  // namespace
}  // namespace cryptopals