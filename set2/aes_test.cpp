#include "aes.h"

#include <openssl/rand.h>

#include <fstream>

#include "absl/strings/escaping.h"
#include "gtest/gtest.h"
#include "rand_util.h"

namespace cryptopals {
namespace {

TEST(AesEcbTest, BlockCircling) {
  std::string key = "YELLOW SUBMARINE";  // 128-bit key
  std::string plaintext(32, 0);          // 256-bit, two blocks
  ASSERT_TRUE(RAND_bytes(reinterpret_cast<unsigned char*>(plaintext.data()),
                         plaintext.size()));

  std::string ciphertext = Aes::EcbEncrypt(plaintext, key);
  EXPECT_EQ(plaintext, Aes::EcbDecrypt(ciphertext, key));
}

TEST(AesCbcTest, BlockCircling) {
  std::string key = "YELLOW SUBMARINE";  // 128-bit key
  std::string plaintext(32, 0);          // 256-bit, two blocks
  ASSERT_TRUE(RAND_bytes(reinterpret_cast<unsigned char*>(plaintext.data()),
                         plaintext.size()));
  std::string iv(16, 0);

  std::string ciphertext = Aes::CbcEncrypt(plaintext, key, iv);
  EXPECT_EQ(plaintext, Aes::CbcDecrypt(ciphertext, key, iv));
}

TEST(AesCbcTest, Decrypt) {
  std::ifstream file("cbc_ciphertext.txt", std::ios::in | std::ios::binary);
  ASSERT_TRUE(file.is_open());
  std::stringstream ss;
  ss << file.rdbuf();
  std::string ciphertext_base64 = ss.str();
  file.close();
  std::string ciphertext;
  ASSERT_TRUE(absl::Base64Unescape(ciphertext_base64, &ciphertext));
  std::string key = "YELLOW SUBMARINE";
  std::string iv(16, 0);

  std::string plaintext = Aes::CbcDecrypt(ciphertext, key, iv);
  std::string expected_end = "Play that funky music \n\x04\x04\x04\x04";
  EXPECT_EQ(plaintext.substr(plaintext.size() - expected_end.size()),
            expected_end);
}

// https://tools.ietf.org/html/rfc3686#section-6
TEST(AesCtrTest, Encryption) {
  // One block
  std::string key = absl::HexStringToBytes("AE6852F8121067CC4BF7A5765577F39E");
  std::string iv(8, 0);
  std::string nonce = absl::HexStringToBytes("00000030");
  std::string plaintext = "Single block msg";
  std::string ciphertext = Aes::CtrEncrypt(plaintext, key, nonce, iv);
  EXPECT_EQ(absl::HexStringToBytes("E4095D4FB7A7B3792D6175A3261311B8"),
            ciphertext);

  // 36 bytes
  key = absl::HexStringToBytes("7691BE035E5020A8AC6E618529F9A0DC");
  iv = absl::HexStringToBytes("27777F3F4A1786F0");
  nonce = absl::HexStringToBytes("00E0017B");
  plaintext = absl::HexStringToBytes(
      "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222"
      "3");
  ciphertext = Aes::CtrEncrypt(plaintext, key, nonce, iv);
  EXPECT_EQ(absl::HexStringToBytes("C1CF48A89F2FFDD9CF4652E9EFDB72D74540A42BDE6"
                                   "D7836D59A5CEAAEF3105325B2072F"),
            ciphertext);
}

TEST(AesCtrTest, Decryption) {
  // One block
  std::string key = absl::HexStringToBytes("AE6852F8121067CC4BF7A5765577F39E");
  std::string iv(8, 0);
  std::string nonce = absl::HexStringToBytes("00000030");
  std::string ciphertext =
      absl::HexStringToBytes("E4095D4FB7A7B3792D6175A3261311B8");
  std::string plaintext = Aes::CtrDecrypt(ciphertext, key, nonce, iv);
  EXPECT_EQ("Single block msg", plaintext);

  // 36 bytes
  key = absl::HexStringToBytes("7691BE035E5020A8AC6E618529F9A0DC");
  iv = absl::HexStringToBytes("27777F3F4A1786F0");
  nonce = absl::HexStringToBytes("00E0017B");
  ciphertext = absl::HexStringToBytes(
      "C1CF48A89F2FFDD9CF4652E9EFDB72D74540A42BDE6D7836D59A5CEAAEF3105325B2072"
      "F");
  plaintext = Aes::CtrDecrypt(ciphertext, key, nonce, iv);
  EXPECT_EQ(absl::HexStringToBytes("000102030405060708090A0B0C0D0E0F10111213141"
                                   "5161718191A1B1C1D1E1F20212223"),
            plaintext);
}

TEST(AesCtrTest, BlockCircling) {
  std::string key = "YELLOW SUBMARINE";       // 128-bit key
  std::string plaintext = util::RandStr(20);  // 1 block + 32 bits
  std::string nonce = util::RandStr(4);
  std::string iv = util::RandStr(8);

  std::string ciphertext = Aes::CtrEncrypt(plaintext, key, nonce, iv);
  EXPECT_EQ(plaintext, Aes::CtrDecrypt(ciphertext, key, nonce, iv));
}

}  // namespace
}  // namespace cryptopals