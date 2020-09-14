#include "key.h"

#include <openssl/aes.h>

#include "absl/strings/escaping.h"
#include "gtest/gtest.h"

namespace cryptopals::aes {
namespace {

TEST(KeyTest, KeyExpansion128) {
  std::string key = absl::HexStringToBytes("2b7e151628aed2a6abf7158809cf4f3c");
  auto ks = KeySchedule::ExpandKey(key);

  AES_KEY aes_key;
  AES_set_encrypt_key(reinterpret_cast<const unsigned char*>(key.data()),
                      static_cast<int>(key.size()) * 8, &aes_key);

  EXPECT_EQ(10, ks->nr);
  EXPECT_EQ(44, ks->enc.size());
  for (int i = 0; i < ks->enc.size(); i++) {
    EXPECT_EQ(aes_key.rd_key[i], ks->enc[i]);
  }
}

TEST(KeyTest, KeyExpansion192) {
  std::string key = absl::HexStringToBytes(
      "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
  auto ks = KeySchedule::ExpandKey(key);

  AES_KEY aes_key;
  AES_set_encrypt_key(reinterpret_cast<const unsigned char*>(key.data()),
                      static_cast<int>(key.size()) * 8, &aes_key);

  EXPECT_EQ(12, ks->nr);
  EXPECT_EQ(52, ks->enc.size());
  for (int i = 0; i < ks->enc.size(); i++) {
    EXPECT_EQ(aes_key.rd_key[i], ks->enc[i]);
  }
}

TEST(KeyTest, KeyExpansion256) {
  std::string key = absl::HexStringToBytes(
      "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
  auto ks = KeySchedule::ExpandKey(key);

  AES_KEY aes_key;
  AES_set_encrypt_key(reinterpret_cast<const unsigned char*>(key.data()),
                      static_cast<int>(key.size()) * 8, &aes_key);

  EXPECT_EQ(14, ks->nr);
  EXPECT_EQ(60, ks->enc.size());
  for (int i = 0; i < ks->enc.size(); i++) {
    EXPECT_EQ(aes_key.rd_key[i], ks->enc[i]);
  }
}

}  // namespace
}  // namespace cryptopals::aes