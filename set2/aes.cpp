#include "aes.h"

#include <openssl/aes.h>

#include <cassert>

#include "../set1/fixed_xor.h"

namespace cryptopals {

namespace {

constexpr int kBlockSize = 16;  // 128-bit block

AES_KEY GenerateAesEncryptKey(std::string_view key) {
  AES_KEY aes_key;
  int res =
      AES_set_encrypt_key(reinterpret_cast<const unsigned char*>(key.data()),
                          static_cast<int>(key.size()) * 8, &aes_key);
  assert(res == 0);
  return aes_key;
}

AES_KEY GenerateAesDecryptKey(std::string_view key) {
  AES_KEY aes_key;
  int res =
      AES_set_decrypt_key(reinterpret_cast<const unsigned char*>(key.data()),
                          static_cast<int>(key.size()) * 8, &aes_key);
  assert(res == 0);
  return aes_key;
}
}  // namespace

std::string Aes::EcbEncrypt(std::string_view plaintext, std::string_view key) {
  std::string ciphertext(plaintext.size(), 0);
  AES_KEY aes_key = GenerateAesEncryptKey(key);
  for (size_t i = 0; i < plaintext.size(); i += kBlockSize) {
    const auto* in = reinterpret_cast<const unsigned char*>(&plaintext[i]);
    auto* out = reinterpret_cast<unsigned char*>(&ciphertext[i]);
    AES_encrypt(in, out, &aes_key);
  }
  return ciphertext;
}

std::string Aes::EcbDecrypt(std::string_view ciphertext, std::string_view key) {
  std::string plaintext(ciphertext.size(), 0);
  AES_KEY aes_key = GenerateAesDecryptKey(key);
  for (size_t i = 0; i < ciphertext.size(); i += kBlockSize) {
    const auto* in = reinterpret_cast<const unsigned char*>(&ciphertext[i]);
    auto* out = reinterpret_cast<unsigned char*>(&plaintext[i]);
    AES_decrypt(in, out, &aes_key);
  }
  return plaintext;
}

std::string Aes::CbcEncrypt(std::string_view plaintext, std::string_view key,
                            std::string_view iv) {
  assert(iv.size() == kBlockSize);
  std::string ciphertext(plaintext.size(), 0);
  AES_KEY aes_key = GenerateAesEncryptKey(key);
  std::string vector = std::string(iv);
  for (size_t i = 0; i < plaintext.size(); i += kBlockSize) {
    std::string input = FixedXor(plaintext.substr(i, kBlockSize), vector);
    const auto* in = reinterpret_cast<const unsigned char*>(input.data());
    auto* out = reinterpret_cast<unsigned char*>(&ciphertext[i]);
    AES_encrypt(in, out, &aes_key);
    vector = ciphertext.substr(i, kBlockSize);
  }
  return ciphertext;
}

std::string Aes::CbcDecrypt(std::string_view ciphertext, std::string_view key,
                            std::string_view iv) {
  assert(iv.size() == kBlockSize);
  std::string plaintext(ciphertext.size(), 0);
  AES_KEY aes_key = GenerateAesDecryptKey(key);
  std::string vector = std::string(iv);
  std::string output = std::string(kBlockSize, 0);
  for (size_t i = 0; i < ciphertext.size(); i += kBlockSize) {
    const auto* in = reinterpret_cast<const unsigned char*>(&ciphertext[i]);
    auto* out = reinterpret_cast<unsigned char*>(output.data());
    AES_decrypt(in, out, &aes_key);
    plaintext.replace(i, kBlockSize, FixedXor(output, vector));
    vector = ciphertext.substr(i, kBlockSize);
  }
  return plaintext;
}

}  // namespace cryptopals