#include "aes.h"

#include <openssl/aes.h>

#include <algorithm>
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

// `dest` needs to have 32 bits reserved
void BigEndianSet(unsigned char* dest, uint32_t counter) {
  dest[3] = counter & 0xffu;
  dest[2] = (counter >> 8u) & 0xffu;
  dest[1] = (counter >> 16u) & 0xffu;
  dest[0] = (counter >> 24u) & 0xffu;
}

}  // namespace

std::string Aes::EcbEncrypt(std::string_view plaintext, std::string_view key) {
  assert(plaintext.size() % kBlockSize == 0);
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
  assert(ciphertext.size() % kBlockSize == 0);
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
  assert(plaintext.size() % kBlockSize == 0);
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
  assert(ciphertext.size() % kBlockSize == 0);
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

std::string Aes::CtrEncrypt(std::string_view plaintext, std::string_view key,
                            std::string_view nonce, std::string_view iv) {
  assert(nonce.size() == 4);
  assert(iv.size() == 8);
  uint32_t counter = 1;

  std::string ciphertext(plaintext.size(), 0);
  AES_KEY aes_key = GenerateAesEncryptKey(key);
  std::string key_stream(kBlockSize, 0);

  unsigned char ctr_block[kBlockSize];
  std::copy(nonce.begin(), nonce.end(), ctr_block);
  std::copy(iv.begin(), iv.end(), ctr_block + 4);

  for (size_t i = 0; i < plaintext.size(); i += kBlockSize) {
    BigEndianSet(ctr_block + 12, counter);  // memcpy has endianness issue
    auto* out = reinterpret_cast<unsigned char*>(key_stream.data());
    AES_encrypt(ctr_block, out, &aes_key);

    // For the last block, string::replace and std::substr will copy len <
    // kBlockSize when it meets std::npos, and FixedXor will return the XOR
    // result with size == min(size(input1), size(input2)).
    ciphertext.replace(i, kBlockSize,
                       FixedXor(plaintext.substr(i, kBlockSize), key_stream));
    counter++;
  }
  return ciphertext;
}

std::string Aes::CtrDecrypt(std::string_view ciphertext, std::string_view key,
                            std::string_view nonce, std::string_view iv) {
  assert(nonce.size() == 4);
  assert(iv.size() == 8);
  uint32_t counter = 1;

  std::string plaintext(ciphertext.size(), 0);
  AES_KEY aes_key =
      GenerateAesEncryptKey(key);  // Note: CTR use AES *encryption*
  std::string key_stream(kBlockSize, 0);

  unsigned char ctr_block[kBlockSize];
  std::copy(nonce.begin(), nonce.end(), ctr_block);
  std::copy(iv.begin(), iv.end(), ctr_block + 4);

  for (size_t i = 0; i < ciphertext.size(); i += kBlockSize) {
    BigEndianSet(ctr_block + 12, counter);  // memcpy has endianness issue
    auto* out = reinterpret_cast<unsigned char*>(key_stream.data());
    AES_encrypt(ctr_block, out, &aes_key);  // Note: CTR use AES *encryption*

    // For the last block, string::replace and std::substr will copy len <
    // kBlockSize when it meets std::npos, and FixedXor will return the XOR
    // result with size == min(size(input1), size(input2)).
    plaintext.replace(i, kBlockSize,
                      FixedXor(ciphertext.substr(i, kBlockSize), key_stream));
    counter++;
  }
  return plaintext;
}

}  // namespace cryptopals