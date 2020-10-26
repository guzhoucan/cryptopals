#include <absl/strings/escaping.h>
#include <absl/strings/str_replace.h>
#include <absl/strings/str_split.h>
#include <absl/strings/substitute.h>
#include <gtest/gtest.h>

#include <cmath>
#include <fstream>

#include "aes.h"
#include "padding.h"
#include "rand_util.h"

namespace cryptopals {
namespace {

class ProfileOracle {
 public:
  std::string GetProfile(std::string_view email) {
    std::string escaped = absl::StrReplaceAll(email, {{"&", ""}, {"=", ""}});
    std::string encoded =
        absl::Substitute("email=$0&uid=10&role=user", escaped);
    auto padded = Padding::Pkcs7Encode(encoded, 16);
    return Aes::EcbEncrypt(padded, random_key_);
  }

  std::string ParseRole(std::string_view ciphertext) {
    auto plaintext = Aes::EcbDecrypt(ciphertext, random_key_);
    auto profile = Padding::Pkcs7Decode(plaintext);
    std::vector<std::string> parts = absl::StrSplit(profile, '&');
    std::vector<std::string> role = absl::StrSplit(parts[2], '=');
    return role[1];
  }

 private:
  std::string random_key_ = util::RandStr(16);
};

TEST(EcbCutAndPaste, TestOracle) {
  ProfileOracle oracle;
  auto output = oracle.GetProfile("foo@gmail.com");
  EXPECT_EQ("user", oracle.ParseRole(output));
}

// Step 1: Figure out the size of the prefix before our input
TEST(EcbCutAndPaste, DetectPrefixSize) {
  int prefix_size = -1;
  ProfileOracle oracle;
  std::string temp(32, 'A');
  for (int sz = 0; sz < 16 && prefix_size == -1; sz++, temp += 'A') {
    auto ciphertext = oracle.GetProfile(temp);
    for (int i = 0; i < ciphertext.size() - 16; i += 16) {
      if (ciphertext.substr(i, 16) == ciphertext.substr(i + 16, 16)) {
        prefix_size = i - sz;
      }
    }
  }
  // we know it's "email=" (len of 6) before our input :)
  EXPECT_EQ(prefix_size, 6);
}

// Step 2: Figure out suffix size after input
TEST(EcbCutAndPaste, DetectSuffixSize) {
  ProfileOracle oracle;
  std::string pad(10, 'A');
  size_t suffix_size = oracle.GetProfile(pad).size() - 16;
  std::string expected_suffix = "&uid=10&role=user";
  EXPECT_EQ(suffix_size, std::ceil(expected_suffix.size() / 16.0) * 16);
  std::cout << "Suffix length is:" << suffix_size << std::endl;
}

// Step 3: How to know the suffix is
// "&uid=10&role=user\017\017\017\017\017\017\017\017\017\017\017\017\017\017
// \017\017"?
// '&' and '=' are escaped from input so method in challenge 12 no longer works.

// Step 4: assume we know the format of the encoded profile...
TEST(EcbCutAndPaste, ConstructAdmin) {
  ProfileOracle oracle;
  std::string pad(10, 'A');
  // "com&uid=10&role=" is one block
  std::string role_block = oracle.GetProfile(pad + "com").substr(16, 16);
  // construct padded tailing block
  // "admin\013\013\013\013\013\013\013\013\013\013\013"
  std::string admin_padded = Padding::Pkcs7Encode("admin", 16);
  std::string admin_block =
      oracle.GetProfile(pad + admin_padded).substr(16, 16);
  // The attacker's email needs to be 10 (or 10 + 16n :P if you like) bytes
  // like "hacker123."
  std::string email_block = oracle.GetProfile("hacker123.").substr(0, 16);
  std::string constructed_ciphertext = email_block + role_block + admin_block;
  EXPECT_EQ("admin", oracle.ParseRole(constructed_ciphertext));
}

}  // namespace
}  // namespace cryptopals
