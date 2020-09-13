# Retrospection
## AES
### Incomplete message encryption/decryption
Initially I wrote the following tests which made me confused --- Why the openssl lib works against input less than 16 bytes?

```c++
TEST(AesEcbTest, NonBlockCircling) {
  std::string key = "YELLOW SUBMARINE";  // 128-bit key
  std::string plaintext = "WTF";

  std::string ciphertext = Aes::EcbEncrypt(plaintext, key);
  ASSERT_EQ(plaintext, Aes::EcbDecrypt(ciphertext, key));
}
TEST(AesCbcTest, NonBlockCircling) {
  std::string key = "YELLOW SUBMARINE";  // 128-bit key
  std::string plaintext = "WTF";
  std::string iv(16, 'a');

  std::string ciphertext = Aes::CbcEncrypt(plaintext, key, iv);
  // There's a potential memory issue with the AES lib, causing the result to
  // be either "WTFaaaaaaaaaaaaa" or "WTFa\xE\aADaaaaaaaa"
  ASSERT_EQ(plaintext, Aes::CbcDecrypt(ciphertext, key, iv).substr(0, 3));
}
```

After discussion and debugging, it happens to have the following properties:
* The compiler arranges more than 3 bytes for `std::string plaintext = "WTF"` and `std::string ciphertext(plaintext.size(), 0)` (in debugger it allocates 16 bytes for meta/data respectively).
```
# Memory View
&plaintext  -> c0 e5 ff ff   ff 7f 00 00   03 00 00 00   00 00 00 00   | ················ |
               57 54 46 00   ff 7f 00 00   c6 d5 5a 55   55 55 00 00   | WTF·······ZUUU·· |
&ciphertext -> e0 e5 ff ff   ff 7f 00 00   03 00 00 00   00 00 00 00   | ················ |
               2a c3 4e 31   92 b4 62 41   f9 44 7d 2b   b1 9a 0b 5f   | *·N1··bA·D}+···_ |
```
* The allocated `ciphertext` is returned without copy (compiler optimization against rvalue-reference)
* ciphertext is a reference/pointer (`std::string_view`) input to `Aes::XXXDecrypt`.
* result of `Aes::XXXDecrypt` also get its 16-byte aligned address

So, the test passes because of the *"generosity"* of my debugging compiler.

Meanwhile, I tried to use `char[3]` for input, it also passes because the `ciphertext` and output of `Aes::XXXDecrypt` are of type `std::string` which have enough space, and I only verified the first three bytes of the result. If I look into the following bytes of the `Aes::XXXDecrypt` output, it will show what's allocated behind my 3-byte input :)

This issue can be easily detected by tools like valgrind, see:

```
# valgrind output
[ RUN      ] AesEcbTest.NonBlockCircling
==4581== Use of uninitialised value of size 8
==4581==    at 0x48E69BC: AES_encrypt (in /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1)
...
```

**Side Story**

Initially I thought there's some platform-based optimization where an implicit padding is applied, but the [source code](https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/crypto/aes/aes_core.c) shows it assumes 16 bytes of memory is allocated and will directly accessing it.

My final question: How is [aes_core.c](https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/crypto/aes/aes_core.c) compiled with two suites of implementation sharing the same function signature?!

## ECB/CBC detection oracle

There's another attack that we can apply to the ECB/CBC detection oracle given the fact we know that it's applying PKCS#7 padding, found by cfenn@.

We can rely on the fact that when the random-sized prefix/suffix happen to make the padded plaintext to be "block-aligned", i.e. `size(padded) % 16 == 0`. Then we know for fact that the final block would be `0x10101010101010101010101010101010`. If we use the input of all `0x10` bytes, we can correctly tell the oracle is using ECB mode. --- Well, it's only gaining us some advantage since the size of padding is not deterministic, but we can get it correct on 1/6 of the chance (which is P(size of prefix + suffix == 15)) with the input of size 33 (1 full block + other 17 bytes to "fill the block" with prefix and suffix). We start to gain non-zero advantage from only 27 bytes of input!
