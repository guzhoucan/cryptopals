# Implementation notes for AES

## Useful documents

### Understand it
* [fips-197](https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf): The spec and math, must read. Also has test vectors.
* [The Rijndael Block Cipher](https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/aes-development/rijndael-ammended.pdf): Additional material to fips-197.
* [A Stick Figure Guide to the Advanced Encryption Standard](http://www.moserware.com/2009/09/stick-figure-guide-to-advanced.html): I love comics.
* [AES Explained - Computerphile](https://www.youtube.com/watch?v=O4xNJsjtN6E&ab_channel=Computerphile): AES walk-through, good channel.
* [Galois field](https://en.wikipedia.org/wiki/Finite_field): I wish something better than wikipedia, like a video?
* As you wish:
  * [Finite fields made easy](https://www.youtube.com/watch?v=z9bTzjy4SCg&ab_channel=RandellHeyman)
  * [Lecture 7: Introduction to Galois Fields for the AES by Christof Paar](https://www.youtube.com/watch?v=x1v2tX4_dkQ&t=4013s&ab_channel=IntroductiontoCryptographybyChristofPaar)
  * [Fields to Galois Theory](https://www.youtube.com/watch?v=TpH0CzAHxNE&list=PLCgncMh0TrCnyT2vrhEO5DwYEAiq4d_Jz&ab_channel=HarpreetBedi)
  * [Finite fields made easy](https://www.youtube.com/watch?v=z9bTzjy4SCg&t=13s&ab_channel=RandellHeyman)

### Code it up
* [golang.org/src/crypto/aes/](https://golang.org/src/crypto/aes/): I strongly recommend this, GJ golang team with nice comments.
  * Better start with [const.go](https://golang.org/src/crypto/aes/const.go), then [aes_test.go](https://golang.org/src/crypto/aes/aes_test.go), later [block.go](https://golang.org/src/crypto/aes/block.go). It shows you what the heck the lookup table is, and how it's generated originally.
* [rijndael-alg-fst.c](https://fastcrypto.org/front/misc/rijndael-alg-fst.c): C impl, contains fast lookup tables.
* [openssl::aes_core.c](https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/crypto/aes/aes_core.c): More readable with better comments, less readable for multiple impls for the same function signature.