# Retrospection


## Character frequency
In [letter_frequency.h](letter_frequency.h), I used some hard-coded weight for common ASCII characters because I haven't found an excellent source of such frequency table covering the full ASCII range. There's another wonderful solution that we can take some text (like <<1984>>) as ground truth and calculate the frequency ourselves.

Meanwhile, there's room for optimization as we can set up some reasonable penalty for non-printable chars over 8-bit range. This might be feasible with a huge enough test suite (can be generated) and we can do some ML on it.

## Break repeating-key XOR
Why the solution works?

First of all, calculating the *edit/Hamming distance* is actually performing an XOR operation and then count the `1`'s in the bitstream.
 
Imagine we already know the `KEYSIZE`, what gives us after performing XOR over two blobs (of `KEYSIZE`) encrypted by the same key is: `(text_1 ^ key) ^ (text_2 ^ key) == text_1 ^ text_2` -- see, the key crosses itself out.

We also know the ASCII table is very structured, character a-z occupies `0x61` to `0x7A`. As we know the plaintext is *English*, which means there's a high chance the XOR result will be some lower characters XORing some other lower characters. What would be the result? -- Very likely `0x0?` or `0x1?`, i.e. first 3 bits are `0`'s. In other word, the *Hamming distance* is expected to be relatively low.

What if we choose the wrong `KEYSIZE`? Then we get `(text_1 ^ key_1) ^ (text_2 ^ key_2) == text_1 ^ text_2 ^ (key_1 ^ key_2)`. Suppose the key is a random byte, then `key_1 ^ key_2 = random` and the result won't have the nice `0x000?????` in the beginning.

In the testcase provided, the correct key has a *Hamming distance* of 2.7 per byte, others are > 3.1.

There's a good way to visualize the process:

1. Select some plaintext, encode it with a random key.
1. Shift the plaintext and shift by each `KEYSIZE` and XOR with itself.
1. Dump the result into a bitmap, with proper (byte-aligned) wrapping size.

You'll see a outstanding "clean" image if the `KEYSIZE` is correct!

Meanwhile, if you look at the ciphertext directly, because of the pattern of English characters in ASCII, you'll see diagonal or even vertical bars if you choose the correct image width. So you know it's something encrypted from English!

Some wild ideas:
* Can we make the ciphertext purely random so no one knows what it is? -- Well, then you need to have customized keys for every single part of the plaintext. It'll be just hiding the entropy into your key -- nothing better than using the plaintext as my key to get an empty ciphertext :P
* Surprisingly, it turns out that using an English key is better than a random bitstream. By doing so you have successfully decreased the number of `1`'s in `key_1 ^ key_2`, and the ture `KEYSIZE` won't be **that** outstanding from all the `KEYSIZE` guesses :)

