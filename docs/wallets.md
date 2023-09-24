# For Wallet Developers

codex32 is a new format for BIP32 master seeds. It is essentially a replacement for
BIP39 or SLIP39 seed words, and the user workflow should be much the same, except
that:

* The character set is different (bech32 characters rather than a wordlist).
* Seeds may be split across multiple shares, rather than encoded as a single string.
* It is possible to do specific error detection/correction during entry.

There are two levels of wallet support:

* The ability to import seeds/shares; here we essentially just have recommendations about dealing with errors.
* The ability to generate seeds/shares on the device; here our guidance is more involved.

We encourage every wallet to support importing seeds and shares, since
* the technical difficulty is low (roughly on par with that of supporting Segwit addresses, plus optional error-correction support);
* the added functionality is isolated from the rest of the wallet (once the seed is imported you don't care where it came from); and
* beyond correctness of the code, there is little risk (no need to source randomness or execute potentially variable-time algorithms).

Supporting seed generation is a little more involved so the tradeoff between
implementation complexity and user value is less clear, especially since the
Codex provides users instructions on doing generation themselves.

## Import Support

codex32 shares may be any length between 128 and 512 bits.
Wallets should support import of 128- or 256-bit seeds; other lengths are optional.

128-bit seeds are 48 characters in length, including the `MS1` prefix.
256-bit seeds are 74. For other bit-lengths, see the BIP.

The process for entering shares is:

1. The user should enter the first string. To the extent possible given screen limitations, data should be displayed in uppercase with visually distinct four-character windows. The first four-character window should include the `MS1` prefix, which should be pre-filled.
1. Once the first string is fully entered, the wallet should validate the checksum and header before accepting it.
   * The user should not be able to enter mixed-case characters. The user must be able to enter all bech32 characters as well as `?` indicating an erasure. Wallets may allow users to enter non-bech32 characters, at their discretion. (This may be useful to guide error correction, by attempting to replace commonly confused characters.)
   * If the header is invalid, the wallet SHOULD highlight this and request confirmation from the user before allowing additional data to be entered. An invalid header is one that starts with a character other than `0` or `2` through `9`, or one which starts with `0` but whose share index is not `S`. For shares after the first, a header is also invalid if its threshold and identifier do not match those of the first string.
   * If the checksum is invalid, the wallet SHOULD use an error-correction algorithm to locate errors in the string and show these to the user. It MAY additionally determine corrected data, but if so, the wallet MUST show these corrections to the user rather than silently applying them.
   * To show locations of substitution errors, the wallet SHOULD highlight the offending 4-character window or the specific offending character.
   * If the wallet can determine insertion or deletion errors, it SHOULD highlight the offending 4-character window or the specific location of the inserted or missing character. When detecting insertion or deletion errors, the wallet MAY assume that the correct string length is 48, 74 or (optionally) 127 characters (corresponding to 16-, 32- or 64-byte seeds).
1. If the string length is *not* 48, 74 or 127 characters, but the checksum passes, the wallet should confirm that the user intends to import a non-standard string length.
   * If the string length is *not* 48, 74 or 127 bytes, and the checksum does *not* pass, then the wallet MAY attempt correction by deleting or inserting up to 3 characters.
1. After the first string has been entered and accepted, the wallet now knows the identifier and threshold value.
   * If the first string had index `S`, this was the codex32 secret and the import process is complete.
   * Otherwise, the first character of the share will be a numeric character between `2` and `9` inclusive. The user must enter this many shares in total.
   * Wallets MAY encrypt and store recovery progress, to allow recovery without having all shares available at once. The details of this are currently outside of the scope of this specification.
1. The user should then enter the remaining shares, in the same manner as the first.
   * The wallet SHOULD pre-fill the header (threshold value and identifier).
   * If the user tries to repeat an already-entered share index, they should be prevented from entering additional data until it is corrected, with the exception that `?` may be used as a share index arbitrarily many times. The wallet may guide the user by indicating that a share index has been repeated; if the user indicates that they are not repeating the share, the share index SHOULD be replaced by `?`.
   * The wallet MUST assume the valid length of all subsequent strings is equal to the valid length of the first string. If the lengths do not match, the wallet MAY attempt correction by deleting or inserting characters.
1. Once all shares are entered, the wallet should derive the master seed and import this.

**The master seed should be used directly as a master seed, as specified in BIP32.**
Unlike in BIP39 or other specifications, no PBKDF or other pre-processing should be applied.

## Generate Support

TODO

