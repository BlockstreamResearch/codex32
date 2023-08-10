# For Wallet Developers

codex32 is a new format for BIP32 master seeds. It is essentially a replacement for
BIP39 or SLIP39 seed words, and the user workflow should be much the same, except
that:

* The character set is different (bech32 characters rather than a wordlist).
* Seeds may be encoded across multiple shares, rather than a single string.
* It is possible to do specific error detection/correction during entry.

There are two levels of wallet support:

* The ability to import seeds/shares; here we essentially just have recommendations about dealing with errors.
* The ability to generate seeds/shares on the device; here our guidance is more involved.

We encourage every wallet to support importing seeds and shares, since
* the technial difficulty is low (roughly on par with that of supporting Segwit addresses, plus optional error-correction support);
* the added functionality is isolated from the rest of the wallet (once the seed is imported you don't care where it came from); and
* beyond correctness of the code, there is little risk (no need to source randomness or execute potentially variable-time algoritms).

Supporting seed generation is a little more involved so the tradeoff between
implementation complexity and user value is less clear, especially since the
Codex provides users instructions on doing generation themselves.

## Import Support

codex32 shares may be any length between 128 and 512 bits.
Wallets should support import of 128- or 256-bit seeds; other lengths are optional.

128-bit seeds are 48 characters in length, including the `MS1` prefix.
256-bit seeds are 74. For other bitlengths, see the BIP.

The process for entering shares is:

1. The user should select the bit length of the import before entering any actual data.
1. Then the user should enter the first share. To the entext possible given screen limitations, when entering share data, data should be displayed in uppercase, visually separated into four-character windows. The first four-character window should include the `MS1` prefix, which should be pre-filled.
1. Once the first share is fully entered, the wallet should validate the checksum and header before accepting it.
   * The user should not be able to entire mixed-case or non-bech32 characters.
   * If the header is invalid, the wallet should highlight this and prevent the user from entering additional data until it is fixed. An invalid header is one that starts with a character other than `0` or `2` through `9`, or one which starts with `0` but whose share index is not `S`.
   * If the checksum is invalid, the wallet may use an error-correction algorithm to determine a corrected share, but the wallet MUST show these corrections to the user rather than silently applying them.
   * For substitution errors, the wallet may highlight the offending 4-character window or the offending character. It may also show the corrected character.
   * If the wallet can determine insertion or deletion errors, it should highlight the offending 4-character window.
1. After the first share has been entered and accepted, the wallet now knows the seed ID and threshold value.
   * If the first share had index `S`, this was the actual seed and the import process is complete.
   * Otherwise, the first character of the share will be a numeric character between `2` and `9` inclusive. The user must enter this many shares in total.
1. The user should then enter the remaining shares, in the same manner as the first.
   * The wallet may pre-fill the header (threshold value and seed ID).
   * If the user tries to repeat an already-entered share index, they should be prevented from entering additional data until it is corrected.
1. Once all shares are entered, the wallet should derive the master seed and import this.

**The master seed should be used directly as a master seed, as specified in BIP32.**
Unlike in BIP39 or other specifications, no PBKDF or other pre-processing should be applied.

## Generate Support

TODO

