# For Wallet Developers

Codex32 is a new format for BIP32 master seeds. It is essentially a replacement for
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

## Error Detection and Correction

Wallets MUST support detection of errors using the codex32 checksum algorithm.
Wallets SHOULD additionally support error correction; such wallets are referred to as "error-correcting wallets (ECWs)" and have additional requirements.

An ECW:

* MUST support correction of up to 4 substitution errors and erasures;
* MAY also support correction of up to 8 erasures, up to 13 if contiguous;
* MAY support correction of further errors, including insertion or deletion errors.

If a wallet is unable to meet these specifications, it is not an ECW and it SHOULD NOT expose error-correction functionality to the user.

## Import Support

Wallets SHOULD support import of 128- and 256-bit seeds; other lengths are optional. 128-bit seeds encode as 48-character codex32 strings, including the `MS1` prefix. 256-bit seeds encode as 74-character codex32 strings. For other bit-lengths, see the BIP.

The process for entering codex32 strings is:

1. The user should enter the first string. To the extent possible given screen limitations, data should be displayed in uppercase with visually distinct four-character windows. The first four-character window should include the `MS1` prefix, which SHOULD be pre-filled.
   * The user MUST be able to enter all bech32 characters.
   * ECWs MUST also allow entry of `?` which indicates an erasure (unknown character).
   * The user SHOULD NOT be able to enter mixed-case characters.
   * If the header is invalid, the wallet SHOULD highlight the problem and request confirmation from the user before allowing additional data to be entered.
     * An invalid header is one that starts with a character other than `0` or `2` through `9`, or one which starts with `0` but whose share index is not `S`. For shares after the first, a header is also invalid if its threshold and identifier do not match those of the first share or whose share index matches any previous share.
     * ECWs MAY replace the offending characters of the header with `?`.
   * Wallets MAY:
     * Allow users to enter invalid characters, at their discretion. (This may be useful to guide error correction, by attempting to replace commonly confused characters.)
     * Use predictive text for on-screen keyboards to suggest the codex32 checksum characters but if so MUST require user to manually accept the prediction.
     * Indicate when the entry has a valid checksum, e.g. by highlighting the string green or displaying the "Submit" option but they MUST NOT submit a string with a valid checksum without user request.
   * ECWs MAY additionally indicate when an entry of sufficient length to correct has an invalid checksum, e.g. by highlighting the string red or displaying an "Attempt Correction" option.


1. Once the first string is fully entered, the wallet MUST validate the checksum and header before accepting it.
   * If the checksum does not pass, then an ECW:
      * MUST attempt error correction of substitution errors and erasures.
      * MAY attempt correction by deleting and/or inserting characters, as long as the resulting string has a valid length for a codex32 string. ECWs MAY assume the correct length is the closest of 48 or 74.
      * MUST show any valid correction candidate found to the user for confirmation rather than silently applying it.
         * If insertion and/or deletion correction candidates are found, the shortest edit distance valid string SHOULD be displayed.
           * This is the sum of all edits with erasures and deletes weighted 1 and substitutions and insertions weighted 2.
         * ECWs displaying a candidate correction MAY highlight corrected 4-character windows and/or specific correction locations.
1. After the first string has been entered and accepted, the wallet now knows the identifier, threshold value and valid length.
   * If the first string had index `S`, this was the codex32 secret and the import process is complete.
   * Otherwise, the fourth character of the share will be a numeric character between `2` and `9` inclusive. The user must enter this many shares in total.
   * Wallets MAY encrypt and store recovery progress, to allow recovery without having all shares available at once. The details of this are currently outside of the scope of this specification.
1. The user should then enter the remaining shares, in the same manner as the first.
   * The wallet SHOULD pre-fill the header (threshold value and identifier).
   * If the user tries to repeat an already-entered share index, they SHOULD be prevented from entering additional data until it is corrected.
      * The wallet MAY guide the user by indicating that a share index has been repeated;
      * ECWs may use `?` as a share index arbitrarily many times. If the user indicates they are not repeating the share, the share index SHOULD be replaced by `?`.
   * If the checksum fails, the wallet MAY attempt correction by deleting and/or inserting characters. However, the wallet MUST assume the valid length of all subsequent shares is equal to the valid length of the first share, so the number of characters inserted and deleted must net out to the correct length.
1. For all invalid codex32 strings entered, if an ECW is able to correct the errors (by deletion, insertion, substitution and/or filling erasures), it MUST show the corrected string to the user and request confirmation that the corrected string **exactly matches** the user's copy of the data. It MUST NOT silently apply corrections without approval from the user.
    * If no valid string is found with a correct hrp, header and unique index within correction distance limits or within 10 seconds of search, give up.
    * ECWs MAY warn the user they've repeated a share if the only valid string found exactly matches a previously entered share.
1. Once all shares are entered, the wallet should recover the master seed and import this.

**The master seed should be used directly as a master seed, as specified in BIP32.**
Unlike in BIP39 or other specifications, no PBKDF or other pre-processing should be applied.

## Generate Support

TODO

