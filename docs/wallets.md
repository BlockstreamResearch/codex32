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

Wallets SHOULD support import of 128- and 256-bit seeds; 512-bit seeds are optional; other lengths are NOT RECOMMENDED. 128-bit seeds encode as 48-character codex32 strings, including the `MS1` prefix. 256-bit seeds encode as 74-character codex32 strings. For other bit-lengths, see the BIP.

The process for entering codex32 strings is:

1. The user should enter the first string. To the extent possible given screen limitations, data should be displayed in uppercase with visually distinct four-character windows. The first four-character window should include the `MS1` prefix, which SHOULD be pre-filled.
   * The user MUST be able to enter all bech32 characters.
   * ECWs MUST also allow entry of `?` which indicates an erasure (unknown character).
   * The user SHOULD NOT be able to enter mixed-case characters.
   * If the header is invalid, the wallet SHOULD highlight the problem and if not an ECW, request confirmation from the user before allowing additional data to be entered.
     * An invalid header is one that starts with a character other than `0` or `2` through `9`, or one which starts with `0` but whose share index is not `S`. For shares after the first, a header is also invalid if its threshold and identifier do not match those of the first share or whose share index matches any previous share.
     * ECWs SHOULD replace the offending characters of the header with `?`.
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
   * If the string has index `S`, this is the codex32 secret and the import process is complete.
   * Otherwise, the fourth character of the share will be a numeric character between `2` and `9` inclusive. The user must enter this many shares in total.
   * Wallets MAY encrypt and store recovery progress, to allow recovery without having all shares available at once. The details of this are currently outside of the scope of this specification.
1. The user should then enter the remaining shares, in the same manner as the first.
   * The wallet SHOULD pre-fill the header (threshold value and identifier).
   * If the user tries to repeat an already-entered share index, they SHOULD be prevented from entering additional data until the user confirms they are not repeating a share.
     * non-ECWs SHOULD highlight the error and request the user to correct it before allowing additional data to be entered.
     * ECWs SHOULD replace the offending share index with `?`.
   * If the checksum fails, the wallet MAY attempt correction by deleting and/or inserting characters. However, the wallet MUST assume the valid length of all subsequent shares is equal to the valid length of the first share, so the number of characters inserted and deleted must net out to the correct length.
1. For all invalid codex32 strings entered, if an ECW is able to correct the errors (by deletion, insertion, substitution and/or filling erasures), it MUST show the corrected string to the user and request confirmation that the corrected string **exactly matches** the user's copy of the data. It MUST NOT silently apply corrections without approval from the user.
    * If no valid string is found with a correct hrp, header and unique index within correction distance limits or within 10 seconds of search, give up.
    * ECWs MAY warn the user they've repeated a share if the only valid string found exactly matches a previously entered share.
1. Once all shares are entered, the wallet should recover the master seed and import this.

**The master seed should be used directly as a master seed, as specified in BIP32.**
Unlike in BIP39 or other specifications, no PBKDF or other pre-processing should be applied.

## Generate Unshared Secrets Support

There are two levels of generate support:

* The ability to generate seeds; here we essentially just have recommendations about encoding, display and confirmation.
* The ability to generate share sets on the device; here our guidance is more involved.

Even wallets that don't need SSS features we encourage to support codex32 seed export as this has several advantages over BIP-39:
- Checksum corrects up to 4 errors and 13 erasures during import
- Hand-verifiable checksums isolate seed integrity checks from hardware exposure risks
- Fixed-length compact encodings are faster to write and confirm
- No wordlist or PBKDF2 dependencies
- Forwards-compatible with Codex32 SSS and SLIP-39
- The added functionality is isolated from the rest of the wallet (once the seed is exported you don't care where it went to)
- The technical difficulty is low (roughly on par with that of generating Segwit addresses)

Supporting share set generation is a little more involved so the tradeoff between
implementation complexity and user value is less clear, especially since the
Codex provides users instructions on doing share generation themselves.

The remainder of this sub-heading gives guidance on exporting seeds as codex32 secrets without SSS. Wallet developers planning to implement SSS should read it first as almost all of it will apply to SSS.

### Unshared (single-string) semantics — REQUIRED

For single-string codex32 secret exports ("unshared") the following semantics are REQUIRED.

1. Bitlength
   * Wallets MUST support generating 128- or 256-bit seeds;
   * SHOULD support generating 128-bit seeds;
   * MAY support generating 256- or 512-bit seeds; other lengths are NOT RECOMMENDED.
     - Wallets which use a 512-bit BIP-0032 master seed (BIP39) SHOULD generate a fresh 128-bit master seed and encourage users to sweep funds to a new seed rather than export it.
       - This can be done deterministically from the existing master seed using the [codex32 BIP-85 application](https://github.com/bitcoin/bips/pull/1958) without needing new entropy if it is merged.

1. Header fields
   * The share index MUST be `S`.
   * The threshold digit SHOULD be `0`.
   * For an unshared secret, the threshold digit is ignored so MAY be used for cosmetic purposes.

1. Identifier policy
   * An identifier is used to group shares belonging to the same secret when shares exist.
   * For generated secrets the identifier SHOULD be chosen by the device and SHOULD be unique per master seed.
     * The default SHOULD be the bech32-encoded BIP-0032 master key fingerprint.
       * By assuming this default, even stateless wallets MAY give useful help finding the correct codex32 strings to import given descriptors and PSBTs.
   * Wallets MAY allow user specified identifiers.
   * Collisions are unlikely but a wallet MAY reject identifiers that conflict with an existing identifier and SHOULD reject headers that are not unique for different master seeds or share sets.
     * Wallets should store, subject to hardware limitations, identifiers used and their corresponding master fingerprint to assist with ensuring uniqueness by warning the user they're reusing an identifier previously confirmed.
  
1. Human-readable part policy
   * Wallets MUST NOT use custom human-readable parts `hrp` without first registering them with [SLIP-0173](https://github.com/satoshilabs/slips/blob/master/slip-0173.md#uses-of-codex32).
   * New `hrp` SHOULD use 2 character strings to simplify implementations' assumptions about lengths.
   * Wallets MUST NOT expose `hrp` as an option as it's fixed by specific network applications.
   * Bitcoin mainnet wallets MUST support 'ms' for master seeds.

### Codex32 secret backup process:

1. User selects OPTIONAL parameters (`identifier`, `bitlength`).
1. Entropy or an existing master seed is extracted and encoded into a codex32 secret.
1. Secret displays for user to note down on paper or metal.
1. Confirm backup by asking user to re-enter from their transcription.
   * Note: This has different rules than during import.
1. Once the codex32 secret is confirmed, the wallet should recover the master seed:
   * automatically from memory and import this; or
   * manually as per "Import Support" by requesting the freshly written codex32 secret.
1. After wallet import, the unshared secret generation process is complete.

**The master seed should be used directly as a master seed, as specified in BIP32.**
Unlike in BIP39 or other specifications, no PBKDF or other pre-processing should be applied.

### Extract and encode entropy

Existing master seeds are converted to bech32 characters. For 128-bit seeds there are 2 padding bits, for 256-bit seeds there are 4 padding bits. 
Padding SHOULD be set by this CRC polynomial: `(1 << pad_len) | 3` using 0 initial value.

```python3
def compute_crc(crc_len, values):
    """Internal function that computes a CRC checksum for padding."""
    if not 0 <= crc_len < 5: # Codex32 string CRC padding
        raise InvalidLength(f"{crc_len!r} (expected int in 0..4)")
    # Define the CRC polynomial (x^crc_len + x + 1) optimal for 1-4
    polynomial = (1 << crc_len) | 3
    crc = 0
    for i, bit in enumerate(values):
        if bit not in (0, 1):
            raise InvalidDataValue(f" 0 or 1 index={i} value={bit}")
        crc = (crc << 1) | int(bit)
        if crc & (1 << crc_len):
            crc ^= polynomial
    return crc & (2 ** crc_len - 1) # Return last crc_len bits as CRC


def convertbits(data, frombits, tobits, pad=True, pad_val=-1):
    """General power-of-2 base conversion with CRC padding."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for i, value in enumerate(data):
        if value < 0 or (value >> frombits):
            raise InvalidDataValue(f" 0 though {frombits} index={i} value={value}")
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
            acc = acc & ((1 << bits) - 1)
    if pad and bits:
        if pad_val == -1:  # Use CRC padding
            data_bits = convertbits(ret, tobits, 1) + convertbits([acc], bits, 1)
            pad_val = compute_crc(tobits - bits, convertbits(data_bits, tobits, 1))
        ret.append(((acc << (tobits - bits)) + pad_val) & maxv)
    elif bits >= frombits:
        raise IncompleteGroup(f"{bits} bits left over")
    return ret
```

Rationale: using a CRC code improves error detection beyond the limits of the codex32 checksum, these are also hand-computable. Only master seed bits are covered as header is unnecessary to recover.

### Display and confirmation

#### Display guidance

1. Wallets SHOULD split the uppercase codex32 string into 4-character windows.
1. Insert a three-per-em space between windows and two between every 6 window group.
1. Instruct users to write down their codex32 string on one line and/or provide a template.
1. To the extent possible given screen limitations, display the formatted string.
    - Monospaced font SHOULD be used for legibility, even if it is not elsewhere.
    - Capability to copy or screenshot the string SHOULD be restricted, if possible.
    - If the wallet must break the string in pieces, it SHOULD number the views.
      - The user SHOULD NOT write these numbers so a template SHOULD be provided.
1. When the user indicates transcription is complete, confirmation SHOULD start.

#### Confirmation guidance

During confirmation, wallets:

- MUST NOT provide error correction.
  - All final entry MUST exactly match the correct string.
- SHOULD only display characters in the upper-case bech32 character set.
  - MAY attempt to silently replace invalid characters with the bech32 character commonly confused with their keystroke.
    - e.g. B with 8 or O with 0 and I with L.
- SHOULD highlight red completed 4-character windows that contain an error.
  - Preferred to highlighting incorrect windows so everything after an insert or delete does not turn red.
- Error detection MUST NOT highlight error locations at finer resolution than 4-character windows.
- MUST NOT flag/highlight until a window is complete, at the earliest.
  - MAY delay, slow fade, or post-pone this until full entry to avoid distracting the user.
  - Unless it is the last window in a string not divisible by 4. Then it is considered complete when its length is correct.
- SHOULD lock correctly entered, unhighlighted boxes from further edits and turn their font color dark green.
  - This feels satisfying and looks like a "progress bar", practically it prevents entry of new errors after confirmation.
- MAY highlight incorrect strings or incorrect 4-character windows.

There are two verification types:
* Full verification which Desktop Wallets SHOULD use.
* Partial verification which other wallets MAY use, particularly those with limited-input.

These have different assurances of string fidelity, vulnerability to keyloggers, shoulder surfing, user fatigue, user skipping due to time costs, ease of entry, and speed.
- If the user skips validation of any string, the wallet MUST NOT automatically import a fresh master seed. A full recovery MUST be performed from the backup to access the seed.
- They should be able to continue confirmation where they left off later, subject to hardware limitations.

#### Partial Verification

If supported, SHOULD support 128-bit and/or 256-bit seeds, MAY support it for 512-bit seeds.

Steps:
1. Split the codex32 string into 4-character windows (the last window may be less).
1. Combine consecutive windows into groups of (up to) three windows each.
1. For each group, display it and have the user confirm one window at random.
  - e.g. `MS10 TEST ____`, `___ TEST STUV`, or `MS10 ____ STUV`.
  - Pick some other undisplayed windows from the string(s) at random as options.
    - Minimum options REQUIRED: 6 for 128-bit entropy, 8 for 256-bit entropy.
      - "entropy" is the total bits extracted from the master seed or RNG earlier.
    - For every 128-bits additional entropy, minimum options increases by 2, for example a 512-bit seed requires minimum 12 options.
  - Add the correct window to the options, then the wallet MUST shuffle the combined options.
  - If user selects or types the wrong window, a wallet MUST:
    - Advise it was incorrect and to check their codex32 backup.
    - Request they try again.
    - MAY require they start over from the beginning to discourage guessing.
    - MAY require the group or window in question be revisited at the end until it is correct on the first try.
    - SHOULD exclude windows confirmed on the first try from being selected again in either optional approach.
All groups ensures wallets MUST at the very least display what is unconfirmed.

#### Full Verification

Steps:

1. The user should type the string. To the extent possible given screen limitations, data should be displayed in uppercase with visually distinct four-character windows.
  - The `MS1` prefix MUST NOT be pre-filled.
  - The header MUST NOT be pre-filled.
  - Wallets MAY highlight windows, groups of windows or strings red that contain at least one error, but
    - This includes substitutions, insertions, deletions, transpositions, etc
  - they MUST NOT highlight specific error characters or locations.
1. If any errors arise, pressing tab should jump to the next error window, and shift tab to the previous. Space bar may also be bound to this as the strings do not contain spaces that need to be typed, they are only cosmetic. 
1. When all characters are correctly entered the entire string will then be locked with dark green text.
1. The software SHOULD procede to the next step automatically without requesting submission.
1. After verification of the final string the wallet should recover the master seed and import it.
1. Wallets MAY make the user perform a recovery from scratch after verification as an extra layer of assurance the backup has been created and transcribed correctly.

### Test vectors

Vector 1 — 128-bit unshared
- label: ut128-1
- entropy_hex: 000102030405060708090a0b0c0d0e0f
- codex32_unshared: ms10x3ppsqqqsyqcyq5rqwzqfpg9scrgwpugdxwtavhv7w48
- decoded_entropy_hex: 000102030405060708090a0b0c0d0e0f

Vector 2 — 256-bit unshared
- label: ut256-1
- entropy_hex: ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100
- codex32_unshared: ms10lwkksllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqpmlzwj5vy2a48f
- decoded_entropy_hex: ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100
