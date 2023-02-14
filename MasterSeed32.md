# codex32

WARNING: Seriously, this is a work in progress, and it is only a concept right now.
If you try to use this for your valuable data, I promise you will lose your data.
You will lose this document and come back here only to find that I have made incompatible changes,
and your data is lost forever. Even if you don't lose this document, there is no warranty or
guarantee of any kind that you will be able to successfully recover your data.

```
  BIP: ????
  Layer: Applications
  Title: codex32
  Author: <list of authors' real names and email addrs>
  Comments-URI: https://github.com/bitcoin/bips/wiki/Comments:BIP-????
  Status: Draft
  Type: <Standards Track | Informational | Process>
  Created: 2023-02-13
  License: BSD-3-Clause
* Post-History: <dates of postings to bitcoin mailing list, or link to thread in mailing list archive>
```

# Introduction

## Abstract

This document describes a standard for backing up and restoring the master seed of a [BIP-0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) hierarchical deterministic wallet,
using Shamir's secret sharing.
It includes an encoding format, a BCH error-correcting checksum, and algorithms for share generation and secret recovery.
Secret data can be split into up to 31 shares.
A minimum threshold of shares, which can be between 1 and 9, is needed to recover the secret,
whereas without sufficient shares, no information about the secret is recoverable.

## Copyright

This document is licensed under the 3-clause BSD license.


## Motivation

BIP-0032 master seed data is the source entropy used to derive all private keys in an HD wallet.
Safely storing this secret data is the hardest and most important part of self-custody.
However, there is a tension between security, which demands limiting the number of backups, and resilience, which demands widely replicated backups.
Encrypting the seed does not change this fundamental tradeoff, since it leaves essentially the same problem of how to back up the encryption key(s).

To allow users freedom to make this tradeoff, we use Shamir's secret sharing,
which guarantees that any number of shares less than the threshold leaks no information about the secret.
This approach allows increasing safety by widely distributing the generated shares,
while also providing security against the compromise of one or more shares
(as long as fewer than the threshold have been compromised).

[SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md) has essentially the same motivations as this standard.
However, unlike SLIP-0039, this standard also aims to be simple enough for hand computation.
Users who demand a higher level of security for particular secrets,
or have a general distrust in digital electronic devices,
have the option of using hand computation to backup and restore secret data in an interoperable manner.
Note that hand computation is optional,
the particular details of hand computation are outside the scope of this standard,
and implementers do not need to be concerned with this possibility.

[BIP-0039](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) serves the same purpose as this standard: encoding master seeds for for storage by users.
However, BIP-0039 has no error-correcting ability, cannot sensibly be extended to support secret sharing, has no support for versioning or other metadata, and has
many technical design decisions that make implementation and interoperability difficult (for example, the use of SHA-512 to derive seeds, or the use of 11-bit words).

# Specification

### MS32

An MS32 string is similar to a Bech32 string defined in [BIP-0173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki).
It reuses the base32 character set from BIP-0173, and consists of:

* A human-readable part, which is the string "ms" (or "MS").
* A separator, which is always "1".
* A data part which is in turn subdivided into:
	* A threshold parameter, which MUST be a single digit between "2" and "9", or the digit "0".
		* If the threshold parameter is "0" then the share index, defined below, MUST have a value of "s" (or "S").
	* An identifier consisting of 4 Bech32 characters.
	* A share index, which is any Bech32 character. Note that a share index value of "s" (or "S") is special and denotes the unshared secret (see section "Unshared Secret").
	* A payload which is a sequence of up to 74 Bech32 characters. (However, see [Long MS32 Strings](#long-ms32-strings) for an exception to this limit.)
	* A checksum which consists of 13 Bech32 characters as described below.

As with Bech32 strings, an MS32 string MUST be entirely uppercase or entirely lowercase. The lowercase form is used when determining a character's value for checksum purposes. For presentation, lowercase is usually preferable, but uppercase SHOULD be used for handwritten MS32 strings.

### Checksum

The last thirteen characters of the data part form a checksum and contain no information.
Valid strings MUST pass the criteria for validity specified by the Python3 code snippet below.
The function `ms32_verify_checksum` must return true when its argument is the data part as a list of integers representing the characters converted using the bech32 character table from BIP-0173.

To construct a valid checksum given the data-part characters (excluding the checksum), the `ms32_create_checksum` function can be used.

```python
MS32_CONST = 0x10ce0795c2fd1e62a

def ms32_polymod(values):
    GEN = [
        0x19dc500ce73fde210,
        0x1bfae00def77fe529,
        0x1fbd920fffe7bee52,
        0x1739640bdeee3fdad,
        0x07729a039cfc75f5a,
    ]
    residue = 0x23181b3
    for v in values:
        b = (residue >> 60)
        residue = (residue & 0x0fffffffffffffff) << 5 ^ v
        for i in range(5):
            residue ^= GEN[i] if ((b >> i) & 1) else 0
    return residue

def ms32_verify_checksum(data):
    if len(data) >= 96:                       # See Long MS32 Strings
        return ms32_verify_long_checksum(data)
    if len(data) <= 93:
        return ms32_polymod(data) == MS32_CONST
    return False

def ms32_create_checksum(data):
    if len(data) > 80:                       # See Long MS32 Strings
        return ms32_create_long_checksum(data)
    values = data
    polymod = ms32_polymod(values + [0] * 13) ^ MS32_CONST
    return [(polymod >> 5 * (12 - i)) & 31 for i in range(13)]
```

### Error Correction

An MS32 string without a valid checksum MUST NOT be used.
The checksum is designed to be an error correcting code that can correct up to 4 character substitutions, up to 8 unreadable characters (called erasures), or up to 13 consecutive erasures.
Implementations SHOULD provide the user with a corrected valid MS32 string if possible.
However, implementations SHOULD NOT automatically proceed with a corrected MS32 string without user confirmation of the corrected string,
either by prompting the user,
or returning a corrected string in an error message and allowing the user to repeat their action.
We do not specify how an implementation should implement error correction.
However, we recommend that:

* Implementations make suggestions to substitute non-bech32 characters with bech32 characters in some situations, such as replacing "B" with "8", "O" with "0", "I" with "l", etc.
* Implementations interpret "?" as an erasure.
* Implementations optionally interpret other non-bech32 characters, or characters with incorrect case, as erasures.
* If a string with 8 or fewer erasures can have those erasures filled in to make a valid MS32 string, then the implementation suggests such a string as a correction.
* If a string consisting of valid Bech32 characters in the proper case can be made valid by substituting 4 or fewer characters, then the implementation suggests such a string as a correction.

## Unshared Secret

When the share index of a valid MS32 string (converted to lowercase) is the letter "s", we call the string an MS32 secret.
The subsequent data characters in an MS32 secret, excluding the final checksum of 13 characters, is a direct encoding of a BIP-0032 HD master seed.

The master seed is decoded by converting the data to bytes:

* Translate the characters to 5 bits values using the bech32 character table from BIP-0173, most significant bit first.
* Re-arrange those bits into groups of 8 bits. Any incomplete group at the end MUST be 4 bits or less, and is discarded.

Note that unlike the decoding process in BIP-0173, we do NOT require that the incomplete group be all zeros.

For an unshared secret, the threshold parameter (the first character of the data part) is ignored (beyond the fact it must be a digit for the MS32 string to be valid).
We recommend using the digit "0" for the threshold parameter in this case.
The 4 character identifier also has no effect beyond aiding users in distinguishing between multiple different master seeds in cases where they have more than one.

## Recovering Master Seed

When the share index of a valid MS32 string (converted to lowercase) is not the letter "s", we call the string an MS32 share.
The first character of the data part indicates the threshold of the share, and it is required to be a non-"0" digit.

In order to recover a master seed, one needs a set of valid MS32 shares such that:

- All shares have the same threshold value, the same identifier, and the same length.
- All of the share index values are distinct.
- The number of MS32 shares is exactly equal to the (common) threshold value.

If all the above conditions are satisfied, the `ms32_recover` function will return a MS32 secret when its argument is the list of MS32 shares with each share represented as a list of integers representing the characters converted using the bech32 character table from BIP-0173.

```python
bech32_inv = [
    0, 1, 20, 24, 10, 8, 12, 29, 5, 11, 4, 9, 6, 28, 26, 31,
    22, 18, 17, 23, 2, 25, 16, 19, 3, 21, 14, 30, 13, 7, 27, 15,
]

def bech32_mul(a, b):
    res = 0
    for i in range(5):
        res ^= a if ((b >> i) & 1) else 0
        a *= 2
        a ^= 41 if (32 <= a) else 0
    return res

def bech32_lagrange(l, x):
    n = 1
    c = []
    for i in l:
        n = bech32_mul(n, i ^ x)
        m = 1
        for j in l:
            m = bech32_mul(m, (x if i == j else i) ^ j)
        c.append(m)
    return [bech32_mul(n, bech32_inv[i]) for i in c]

def ms32_interpolate(l, x):
    w = bech32_lagrange([s[5] for s in l], x)
    res = []
    for i in range(len(l[0])):
        n = 0
        for j in range(len(l)):
            n ^= bech32_mul(w[j], l[j][i])
        res.append(n)
    return res

def ms32_recover(l):
    return ms32_interpolate(l, 16)
```

## Generating Shares

If we already have _t_ valid MS32 strings such that:

* All strings have the same threshold value _t_, the same identifier, and the same length
* All of the share index values are distinct

Then we can derive additional shares with the `ms32_interpolate` function by passing it a list of exactly _t_ of these MS32 strings,
together with a fresh share index distinct from all of the existing share indexes.
The newly derived share will have the provided share index.

Once a user has generated _n_ MS32 shares, they may discard the MS32 secret (if it exists).
The _n_ shares form a _t_ of _n_ Shamir's secret sharing scheme of an MS32 secret.

There are two ways to create an initial set of _t_ valid MS32 strings,
depending on whether the user already has an existing master seed to split.

### For an existing master seed

Before generating shares for an existing master seed, it first must be converted into an MS32 secret, as described above.
The conversion process consists of:

* Choosing a threshold value _t_ between 2 and 9, inclusive
* Choosing a 4 bech32 character identifier
	* We do not define how to choose the identifier, beyond noting that it SHOULD be distinct for every master seed the user may need to disambiguate.
* Setting the share index to "s"
* Setting the payload to a Bech32 encoding of the master seed, padded with arbitrary bits
* Generating a valid checksum in accordance with the Checksum section

Along with the MS32 secret, the user must generate _t_-1 other MS32 shares,
each with the same threshold value, the same identifier, and a distinct share index.
The set of share indexes may be chosen arbitrarily.
The payload of each of these MS32 shares is chosen uniformly at random such that it has the same length as the payload of the MS32 secret.
For each share, valid checksum must be generated in accordance with the Checksum section.

The MS32 secret and the _t_-1 MS32 shares form a set of _t_ valid MS32 strings from which additional shared can be derived as described above.

### For a fresh master seed

In the case that the user wishes to generate a fresh master secret,
the user chooses a threshold value _t_ and an identifier,
then generates _t_ random MS32 shares, using the generation procedure from the previous section.
As before, each share must have the same threshold value _t_, the same identifier, and a distinct share index.

With this set of _t_ MS32 shares, new shares can be derived as discussed above.
This process generates a fresh master seed, whose value can be retrieved by running the recovery process on any _t_ of these shares.

## Long MS32 Strings

The 13 character checksum design only supports up to 80 data characters.
Excluding the threshold, identifier and index characters this limits the payload to 74 characters or 46 bytes.
While this is enough to support the 32-byte advised size of BIP-32 master seeds, BIP-32 allows seeds to be up to 64 bytes in size.
We define a long MS32 string format to support these longer seeds by defining an alternative checksum.

```python
MS32_LONG_CONST = 0x43381e570bf4798ab26

def ms32_long_polymod(values):
    GEN = [
        0x3d59d273535ea62d897,
        0x7a9becb6361c6c51507,
        0x543f9b7e6c38d8a2a0e,
        0x0c577eaeccf1990d13c,
        0x1887f74f8dc71b10651,
    ]
    residue = 0x23181b3
    for v in values:
        b = (residue >> 70)
        residue = (residue & 0x3fffffffffffffffff) << 5 ^ v
        for i in range(5):
            residue ^= GEN[i] if ((b >> i) & 1) else 0
    return residue

def ms32_verify_long_checksum(data):
    return ms32_long_polymod(data) == MS32_LONG_CONST

def ms32_create_long_checksum(data):
    values = data
    polymod = ms32_long_polymod(values + [0] * 15) ^ MS32_LONG_CONST
    return [(polymod >> 5 * (14 - i)) & 31 for i in range(15)]
```

A long MS32 string follows the same specification as a regular MS32 string with the following changes.

* The payload is a sequence of between 75 and 103 Bech32 characters.
* The checksum consists of 15 Bech32 characters as defined above.

A MS32 string with a data part of 94 or 95 charaters is never legal as a regular MS32 string is limited to 93 data characters and a long MS32 string is at least 96 characters.

Generation of long shares and recovery of the master seed from long shares proceeds in exactly the same was as for regular shares with the `ms32_interpolate` function.

The long checksum is designed to be an error correcting code that can correct up to 4 character substitutions, up to 8 unreadable characters (called erasures), or up to 15 consecutive erasures.
As with regular checksums we do not specify how an implementation should implement error correction, and all our recommendations for error correction of regular MS32 strings also apply to long MS32 strings.

# Rationale

Storing master seeds is the most important component of self-custody.
Users who do not wish to use multisignature setups or sweep their coins must do so by encoding the master secret and physically encoding it.
The current best practices for this are either to:

* Use BIP39, which suffers from a weak checksum, uses English words which are have inconsistent lengths and near collisions (or other word lists, the choice of which affects the derived secret but is not explicitly encoded anywhere), and has no natural way to add Shamir Secret Sharing; or
* Use SLIP-39, which also uses English words, includes features such as passphrase-based hardening and two-level sharing that may not be worth the additional implementation complexity, and does not have a BIP number.

codex32 is a simpler version of SLIP-39 which has a slightly stronger checksum, a more compact and language-independent encoding, and is simple enough that all parts of the scheme (including error detection but not error correction), can be implemented without the use of electronic computers.

# Backwards Compatibility

codex32 is an alternative to BIP39 and SLIP-39.
It is technically  possible to derive the BIP32 master seed from seed words encoded in one of these schemes, and then to encode this seed in codex32.
For BIP39 this process is irreversible, since it involves hashing the original words.
Furthermore, the resulting seed will be 512 bits long, which may be too large to be safely and conveniently handled.

SLIP-39 seed words can be reversibly converted to master seeds, so it is possible to interconvert between SLIP-39 and codex32.
However, SLIP-39 **shares** cannot be converted to codex32 shares because the two schemes use a different underlying field.

The authors of this BIP do not recommend interconversion. Instead, users who wish to switch to codex32 should generate a fresh seed and sweep their coins.

# Reference Implementation

* [Reference PostScript Implementation](https://github.com/roconnor-blockstream/SSS32/)
* FIXME add Python implementation
* FIXME add Rust implementation

# Test Vectors

## Test vector 1

This example shows the MS32 format, when used without splitting the secret into any shares. The data part contains 26 Bech32 characters, which corresponds to 130 bits. We truncate the last two bits in order to obtain a 128-bit master secret.

MS32 secret (Bech32): `ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw`

Master secret (hex): `318c6318c6318c6318c6318c6318c631`

* human-readable part: `ms`
* separator: `1`
* k value: `0` (no secret splitting)
* identifier: `test`
* share index: `s` (the secret)
* data: `xxxxxxxxxxxxxxxxxxxxxxxxxx`
* checksum: `4nzvca9cmczlw`

## Test vector 2

This example shows generating a new master secret using "random" MS32 shares, as well as deriving an additional MS32 share, using `k = 2` and an identifier of `NAME`. Although MS32 strings are canonically all lowercase, it's also valid to use all uppercase.

Share with index `A`: `MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM`

Share with index `C`: `MS12NAMECACDEFGHJKLMNPQRSTUVWXYZ023FTR2GDZMPY6PN`

* Derived share with index `D`: `MS12NAMEDLL4F8JLH4E5VDVULDLFXU2JHDNLSM97XVENRXEG`
* Secret share with index `S`: `MS12NAMES6XQGUZTTXKEQNJSJZV4JV3NZ5K3KWGSPHUH6EVW`
* Master secret (hex): `d1808e096b35b209ca12132b264662a5`

Note that per BIP-173, the lowercase form is used when determining a character's value for checksum purposes. In particular, given an all uppercase MS32 string, we still use lowercase `ms` as the human-readable part during checksum construction.

## Test vector 3

This example shows splitting an existing 128-bit master secret into "random" MS32 shares, using `k = 3` and an identifier of `cash`. We appended two zero bits in order to obtain 26 Bech32 characters (130 bits of data) from the 128-bit master secret.

Master secret (hex): `ffeeddccbbaa99887766554433221100`

Secret share with index `s`: `ms13cashsllhdmn9m42vcsamx24zrxgs3qqjzqud4m0d6nln`

Share with index `a`: `ms13casha320zyxwvutsrqpnmlkjhgfedca2a8d0zehn8a0t`

Share with index `c`: `ms13cashcacdefghjklmnpqrstuvwxyz023949xq35my48dr`

* Derived share with index `d`: `ms13cashd0wsedstcdcts64cd7wvy4m90lm28w4ffupqs7rm`
* Derived share with index `e`: `ms13casheekgpemxzshcrmqhaydlp6yhms3ws7320xyxsar9`
* Derived share with index `f`: `ms13cashf8jh6sdrkpyrsp5ut94pj8ktehhw2hfvyrj48704`

Any three of the five shares among `acdef` can be used to recover the secret.

Note that the choice to append two zero bits was arbitrary, and any of the following four secret shares would have been valid choices. However, each choice would have resulted in a different set of derived shares.

* `ms13cashsllhdmn9m42vcsamx24zrxgs3qqjzqud4m0d6nln`
* `ms13cashsllhdmn9m42vcsamx24zrxgs3qpte35dvzkjpt0r`
* `ms13cashsllhdmn9m42vcsamx24zrxgs3qzfatvdwq5692k6`
* `ms13cashsllhdmn9m42vcsamx24zrxgs3qrsx6ydhed97jx2`

## Test vector 4

This example shows converting a 256-bit secret into an MS32 secret, without splitting the secret into any shares. We appended four zero bits in order to obtain 52 Bech32 characters (260 bits of data) from the 256-bit secret.

256-bit secret (hex): `ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100`

* MS32 secret: `ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqtum9pgv99ycma`

Note that the choice to append four zero bits was arbitrary, and any of the following sixteen MS32 secrets would have been valid:

* `ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqtum9pgv99ycma`
* `ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqpj82dp34u6lqtd`
* `ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqzsrs4pnh7jmpj5`
* `ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqrfcpap2w8dqezy`
* `ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqy5tdvphn6znrf0`
* `ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq9dsuypw2ragmel`
* `ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqx05xupvgp4v6qx`
* `ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq8k0h5p43c2hzsk`
* `ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqgum7hplmjtr8ks`
* `ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqf9q0lpxzt5clxq`
* `ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq28y48pyqfuu7le`
* `ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqt7ly0paesr8x0f`
* `ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqvrvg7pqydv5uyz`
* `ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqd6hekpea5n0y5j`
* `ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqwcnrwpmlkmt9dt`
* `ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq0pgjxpzx0ysaam`

### Test vector 5

This example shows generating a new 512-bit master secret using "random" MS32 characters and appending a checksum.
The payload contains 103 Bech32 characters, which corresponds to 515 bits.
The last three bits are discarded when converting to a 512-bit master secret.

This is an example of a [Long MS32 String](#long-ms32-strings).

* Secret share with index `S`: `MS100C8VSM32ZXFGUHPCHTLUPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZYGSFJD6AN074RXVCEMLH8WU3TK925ACDEFGHJKLMNPQRSTUVWXY06FHPV80UNDVARHRAK`
* Master secret (hex): `dc5423251cb87175ff8110c8531d0952d8d73e1194e95b5f19d6f9df7c01111104c9baecdfea8cccc677fb9ddc8aec5553b86e528bcadfdcc201c17c638c47e9`
