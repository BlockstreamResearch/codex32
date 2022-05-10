# Master Seed 32

WARNING: Seriously, this is a work in progress, and it is only a concept right now.
If you try to use this for your valuable data, I promise you will lose your data.
You will lose this document and come back here only to find that I have made incompatible changes,
and your data is lost forever. Even if you don't lose this document, there is no warranty or
guarantee of any kind that you will be able to successfully recover your data.

## Abstract

This document describes a standard for backing up and restoring the master seed of a [BIP-0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) hierarchical deterministic wallet,
using Shamir's secret sharing.
It includes an encoding format, a BCH error-correcting checksum, and algorithms for share generation and secret recovery.
Secret data can be split into up to 31 shares.
A minimum threshold of shares, which can be between 1 and 9, is needed to recover the secret,
whereas without sufficient shares, no information about the secret is recoverable.

## Motivation

BIP-0032 master seed data is the source entropy used to derive all private keys in an HD wallet.
The secure and safe storage of this secret data is paramount for backup and recovery of the entire wallet.
However, there is a tension between security, which demands limiting the number of backups, and safety, which demands widely replicated backups.
Using encrypted backups is an option, but doing so leads back to essentially the same problem of how to back up the secret key(s) used for encryption.

A naive solution is to cut the secret into 3 overlapping pieces,
such that any threshold of two pieces can be used to reconstruct the entire secret.
For example, if the secret is encoded as a [BIP-0039](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) word list of 24 words,
then each piece might contain 16 words.

Unfortunately, this naive solution has significant flaws.
Each piece leaks 2/3rds of the master secret;
leaking 2/3rds of a 256-bit secret leaves only 85 bits of entropy, which is on the cusp of being considered insecure, and
leaking 2/3rds of a 128-bit secret would be considered a catastrophic failure.
Furthermore, it is difficult to generalize this approach to different numbers of pieces or different thresholds.

In this standard, we instead use Shamir's secret sharing,
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

## Specification

### MS32

This specification reuses the Bech32 character set encoding from [BIP-173](https://en.bitcoin.it/wiki/BIP_0173) to encode the shares.
Following the Bech32 format, a MS32 string consists of:

* A human-readable part, which is the string "ms" or "MS".
* A separator, which is always "1".
* A data part which is in turn subdivided into:
 + A threshold parameter, which MUST be a single digit between "2" and "9", or the digit "0".
   If the threshold parameter is "0" then the share index, defined below, MUST have a value of "s" (or "S")
 + An identifier consisting of 4 Bech32 characters.
 + A share index, which is any Bech32 character.  Note that a share index value of "s" (or "S") is special and denotes the unshared secret (see section "Unshared Secret").
 + A secret share which is a sequence of upto 74 Bech32 characters. (However, see long strings for an exception to this limit.)
 + A checksum which consists of 13 Bech32 characters as described below.

As with Bech32 strings, a MS32 string must be entirely uppercase or entirely lowercase, with lowercase being the canonical choice.

### Checksum

The last thirteen characters of the data part form a checksum and contain no information.
Valid strings MUST pass the criteria for validity specified by the Python3 code snippet below.
The function `ms32_verify_checksum` must return true when its argument is the data part as a list of integers representing the characters converted using the bech32 character table from [BIP-173](https://en.bitcoin.it/wiki/BIP_0173).

To construct a valid checksum given the data-part characters (excluding the checksum), the `ms32_create_checksum` function can be used.

```python
MS32_CONST = 0x10ce0795c2fd1e62a

def ms32_polymod(values):
  GEN = [0x19dc500ce73fde210, 0x1bfae00def77fe529, 0x1fbd920fffe7bee52, 0x1739640bdeee3fdad, 0x07729a039cfc75f5a]
  residue = 0x23181b3
  for v in values:
    b = (residue >> 60)
    residue = (residue & 0x0fffffffffffffff) << 5 ^ v
    for i in range(5):
      residue ^= GEN[i] if ((b >> i) & 1) else 0
  return residue

def ms32_verify_checksum(data):
  return ms32_polymod(data) == MS32_CONST

def ms32_create_checksum(data):
  values = data
  polymod = ms32_polymod(values + [0] * 13) ^ MS32_CONST
  return [(polymod >> 5 * (12 - i)) & 31 for i in range(13)]
```

### Error Correction

If an MS32 string without a valid checksum MUST not be used.
However the checksum is designed to be an error correcting code that can correct upto 4 character substitutions, and upto 8 unreadable characters (called erasures) or upto 13 erassures if they are consecutive.
Implementations SHOULD provide the user with a corrected valid MS32 string if possible.
However, implementations SHOULD NOT automatically proceed with a corrected MS32 string without user confirmation of the corrected string, either by prompting the user, or returning a corrected string in an error message and allowing the
user to repeat their action.
We do not specify how an implementation chooses to implement error correction.
We recommend that implementations make suggestions to substitute non-bech32 characters with bech32 characters in some situations, such as replacing "B" with "8" or "O" with "0", or "I" with "l", etc.
We recommend that implementations interpret "?" as an erasure, but may also interpret other non-bech32 characters, or characters with incorrect case, also as erasures.
We recommend that if a string with 8 or fewer erasures that can have those erasures filled in to make a valid MS32 string, then the implementation suggests such a string as a correction.
We recommend that if a string consisting of valid Bech32 characters in the proper case can be made valid by substituting 4 or fewer characters, then the implementation suggests such a string as a correction.

## Unshared Secret

When the share index of a valid MS32 string (converted to lowercase) is the letter "s", we call the string an MS32 secret.
The subsequent data characters in an MS32 secret, excluding the final checksum of 13 characters, is a direct encoding of a BIP-32 HD master seed.

The master seed is decoded by converting the data to bytes:

- Translate the characters to 5 bits values using the bech32 character table from [BIP-173](https://en.bitcoin.it/wiki/BIP_0173), most significant bit first.
- Re-arrange those bits into groups of 8 bits. Any incomplete group at the end MUST be 4 bits or less, and is discarded.

Note, unlike the decoding process in [BIP-173](https://en.bitcoin.it/wiki/BIP_0173), we do NOT require that the incomplete be all zeros.

For an unshared secret, the thereshold character (the first character) is ignored (beyond the fact it must be a digit for the MS32 string to be valid).
We recommend using the digit "0" for the threshold if Shamir's Secret Sharing is not going to be used.
The 4 character identifier also has no effect beyond aiding users in distinguishing between multiple different master seeds in cases where they have more than one.

## Recovering Master Seed

When the share index of a valid MS32 string is not "s", then we call it an MS32 share.
The first character of the string indicates the threshold of the share, and it is required to be a non-"0" digit.

In order to recover a master seed, one needs a set of valid MS32 shares with:

- all with the same threshold value, the same identifier, and the same length.
- the number of MS32 shares must be exactly equal to the threshold digit amount.
- all of the share index values must be distinct.

If all the above conditions are satisfied, the `ms32_recover` function will return a MS32 secret when its argument is the list of MS32 shares with each share represented as a list of integers representing the characters converted using t
he bech32 character table from [BIP-173](https://en.bitcoin.it/wiki/BI    P_0173).

```python
bech32_inv = [0, 1, 20, 24, 10, 8, 12, 29, 5, 11, 4, 9, 6, 28, 26, 31, 22, 18, 17, 23, 2, 25, 16, 19, 3, 21, 14, 30, 13, 7, 27, 15]

def bech32_mul(a, b):
  res = 0
  for i in range(5):
    res ^= a if ((b >> i) & 1) else 0
    a *= 2
    if (32 <= a):
      a ^= 41
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

If we already have _t_ many valid MS32 strings:

- all with the same threshold value _t_, the same identifier, and the same length.
- all of the share index values are distinct.

We can derive additional shares with the `ms32_interpolate` function by passing it a list of exactly _t_ many of these MS32 strings, and a fresh share index that is distinct from all of the other share indexes.
The derived share will have a share index equal to the provided argument.

Once a user has generated _n_ many MS32 shares they may discard the MS32 secret (if it exists) and the _n_ shares form a _t_ of _n_ Shamir's Secret Sharing scheme of a MS32 secret.

There are two ways to create an initial set of _t_ valid MS32 strings, depending on whether you have an existing master seed you wish to split, or wish to generate a fresh master seed.

### For an existing master seed

For an existing master seed need, it first needs to be converted to the format of a MS32 secret.

The data portion of the MS32 secret needs to have a threshold value of _t_ and an identifier for the master seed chosen (to distinguish it from other master seeds the user may have or later generate).
We do not define how to choose the identifier beyond noting that it SHOULD be distinct for every master seed the user may have to deal with simultaneously.
The share index must be "s".
The secret share is a Bech32 encoding of the bytes of the master seed, padded with arbitrary bits.
Lastly a valid checksum needs to be generated in accordance with the Checksum section.

Along with the MS32 secret, the user needs to generate _t_-1 other MS32 shares with the same threshold value and the same identifier, and each with a distinct share index.
The set of share indexes may be chosen arbitrarily.
The secret share of each of these MS32 shares is chosen uniformly at random such that it has the same length as the secret share of the MS32 secret.
Lastly a valid checksum needs to be generated in accordance with the Checksum section for each share.

The MS32 secret, and the _t_-1 MS32 shares form a set of _t_ many valid MS32 strings from which additions shared can be derived as described above.

### For a fresh master seed

In the case that the user wishes to generate a fresh master secret, then the user generates _t_ many random MS32 shares, all with threshold _t_ and all with the same identifier, using the generation procedure from the previous section.

With this set of _t_ many MS32 shares, new shares can be derived as discussed above.
This process generates a fresh master seed, whose value can be retrieved by running the recovery process on any _t_ many of these shares.

## Long Strings

## Test Vectors

### Test vector 1

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

### Test vector 2

This example shows generating a new master secret using "random" MS32 shares, as well as deriving an additional MS32 share, using `k = 2` and an identifier of `NAME`. Although MS32 strings are canonically all lowercase, it's also valid to use all uppercase.

Share with index `A`: `MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM`

Share with index `C`: `MS12NAMECACDEFGHJKLMNPQRSTUVWXYZ023FTR2GDZMPY6PN`

* Derived share with index `D`: `MS12NAMEDLL4F8JLH4E5VDVULDLFXU2JHDNLSM97XVENRXEG`
* Secret share with index `S`: `MS12NAMES6XQGUZTTXKEQNJSJZV4JV3NZ5K3KWGSPHUH6EVW`
* Master secret (hex): `d1808e096b35b209ca12132b264662a5`

Note that per BIP-173, the lowercase form is used when determining a character's value for checksum purposes. In particular, given an all uppercase MS32 string, we still use lowercase `ms` as the human-readable part during checksum construction.

### Test vector 3

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

### Test vector 4

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
