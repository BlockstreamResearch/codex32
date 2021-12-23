# Master Seed 32

WARNING: Seriously, this is a work in progress, and it is only a concept right now.
If you try to use this for your valuable data, I promise you will lose your data.
You will lose this document and come back here only to find that I have made incompatible changes,
and your data is lost forever. Even if you don't lose this document, there is no warranty or
guarantee of any kind that you will be able to successfully recover your data.

## Abstract

This document describes a standard format for encoding of BIP-32 HD master seed data by splitting it into upto 31 shares using Shamir's secret sharing.
A minimum threshold of shares, which can be between 1 and 9, of the total number of shares is needed to recover the master seed data.
Without sufficient shares, no information about the master seed is recoverable.
Each share contains a BCH error-correcting checksum as a suffix to aid in the recovery of any partially corrupted share.

## Motivation

The secure and safe storage of BIP-39 master seed data is paramount for backup and recovery of the source entropy used to derive all private keys in HD wallets and other private secret data.
There is a tension between security, which demands limiting the replicas of the backup, and safety, which demands widely replicated backups.
While encrypted backups are, of course, an option, that ultimately leads back to essentially the same problem of how to backup the secret key used for encryption.

A naive solution is to cut the master secret into 3 overlapping pieces that each contain 2/3rds of the master secret that is encoded in a BIP-39 word list of 24 words.
This way the full master secret can be recovered by any two pieces.
Unfortunately each piece leaks 2/3rd of the master secret, leaving only 88 bits of entropy remaining, a value that is on the cusp of what is considered secure.
Furthermore it is difficult to generalize this scheme.
While more sets of overlapping pieces can be constructed, there comes a point where, with enough shares, even though they do not reconstruct the whole master seed, leave too little remaining entropy to be secure.

In this standard we choose to use Shamir's secret sharing.
This allows one to diversely distribute the generated shares, with the property that the compromise of any one share (or more depending on the choice of threshold) reveals no information about the master seed.

[SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md) has essentially the same motivations as this standard.
The main difference is that this standard aims to be amenable to hand computation for those people who have a general distrust in having digital electronic devices manipulating their secret master seed.
SLIP-0039 also directly contains a two-level sharing scheme, while a companion scheme will be needed to split shares in this scheme into a second level.

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
  GEN = [0x1f28f80fffe92f842, 0x1751a20bdef255484, 0x07a316039ceda0d08, 0x0e0e2c0739da09a10, 0x1c164a0e739d13129]
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
