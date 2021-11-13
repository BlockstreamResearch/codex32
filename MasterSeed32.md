# Master Seed 32

WARNING: Seriously, this is a work in progress, and it is only a concept right now.
If you try to use this for your valuable data, I promise you will lose your data.
You will lose this document and come back here only to find that I have made incompatible changes,
and your data is lost forever. Even if you don't lose this document, there is no warranty or
guarantee of any kind that you will be able to recover successfully recover your data.

## Abstract

This document describes a standard format for encoding of BIP32 HD master seed data by splitting it into upto 31 shares using Shamir's secret sharing.
A minimum threshold of shares, which can be between 1 and 9, of the total number of shares is needed to recover the master seed data.
Without sufficient shares, no information about the master seed is recoverable.
Each share contains a BCH error-correcting checksum as a suffix to aid in the recovery of any partially corrupted share.

## Motiviation

The secure and safe storage of BIP-39 master seed data is paramount for backup and recovery of the source entropy used to derive all private keys in HD wallets and other private secret data.
There is a tension between security, which demands limiting the replicas of the backup, and safety which demands widely replicated backups.
While encrypted backups are, of course, an option, that ultimately leads back to essentially the same problem of how to backup the secret key used for encryption.

A naive solution is to cut the master secret into 3 overlapping pieces that each contain 2/3rds of the master secret that is encoded in a BIP-39 word list of 24 words.
This way the full master secret can be recovered by any two pieces.
Unfortunately each piece leaks 2/3rd of the master secret, leaving only 88 bits of entropy remaining, a value that is on the cusp of what is considered secure.
Furthermore it is difficult to generalize this scheme.
While more sets of overlapping pieces can be constructed, there comes a point where, with enough shares, even though they do not reconstruct the whole master seed, leave too little remaining entropy to be secure.

In this standard we choose to use Shamir's secret sharing.
This allows one to diversely distribute the generated shares, with the property that the compromise of any one share (or more depending on the choice of threshold) reveals no information about the master seed.

[SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md) has essentially the same motivations as this standard.
The main difference is that this standard aims to amenable to hand computation for those people who have a general distrust in having digital electronic devices manipulating thier secret master seed.
SLIP-0039 also directly contains a two-level sharing scheme, while a companion scheme will be needed to to split shares in this scheme into a second level.

## Specification

### MS32

This specification reuses the Bech32 character set encoding from [BIP-173](https://en.bitcoin.it/wiki/BIP_0173) to encode the shares.
Following the Bech32 format, a MS32 string consists of:

* A human-readable part, which is the string "ms32" or "MS32".
* A separator, which is always "1".
* A data part which is in turn subdivided into:
  + A threshold parameter, which is a single digit between "2" and "9", or the digit "0" which is only allowed in the unshared format (see section "Unshared Secret").
  + A "unique" identifier consisting of 3 Bech32 characters.
  + A share index, which is any Bech32 character.  Note that the a share index value of "S" is special and denotes the unshared format (see section "Unshared Secret").
  + A secret share which is 16 to 32 bytes encoded as a sequence of 26 to 52 Bech32 characters using the same procedure as Bech32's segwit address format.
  + A checksum which consists of 13 Bech32 characters as described below.

As with Bech32 strings, a MS32 string must be entirely uppercase or entirely lowercase, with lowercase being the canonical choice.

### Checksum

## Recovery

## Unshared Secret

## Generating Shares

### Sharing existing master seed

### Generating a fresh master seed
