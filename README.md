# codex32

**codex32** is a scheme for checksumming and Shamir Secret Sharing based on paper computers (volvelles).
It is currently under construction and far from production-ready, but is usable by motivated experimentors.
This scheme is tedious and not for the faint-of-heart, but does not require any mathematical understanding; only perseverance, focus, and an ability to follow precise instructions.

We welcome feedback from everybody, either through issues on this Github repo or email to `pearlwort@wpsoftware.net`.

![Image of two Volvelles used for secret recovery](./images/volvelles.jpg)

## What is this repo?

Aside from documentation, this repository contains a single file, `SSS32.ps`, which contains the entire source code of the project.
It is hand-written Postscript, which means that it can be opened by a document viewer but also in a text editor, which will reveal the code used to generate the wheels and worksheets.
(If you are unable to open the file with a popular document viewer, please let us know!)

To produce a PDF file, on a Linux machine the most straightforward way is to run the command
```
ps2pdf -dPDFSETTINGS=/prepress SSS32.ps

```

If you are a software developer or mathematician who would like to contribute, feel free to open a pull request, join us on IRC (Libera) `#volvelle-wizards`, or contact Pearlwort by email.

## What is this project?

This project is a scheme to  generate, encode, checksum, split and recover Bitcoin secret keys, using pencil, paper and lookup tables (alternately, volvelles).
It works with 128- or 256-bit secrets, encoded in the [bech32](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) alphabet.
**No wallets currently support such secrets. Do not use this scheme with real money.**

The project began in early 2020, as an extension of a "[2018 blog point on computing Bech32 checksums with pen and paper](http://r6.ca/blog/20180106T164028Z.html)".
It uses a stronger error-correcting code than bech32 and introduces volvelles as a faster and less error-prone alternate to lookup tables.
Initially it was a hobby project by the first author, Leon Olsson Curr, who was later joined by Pearlwort Snead.
Pearlwort is the primary advocate for mainstream usage and any real-life problems or complaints should be directed to him.

codex32, in addition to generating and verifying checksums, also includes an implementation of Shamir's Secret Sharing Scheme (SSSS).
This scheme gives users the ability to split their checksummed secrets into many pieces, such that the original secret can be recovered by threshold-many pieces.
The threshold is set by the user and is typically 2 or 3.

## Where are the artistic wheels?

This repository is actively being developed and does not cointain the latest experimental work. In particular,

* The color illustrations are available in [Pearlwort's "complete" branch](https://github.com/apoelstra/SSS32/tree/complete)
* The mathematical companion can be found in [a separate repo](https://github.com/apoelstra/volvelle-math-companion)
* The official website is at [not yet hosted]


