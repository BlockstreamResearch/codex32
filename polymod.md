# SSS32

## Polymod

See also <https://en.wikipedia.org/wiki/BCH_code>.

I requested a generator for a BCH code that can correct 4 errors on 57 data characters (supporting at least 285 bits) from sipa, who suggested three available generators with a 13 character checksum:

1. `x^13 + {10}x^12 + {30}x^11 + {14}x^10 + {26}x^9           + {17}x^7 + {28}x^6 + {18}x^5 + {18}x^4 +  {5}x^3 + {26}x^2 +  {6}x + {22}`
1. `x^13 + {27}x^12 +  {7}x^11 + {15}x^10 +  {3}x^9 + {20}x^8 + {30}x^7 + {10}x^6 + {17}x^5 +     x^4 +  {6}x^3 +  {3}x^2 + {15}x + {15}`
1. `x^13 + {29}x^12 + {30}x^11 + {16}x^10 + {26}x^9           + {16}x^7 +  {8}x^6 +  {4}x^5 + {29}x^4 + {16}x^3 + {11}x^2 + {16}x +  {8}`

These are all distance 9 (can correct 4 errors) BCH codes of degree 2 over GF(32) of length 93.
They can support payloads upto 80 characters (50 bytes; 400 bits). (Note: codewords of length 93 with a 13 character checksum leaves 80 characters for the payload)

### Derivation

The Bech32 character set encodes `F := GF(32)` as polynomials over `GF(2)` modulo `x^5 + x^3 + 1`.
We define a generator for `F` as `gen[F]` where `gen[F]^5 + gen[F]^3 + 1 = 0`.
We define `{n}` for 5-bit values `n`, which represent the value `b[0] + b[1]gen[F] + b[2]gen[F]^2 + b[3]gen[F]^3 + b[4]gen[F]^4` where `b[0]` is the least signficant bit of `n` and `b[4]` is the most sigificant bit of `n`.

The above BCH generators are all of degree 2, so requires us to consider the field extesion `E := GF(32^2) = GF(1024)` which we define as polynomials over `GF(32)` modulo `x^2 + x + {3}`.
We define a generator for `E` as `gen[E]` where `gen[E]^2 + gen[E] + {3} = 0`.

The first generator is specified by the minimal polynomials of `alpha[1]^2, alpha[1]^3, ... alpha[1]^9` where `alpha[1] = gen[E]^((1024-1)/93) = gen[E]^11 = {6}gen[E] + {22}`.
These minimal polynomials are as follows:

- `m(alpha[1]^2) = x^2 + {20}x + {10}`
- `m(alpha[1]^3) =           x +  {3}`
- `m(alpha[1]^4) = x^2 + {10}x + {22}`
- `m(alpha[1]^5) = x^2 + {21}x + {11}`
- `m(alpha[1]^6) =           x +  {5}`
- `m(alpha[1]^7) = x^2 + {30}x + {28}`
- `m(alpha[1]^8) = x^2 + {22}x + {14}`
- `m(alpha[1]^9) =           x + {15}`

The LCM of these 7 polynomials is the first listed generator, and thus `alpha[1]^2, ... alpha[1]^9` are all roots of that generating polynomial.

## Other polymods

Sipa said that to correct 3 errors would require a checksum of 10 characters on length 93 (which would support 83 characters for the payload).
To correct 5 errors would require a checksum of 16 characters on length 93 (which would support 77 characters for the payload).
