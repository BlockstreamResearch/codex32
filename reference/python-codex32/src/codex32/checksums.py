# codex32 constants in this file are derived from work by:
#   Author: Leon Olsson Curr and Pearlwort Sneed <pearlwort@wpsoftware.net>
#   License: BSD-3-Clause
#
# Additional code:
# Copyright (c) 2026 Ben Westgate <benwestgate@protonmail.com>, MIT License
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""Checksum specs and utilities for codex32 and CRC variants."""


# Generators are the reduction polynomials for polymod computations
CODEX32_GEN = [
    0x19DC500CE73FDE210,
    0x1BFAE00DEF77FE529,
    0x1FBD920FFFE7BEE52,
    0x1739640BDEEE3FDAD,
    0x07729A039CFC75F5A,
]
CODEX32_LONG_GEN = [
    0x3D59D273535EA62D897,
    0x7A9BECB6361C6C51507,
    0x543F9B7E6C38D8A2A0E,
    0x0C577EAECCF1990D13C,
    0x1887F74F8DC71B10651,
]
CODEX32_CONST = 0x10CE0795C2FD1E62A
CODEX32_LONG_CONST = 0x43381E570BF4798AB26


class Checksum:
    """Checksum spec (polynomial gens, length, constant, coverage, create and verify)."""

    def __init__(self, kind: str, specs, coverage):
        self.kind = kind
        self.gen, self.cs_len, self.const = specs
        self.coverage = range(coverage[0], coverage[1] + 1)  # valid lengths
        self.shift = len(self.gen) * (self.cs_len - 1)
        self.mask = (1 << self.shift) - 1

    def polymod(self, values, residue=1):
        """Internal function that computes the Bech32/Codex32/CRC checksums."""
        for value in values:
            top = residue >> self.shift
            residue = (residue & self.mask) << len(self.gen) ^ value
            for i, g in enumerate(self.gen):
                residue ^= g if ((top >> i) & 1) else 0
        return residue

    def verify(self, values):
        """Verify a checksum given values."""
        return self.polymod(values) == self.const

    def create(self, values):
        """Compute the checksum values given values."""
        polymod = self.polymod(values + [0] * self.cs_len) ^ self.const
        mask = (1 << (w := len(self.gen))) - 1
        cs_len = self.cs_len
        return [(polymod >> (w * (cs_len - 1 - i))) & mask for i in range(cs_len)]


codex32_long_spec = (CODEX32_LONG_GEN, 15, CODEX32_LONG_CONST)  # detects 8 errors
CODEX32_LONG = Checksum("Long codex32", codex32_long_spec, (96, 1023))  # expanded
CODEX32 = Checksum("codex32", (CODEX32_GEN, 13, CODEX32_CONST), (0, 93))
CRC1 = Checksum("CRC1", ([1], 1, 0), (0, 0))
CRC2 = Checksum("CRC2", ([3], 2, 0), (0, 1))  # detects 2 errors
CRC3 = Checksum("CRC3", ([3], 3, 0), (0, 4))
CRC4 = Checksum("CRC4", ([3], 4, 0), (0, 11))


def crc_pad(bits: list[int]) -> int:
    """Compute the CRC padding value given payload bits list."""
    crc = [None, CRC1, CRC2, CRC3, CRC4][k := ((-len(bits) % 5) or (len(bits) % 8))]
    crc_bits = crc.create(bits[: len(bits) // 8 * 8]) if crc else []
    return sum(b << (k - 1 - i) for i, b in enumerate(crc_bits)) if k else 0
