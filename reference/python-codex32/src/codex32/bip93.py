# Portions of this file are derived from work by:
#   Author: Leon Olsson Curr and Pearlwort Sneed <pearlwort@wpsoftware.net>
#   License: BSD-3-Clause
# Derived work: BECH32_INV, bech32_mul, bech32_lagrange, codex32_interpolate
#
# Modifications and additional code:
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

"""Reference implementation for codex32/Long codex32 and codex32-encoded master seeds."""


from codex32.bech32 import (
    CHARSET,
    InvalidLength,
    chars_to_u5,
    convertbits,
    u5_to_chars,
    u5_decode,
    u5_encode,
    u5_parse,
)
from codex32.checksums import CODEX32, CODEX32_LONG
from codex32.errors import CodexError

BECH32_INV = [
    0,
    1,
    20,
    24,
    10,
    8,
    12,
    29,
    5,
    11,
    4,
    9,
    6,
    28,
    26,
    31,
    22,
    18,
    17,
    23,
    2,
    25,
    16,
    19,
    3,
    21,
    14,
    30,
    13,
    7,
    27,
    15,
]


# pylint: disable=missing-class-docstring


class InvalidThreshold(CodexError): ...


class InvalidShareIndex(CodexError): ...


class MismatchedLength(CodexError): ...


class MismatchedHrp(CodexError): ...


class MismatchedThreshold(CodexError): ...


class MismatchedId(CodexError): ...


class RepeatedIndex(CodexError): ...


class ThresholdNotPassed(CodexError): ...


def bech32_mul(a, b):
    """Multiply two Bech32 values."""
    res = 0
    for i in range(5):
        res ^= a if ((b >> i) & 1) else 0
        a *= 2
        a ^= 41 if (32 <= a) else 0
    return res


def bech32_lagrange(pts, x):
    """Compute Bech32 lagrange."""
    n = 1
    c = []
    for i in pts:
        n = bech32_mul(n, i ^ x)
        m = 1
        for j in pts:
            m = bech32_mul(m, (x if i == j else i) ^ j)
        c.append(m)
    return [bech32_mul(n, BECH32_INV[i]) for i in c]


def codex32_decode(codex):
    """Validate a codex32 string's checksum and header, and determine HRP and data."""
    hrp, data, spec = u5_decode(codex, [CODEX32_LONG, CODEX32])
    if len(header := u5_to_chars(data[:6])) < 6:
        raise MismatchedLength(f"'{header}' header too short: {len(data)} < 6")
    if not (k := header[0]).isdigit():
        raise InvalidThreshold(f"threshold parameter '{k}' must be a digit")
    if k == "0" and (idx := header[5]) != "s":
        raise InvalidShareIndex(f"share index '{idx}' must be 's' when k='0'")
    return hrp, data, spec


def ms32_verify(s: str):
    """Validate a codex32-encoded master seed or share, and determine HRP and data."""
    if (hrp := u5_parse(s)[0]) != "ms":
        raise MismatchedHrp(f"{hrp} != ms")
    if len(s) not in (48, 54, 61, 67, 74, 127):  # 16-32 (by 4) or 64 byte seeds
        raise InvalidLength("'ms' strings must be 48, 54, 61, 67, 74 or 127 chars")
    return codex32_decode(s)


def codex32_interpolate(strings, x):
    """Interpolate a set of codex32 data values given target index."""
    w = bech32_lagrange([s[5] for s in strings], x)
    res = []
    for i in range(len(strings[0])):
        n = 0
        for j, val in enumerate(strings):
            n ^= bech32_mul(w[j], val[i])
        res.append(n)
    return res


def codex32_encode(hrp: str, data):
    """Compute a codex32 string given HRP and data values."""
    spec = CODEX32_LONG if 2 * len(hrp) + 1 + len(data) + 13 > 93 else CODEX32
    return u5_encode(hrp, data, spec)


def decode(s: str, pad_val: int | str = "any"):
    """Decode a codex32-encoded master seed, and determine header, seed, and padding."""
    data = ms32_verify(s)[1]
    if (header := u5_to_chars(data[:6]))[5] != "s":
        raise InvalidShareIndex(f"only master seeds ('s') have bytes, got '{header}'")
    decoded = convertbits(data[6:], 5, 8, False, pad_val)
    pad = data[-1] % (1 << ((len(data[6:]) * 5) % 8))
    return header, bytes(decoded), pad if pad_val == "any" else pad_val


def encode(header: str, seed: bytes, pad_val: int | str = "CRC"):
    """Encode a codex32-encoded master seed given header, seed, and padding."""
    if header[5:] != "s":
        raise InvalidShareIndex(f"only secrets ('s') encode bytes, got '{header}'")
    u5_payload = convertbits(seed, 8, 5, True, pad_val)
    ret = codex32_encode("ms", chars_to_u5(header) + u5_payload)
    if len(header) != 6 or (header, seed, pad_val) != decode(ret, pad_val):
        raise MismatchedLength(f"'{header}' header must be 6 chars, got {len(header)}")
    return ret


class Codex32String:
    """Class representing a codex32 string."""

    def __init__(self, s: str) -> None:
        """Initialize Codex32String from a codex32 string."""
        self.s, self.is_upper = s, s.isupper()
        verify = ms32_verify if u5_parse(s)[0] == "ms" else codex32_decode
        self.hrp, data, _ = verify(s)
        header, self.payload = u5_to_chars(data[:6]), u5_to_chars(data[6:])
        self.k, self.ident, self.share_idx = header[0], header[1:5], header[5]

    def data(self) -> bytes:
        """Return the master seed bytes of a codex32-encoded master seed."""
        return decode(self.s)[1]

    def __str__(self) -> str:
        return self.s

    def __len__(self) -> int:
        return len(self.s)

    @property
    def checksum(self) -> str:
        """Return the checksum part of the codex32 string."""
        return self.s[-codex32_decode(self.s)[2].cs_len :]

    @classmethod
    def from_unchecksummed_string(cls, s: str) -> "Codex32String":
        """Create Codex32String from unchecksummed string."""
        ret = codex32_encode(*u5_parse(s))
        return cls(ret.upper() if s.isupper() else ret)

    @classmethod
    def from_string(cls, hrp: str, s: str) -> "Codex32String":
        """Create Codex32String from a given codex32 string and HRP."""
        if (hrpgot := u5_parse(s)[0]) != hrp:
            raise MismatchedHrp(f"{hrpgot} != {hrp}")
        return cls(s)

    @classmethod
    def interpolate_at(
        cls, shares: list["Codex32String"], target: str = "s"
    ) -> "Codex32String":
        """Interpolate a set of Codex32String objects to a specific target index."""
        if not all(isinstance(share, Codex32String) for share in shares):
            raise TypeError("All shares must be Codex32String instances")
        if (threshold := int(shares[0].k) if shares else 1) > len(shares):
            raise ThresholdNotPassed(f"threshold={threshold}, n_shares={len(shares)}")
        for share in shares:
            if len(shares[0]) != len(share):
                raise MismatchedLength(f"{len(shares[0])}, {len(share)}")
            if shares[0].hrp != share.hrp:
                raise MismatchedHrp(f"{shares[0].hrp}, {share.hrp}")
            if shares[0].k != share.k:
                raise MismatchedThreshold(f"{shares[0].k}, {share.k}")
            if shares[0].ident != share.ident:
                raise MismatchedId(f"{shares[0].ident}, {share.ident}")
            if [share.share_idx for share in shares].count(share.share_idx) > 1:
                raise RepeatedIndex(share.share_idx)
        if ret := [share for share in shares if share.share_idx == target.lower()]:
            return ret.pop()
        u5_shares = [codex32_decode(share.s)[1] for share in shares]
        data = codex32_interpolate(u5_shares, CHARSET.find(target.lower()))
        ret = codex32_encode(shares[0].hrp, data)
        return cls(ret.upper() if all(s.s.upper() == s.s for s in shares) else ret)

    @classmethod
    def from_seed(
        cls, data: bytes, prefix: str, pad_val: int | str = "CRC"
    ) -> "Codex32String":
        """Create a master seed secret given prefix (ms1, k, ident) and seed bytes."""
        hrp, data_part = u5_parse(prefix)
        if hrp != "ms":
            raise MismatchedHrp(f"{hrp} != ms")
        header = u5_to_chars(data_part) + ("s" if len(data_part) == 5 else "")
        return cls(encode(header, data, pad_val))
