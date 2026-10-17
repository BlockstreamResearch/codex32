# Portions of this file are derived from work by:
#   Copyright (c) 2017, 2020 Pieter Wuille
#
# Additional code and modifications:
#   Copyright (c) 2026 Ben Westgate <benwestgate@protonmail.com>
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

"""Internal bech32 and u5 helpers for Bech32/codex32 encoding and decoding."""

from codex32.errors import CodexError
from codex32.checksums import Checksum, crc_pad


# pylint: disable=missing-class-docstring
class InvalidDataValue(CodexError): ...


class IncompleteGroup(CodexError): ...


class InvalidLength(CodexError): ...


class InvalidChar(CodexError): ...


class InvalidCase(CodexError): ...


class InvalidChecksum(CodexError): ...


class InvalidPadding(CodexError): ...


class MissingHrp(CodexError): ...


class SeparatorNotFound(CodexError): ...


class MissingChecksum(CodexError): ...


class MissingEncoding(CodexError): ...


CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_hrp_expand(hrp: str) -> list[int]:
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def u5_to_chars(data: list[int]) -> str:
    """Map list of 5-bit integers (0-31) -> Bech32 data-part string."""
    for i, x in enumerate(data):
        if not 0 <= x < 32:
            raise InvalidDataValue(f"from 0 to 31 index={i} value={x}")
    return "".join(CHARSET[d] for d in data)


def u5_encode(hrp: str, data: list[int], spec: Checksum) -> str:
    """Compute a Bech32 string given HRP and data values."""
    combined = data + spec.create(bech32_hrp_expand(hrp) + data)
    return hrp + "1" + u5_to_chars(combined)


def chars_to_u5(bech: str) -> list[int]:
    """Map Bech32 data-part string -> list of 5-bit integers (0-31)."""
    for i, ch in enumerate(bech):
        if ch not in CHARSET:
            raise InvalidChar(f"'{ch!r}' at pos={i} in data part")
    return [CHARSET.find(x) for x in bech]


def u5_parse(bech: str) -> tuple[str, list[int]]:
    """Parse a Bech32/Codex32 string, and return HRP and 5-bit data."""
    for i, ch in enumerate(bech):
        if ord(ch) < 33 or ord(ch) > 126:
            raise InvalidChar(f"non-printable U+{ord(ch):04X} at pos={i}")
    if bech.upper() != bech and bech.lower() != bech:
        raise InvalidCase("mixed upper/lower case bech32 string")
    if (pos := (bech := bech.lower()).rfind("1")) < 1:
        raise MissingHrp("empty HRP") if not pos else SeparatorNotFound("'1' not found")
    if len(hrp := bech[:pos]) > 83:
        raise InvalidLength(f"HRP has {len(hrp)} characters, the maximum is 83")
    data = chars_to_u5(bech[pos + 1 :])
    return hrp, data


def u5_decode(bech: str, encodings: list[Checksum]) -> tuple[str, list[int], Checksum]:
    """Validate a Bech32/Codex32 string, and determine HRP and data."""
    hrp, data = u5_parse(bech)
    e = MissingEncoding("no encoding or encodings were passed")
    for spec in encodings:
        explen = len(bech32_hrp_expand(hrp)) + len(data)
        if spec.cs_len <= len(data):
            if explen in (c := spec.coverage):
                if spec.verify(bech32_hrp_expand(hrp) + data):
                    return hrp, data[: -spec.cs_len], spec
                e = InvalidChecksum(f"{spec.kind} checksum invalid for hrp and data")
            if not isinstance(e, InvalidChecksum):
                e = InvalidLength(f"{explen} expanded, {spec.kind}: {min(c)}-{max(c)}")
        if not isinstance(e, (InvalidLength, InvalidChecksum)):
            e = MissingChecksum(f"{spec.kind}: {len(data)} data chars < {spec.cs_len}")
    raise e


def convertbits(
    data: list[int] | bytes,
    frombits: int,
    tobits: int,
    pad: bool = True,
    pad_val: int | str = 0,
) -> list[int]:
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise InvalidDataValue(f"{value} is not in 0 to {(1 << frombits) - 1}")
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if not pad and bits >= frombits:
        raise IncompleteGroup(f" {bits} bits remaining, must be {frombits - 1} or less")
    pad_len = (tobits - bits) if pad and bits else bits
    pv = crc_pad(convertbits(data, frombits, 1)) if pad_val == "CRC" else pad_val
    if isinstance(pad_val, int) and not 0 <= pad_val < (1 << pad_len):
        raise InvalidDataValue(f"padding int {pad_val} must be 0 to {(1<<pad_len) - 1}")
    if pad and bits:
        if not isinstance(pv, int):
            raise InvalidPadding(f"pad_val must be int or 'CRC' if pad=True, got {pv}")
        ret.append((acc << (tobits - bits) | pv) & maxv)
    elif pv not in ("any", acc % (1 << bits)):
        raise InvalidPadding(f"padding has to be {pad_val}")
    return ret
