# tests/test_bip93.py
"""Tests for BIP-93 codex32 implementation."""
import pytest
from data.bip93_vectors import (
    VECTOR_1,
    VECTOR_2,
    VECTOR_3,
    VECTOR_4,
    VECTOR_5,
    VECTOR_6,
    VALID_CODEX32,
    VALID_CODEX32_LONG,
    INVALID_CODEX32,
    INVALID_CODEX32_LONG,
    INVALID_MASTER_SEED,
    INVALID_MASTER_SEED_ENC,
    BAD_CHECKSUMS,
    WRONG_CHECKSUMS,
    INVALID_LENGTHS,
    INVALID_SHARE_INDEX,
    INVALID_THRESHOLD,
    INVALID_PREFIX_OR_SEPARATOR,
    BAD_CASES,
)
from codex32.bip93 import (
    Codex32String,
    InvalidSeedLength,
    MismatchedHrp,
    MismatchedLength,
    codex32_decode,
    encode,
    decode,
    InvalidThreshold,
    InvalidShareIndex,
)
from codex32.bech32 import (
    InvalidCase,
    InvalidChecksum,
    InvalidDataValue,
    IncompleteGroup,
    InvalidLength,
    InvalidChar,
    MissingHrp,
    SeparatorNotFound,
)
from codex32.checksums import CODEX32, CODEX32_LONG


def test_parts():
    """Test Vector 1: parse a codex32 string into parts"""
    s = Codex32String(VECTOR_1["secret_s"])
    assert str(s) == VECTOR_1["secret_s"]
    assert s.hrp == VECTOR_1["hrp"]
    assert s.k == VECTOR_1["k"]
    assert s.share_idx == VECTOR_1["share_index"]
    assert s.ident == VECTOR_1["identifier"]
    assert s.payload == VECTOR_1["payload"]
    assert s.checksum == VECTOR_1["checksum"]
    assert s.data.hex() == VECTOR_1["secret_hex"]


def test_derive_and_recover():
    """Test Vector 2: derive new share and recover the secret"""
    a = Codex32String(VECTOR_2["share_A"])
    c = Codex32String(VECTOR_2["share_C"])
    # interpolation target is 'D' (uppercase as inputs are uppercase)
    assert a.data is None and c.pad_val is None  # shares have no seed bytes
    d = Codex32String.interpolate_at([a, c], "D")
    assert str(d) == VECTOR_2["derived_D"]
    s = Codex32String.interpolate_at([a, c], "S")
    assert str(s) == VECTOR_2["secret_S"]
    assert s.data.hex() == VECTOR_2["secret_hex"]


def test_from_seed_and_interpolate_3_of_5():
    """Test Vector 3: encode secret share from seed and split 3-of-5"""
    seed = bytes.fromhex(VECTOR_3["secret_hex"])
    a = Codex32String(VECTOR_3["share_a"])
    c = Codex32String(VECTOR_3["share_c"])
    s = Codex32String.from_seed(seed, f"{a.hrp}1{a.k}{a.ident}", 0)
    assert str(s) == VECTOR_3["secret_s"]
    d = Codex32String.interpolate_at([s, a, c], "d")
    e = Codex32String.interpolate_at([s, a, c], "e")
    f = Codex32String.interpolate_at([s, a, c], "f")
    assert str(d) == VECTOR_3["derived_d"]
    assert str(e) == VECTOR_3["derived_e"]
    assert str(f) == VECTOR_3["derived_f"]
    for pad_val in range(0b11 + 1):
        s = Codex32String.from_seed(seed, f"{a.hrp}1{a.k}{a.ident}", pad_val)
        assert str(s) == VECTOR_3[f"secret_s_alternate_{pad_val}"]


def test_from_seed_and_alternates():
    """Test Vector 4: encode secret share from seed"""
    seed = bytes.fromhex(VECTOR_4["secret_hex"])
    for pad_val in range(0b1111 + 1):
        # confirm all 16 encodings decode to same master data
        s = Codex32String.from_seed(seed, "ms10leet", pad_val)
        assert str(s) == VECTOR_4[f"secret_s_alternate_{pad_val}"]
        assert s.data.hex() == VECTOR_4["secret_hex"]


def test_long_string():
    """Test Vector 5: decode long codex32 secret and confirm secret bytes."""
    s = Codex32String.from_unchecksummed_string(
        VECTOR_5["hrp"]
        + "1"
        + VECTOR_5["k"]
        + VECTOR_5["identifier"]
        + VECTOR_5["share_idx"]
        + VECTOR_5["payload"]
    )
    assert s.checksum == VECTOR_5["checksum"]
    assert str(s) == VECTOR_5["secret_s"]
    assert s.data.hex() == VECTOR_5["secret_hex"]
    long_str = VECTOR_5["secret_s"]
    long_seed = Codex32String(long_str)
    assert long_seed.data.hex() == VECTOR_5["secret_hex"]


def test_alternate_hrp():
    """Test Vector 6: codex32 strings with "cl" HRP."""
    c0 = Codex32String(VECTOR_6["codex32_luea"])
    assert str(c0) == VECTOR_6["codex32_luea"]
    c1 = Codex32String(VECTOR_6["codex32_cln2"])
    assert str(c1) == VECTOR_6["codex32_cln2"]
    c2 = Codex32String.from_string("cl", VECTOR_6["codex32_peev"])
    assert str(c2) == VECTOR_6["codex32_peev"]


def test_valid_codex32():
    """Test checksum creation and validation."""
    for spec in CODEX32, CODEX32_LONG:
        tests = VALID_CODEX32 if spec == CODEX32 else VALID_CODEX32_LONG
        for test in tests:
            hrp, _, dspec = codex32_decode(test)
            assert hrp is not None and dspec == spec
            pos = test.rfind("1")
            test = test[: pos + 1] + chr(ord(test[pos + 1]) ^ 1) + test[pos + 2 :]
            with pytest.raises(InvalidChecksum):
                codex32_decode(test)


def test_invalid_checksum():
    """Test validation of invalid checksums."""
    for spec in CODEX32, CODEX32_LONG:
        tests = INVALID_CODEX32 if spec == CODEX32 else INVALID_CODEX32_LONG
        for test in tests:
            with pytest.raises(
                (InvalidChecksum, InvalidLength, InvalidChar, AssertionError)
            ):
                _, _, dspec = codex32_decode(test)
                assert dspec != spec


def test_invalid_master_seed():
    """Test whether invalid addresses fail to decode."""
    for test in INVALID_MASTER_SEED:
        with pytest.raises(
            (
                MismatchedHrp,
                MismatchedLength,
                InvalidChecksum,
                InvalidSeedLength,
                InvalidLength,
                InvalidChar,
                InvalidThreshold,
                InvalidCase,
                IncompleteGroup,
            )
        ):
            decode("ms", test)


def test_invalid_master_seed_enc():
    """Test whether master seed encoding fails on invalid input."""
    for hrp, header, data in INVALID_MASTER_SEED_ENC:
        with pytest.raises(
            (
                MissingHrp,
                MismatchedLength,
                InvalidSeedLength,
                InvalidChar,
                InvalidCase,
                InvalidDataValue,
                InvalidThreshold,
                InvalidShareIndex,
                AssertionError,
            )
        ):
            encode(hrp, header, data)


def test_bad_checksums():
    """Test strings with bad checksums."""
    for chk in BAD_CHECKSUMS:
        with pytest.raises((InvalidChecksum)):
            Codex32String(chk)


def test_wrong_checksums_or_length():
    """Test strings with wrong checksums or lengths."""
    for chk in WRONG_CHECKSUMS:
        with pytest.raises(
            (InvalidLength, InvalidSeedLength, IncompleteGroup, InvalidChecksum)
        ):
            Codex32String(chk)


def test_invalid_length():
    """Test strings with invalid lengths."""
    for chk in INVALID_LENGTHS:
        with pytest.raises((InvalidLength, InvalidSeedLength, IncompleteGroup)):
            Codex32String(chk)


def test_invalid_index():
    """Test strings with invalid share indices."""
    for chk in INVALID_SHARE_INDEX:
        with pytest.raises(InvalidShareIndex):
            Codex32String(chk)


def test_invalid_threshold():
    """Test strings with invalid threshold characters."""
    for chk in INVALID_THRESHOLD:
        with pytest.raises(InvalidThreshold):
            Codex32String(chk)


def test_invalid_prefix_or_separator():
    """Test strings with invalid prefixes or separators."""
    for chk in INVALID_PREFIX_OR_SEPARATOR:
        with pytest.raises((MismatchedHrp, SeparatorNotFound, MissingHrp)):
            Codex32String.from_string("ms", chk)


def test_invalid_case_examples():
    """Test strings with invalid casing."""
    for chk in BAD_CASES:
        with pytest.raises(InvalidCase):
            Codex32String(chk)
