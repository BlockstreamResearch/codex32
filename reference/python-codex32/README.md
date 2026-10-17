# python-codex32

Reference implementation of BIP-0093 (codex32): checksummed, SSSS-aware BIP32 seed strings.

This repository implements the codex32 string format described by BIP-0093.
It provides encoding/decoding, regular/long codex32 checksums, CRC padding for base conversions,
Shamir secret sharing scheme (SSSS) interpolation helpers and helpers to build codex32 secrets from seed bytes.
Shares are made only by interpolation, never from bytes.

## Features
- Encode/decode codex32 data via `from_string` and `from_unchecksummed_string`.
- Regular and long codex32 checksum support.
- Construct codex32 secrets (share index `s`) from raw seed bytes via `from_seed`, with CRC padding by default.
- Interpolate shares recover secrets via `interpolate_at`.
- Parse codex32 strings and access parts via properties.

## Security
Caution: This is reference code. Verify carefully before using with real funds.

## Installation
**Compatibility:** Python 3.10–3.14

**Recommended:** use a virtual environment
### Linux / macOS
```bash
python -m venv .venv
source .venv/bin/activate
pip install codex32
```
### Windows
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install codex32
```


## Quick usage
```python
from codex32 import Codex32String

# Create from seed bytes
s = Codex32String.from_seed(
    bytes.fromhex('ffeeddccbbaa99887766554433221100'),
    "ms13cashs",        # prefix string, (HRP + '1' + header)
    0                   # padding value (default "CRC", otherwise integer)
)
print(s.s)              # codex32 string

# Parse an existing codex32 string and inspect parts
a = Codex32String("ms13casha320zyxwvutsrqpnmlkjhgfedca2a8d0zehn8a0t")
print(a.hrp)            # human-readable part
print(a.k)              # threshold parameter
print(a.ident)          # 4 character identifier
print(a.share_idx)      # share index character
print(a.payload)        # payload part
print(a.checksum)       # checksum part
print(len(a))           # length of the codex32 string
print(a.is_upper)       # case is upper True/False
print(s.data.hex())     # raw seed bytes as hex (None for shares)
print(s.pad_val)        # padding value integer, (MSB first) (None for shares)



# Create from unchecksummed string (will append checksum)
c = Codex32String.from_unchecksummed_string("ms13cashcacdefghjklmnpqrstuvwxyz023")
print(str(c))           # equivalent to print(c.s)

# Interpolate shares to recover or derive target share index
shares = [s, a, c]
derived_share_d = Codex32String.interpolate_at(shares, target='d')
print(derived_share_d.s)

# Create Codex32String object from existing codex32 string and validate any HRP
e = Codex32String.from_string("cl", "cl10lueasd35kw6r5de5kueedxyesqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqanvrktzhlhusz")
print(e.ident)
print(e.s)
```

## Tests
``` bash
pip install -e .[dev]
pytest
```
