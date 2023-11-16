#!/bin/python3
# Author: Leon Olsson Curr and Pearlwort Sneed <pearlwort@wpsoftware.net>
# License: BSD-3-Clause

import hashlib

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
MS32_CONST = 0x10ce0795c2fd1e62a
MS32_LONG_CONST = 0x43381e570bf4798ab26
bech32_inv = [
    0, 1, 20, 24, 10, 8, 12, 29, 5, 11, 4, 9, 6, 28, 26, 31,
    22, 18, 17, 23, 2, 25, 16, 19, 3, 21, 14, 30, 13, 7, 27, 15,
]


def ms32_polymod(values):
    GEN = [
        0x19dc500ce73fde210,
        0x1bfae00def77fe529,
        0x1fbd920fffe7bee52,
        0x1739640bdeee3fdad,
        0x07729a039cfc75f5a,
    ]
    residue = 0x23181b3
    for v in values:
        b = (residue >> 60)
        residue = (residue & 0x0fffffffffffffff) << 5 ^ v
        for i in range(5):
            residue ^= GEN[i] if ((b >> i) & 1) else 0
    return residue


def ms32_verify_checksum(data):
    if len(data) >= 96:  # See Long codex32 Strings
        return ms32_verify_long_checksum(data)
    if len(data) <= 93:
        return ms32_polymod(data) == MS32_CONST
    return False


def ms32_create_checksum(data):
    if len(data) > 80:  # See Long codex32 Strings
        return ms32_create_long_checksum(data)
    values = data
    polymod = ms32_polymod(values + [0] * 13) ^ MS32_CONST
    return [(polymod >> 5 * (12 - i)) & 31 for i in range(13)]


def ms32_long_polymod(values):
    GEN = [
        0x3d59d273535ea62d897,
        0x7a9becb6361c6c51507,
        0x543f9b7e6c38d8a2a0e,
        0x0c577eaeccf1990d13c,
        0x1887f74f8dc71b10651,
    ]
    residue = 0x23181b3
    for v in values:
        b = (residue >> 70)
        residue = (residue & 0x3fffffffffffffffff) << 5 ^ v
        for i in range(5):
            residue ^= GEN[i] if ((b >> i) & 1) else 0
    return residue


def ms32_verify_long_checksum(data):
    return ms32_long_polymod(data) == MS32_LONG_CONST


def ms32_create_long_checksum(data):
    values = data
    polymod = ms32_long_polymod(values + [0] * 15) ^ MS32_LONG_CONST
    return [(polymod >> 5 * (14 - i)) & 31 for i in range(15)]


def bech32_mul(a, b):
    res = 0
    for i in range(5):
        res ^= a if ((b >> i) & 1) else 0
        a *= 2
        a ^= 41 if (32 <= a) else 0
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


# Copyright (c) 2023 Ben Westgate
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


def ms32_encode(hrp, data):
    """Compute a MS32 string given HRP and data values."""
    combined = data + ms32_create_checksum(data)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])


def ms32_decode(bech):
    """Validate a MS32 string, and determine HRP and data."""
    if ((any(ord(x) < 33 or ord(x) > 126 for x in bech)) or
            (bech.lower() != bech and bech.upper() != bech)):
        return (None, None, None, None, None)
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 46 > len(bech):
        return (None, None, None, None, None)
    if not all(x in CHARSET for x in bech[pos + 1:]):
        return (None, None, None, None, None)
    hrp = bech[:pos]
    k = bech[pos + 1]
    if k == "1" or not k.isdigit():
        return (None, None, None, None, None)
    identifier = bech[pos + 2:pos + 6]
    share_index = bech[pos + 6]
    if k == "0" and share_index != "s":
        return (None, None, None, None, None)
    data = [CHARSET.find(x) for x in bech[pos + 1:]]
    checksum_length = 13 if len(data) < 95 else 15
    if not ms32_verify_checksum(data):
        return (None, None, None, None, None)
    return (hrp, k, identifier, share_index, data[:-checksum_length])


def convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits:
        return None
    return ret


def decode(hrp, codex_str):
    """Decode a codex32 string."""
    hrpgot, k, identifier, share_index, data = ms32_decode(codex_str)
    if hrpgot != hrp:
        return (None, None, None, None)
    decoded = convertbits(data[6:], 5, 8, False)
    if decoded is None or len(decoded) < 16 or len(decoded) > 64:
        return (None, None, None, None)
    if k == "1":
        return (None, None, None, None)
    return (k, identifier, share_index, decoded)


def encode(hrp, k, identifier, share_index, payload):
    """Encode a codex32 string"""
    if share_index.lower() == 's':  # add double sha256 hash byte to pad seeds
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
    else:
        checksum = b'' # TODO: use a reed solomon or bch binary ECCcode for padding.
    data = convertbits(payload + checksum, 8, 5, False)[:len(convertbits(payload, 8, 5))]
    ret = ms32_encode(hrp, [CHARSET.find(x.lower()) for x in k + identifier + share_index] + data)
    if decode(hrp, ret) == (None, None, None, None):
        return None
    return ret


def recover_master_seed(share_list = []):
    """Recover a master seed from a threshold of valid codex32 shares."""
    ms32_share_list = [ms32_decode(share)[4] for share in share_list]
    return bytes(convertbits(ms32_recover(ms32_share_list)[6:],5,8, False))


def derive_additional_share(codex32_string_list = [], fresh_share_index = "s"):
    """Derive additional share at distinct new index from a threshold of valid codex32 strings."""
    ms32_share_list = [ms32_decode(string)[4] for string in codex32_string_list]
    ms32_share_index = CHARSET.find(fresh_share_index.lower())
    return ms32_encode('ms', ms32_interpolate(ms32_share_list, ms32_share_index))

def fingerprint_identifier(master_seed):
    from cryptography.hazmat.primitives import hashes, hmac
    from cryptography.hazmat.primitives.asymmetric.ec import derive_private_key, SECP256K1
    SECP256K1

    i = hmac.HMAC(b'Bitcoin seed', hashes.SHA512()).update(master_seed).finalize()
    master_secret_key = int(i[:32])
    private_masterkey_data = derive_private_key(master_secret_key, SECP256K1)
    public_master_key_data = private_masterkey_data.public_key()


    hashlib.new('ripemd')

def relabel_shares(hrp, share_list, new_identifier):
    """Change the identifier on a list of shares."""
    new_share_list = []
    for share in share_list:
        k, identifier, share_index, decoded = decode(hrp, share)
        new_share_list += [encode(hrp, k, new_identifier, share_index, decoded)]
    return new_share_list


def fresh_master_seed(bitcoin_core_entropy, user_entropy = '', seed_length = 16, k = '2', identifier = ''):
    """Derive a fresh master seed of seed length bytes with optional user-provided entropy."""
    import hmac
    import hashlib
    share_list = []
    share_payload = []
    if 16 > seed_length > 64:
        return None
    if 9 < k < 2:
        return None
    available_indices = list(CHARSET)
    letters = sorted(filter(lambda c: c.isalpha(), CHARSET))
    key = hashlib.scrypt(password=bytes(user_entropy + str(seed_length+k+identifier), "utf"),
                                 salt=bytes(bitcoin_core_entropy, "utf"), n=2 ** 20, r=8, p=1, maxmem=1025 ** 3, dklen=64)
    if not identifier:
        identifier = 'temp' # place-holder until strings can be relabeled with better info
    for i in range(int(k)):
        # generate random initial shares
        share_index = letters[i]
        available_indices.remove(share_index)
        header = 'ms1'+ k + identifier + share_index
        info = str(seed_length)+'-byte share with header: '+header
        share_payload[i] = hmac.new(key, info, hashlib.sha512).digest()[:seed_length]
        share_list += [encode('ms1', k, identifier, share_index, share_payload[i])]

    master_seed = recover_master_seed(share_list)
    if identifier == 'temp':
        salt = b''.join(share_payload)
        identifier_data = hashlib.pbkdf2_hmac('sha512', password = master_seed, salt = salt,
                                             iterations = 2048, dklen = 3)
        new_identifier =  ''.join([CHARSET[d] for d in convertbits(identifier_data, 8, 5)[:4]])
        share_list = relabel_shares('ms1', share_list, new_identifier)
        return master_seed, share_list




def generate_shares(hrp, share_list, n, k = '2', identifier = '',reshare = False):
    """Derive n new set of n shares deterministically from provided share list. Resets identifier."""
    for i, codex_string in enumerate(share_list):
        k[i], identifier[i], share_index[i], decoded[i] = decode(hrp, codex_string)
    decode('ms',)

def generate_shares_from_existing_master_seed(hrp, share_list, n, k = '2', identifier = '',reshare = False):
    """Derive n new set of n shares deterministically from provided share list. Resets identifier."""
    for i, codex_string in enumerate(share_list):
        k[i], identifier[i], share_index[i], decoded[i] = decode(hrp, codex_string)
    decode('ms',)



def seed_identifier(master_seed):
    """Derive identifier from master seed hash to distinguish between multiple different master seeds."""
    identifier = ''
    h = hashlib.new('ripemd160')
    h.update(master_seed)
    hd_seed_id = h.digest()
    for char in convertbits(list(hd_seed_id), 8, 5)[:4]:
        identifier += CHARSET[char]
    return identifier  # allows connecting different share sets to the same master seed


def existing_master_seed(master_seed, k, identifier, n, passphrase):
    """Derive codex32 shares from a master_seed, threshold k, identifier, n and passphrase."""
    import random
    import hmac
    derived_share_list = []
    if int(k) - 1 > n > 30 or 9 < int(k) < 2:
        return (None)
    seed_length = len(master_seed)
    codex32_secret = encode("ms", seed_length, k, identifier, "s", list(master_seed))
    codex32_kdf_share, salt, indices_free = kdf_share(passphrase, k, identifier, seed_length)
    random.seed(a=hmac.digest(master_seed, salt, 'sha512'))
    share_index = random.sample(indices_free, n)
    share_list = [codex32_secret, codex32_kdf_share]
    if int(k) > 2:
        share_entropy = hashlib.scrypt(password=master_seed, salt=salt, n=2 ** 20, r=8, p=1, maxmem=1025 ** 3,
                                       dklen=(int(k) - 2) * (seed_length + 1))
    for x in range(int(k) - 2):
        data = list(share_entropy[x * (seed_length + 1):x * (seed_length + 1) + seed_length + 1])
        share_list += [encode("ms", seed_length, k, identifier, share_index[x], data)]
    for x in range(int(k) - 2, n):
        derived_share_list += [derive_new_share(share_list, share_index[x])]
    paper_shares = share_list[2:] + derived_share_list
    for share in paper_shares:
        print(share)
    return share_list + derived_share_list


def kdf_share(passphrase, hrp, k, identifier, seed_length):
    """Derive codex32 share from a passphrase and header+length salt."""
    import random
    salt = bytes(hrp + k + identifier + str(seed_length), "utf")
    pw_hash = hashlib.scrypt(password=bytes(passphrase, "utf"), salt=salt, n=2 ** 20, r=8, p=1, maxmem=1025 ** 3,
                             dklen=seed_length)
    indices_free = CHARSET.replace('s', '')
    random.seed(a=salt)
    kdf_share_index = random.choice(indices_free)
    indices_free = indices_free.replace(kdf_share_index, '')
    codex32_kdf_share = encode("ms", seed_length, k, identifier, kdf_share_index, list(pw_hash))
    return (codex32_kdf_share, salt, indices_free)


def recover_master_seed(share_list=[]):
    """Derive codex32 secret from a threshold of shares."""
    k = [None] * len(share_list)
    identifier = [None] * len(share_list)
    share_index = [None] * len(share_list)
    decoded = [None] * len(share_list)
    for i in range(len(share_list)):
        k[i], identifier[i], share_index[i], decoded[i] = decode("ms", share_list[i])
    if k.count(k[0]) != len(k) or identifier.count(identifier[0]) != len(identifier):
        return (None)
    if len({len(i) for i in decoded}) != 1:
        return (None)
    return recover(share_list, 's')


def identifier_verify_checksum(codex32_secret):
    """Verify an identifier checksum in a codex32 secret."""
    k, identifier, share_index, decoded = decode("ms", codex32_secret)
    hash_id = seed_identifier(bytes(decoded))
    if share_index != 's' or hash_id[:3] != identifier[:3]:
        print('1')
        return False
    print('0')
    return True


def verify_checksum(codex32_string):
    """Verify a codex32 checksum in a codex32 string."""
    k, identifier, share_index, decoded = decode("ms", codex32_string)
    if decoded == None or len(decoded) < 16:
        print('1')
        return False
    print('0')
    return True


def rotate_shares(codex32_secret, k, n, passphrase=''):
    """Rotate codex32 backup shares after a lost or stolen share or passphrase or to change k."""
    old_k, identifier, index, master_seed = decode('ms', codex32_secret)
    if index != 's':
        return (None)
    hrp, old_k, old_id, ms32_index, ms32_decoded = ms32_decode(codex32_secret)
    ms32_decoded[4] = (ms32_decoded[4] + 1) % 32
    new_id = ms32_encode('ms', ms32_decoded)[4:8]
    return existing_master_seed(bytes(master_seed), k, new_id, n, passphrase)


# import secrets

# master_seed = fresh_master_seed(16,'Walletasdfpassword34','L5EZftvrYaSudiozVRzTqLcHLNDoVn7H5HSfM9BAN6tMJX8oTWz6')
master_seed = b"\x8a\xa0'm\xad\xa1\xf9\tY\xc5\x86r\xfd\x96\x1bY"
id = 'cash'
print(id)
codex_secret = encode("ms", "0", id, 's', master_seed)
print(codex_secret)
# backup = existing_master_seed(master_seed,'3',id,4,'password')
# new_backup = rotate_shares('ms13uccps32szwmdd58usjkw9see0m9smtydt6h374kxafvw','2',2,'password1')
# print(backup)
# print(new_backup)
# new_backup = existing_master_seed(new_master_seed,'2','6666',4,'password')
# print(new_backup)
# print(recover_master_seed(new_backup[2:4]))
# print(recover_master_seed(new_backup[3:5]))
# print(recover_master_seed(new_backup[4:]))
# print(recover_master_seed([new_backup[3]],'password'))
# print(recover_master_seed([new_backup[5]],'password'))
# codex_secret = recover_master_seed([new_backup[5]],'password')
# print(verify_identifier_checksum(codex_secret))

# new_backup = existing_master_seed(new_master_seed,'2','0g0d',4,'password')
# print(new_backup)
# codex_secret = recover_master_seed([new_backup[5]],'password')
# print(verify_identifier_checksum(codex_secret))


# test vector 1
# test_vec1 = ['MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM','MS12NAMECACDEFGHJKLMNPQRSTUVWXYZ023FTR2GDZMPY6PN']
# print(recover_master_seed(test_vec1))
# new_secret = recover_master_seed([test_vec1[0]],'a strong password')


# ['ms126gpdszx8y0uuwrqtxfkdvxecqzm52ulrhkkhsn2d6704', 'ms126gpd2uen8lyvrl38wyfp6x6ae7rrd7ff09gp694a74mu', 'ms126gpdxru7qp4j9a4mpzva2xa5jujferem7uh3g4srdakf', 'ms126gpd5s9m79nkv6mcrt47mxrl7m5jxhgdcxyq7yf8vpnp', 'ms126gpd07yg0rks42jwqj5gkxj95t3szf9sa32drfgpenqd', 'ms126gpdadad38s5ududzmdt8xvwcvhtaa5xmteu4c39c099']
# test vectors
# seed = "dc5423251cb87175ff8110c8531d0952d8d73e1194e95b5f19d6f9df7c01111104c9baecdfea8cccc677fb9ddc8aec5553b86e528bcadfdcc201c17c638c47e9"
# seed_bytes = list(bytes.fromhex(seed))
# print(encode("ms","0","0C8V","S",seed_bytes))
# print(decode("ms","MS100C8VSM32ZXFGUHPCHTLUPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZYGSFJD6AN074RXVCEMLH8WU3TK925ACDEFGHJKLMNPQRSTUVWXY06FHPV80UNDVARHRAK"))
# print(encode("ms","0","0c8v","s",decode("ms","MS100C8VSM32ZXFGUHPCHTLUPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZYGSFJD6AN074RXVCEMLH8WU3TK925ACDEFGHJKLMNPQRSTUVWXY06FHPV80UNDVARHRAK")[3]))
# seed = decode("ms","MS100C8VSM32ZXFGUHPCHTLUPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZYGSFJD6AN074RXVCEMLH8WU3TK925ACDEFGHJKLMNPQRSTUVWXY06FHPV80UNDVARHRAK")
# print(encode("ms", '0', 'leet', 's', seed[3]))
# print(seed_bytes)
# print(encode("ms", seed_bytes))
# print(decode("ms","ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw")[3])
# print(encode("ms","0","test", "s", seed_bytes))
# ms_string = encode("ms","0","test","s",list(bytes.fromhex("318c6318c6318c6318c6318c6318c631")))
# print(ms_string)
# print(decode("ms","ms13cashsllhdmn9m42vcsamx24zrxgs3qqjzqud4m0d6nln"))
# print(decode("ms","ms13cashsllhdmn9m42vcsamx24zrxgs3qpte35dvzkjpt0r"))
# print(ms32_encode("ms",derive_new_share(["MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM","MS12NAMECACDEFGHJKLMNPQRSTUVWXYZ023FTR2GDZMPY6PN"],"D")))

# print(ms32_encode("ms",derive_new_share(["ms13cashsllhdmn9m42vcsamx24zrxgs3qqjzqud4m0d6nln","ms13casha320zyxwvutsrqpnmlkjhgfedca2a8d0zehn8a0t","ms13cashcacdefghjklmnpqrstuvwxyz023949xq35my48dr"],"f")))
