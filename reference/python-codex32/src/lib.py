CHARSET = ''
import hashlib

def generate_master_seed(user_entropy = '', app_entropy, seed_len):
    print(app_entropy) # unconditional display
    master_seed = hashlib.scrypt(password = bytes(user_entropy), salt = app_entropy, r = 8, dk_len = seed_len)
    return master_seed
    
def generate_id(master_seed):
    fingerprint = bip32.fingerprint(master_seed)
    return bech32.encode(fingerprint)[:4]

def generate_secret(hrp = 'ms', k = '0', id = '', master_seed):
    if not id:
        id = generate_id(master_seed)
    codex32_secret = encode(hrp, k, id, "s", master_seed)
    return codex32_secret

def generate_shares(codex32_string_list = [], start = 0, stop, step=1):
    indexes_available = CHARSET
    for codex32_string in codex32_string_list:
        hrp, k, identifier, share_index, data = decode(string)
        indexes_available = indexes_available.remove(share_index)
        if share_index == "s":
            master_seed = data
            
    for i in range(start, stop, step):
        new_shares += [share[i]]
    return new_shares