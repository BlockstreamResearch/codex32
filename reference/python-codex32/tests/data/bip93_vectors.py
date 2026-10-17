# tests/data/bip93_vectors.py
# pylint: disable=line-too-long
"""BIP-93 / codex32 canonical test vectors."""
VECTOR_1 = {
    "secret_s": "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw",
    "secret_hex": "318c6318c6318c6318c6318c6318c631",
    "hrp": "ms",
    "k": "0",
    "identifier": "test",
    "share_index": "s",
    "payload": "xxxxxxxxxxxxxxxxxxxxxxxxxx",
    "checksum": "4nzvca9cmczlw",
}

VECTOR_2 = {
    "share_A": "MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM",
    "share_C": "MS12NAMECACDEFGHJKLMNPQRSTUVWXYZ023FTR2GDZMPY6PN",
    "derived_D": "MS12NAMEDLL4F8JLH4E5VDVULDLFXU2JHDNLSM97XVENRXEG",
    "secret_S": "MS12NAMES6XQGUZTTXKEQNJSJZV4JV3NZ5K3KWGSPHUH6EVW",
    "secret_hex": "d1808e096b35b209ca12132b264662a5",
}

VECTOR_3 = {
    "secret_hex": "ffeeddccbbaa99887766554433221100",
    "secret_s": "ms13cashsllhdmn9m42vcsamx24zrxgs3qqjzqud4m0d6nln",
    "share_a": "ms13casha320zyxwvutsrqpnmlkjhgfedca2a8d0zehn8a0t",
    "share_c": "ms13cashcacdefghjklmnpqrstuvwxyz023949xq35my48dr",
    "derived_d": "ms13cashd0wsedstcdcts64cd7wvy4m90lm28w4ffupqs7rm",
    "derived_e": "ms13casheekgpemxzshcrmqhaydlp6yhms3ws7320xyxsar9",
    "derived_f": "ms13cashf8jh6sdrkpyrsp5ut94pj8ktehhw2hfvyrj48704",
    "secret_s_alternate_0": "ms13cashsllhdmn9m42vcsamx24zrxgs3qqjzqud4m0d6nln",
    "secret_s_alternate_1": "ms13cashsllhdmn9m42vcsamx24zrxgs3qpte35dvzkjpt0r",
    "secret_s_alternate_2": "ms13cashsllhdmn9m42vcsamx24zrxgs3qzfatvdwq5692k6",
    "secret_s_alternate_3": "ms13cashsllhdmn9m42vcsamx24zrxgs3qrsx6ydhed97jx2",
}

VECTOR_4 = {
    "secret_hex": "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
    "secret_s": "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqtum9pgv99ycma",
    "secret_s_alternate_0": "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqtum9pgv99ycma",
    "secret_s_alternate_1": "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqpj82dp34u6lqtd",
    "secret_s_alternate_2": "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqzsrs4pnh7jmpj5",
    "secret_s_alternate_3": "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqrfcpap2w8dqezy",
    "secret_s_alternate_4": "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqy5tdvphn6znrf0",
    "secret_s_alternate_5": "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq9dsuypw2ragmel",
    "secret_s_alternate_6": "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqx05xupvgp4v6qx",
    "secret_s_alternate_7": "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq8k0h5p43c2hzsk",
    "secret_s_alternate_8": "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqgum7hplmjtr8ks",
    "secret_s_alternate_9": "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqf9q0lpxzt5clxq",
    "secret_s_alternate_10": "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq28y48pyqfuu7le",
    "secret_s_alternate_11": "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqt7ly0paesr8x0f",
    "secret_s_alternate_12": "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqvrvg7pqydv5uyz",
    "secret_s_alternate_13": "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqd6hekpea5n0y5j",
    "secret_s_alternate_14": "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqwcnrwpmlkmt9dt",
    "secret_s_alternate_15": "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyq0pgjxpzx0ysaam",
}

VECTOR_5 = {
    "hrp": "MS",
    "k": "0",
    "identifier": "0C8V",
    "share_idx": "S",
    "payload": "M32ZXFGUHPCHTLUPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZYGSFJD6AN074RXVCEMLH8WU3TK925ACDEFGHJKLMNPQRSTUVWXY06F",
    "checksum": "HPV80UNDVARHRAK",
    "secret_s": "MS100C8VSM32ZXFGUHPCHTLUPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZYGSFJD6AN074RXVCEMLH8WU3TK925ACDEFGHJKLMNPQRSTUVWXY06FHPV80UNDVARHRAK",
    "secret_hex": "dc5423251cb87175ff8110c8531d0952d8d73e1194e95b5f19d6f9df7c01111104c9baecdfea8cccc677fb9ddc8aec5553b86e528bcadfdcc201c17c638c47e9",
}

VECTOR_6 = {
    "codex32_luea": "cl10lueasd35kw6r5de5kueedxyesqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqanvrktzhlhusz",
    "codex32_cln2": "cl10cln2sd35kw6r5de5kueedxyesqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqn9lcvcu7cez4s",
    "codex32_peev": "cl10peevst6cqh0wu7p5ssjyf4z4ez42ks9jlt3zneju9uuypr2hddak6tlqsjhsks4laxts8q",
}


VALID_CODEX32 = [
    "A12UEL5LLGCHJ4UJCQVHG",
    "a12uel5llgchj4ujcqvhg",
    "a74characterlonghumanreadablepartcontainingnumber1andexcludedcharactersbio15tttgsdupy3h58nvmja",
    "abcdef13qpzry9x8gf2tvdw0s3jn54khce6mua7lclc606q3t75r4",
    "1199999999999999999999999999999999999999999999999999999999999999999999999999999997f7ekwq8dq7tm",
    "split12checkupstagehandshakeupstreamerranterredcaperred75pe8uz2kh9ey",
    "?13zyfclf624rkvjcl35t",
]

VALID_CODEX32_LONG = [
    "A12UEL5LQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQV3RR8ZLCK96GTC3",
    "a12uel5lqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqv3rr8zlck96gtc3",
    "a1002characterlonghumanreadablepartthatcontainsthenumber1,theexcludedcharactersbio,andeveryus-asciicharacterin[33-126]!\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~!\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~!\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~!\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~!\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~!\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~!\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~!\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~!\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~!\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~!\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~!\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~!\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~15ttgtscr3gvktxamm8mzt",
    "abcdef12l7aum6echk45nj3s0wdvt2fg8x9yrzpql7aum6echk45nj3s0wdvt2fg8x9yrzpql7aum6echk45nj3s0wdvt2fg8x9yrzpqp9evrmhc52umqew",
    "1177777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777fn0jxg9gc35xwa8",
    "split13checkupstagehandshakeupstreamerranterredcaperredscatteredsusurrantplunderedqsp5ws8r2klm66l",
    "?17v59aaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq2uwygewx4t4gps0",
]
INVALID_CODEX32 = {
    " 12fauxxpgjxu9gyqhql4",  # HRP character out of range
    "\x7f" + "12fauxxk7kd7xqlns9mj",  # HRP character out of range
    "\x80" + "12fauxxgqp5ecwf5kzg3",  # HRP character out of range
    # overall max length exceeded
    "a75characterslonghumanreadablepartcontainingnumber1andexcludedcharactersbio12fauxxau7wnkdhzp90r",
    "x12fauxbhf2k7v7ay7ua5",  # Invalid data character
    "li12fauxxz4pdg55uwav3",  # Too short checksum
    "de12fauxxrmt7mj886swl" + "\xff",  # Invalid character in checksum
    "A12FAUXXMRQDLRATCD0WJ",  # Checksum calculated with uppercase form of HRP
}

INVALID_CODEX32_LONG = {
    " 12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx8qt67zg4n9sqylv",  # HRP character out of range
    "\x7f"
    + "12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx836hdd09mhkhkhx",  # HRP character out of range
    "\x80"
    + "12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxlhf5ywnkmk4r3tc",  # HRP character out of range
    # overall max length exceeded
    "a1003characterslonghumanreadablepartthatcontainsthenumber1,theexcludedcharactersbio,andeveryus-asciicharacterin[33-126]!\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~!\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~!\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~!\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~!\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~!\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~!\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~!\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~!\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~!\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~!\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~!\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~!\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~12fauxxru38cppmlpu0t6l",
    "y12bfauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxt3y5fewy4gnw2hs",  # Invalid data character
    "lt12ifauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxjxd0ehq868vm3zl",  # Invalid data character
    "in12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxvgegljrsvs5w9q",  # Too short checksum
    "mm12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxbz9tqm7y53swfaw",  # Invalid character in checksum
    "au12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxoqz9gl44za2owxc",  # Invalid character in checksum
    "M12FAUXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX4DZ47P062DVJUNM",  # Checksum calculated with uppercase form of HRP
}

INVALID_MASTER_SEED = [
    # Invalid HRP
    "cl10fauxs0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq3yaqk7cywvn0h",
    # Invalid checksum algorithm (long codex32 instead of codex32)
    "ms10fauxs0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq7rvjegpr4vhajgq",
    # Invalid checksum algorithm (bech32m instead of codex32)
    "ms10fauxs0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqu8ld7l",
    # Invalid checksum algorithm (bech32 instead of codex32)
    "MS10FAUXS0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQFM0PMA",
    # Invalid checksum algorithm (bech32m instead of codex32)
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
    # Invalid checksum algorithm (bech32 instead of long codex32)
    "ms10fauxsxlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq7dmzyl",
    # Invalid checksum algorithm (codex32 instead of long codex32)
    "ms10fauxsxlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq3vy27qhysq096",
    # Invalid character in checksum
    "ms10fauxs0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqg4khy5dvhao86",
    # Invalid seed length (15 byte)
    "MS10FAUXS508D6QEJXTDG4Y5R3ZARVARYEQ3F4VK4PNLXD",
    # Invalid seed length (65 bytes)
    "ms10fauxsxlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqqqetj40aljmajm22",
    # Mixed case
    "ms10fauxs0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqg4khy5dvhA686",
    # More than 4 padding bits
    "ms10fauxs508d6qejxtdg4y5r3zarvary234567890z2jnc3fj9mqt9",
    # Empty data section
    "ms1pg7d74n5v8xrz",
    # Empty payload section
    "ms12fauxxcel69nm8tntnn",
]

INVALID_MASTER_SEED_ENC = [
    ("MS", "0FAUXS", bytes(16)),  # Invalid uppercase
    ("MS", "0fauxs", bytes(16)),  # Invalid mixed case
    ("ms", "0FAUXS", bytes(16)),  # Invalid mixed case
    ("", "0fauxs", bytes(16)),  # Invalid empty HRP
    ("ms", "", b"\xd0" * 32),  # Invalid empty header
    ("ms", "0faux", b"\x80" * 32),  # Invalid missing share idx
    ("ms", "0", b"\x80" * 32),  # Invalid missing identifier and share idx
    ("ms", "0fauxxxs", bytes(16)),  # Invalid identifier length
    ("ms", "fauxxs", bytes(32)),  # Invalid threshold
    ("ms", "0fauxx", bytes(64)),  # Invalid share idx
    ("ms", "2fauxa", bytes(16)),  # Invalid share idx: shares are not encoded from bytes
    ("ms", "0fauxs", bytes(15)),  # Invalid seed length (<16 bytes)
    ("ms", "0fauxs", bytes(65)),  # Invalid seed length (>64 bytes)
    ("ms", "0fauxs", bytes(17)),  # Invalid seed length (non-multiple of 4 bytes)
    ("ms", "0fauxs", bytes(18)),  # Invalid seed length (non-multiple of 4 bytes)
    ("ms", "0fauxs", bytes(19)),  # Invalid seed length (non-multiple of 4 bytes)
]


BAD_CHECKSUMS = [
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxve740yyge2ghq",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxve740yyge2ghp",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxlk3yepcstwr",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxx6pgnv7jnpcsp",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxx0cpvr7n4geq",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxm5252y7d3lr",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxrd9sukzl05ej",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxc55srw5jrm0",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxgc7rwhtudwc",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxx4gy22afwghvs",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxme084q0vpht7pe0",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxme084q0vpht7pew",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxqyadsp3nywm8a",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxzvg7ar4hgaejk",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxcznau0advgxqe",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxch3jrc6j5040j",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx52gxl6ppv40mcv",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx7g4g2nhhle8fk",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx63m45uj8ss4x8",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxy4r708q7kg65x",
]

WRONG_CHECKSUMS = [
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxurfvwmdcmymdufv",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxcsyppjkd8lz4hx3",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxu6hwvl5p0l9xf3c",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxwqey9rfs6smenxa",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxv70wkzrjr4ntqet",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx3hmlrmpa4zl0v",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxrfggf88znkaup",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxpt7l4aycv9qzj",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxus27z9xtyxyw3",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxcwm4re8fs78vn",
]

INVALID_LENGTHS = [
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxw0a4c70rfefn4",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxk4pavy5n46nea",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxx9lrwar5zwng4w",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxr335l5tv88js3",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxvu7q9nz8p7dj68v",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxpq6k542scdxndq3",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxkmfw6jm270mz6ej",
    "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxzhddxw99w7xws",
    "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxx42cux6um92rz",
    "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxarja5kqukdhy9",
    "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxky0ua3ha84qk8",
    "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx9eheesxadh2n2n9",
    "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx9llwmgesfulcj2z",
    "ms12fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx02ev7caq6n9fgkf",
]

INVALID_SHARE_INDEX = [
    "ms10fauxxxxxxxxxxxxxxxxxxxxxxxxxxxx0z26tfn0ulw3p",
]

INVALID_THRESHOLD = [
    "ms1fauxxxxxxxxxxxxxxxxxxxxxxxxxxxxxda3kr3s0s2swg",
]

INVALID_PREFIX_OR_SEPARATOR = [
    "0fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
    "10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
    "ms0fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
    "m10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
    "s10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
    "0fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxhkd4f70m8lgws",
    "10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxhkd4f70m8lgws",
    "m10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxx8t28z74x8hs4l",
    "s10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxh9d0fhnvfyx3x",
]

BAD_CASES = [
    "Ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
    "mS10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
    "MS10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
    "ms10FAUXsxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
    "ms10fauxSxxxxxxxxxxxxxxxxxxxxxxxxxxuqxkk05lyf3x2",
    "ms10fauxsXXXXXXXXXXXXXXXXXXXXXXXXXXuqxkk05lyf3x2",
    "ms10fauxsxxxxxxxxxxxxxxxxxxxxxxxxxxUQXKK05LYF3X2",
]
