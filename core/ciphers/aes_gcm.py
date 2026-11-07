"""Minimal AES-256-GCM arithmetic, following FIPS 197 and NIST SP 800-38D.

Only 32-byte keys, 12-byte nonces and full 16-byte tags are supported.
The caller supplies a fresh nonce for each encryption under the same key.
This table-based, pure-Python experiment is NOT a constant-time implementation.
No random generation, file access or external crypto implementation is used here.
"""

from hmac import compare_digest


NONCE_SIZE = 12


SBOX = bytes.fromhex(
    '637c777bf26b6fc53001672bfed7ab76'
    'ca82c97dfa5947f0add4a2af9ca472c0'
    'b7fd9326363ff7cc34a5e5f171d83115'
    '04c723c31896059a071280e2eb27b275'
    '09832c1a1b6e5aa0523bd6b329e32f84'
    '53d100ed20fcb15b6acbbe394a4c58cf'
    'd0efaafb434d338545f9027f503c9fa8'
    '51a3408f929d38f5bcb6da2110fff3d2'
    'cd0c13ec5f974417c4a77e3d645d1973'
    '60814fdc222a908846eeb814de5e0bdb'
    'e0323a0a4906245cc2d3ac629195e479'
    'e7c8376d8dd54ea96c56f4ea657aae08'
    'ba78252e1ca6b4c6e8dd741f4bbd8b8a'
    '703eb5664803f60e613557b986c11d9e'
    'e1f8981169d98e949b1e87e9ce5528df'
    '8ca1890dbfe6426841992d0fb054bb16'
)


def encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b'') -> bytes:
    """Return ciphertext || tag; nonce must not repeat under the same key."""
    _validate(nonce, len(plaintext), len(aad))
    round_keys = _expand_key(key)
    ciphertext = _crypt(round_keys, nonce, plaintext)
    h = int.from_bytes(_encrypt_block(round_keys, bytes(16)), 'big')
    mask = _encrypt_block(round_keys, nonce + b'\x00\x00\x00\x01')
    tag = bytes(x ^ y for x, y in zip(mask, _ghash(h, aad, ciphertext)))
    return ciphertext + tag


def decrypt(key: bytes, nonce: bytes, data: bytes, aad: bytes = b'') -> bytes:
    """Authenticate the complete ciphertext before decrypting its contents."""
    if len(data) < 16:
        raise ValueError('AES-GCM data must include a 16-byte tag')
    ciphertext, tag = data[:-16], data[-16:]
    _validate(nonce, len(ciphertext), len(aad))
    round_keys = _expand_key(key)
    h = int.from_bytes(_encrypt_block(round_keys, bytes(16)), 'big')
    mask = _encrypt_block(round_keys, nonce + b'\x00\x00\x00\x01')
    expected = bytes(x ^ y for x, y in zip(mask, _ghash(h, aad, ciphertext)))
    if not compare_digest(tag, expected):
        raise ValueError('AES-GCM authentication failed')
    return _crypt(round_keys, nonce, ciphertext)


def encrypt_block(key: bytes, block: bytes) -> bytes:
    """AES-256 block primitive, exposed for the FIPS known-answer tests."""
    if len(block) != 16:
        raise ValueError(f'AES block must be 16 bytes, got {len(block)}')
    return _encrypt_block(_expand_key(key), block)


def _validate(nonce, data_size, aad_size):
    if len(nonce) != 12:
        raise ValueError(f'AES-GCM nonce must be 12 bytes, got {len(nonce)}')
    if data_size > (2 ** 32 - 2) * 16:
        raise ValueError('AES-GCM message exceeds the counter limit')
    if aad_size >= 2 ** 61:
        raise ValueError('AES-GCM AAD bit length exceeds 64 bits')


def _xtime(value):
    return ((value << 1) ^ (0x11b if value & 0x80 else 0)) & 0xff


def _expand_key(key):
    if len(key) != 32:
        raise ValueError(f'AES-256 key must be 32 bytes, got {len(key)}')
    expanded = list(key)
    rcon = 1
    while len(expanded) < 240:
        word = expanded[-4:]
        if len(expanded) % 32 == 0:
            word = [SBOX[value] for value in word[1:] + word[:1]]
            word[0] ^= rcon
            rcon = _xtime(rcon)
        elif len(expanded) % 32 == 16:
            word = [SBOX[value] for value in word]
        for value in word:
            expanded.append(expanded[-32] ^ value)
    return [expanded[i:i + 16] for i in range(0, 240, 16)]


def _encrypt_block(round_keys, block):
    # State is column-major, as in FIPS 197; AES-256 has 14 rounds.
    state = [value ^ key for value, key in zip(block, round_keys[0])]
    for round_index in range(1, 15):
        state = [SBOX[state[4 * ((column + row) % 4) + row]] for column in range(4) for row in range(4)]
        if round_index != 14:
            for i in range(0, 16, 4):
                a, b, c, d = state[i:i + 4]
                total = a ^ b ^ c ^ d
                state[i:i + 4] = [a ^ total ^ _xtime(a ^ b), b ^ total ^ _xtime(b ^ c), c ^ total ^ _xtime(c ^ d), d ^ total ^ _xtime(d ^ a)]
        state = [value ^ key for value, key in zip(state, round_keys[round_index])]
    return bytes(state)


def _multiply(x, y):
    # GF(2^128), with GCM's bit ordering and reduction polynomial.
    result = 0
    for bit in range(127, -1, -1):
        if (x >> bit) & 1:
            result ^= y
        y = (y >> 1) ^ (0xe1000000000000000000000000000000 if y & 1 else 0)
    return result


def _ghash(h, aad, ciphertext):
    value = 0
    for data in (aad, ciphertext):
        for start in range(0, len(data), 16):
            block = int.from_bytes(data[start:start + 16].ljust(16, b'\x00'), 'big')
            value = _multiply(value ^ block, h)
    sizes = (len(aad) * 8).to_bytes(8, 'big') + (len(ciphertext) * 8).to_bytes(8, 'big')
    return _multiply(value ^ int.from_bytes(sizes, 'big'), h).to_bytes(16, 'big')


def _crypt(round_keys, nonce, data):
    result = bytearray(len(data))
    for start in range(0, len(data), 16):
        counter = nonce + (2 + start // 16).to_bytes(4, 'big')
        stream = _encrypt_block(round_keys, counter)
        for offset, value in enumerate(data[start:start + 16]):
            result[start + offset] = value ^ stream[offset]
    return bytes(result)
