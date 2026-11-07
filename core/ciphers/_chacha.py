"""RFC 8439 / draft-irtf-cfrg-xchacha-03 的纯 Python 原理实现。

encrypt/decrypt 接受 12 字节 IETF nonce 或 24 字节 XChaCha nonce；输出为密文 || 16 字节 tag。
调用方负责不重复使用同一 key + nonce。Python 大整数运算不承诺常量时间，也不承诺秘密内存清零。
规范：https://www.rfc-editor.org/rfc/rfc8439.html
      https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03
"""

from hmac import compare_digest
from struct import pack, unpack


def encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b'') -> bytes:
    key, nonce = _key_nonce(key, nonce)
    _check_lengths(len(plaintext), len(aad))
    ciphertext = chacha20_xor(key, nonce, plaintext, counter=1)
    return ciphertext + _tag(key, nonce, ciphertext, aad)


def decrypt(key: bytes, nonce: bytes, data: bytes, aad: bytes = b'') -> bytes:
    key, nonce = _key_nonce(key, nonce)
    if len(data) < 16:
        raise ValueError('密文缺少完整的 16 字节认证 tag')
    _check_lengths(len(data) - 16, len(aad))
    ciphertext, tag = data[:-16], data[-16:]
    if not compare_digest(_tag(key, nonce, ciphertext, aad), tag):
        raise ValueError('认证失败')
    return chacha20_xor(key, nonce, ciphertext, counter=1)


def chacha20_block(key: bytes, nonce: bytes, counter: int = 0) -> bytes:
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError('ChaCha20 要求 32 字节 key 和 12 字节 nonce')
    if not isinstance(counter, int) or not 0 <= counter < 2 ** 32:
        raise ValueError('ChaCha20 counter 必须是 32 位无符号整数')
    state = list(unpack('<16I', b'expand 32-byte k' + key + pack('<I', counter) + nonce))
    values = state.copy()
    _rounds(values)
    return pack('<16I', *((value + initial) & 0xffffffff for value, initial in zip(values, state)))


def chacha20_xor(key: bytes, nonce: bytes, data: bytes, counter: int = 1) -> bytes:
    """裸流密码运算，不带认证；用于算法验证及 nonce 重用实验。"""
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError('ChaCha20 要求 32 字节 key 和 12 字节 nonce')
    if not isinstance(counter, int) or not 0 <= counter < 2 ** 32:
        raise ValueError('ChaCha20 counter 必须是 32 位无符号整数')
    if len(data) > (2 ** 32 - counter) * 64:
        raise ValueError('数据长度会使 ChaCha20 counter 溢出')
    result = bytearray(len(data))
    for offset in range(0, len(data), 64):
        stream = chacha20_block(key, nonce, counter + offset // 64)
        block = data[offset:offset + 64]
        result[offset:offset + len(block)] = bytes(a ^ b for a, b in zip(block, stream))
    return bytes(result)


def hchacha20(key: bytes, nonce: bytes) -> bytes:
    if len(key) != 32 or len(nonce) != 16:
        raise ValueError('HChaCha20 要求 32 字节 key 和 16 字节 nonce')
    state = list(unpack('<16I', b'expand 32-byte k' + key + nonce))
    _rounds(state)
    # HChaCha20 不做 ChaCha20 最后的原状态相加，只取首尾各四个字。
    return pack('<8I', *(state[:4] + state[12:]))


def poly1305(key: bytes, data: bytes) -> bytes:
    """一次性 MAC；此处按整数公式表达，不提供常量时间保证。"""
    if len(key) != 32:
        raise ValueError('Poly1305 要求 32 字节一次性 key')
    r = int.from_bytes(key[:16], 'little') & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:], 'little')
    value = 0
    for offset in range(0, len(data), 16):
        block = int.from_bytes(data[offset:offset + 16] + b'\x01', 'little')
        value = ((value + block) * r) % (2 ** 130 - 5)
    return ((value + s) % (2 ** 128)).to_bytes(16, 'little')


def _key_nonce(key, nonce):
    if len(key) != 32:
        raise ValueError('要求 32 字节 key')
    if len(nonce) == 24:
        return hchacha20(key, nonce[:16]), b'\x00' * 4 + nonce[16:]
    if len(nonce) == 12:
        return key, nonce
    raise ValueError('nonce 必须是 12 字节或 24 字节')


def _check_lengths(size, aad_size):
    if size > (2 ** 32 - 1) * 64 or aad_size >= 2 ** 64:
        raise ValueError('消息或 AAD 长度超过 ChaCha20-Poly1305 上限')


def _tag(key, nonce, ciphertext, aad):
    data = aad + b'\x00' * (-len(aad) % 16) + ciphertext + b'\x00' * (-len(ciphertext) % 16)
    data += pack('<QQ', len(aad), len(ciphertext))
    return poly1305(chacha20_block(key, nonce, counter=0)[:32], data)


def _rounds(state):
    for _ in range(10):
        _quarter(state, 0, 4, 8, 12)
        _quarter(state, 1, 5, 9, 13)
        _quarter(state, 2, 6, 10, 14)
        _quarter(state, 3, 7, 11, 15)
        _quarter(state, 0, 5, 10, 15)
        _quarter(state, 1, 6, 11, 12)
        _quarter(state, 2, 7, 8, 13)
        _quarter(state, 3, 4, 9, 14)


def _quarter(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & 0xffffffff
    state[d] ^= state[a]
    state[d] = ((state[d] << 16) | (state[d] >> 16)) & 0xffffffff
    state[c] = (state[c] + state[d]) & 0xffffffff
    state[b] ^= state[c]
    state[b] = ((state[b] << 12) | (state[b] >> 20)) & 0xffffffff
    state[a] = (state[a] + state[b]) & 0xffffffff
    state[d] ^= state[a]
    state[d] = ((state[d] << 8) | (state[d] >> 24)) & 0xffffffff
    state[c] = (state[c] + state[d]) & 0xffffffff
    state[b] ^= state[c]
    state[b] = ((state[b] << 7) | (state[b] >> 25)) & 0xffffffff
