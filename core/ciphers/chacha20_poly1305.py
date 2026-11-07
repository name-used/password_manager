"""ChaCha20-Poly1305：32 字节密钥、12 字节 nonce、16 字节认证标签。"""

from . import _chacha


NONCE_SIZE = 12


def encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b'') -> bytes:
    """返回密文 || 标签；调用者负责同一密钥下 nonce 不重复。"""
    if len(nonce) != NONCE_SIZE:
        raise ValueError('ChaCha20-Poly1305 要求 12 字节 nonce')
    return _chacha.encrypt(key, nonce, plaintext, aad)


def decrypt(key: bytes, nonce: bytes, data: bytes, aad: bytes = b'') -> bytes:
    """验证标签后返回明文；密钥错误或数据被修改时抛出 ValueError。"""
    if len(nonce) != NONCE_SIZE:
        raise ValueError('ChaCha20-Poly1305 要求 12 字节 nonce')
    return _chacha.decrypt(key, nonce, data, aad)
