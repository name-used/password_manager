"""同一套密码流程：参数包 -> Argon2id -> 指定 AEAD -> 记录。

process('encrypt'/'decrypt', {'book_code': ..., 'entry': ...}, master, password)
process('generate', rules) 生成最短符合规则的 ASCII 密码。
这里不访问文件、GUI 或网络，也不缓存管理密码和派生密钥。
"""

from base64 import b64decode, b64encode
from secrets import choice, token_bytes
from string import ascii_lowercase, ascii_uppercase, digits

import config

from . import argon2id_native as argon2id
from .ciphers import aes_gcm, chacha20_poly1305, xchacha20_poly1305
from .text_decoder import (
    VERIFIER_KEYS, validate_cipher_settings, validate_code, validate_entry, validate_rules, validate_salt, validate_verifier,
)


_VERIFIER_PLAINTEXT = b'LOCALVAULT-CHECK\x00\x00'
_EXCLUDE_AMBIGUOUS = str.maketrans('', '', 'Oo0Iil')


def process(action, parameters, master='', password=None):
    """encrypt 返回新记录；decrypt / generate 返回密码字符串；不修改调用方的参数包。"""
    if action == 'generate':
        validate_rules(parameters)
        groups = {'U': ascii_uppercase, 'L': ascii_lowercase, 'D': digits, 'S': parameters['symbols']}
        groups = [groups[name].translate(_EXCLUDE_AMBIGUOUS) for name in parameters['allowed']]
        alphabet = ''.join(groups)
        length = max(parameters['length'], parameters['categories'])
        # 每个候选在可用字符集上均匀采样；拒绝不符合类别数的候选，避免固定位置偏差。
        while True:
            result = ''.join(choice(alphabet) for _ in range(length))
            if sum(any(char in group for char in result) for group in groups) >= parameters['categories']:
                return result

    if action not in ('encrypt', 'decrypt'):
        raise ValueError(f'未知操作：{action}')
    if not isinstance(parameters, dict):
        raise ValueError('加解密参数包必须是字典')
    fields = set(parameters)
    if action == 'encrypt':
        fields.discard('salt_override')
    if fields != {'book_code', 'entry'}:
        raise ValueError('加解密参数包需要 book_code 和 entry，只有加密可以指定 salt_override')
    validate_code(parameters['book_code'])
    entry = parameters['entry']
    validate_entry(entry)
    if not isinstance(master, str) or not master:
        raise ValueError('请输入管理密码。')

    cipher, nonce_length = _cipher(entry['algorithm'])

    if action == 'encrypt':
        if not isinstance(password, str):
            raise ValueError('待加密的网站密码必须是文本。')
        password_bytes = password.encode('utf-8')
        if len(password_bytes) > 65535:
            raise ValueError('网站密码以 UTF-8 编码后不能超过 65535 字节。')
        if 'salt_override' in parameters:
            salt_text = parameters['salt_override']
            validate_salt(salt_text)
            salt = bytes.fromhex(salt_text)
        else:
            salt = token_bytes(16)
            salt_text = salt.hex()
        nonce = token_bytes(nonce_length)
        # 保留格式 1 的 16 字节前缀。条目认证通过后可在任意账本读取。
        plaintext = bytes.fromhex(parameters['book_code']) + len(password_bytes).to_bytes(2, 'big') + password_bytes
    else:
        if not entry['data']:
            raise ValueError('这条记录还没有保存网站密码。')
        salt = bytes.fromhex(entry['salt'])
        data = b64decode(entry['data'], validate=True)
        if not nonce_length + 16 + 18 <= len(data) <= nonce_length + 16 + 18 + 65535:
            raise ValueError('“密码密文”的长度不符合账本格式，请检查该字段是否完整。')
        nonce, data = data[:nonce_length], data[nonce_length:]

    key = _derive(master, salt, entry)
    if action == 'encrypt':
        data = nonce + cipher.encrypt(key, nonce, plaintext)
        return {**entry, 'rules': entry['rules'].copy(), 'salt': salt_text, 'data': b64encode(data).decode('ascii')}

    try:
        plaintext = cipher.decrypt(key, nonce, data)
    except ValueError:
        raise ValueError('管理密码错误，或这条记录的密码密文、随机码、加密参数已被改动。') from None
    length = int.from_bytes(plaintext[16:18], 'big')
    if len(plaintext) < 18 or len(plaintext) != 18 + length:
        raise ValueError('解密后的密码长度与记录中的长度不一致。')
    try:
        return plaintext[18:].decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError('解密后的密码无法按 UTF-8 读取。') from None


def create_verifier(master, *, profile=None):
    if not isinstance(master, str) or not master:
        raise ValueError('请输入管理密码。')
    if profile is None:
        profile = dict(algorithm=config.DEFAULT_ALGORITHM, memory_kib=config.MEMORY_KIB, iterations=config.ITERATIONS, lanes=config.LANES)
    settings = VERIFIER_KEYS[:4]
    if not isinstance(profile, dict) or not set(settings) <= profile.keys():
        raise ValueError('校验样本缺少加密设置。')
    verifier = {key: profile[key] for key in settings}
    validate_cipher_settings(verifier)
    cipher, nonce_length = _cipher(verifier['algorithm'])
    salt, nonce = token_bytes(16), token_bytes(nonce_length)
    key = _derive(master, salt, verifier)
    data = nonce + cipher.encrypt(key, nonce, _VERIFIER_PLAINTEXT)
    return {**verifier, 'salt': salt.hex(), 'data': b64encode(data).decode('ascii')}


def verify_master(verifier, master):
    if not isinstance(master, str) or not master:
        raise ValueError('请输入管理密码。')
    data = validate_verifier(verifier)
    cipher, nonce_length = _cipher(verifier['algorithm'])
    key = _derive(master, bytes.fromhex(verifier['salt']), verifier)
    try:
        plaintext = cipher.decrypt(key, data[:nonce_length], data[nonce_length:])
    except ValueError:
        raise ValueError('管理密码错误，或账本的校验样本已被改动。') from None
    if plaintext != _VERIFIER_PLAINTEXT:
        raise ValueError('账本的校验样本内容不正确。')
    return True


def _cipher(algorithm):
    if algorithm == 'AES-256-GCM':
        return aes_gcm, 12
    if algorithm == 'CHACHA20-POLY1305':
        return chacha20_poly1305, 12
    return xchacha20_poly1305, 24


def _derive(master, salt, record):
    return argon2id.derive(master.encode('utf-8'), salt, record['memory_kib'], record['iterations'], record['lanes'], length=32)
