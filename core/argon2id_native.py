"""标准库 ctypes 调用本目录中的自有 C 实现；首次 derive 时加载，无自动编译或下载。"""

import ctypes
from pathlib import Path
import sys


_library = None


def derive(password, salt, memory_kib=65536, iterations=3, lanes=4, length=32, secret=b'', associated_data=b''):
    """与纯 Python argon2id.derive 相同的参数和结果；不缓存秘密或派生密钥。"""
    for name, value in (('password', password), ('salt', salt), ('secret', secret), ('associated_data', associated_data)):
        if not isinstance(value, bytes):
            raise TypeError(f'{name} must be bytes')
        if len(value) >= 2 ** 32:
            raise ValueError(f'{name} exceeds the Argon2 length field')
    if type(lanes) is not int or not 1 <= lanes < 2 ** 24:
        raise ValueError('lanes must be an integer in 1..2**24-1')
    if type(memory_kib) is not int or not 8 * lanes <= memory_kib < 2 ** 32:
        raise ValueError('memory_kib must be an integer in 8*lanes..2**32-1')
    if type(iterations) is not int or not 1 <= iterations < 2 ** 32:
        raise ValueError('iterations must be an integer in 1..2**32-1')
    if type(length) is not int or not 4 <= length < 2 ** 32:
        raise ValueError('output length must be an integer in 4..2**32-1')

    library = _load()
    output = ctypes.create_string_buffer(length)
    status = library.vault_argon2id(password, len(password), salt, len(salt), memory_kib, iterations, lanes,
                                  output, length, secret, len(secret), associated_data, len(associated_data))
    if status == 1:
        raise ValueError('这条记录的加密参数超出支持范围，或要求的内存超过当前程序可用的范围。')
    if status == 2:
        raise MemoryError('当前内存不足，无法完成密码计算。')
    if status != 0:
        raise RuntimeError(f'加密组件无法完成密码计算（错误码 {status}）。')
    return output.raw


def _load():
    global _library
    if _library is None:
        name = 'argon2id.dll' if sys.platform == 'win32' else ('libargon2id.dylib' if sys.platform == 'darwin' else 'libargon2id.so')
        path = Path(__file__).resolve().with_name(name)
        try:
            library = ctypes.CDLL(str(path))
        except OSError as error:
            raise OSError(f'无法加载加密组件“{name}”。请确认程序文件完整且适用于当前系统。') from error
        byte_input, integer = ctypes.c_char_p, ctypes.c_uint32
        library.vault_argon2id.argtypes = [byte_input, integer, byte_input, integer, integer, integer, integer,
                                          ctypes.c_void_p, integer, byte_input, integer, byte_input, integer]
        library.vault_argon2id.restype = ctypes.c_int
        _library = library
    return _library
