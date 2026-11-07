"""核心只有两个调用入口：结构化 process，文本组合入口 text_process。"""

from secrets import token_hex

from .process import process
from . import text_decoder


__all__ = ['process', 'text_process']


def text_process(action, text='', index=None, master='', password=None, parameters=None):
    """文本入口；encode / append 使用 parameters=book；generate 使用 parameters=rules。

    encrypt / decrypt 使用 text + index；encrypt 返回更新后的文本，decrypt 返回明文。
    new 返回新空账本文本。decode 返回逐条保存参数的账本结构。
    portable 返回该账本结构和待保存文本，格式 1 原样保留，格式 2 展开成格式 1。
    所有操作均不读写文件。
    """
    if action == 'new':
        return text_decoder.encode({'version': 1, 'book_code': token_hex(16), 'entries': []})
    if action in ('decode', 'portable'):
        source = text_decoder.decode(text)
        book = _portable_book(source)
        if action == 'portable':
            return book, text if source['version'] == 1 else text_decoder.encode(book)
        return book
    if action == 'encode':
        return text_decoder.encode(parameters)
    if action == 'append':
        # 完整文本只取条目，无头条目片段借用当前账本头来解析。
        text_decoder.encode(parameters)
        if not isinstance(text, str):
            raise ValueError('追加内容必须是账本文本')
        incoming = text.removeprefix('\ufeff')
        first_line = next((line.removesuffix('\r') for line in incoming.split('\n') if line.strip()), '')
        fragment = first_line == '[条目]'
        prefix = text_decoder.encode({**parameters, 'entries': []}) + '\n' if fragment else ''
        addition = text_decoder.decode(prefix + incoming, line_offset=prefix.count('\n'), fragment=fragment)
        return text_decoder.encode({**parameters, 'entries': [*parameters['entries'], *addition['entries']]})
    if action == 'generate':
        return process('generate', parameters)
    if action not in ('encrypt', 'decrypt'):
        raise ValueError(f'未知文本操作：{action}')
    book = _portable_book(text_decoder.decode(text))
    if type(index) is not int or not 0 <= index < len(book['entries']):
        raise ValueError('条目索引超出范围')
    result = process(action, {'book_code': book['book_code'], 'entry': book['entries'][index]}, master, password)
    if action == 'decrypt':
        return result
    book['entries'][index] = result
    return text_decoder.encode(book)


def _portable_book(book):
    return {'version': 1, 'book_code': book['book_code'], 'entries': book['entries']}
