"""账本文本与参数包的双向转换；只处理公开字段和密文，不进行密钥派生。

每行以首个中文冒号分隔字段和值。值的空格原样保留；反斜线、换行、回车、制表符须转义。
字段固定，不接收明文密码或管理密码字段；账本可自由增删、排序和修改公开资料。
"""

from base64 import b64decode, b64encode
from binascii import Error
import re


ALGORITHMS = ('AES-256-GCM', 'CHACHA20-POLY1305', 'XCHACHA20-POLY1305')
KDF_FIELDS = {'内存KiB': 'memory_kib', '迭代次数': 'iterations'}
HEADER_LABELS = {'格式', '校验码'}
ENTRY_FIELDS = {
    '服务名': 'service', '应用地址': 'addresses', '服务编码': 'code', '用户名': 'username', '昵称': 'nickname',
    '加密算法': 'algorithm', **KDF_FIELDS, '并行通道': 'lanes', '随机码': 'salt', '密码密文': 'data',
}
ENTRY_KEYS = set(ENTRY_FIELDS.values()) | {'rules'}
TEXT_FIELDS = {'service', 'addresses', 'code', 'username', 'nickname', 'algorithm', 'salt', 'data'}
ENTRY_LABELS = set(ENTRY_FIELDS) | {'密码规则', '可用符号'}
OPTIONAL_LABELS = {'备注'}
ESCAPES = {'\\': '\\', 'n': '\n', 'r': '\r', 't': '\t'}


def decode(text, *, line_offset=0, fragment=False):
    """解析完整账本；错误包含行号；不执行文本中的任何内容。"""
    if not isinstance(text, str):
        raise ValueError('请提供账本文本。')
    sections, current, start_line = [], None, 0
    for line_number, line in enumerate(text.removeprefix('\ufeff').split('\n'), 1 - line_offset):
        if line.endswith('\r'):
            line = line[:-1]
        if not line.strip():
            continue
        if line in ('[账本]', '[条目]'):
            if current is not None:
                sections.append((section, current, field_lines, start_line))
            section, current, field_lines, start_line = line, {}, {}, line_number
            continue
        if current is None:
            raise ValueError(f'第 {line_number} 行的字段前缺少 [账本] 或 [条目]。')
        if '：' not in line:
            raise ValueError(f'第 {line_number} 行缺少中文冒号“：”。请用它分隔字段名和值。')
        label, value = line.split('：', 1)
        labels = HEADER_LABELS | KDF_FIELDS.keys() if section == '[账本]' else ENTRY_LABELS | OPTIONAL_LABELS
        if label not in labels:
            raise ValueError(f'第 {line_number} 行的“{label}”不是 {section} 中支持的字段。')
        if label in current:
            raise ValueError(f'第 {line_number} 行重复填写了“{label}”。首次出现在第 {field_lines[label]} 行。')
        try:
            current[label] = _unescape(value)
        except ValueError as error:
            raise ValueError(f'第 {line_number} 行的“{label}”{error}') from None
        field_lines[label] = line_number
    if current is not None:
        sections.append((section, current, field_lines, start_line))
    if not sections:
        raise ValueError('账本文本为空。完整账本应以 [账本] 开头。')
    if sections[0][0] != '[账本]':
        raise ValueError(f'第 {sections[0][3]} 行前缺少 [账本]。')

    section, header, header_lines, line_number = sections[0]
    _require_fields(section, header, HEADER_LABELS, line_number)
    if header['格式'] not in ('1', '2'):
        raise ValueError(f'{_field("格式", header_lines)}不受支持。当前仅支持格式 1 和 2。')
    version = int(header['格式'])
    validate_code(header['校验码'], field_lines=header_lines)
    book = {'version': version, 'book_code': header['校验码'], 'entries': []}
    header_profile = {}
    if version == 2:
        _require_fields(section, header, KDF_FIELDS.keys(), line_number)
        header_profile = {key: _parse_int(label, header, header_lines) for label, key in KDF_FIELDS.items()}
        validate_profile(header_profile, field_lines=header_lines)
        book.update(header_profile)
    else:
        for label in KDF_FIELDS:
            if label in header:
                raise ValueError(f'{_field(label, header_lines)}只能写在格式 1 的 [条目] 中。')

    for section, fields, field_lines, line_number in sections[1:]:
        if section == '[账本]':
            raise ValueError(f'第 {line_number} 行出现了第二个 [账本]。一个文件只能包含一个账本。')
        explicit_profile = KDF_FIELDS.keys() & fields.keys()
        if version == 2 and explicit_profile:
            label = min(explicit_profile, key=field_lines.get)
            raise ValueError(f'{_field(label, field_lines)}只能写在格式 2 的 [账本] 中。')
        if version == 1 and fragment and not explicit_profile:
            raise ValueError(f'第 {line_number} 行的 [条目] 缺少“内存KiB”和“迭代次数”。请复制包含 [账本] 头的完整源账本。')
        inherited = version == 2
        expected = ENTRY_LABELS - KDF_FIELDS.keys() if inherited else ENTRY_LABELS
        _require_fields(section, fields, expected, line_number)

        entry = {key: fields[label] for label, key in ENTRY_FIELDS.items() if label in fields}
        entry['lanes'] = _parse_int('并行通道', fields, field_lines)
        if inherited:
            entry.update(header_profile)
            field_lines.update({label: header_lines[label] for label in KDF_FIELDS})
        else:
            entry.update({key: _parse_int(label, fields, field_lines) for label, key in KDF_FIELDS.items()})
        if fields.get('备注'):
            entry['notes'] = fields['备注']
        match = re.fullmatch(r'长度>=([0-9]+);类别>=([0-9]+);字符=([ULDS]+)', fields['密码规则'])
        if match is None:
            raise ValueError(f'{_field("密码规则", field_lines)}应按示例填写：长度>=8;类别>=3;字符=ULDS')
        try:
            entry['rules'] = {'length': int(match[1]), 'categories': int(match[2]), 'allowed': match[3], 'symbols': fields['可用符号']}
        except ValueError:
            raise ValueError(f'{_field("密码规则", field_lines)}中的长度或类别数过大。') from None
        validate_entry(entry, field_lines=field_lines)
        book['entries'].append(entry)
    return book


def encode(book):
    """输出规范文本，不保留注释或额外字段，不改变任何字段值。"""
    expected = {'version', 'book_code', 'entries'}
    if not isinstance(book, dict) or set(book) != expected:
        raise ValueError('账本参数必须仅包含 version、book_code、entries。')
    if type(book['version']) is not int or book['version'] != 1:
        raise ValueError('只能保存格式 1 的账本。')
    validate_code(book['book_code'])
    if not isinstance(book['entries'], list):
        raise ValueError('entries 必须是列表')
    lines = ['[账本]', '格式：1', f'校验码：{book["book_code"]}']
    for entry in book['entries']:
        validate_entry(entry)
        lines.extend(('', '[条目]'))
        for label, key in ENTRY_FIELDS.items():
            lines.append(f'{label}：{_escape(str(entry[key]))}')
            if key == 'nickname':
                if entry.get('notes'):
                    lines.append(f'备注：{_escape(entry["notes"])}')
                rules = entry['rules']
                lines.append(f'密码规则：长度>={rules["length"]};类别>={rules["categories"]};字符={rules["allowed"]}')
                lines.append(f'可用符号：{_escape(rules["symbols"])}')
    return '\n'.join(lines) + '\n'


def _field(label, lines):
    return f'第 {lines[label]} 行的“{label}”' if lines is not None and lines[label] > 0 else f'“{label}”'


def _require_fields(section, fields, expected, line_number):
    missing = expected - fields.keys()
    if missing:
        names = '、'.join(f'“{label}”' for label in sorted(missing))
        raise ValueError(f'第 {line_number} 行开始的 {section} 缺少 {names}。')


def _parse_int(label, fields, field_lines):
    if not re.fullmatch(r'[0-9]+', fields[label]):
        raise ValueError(f'{_field(label, field_lines)}只能填写十进制数字。')
    try:
        return int(fields[label])
    except ValueError:
        raise ValueError(f'{_field(label, field_lines)}的数值过大。') from None


def validate_profile(profile, *, field_lines=None):
    if type(profile['memory_kib']) is not int or not 8 <= profile['memory_kib'] < 2 ** 32:
        raise ValueError(f'{_field("内存KiB", field_lines)}必须是 8 到 {2 ** 32 - 1} 之间的整数。')
    if type(profile['iterations']) is not int or not 1 <= profile['iterations'] < 2 ** 32:
        raise ValueError(f'{_field("迭代次数", field_lines)}必须是 1 到 {2 ** 32 - 1} 之间的整数。')


def validate_code(value, *, field_lines=None):
    if not isinstance(value, str) or re.fullmatch(r'[0-9a-fA-F]{32}', value) is None:
        raise ValueError(f'{_field("校验码", field_lines)}必须是 32 位十六进制字符（0–9、A–F，不区分大小写）。')


def validate_salt(value, *, field_lines=None):
    if not isinstance(value, str) or re.fullmatch(r'[0-9a-fA-F]{32}', value) is None:
        raise ValueError(f'{_field("随机码", field_lines)}必须是 32 位十六进制字符（0–9、A–F，不区分大小写）。')


def validate_rules(rules, *, field_lines=None):
    if not isinstance(rules, dict) or set(rules) != {'length', 'categories', 'allowed', 'symbols'}:
        raise ValueError('密码规则必须仅包含 length、categories、allowed、symbols')
    allowed, symbols = rules['allowed'], rules['symbols']
    if not isinstance(allowed, str) or not allowed or len(set(allowed)) != len(allowed) or not set(allowed) <= set('ULDS'):
        raise ValueError(f'{_field("密码规则", field_lines)}必须至少选择一类字符。U、L、D、S 各只能出现一次。')
    if type(rules['length']) is not int or not 1 <= rules['length'] <= 65535:
        raise ValueError(f'{_field("密码规则", field_lines)}中的最短长度必须在 1 到 65535 之间。')
    if type(rules['categories']) is not int or not 1 <= rules['categories'] <= len(allowed):
        raise ValueError(f'{_field("密码规则", field_lines)}中的最少类别数必须在 1 到已选类别数之间。')
    if not isinstance(symbols, str) or any(not 33 <= ord(char) <= 126 or char.isalnum() for char in symbols):
        raise ValueError(f'{_field("可用符号", field_lines)}只能使用英文标点或特殊符号，例如 !@#。')
    if len(set(symbols)) != len(symbols) or ('S' in allowed and not symbols):
        raise ValueError(f'{_field("可用符号", field_lines)}不能重复。选用符号类别时至少填写一个。')


def validate_entry(entry, *, field_lines=None):
    if not isinstance(entry, dict) or set(entry) - {'notes'} != ENTRY_KEYS:
        raise ValueError('条目字段不完整或含有未知字段；禁止加入明文密码字段')
    if 'notes' in entry and not isinstance(entry['notes'], str):
        raise ValueError('备注必须是字符串')
    if any(not isinstance(entry[key], str) for key in TEXT_FIELDS):
        raise ValueError('服务资料、算法、随机码和密文必须是字符串')
    if entry['algorithm'] not in ALGORITHMS:
        raise ValueError(f'{_field("加密算法", field_lines)}指定了不受支持的算法：{entry["algorithm"]}')
    validate_rules(entry['rules'], field_lines=field_lines)
    if type(entry['lanes']) is not int or not 1 <= entry['lanes'] < 2 ** 24:
        raise ValueError(f'{_field("并行通道", field_lines)}必须是 1 到 {2 ** 24 - 1} 之间的整数。')
    if type(entry['memory_kib']) is not int or not 8 * entry['lanes'] <= entry['memory_kib'] < 2 ** 32:
        raise ValueError(f'{_field("内存KiB", field_lines)}必须至少为“并行通道”的 8 倍，且小于 {2 ** 32}。')
    if type(entry['iterations']) is not int or not 1 <= entry['iterations'] < 2 ** 32:
        raise ValueError(f'{_field("迭代次数", field_lines)}必须是 1 到 {2 ** 32 - 1} 之间的整数。')
    if bool(entry['salt']) != bool(entry['data']):
        raise ValueError(f'{_field("随机码", field_lines)}和{_field("密码密文", field_lines)}必须一起填写。草稿中两者均可留空。')
    if entry['salt']:
        validate_salt(entry['salt'], field_lines=field_lines)
        try:
            data = b64decode(entry['data'], validate=True)
        except (ValueError, Error):
            raise ValueError(f'{_field("密码密文", field_lines)}不是有效的 Base64 文本，请检查是否复制完整。') from None
        if b64encode(data).decode('ascii') != entry['data']:
            raise ValueError(f'{_field("密码密文", field_lines)}不是标准的 Base64 文本，请从原账本完整复制。')


def _escape(value):
    return value.replace('\\', '\\\\').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')


def _unescape(value):
    result, index = [], 0
    while index < len(value):
        char = value[index]
        if char == '\\':
            index += 1
            if index == len(value) or value[index] not in ESCAPES:
                raise ValueError(r'含有无效的转义。请使用 \\ 表示反斜杠，用 \n、\r、\t 表示换行、回车和制表符。')
            char = ESCAPES[value[index]]
        elif char in '\r\t':
            raise ValueError(r'含有回车或制表符。请写作 \r 或 \t。')
        result.append(char)
        index += 1
    return ''.join(result)
