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
VERIFIER_LABEL = '校验样本'
VERIFIER_KEYS = ('algorithm', 'memory_kib', 'iterations', 'lanes', 'salt', 'data')
VERIFIER_BOOK_CODE = '0' * 32
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
        labels = HEADER_LABELS | KDF_FIELDS.keys() | {VERIFIER_LABEL} if section == '[账本]' else ENTRY_LABELS | OPTIONAL_LABELS
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
    _require_fields(section, header, {'格式'}, line_number)
    if header['格式'] not in ('1', '2', '3'):
        raise ValueError(f'{_field("格式", header_lines)}不受支持。当前仅支持格式 1、2 和 3。')
    version = int(header['格式'])
    expected_header = {'格式', VERIFIER_LABEL} if version == 3 else HEADER_LABELS
    if version == 2:
        expected_header = expected_header | KDF_FIELDS.keys()
    _require_fields(section, header, expected_header, line_number)
    for label in header:
        if label not in expected_header:
            raise ValueError(f'{_field(label, header_lines)}不能写在格式 {version} 的 [账本] 中。')
    book = {'version': version, 'book_code': VERIFIER_BOOK_CODE, 'entries': []}
    if version != 3:
        validate_code(header['校验码'], field_lines=header_lines)
        book['book_code'] = header['校验码']
    else:
        book['verifier'] = _parse_verifier(header[VERIFIER_LABEL], header_lines)
    header_profile = {}
    if version == 2:
        header_profile = {key: _parse_int(label, header, header_lines) for label, key in KDF_FIELDS.items()}
        validate_profile(header_profile, field_lines=header_lines)
        book.update(header_profile)

    for section, fields, field_lines, line_number in sections[1:]:
        if section == '[账本]':
            raise ValueError(f'第 {line_number} 行出现了第二个 [账本]。一个文件只能包含一个账本。')
        explicit_profile = KDF_FIELDS.keys() & fields.keys()
        if version == 2 and explicit_profile:
            label = min(explicit_profile, key=field_lines.get)
            raise ValueError(f'{_field(label, field_lines)}只能写在格式 2 的 [账本] 中。')
        if fragment and not explicit_profile:
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
    if not isinstance(book, dict) or type(book.get('version')) is not int or book['version'] not in (1, 3):
        raise ValueError('只能保存格式 1 或格式 3 的账本。')
    version = book['version']
    expected = {'version', 'book_code', 'entries'}
    if version == 3:
        expected.add('verifier')
    if set(book) != expected:
        raise ValueError('账本字段与指定格式不一致。')
    validate_code(book['book_code'])
    if not isinstance(book['entries'], list):
        raise ValueError('entries 必须是列表')
    lines = ['[账本]', f'格式：{version}']
    if version == 3:
        if book['book_code'] != VERIFIER_BOOK_CODE:
            raise ValueError('格式 3 的账本不保存旧校验码。')
        verifier = book['verifier']
        validate_verifier(verifier)
        lines.append(f'{VERIFIER_LABEL}：' + ','.join(str(verifier[key]) for key in VERIFIER_KEYS))
    else:
        lines.append(f'校验码：{book["book_code"]}')
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


def _parse_verifier(value, field_lines):
    try:
        parts = value.split(',')
        if len(parts) != len(VERIFIER_KEYS) or any(not re.fullmatch(r'[0-9]+', part) for part in parts[1:4]):
            raise ValueError('应依次填写算法、内存KiB、迭代次数、并行通道、随机码和密码密文，以英文逗号分隔。')
        verifier = dict(zip(VERIFIER_KEYS, parts))
        try:
            verifier.update(memory_kib=int(parts[1]), iterations=int(parts[2]), lanes=int(parts[3]))
        except ValueError:
            raise ValueError('加密参数的数值过大。') from None
        validate_verifier(verifier)
        return verifier
    except ValueError as error:
        raise ValueError(f'{_field(VERIFIER_LABEL, field_lines)}无效。{error}') from None


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
    validate_rules(entry['rules'], field_lines=field_lines)
    _validate_cipher_data(entry, field_lines=field_lines)


def validate_cipher_settings(record, *, field_lines=None):
    if record['algorithm'] not in ALGORITHMS:
        raise ValueError(f'{_field("加密算法", field_lines)}指定了不受支持的算法：{record["algorithm"]}')
    if type(record['lanes']) is not int or not 1 <= record['lanes'] < 2 ** 24:
        raise ValueError(f'{_field("并行通道", field_lines)}必须是 1 到 {2 ** 24 - 1} 之间的整数。')
    if type(record['memory_kib']) is not int or not 8 * record['lanes'] <= record['memory_kib'] < 2 ** 32:
        raise ValueError(f'{_field("内存KiB", field_lines)}必须至少为“并行通道”的 8 倍，且小于 {2 ** 32}。')
    if type(record['iterations']) is not int or not 1 <= record['iterations'] < 2 ** 32:
        raise ValueError(f'{_field("迭代次数", field_lines)}必须是 1 到 {2 ** 32 - 1} 之间的整数。')


def _validate_cipher_data(entry, *, field_lines=None):
    validate_cipher_settings(entry, field_lines=field_lines)
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
        return data
    return b''


def validate_verifier(verifier):
    if not isinstance(verifier, dict) or set(verifier) != set(VERIFIER_KEYS):
        raise ValueError('校验样本字段不完整。')
    if not isinstance(verifier['salt'], str) or not isinstance(verifier['data'], str):
        raise ValueError('校验样本的随机码和密码密文必须是文本。')
    data = _validate_cipher_data(verifier)
    nonce_length = 24 if verifier['algorithm'] == 'XCHACHA20-POLY1305' else 12
    if len(data) != nonce_length + 18 + 16:
        raise ValueError('校验样本的密码密文长度不正确。')
    return data


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
