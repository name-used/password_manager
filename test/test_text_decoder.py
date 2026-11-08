import unittest

from core import create_verifier, text_process, verify_master, with_verifier
from test.test_process import sample_entry


class TextDecoderTests(unittest.TestCase):
    def setUp(self):
        self.book = {'version': 1, 'book_code': '0123456789abcdef0123456789abcdef', 'entries': [sample_entry()]}

    def test_exact_text_values_roundtrip(self):
        values = ('', ' user ', 'a：b:c', '[条目]', '\\n not newline\nreal\r\ttab', '\x00\v\f\x85\u2028\u2029🙂')
        for value in values:
            with self.subTest(value=value):
                self.book['entries'][0]['username'] = value
                text = text_process('encode', parameters=self.book)
                self.assertEqual(text_process('decode', text), self.book)
                self.assertEqual(text_process('decode', '\ufeff' + text.replace('\n', '\r\n')), self.book)

    def test_field_order_and_blank_lines(self):
        text = text_process('encode', parameters=self.book)
        header, entry = text.split('[条目]\n')
        text = header + '[条目]\n' + '\n\n'.join(reversed(entry.rstrip('\n').split('\n'))) + '\n'
        self.assertEqual(text_process('decode', text), self.book)

    def test_missing_unknown_duplicate_and_escape_errors(self):
        text = text_process('encode', parameters=self.book)
        invalid = (
            text.replace('用户名：jassor\n', ''),
            text + '密码明文：secret\n',
            text + '用户名：another\n',
            text.replace('用户名：jassor', '用户名：bad\\q'),
            text.replace('用户名：jassor', '用户名：bad\\'),
            text.replace('格式：1', '格式：2'),
            text + '[账本]\n格式：1\n校验码：' + self.book['book_code'],
            text.replace('迭代次数：1', '迭代次数：1.0'),
            text.replace('随机码：\n', '随机码：00\n'),
        )
        for value in invalid:
            with self.subTest(text=value), self.assertRaises(ValueError):
                text_process('decode', value)

    def test_unknown_structure_fields_not_silently_saved(self):
        for location in (self.book, self.book['entries'][0], self.book['entries'][0]['rules']):
            location['password'] = 'must-not-be-written'
            with self.assertRaises(ValueError):
                text_process('encode', parameters=self.book)
            location.pop('password')

    def test_field_error_uses_source_line_for_complete_text_and_fragment(self):
        text = text_process('encode', parameters=self.book)
        for label, invalid in (('迭代次数', '1.0'), ('并行通道', '0'), ('密码规则', 'invalid')):
            lines = text.splitlines(keepends=True)
            index = next(index for index, line in enumerate(lines) if line.startswith(f'{label}：'))
            lines[index] = f'{label}：{invalid}\n'
            malformed = ''.join(lines)
            with self.subTest(field=label), self.assertRaisesRegex(ValueError, f'^第 {index + 1} 行的“{label}”'):
                text_process('decode', malformed)

            fragment = '\ufeff\r\n\r\n' + malformed[malformed.index('[条目]'):].replace('\n', '\r\n')
            line_number = next(index for index, line in enumerate(fragment.split('\r\n'), 1) if line.startswith(f'{label}：'))
            with self.subTest(fragment_field=label), self.assertRaisesRegex(ValueError, f'^第 {line_number} 行的“{label}”'):
                text_process('append', fragment, parameters=self.book)

    def test_ciphertext_base64_is_validated_without_kdf(self):
        entry = self.book['entries'][0]
        entry['salt'] = '00' * 16
        for data in ('bad base64', 'AB==', '\u4e2d\u6587', ''):
            entry['data'] = data
            with self.subTest(data=data), self.assertRaises(ValueError):
                text_process('encode', parameters=self.book)

    def test_read_provisional_format_two_and_encrypt_as_format_one(self):
        self.book['entries'][0].update(memory_kib=48, iterations=2, lanes=2)
        master = 'synthetic master'
        normal = text_process('encode', parameters=self.book)
        self.assertIn('格式：1\n', text_process('new', parameters={'memory_kib': 48, 'iterations': 2}))
        provisional = self._provisional_text(normal)
        self.assertEqual(text_process('decode', provisional), self.book)
        self.assertEqual(text_process('portable', provisional), (self.book, normal))
        exact = '\ufeff\r\n' + normal.replace('\n', '\r\n') + '\r\n'
        self.assertEqual(text_process('portable', exact), (self.book, exact))

        encrypted = text_process('encrypt', provisional, 0, master, 'original password')
        self.assertIn('格式：1\n', encrypted)
        self.assertNotIn('内存KiB：', encrypted.partition('[条目]')[0])
        self.assertIn('内存KiB：48\n迭代次数：2\n并行通道：2\n', encrypted)
        provisional_encrypted = self._provisional_text(encrypted)
        self.assertEqual(text_process('decrypt', provisional_encrypted, 0, master), 'original password')
        self.assertEqual(text_process('portable', provisional_encrypted), (text_process('decode', encrypted), encrypted))

    def test_provisional_format_two_still_validates_shared_fields(self):
        self.book['entries'][0].update(memory_kib=48, iterations=2)
        provisional = self._provisional_text(text_process('encode', parameters=self.book))
        empty = provisional.partition('\n\n')[0] + '\n'
        self.assertEqual(text_process('decode', empty), {**self.book, 'entries': []})
        invalid = (
            (provisional.replace('迭代次数：2\n', ''), '缺少.*迭代次数'),
            (provisional.replace('内存KiB：48', '内存KiB：0'), '第 4 行的“内存KiB”'),
            (provisional.replace('[条目]\n', '[条目]\n内存KiB：48\n'), '第 8 行的“内存KiB”'),
        )
        for malformed, message in invalid:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                text_process('decode', malformed)

    def test_append_retains_distinct_entry_profiles_in_both_formats(self):
        master = 'synthetic master'
        target = text_process('decode', text_process('new'))
        target['entries'].append(sample_entry())
        target_text = text_process('encode', parameters=target)
        target = text_process('decode', text_process('encrypt', target_text, 0, master, 'target'))
        self.book['entries'][0].update(memory_kib=48, iterations=2, lanes=2)
        self.book['entries'].append(dict(self.book['entries'][0], service='draft'))
        source_text = text_process('encode', parameters=self.book)
        normal = text_process('encrypt', source_text, 0, master, 'source')
        provisional = self._provisional_text(normal)
        fragment = normal[normal.index('[条目]'):]
        for pasted in (normal, fragment, provisional):
            with self.subTest(format=pasted.splitlines()[0]):
                result = text_process('append', pasted, parameters=target)
                merged = text_process('decode', result)
                self.assertEqual(merged['entries'], target['entries'] + text_process('decode', normal)['entries'])
                self.assertEqual(merged['book_code'], target['book_code'])
                self.assertEqual(text_process('decrypt', result, 0, master), 'target')
                self.assertEqual(text_process('decrypt', result, 1, master), 'source')
        with self.assertRaisesRegex(ValueError, '第 2 行.*完整源账本'):
            text_process('append', '\ufeff\r\n' + provisional[provisional.index('[条目]'):], parameters=target)

    def test_verifier_header_roundtrip_keeps_entry_parameters_and_omits_old_code(self):
        master = 'synthetic master'
        verifier = create_verifier(master, profile=self.book['entries'][0])
        book = with_verifier(self.book, verifier)
        self.assertEqual(book, {'version': 3, 'book_code': '0' * 32, 'entries': self.book['entries'], 'verifier': verifier})
        self.assertEqual(self.book['version'], 1)
        text = text_process('encode', parameters=book)
        sample_line = f'校验样本：XCHACHA20-POLY1305,32,1,1,{verifier["salt"]},{verifier["data"]}'
        self.assertEqual(text.splitlines()[:3], ['[账本]', '格式：3', sample_line])
        self.assertNotIn('校验码：', text)
        self.assertEqual(text_process('decode', text), book)
        exact = '\ufeff' + text.replace('\n', '\r\n')
        self.assertEqual(text_process('portable', exact), (book, exact))
        self.assertTrue(verify_master(text_process('decode', text)['verifier'], master))
        encrypted = text_process('encrypt', text, 0, master, 'synthetic site password')
        self.assertEqual(text_process('decode', encrypted)['verifier'], verifier)
        self.assertEqual(text_process('decrypt', encrypted, 0, master), 'synthetic site password')

        invalid = (
            (text.replace(sample_line + '\n', ''), '缺少.*校验样本'),
            (text.replace(sample_line, '校验样本：invalid'), '第 3 行的“校验样本”'),
            (text.replace(sample_line, sample_line + '\n校验码：' + self.book['book_code']), '第 4 行的“校验码”'),
        )
        for malformed, message in invalid:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                text_process('decode', malformed)

    def test_append_keeps_the_target_verifier_and_the_original_entries(self):
        master = 'synthetic master'
        verifier = create_verifier(master, profile=self.book['entries'][0])
        target = with_verifier({**self.book, 'entries': []}, verifier)
        self.book['entries'][0].update(memory_kib=48, iterations=2)
        original = text_process('encode', parameters=self.book)
        encrypted = text_process('encrypt', original, 0, master, 'original')
        source = text_process('decode', encrypted)
        v3_source = text_process('encode', parameters=with_verifier(source, create_verifier('other master', profile=source['entries'][0])))
        fragment = encrypted[encrypted.index('[条目]'):]
        for pasted in (encrypted, fragment, self._provisional_text(encrypted), v3_source):
            merged = text_process('append', pasted, parameters=target)
            self.assertEqual(text_process('decode', merged), {**target, 'entries': source['entries']})
            self.assertEqual(text_process('decrypt', merged, 0, master), 'original')

    def _provisional_text(self, format_one_text):
        return (format_one_text.replace('内存KiB：48\n迭代次数：2\n', '')
                .replace('格式：1\n', '格式：2\n', 1)
                .replace('\n\n[条目]', '\n内存KiB：48\n迭代次数：2\n\n[条目]', 1))


if __name__ == '__main__':
    unittest.main()
