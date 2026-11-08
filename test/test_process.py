"""流程语义测试用 32 KiB / 1 遍 / 1 通道，不能作为真实密码保护配置。"""

from base64 import b64decode, b64encode
from copy import deepcopy
from unittest.mock import patch
import unittest

from core import create_verifier, process, text_process, verify_master


def sample_entry(algorithm='XCHACHA20-POLY1305'):
    return {
        'service': '百度', 'addresses': 'www.baidu.com、api.baidu.com', 'code': 'baidu', 'username': 'jassor', 'nickname': '大马',
        'rules': {'length': 12, 'categories': 3, 'allowed': 'ULDS', 'symbols': '!@#$%^&*_-+=.?'},
        'algorithm': algorithm, 'memory_kib': 32, 'iterations': 1, 'lanes': 1, 'salt': '', 'data': '',
    }


class ProcessTests(unittest.TestCase):
    book_code = '0123456789abcdef0123456789abcdef'
    master = '测试管理密码 with spaces'

    def test_verifier_checks_only_the_authenticated_empty_sample(self):
        for algorithm, nonce_length in (('AES-256-GCM', 12), ('CHACHA20-POLY1305', 12), ('XCHACHA20-POLY1305', 24)):
            with self.subTest(algorithm=algorithm):
                entry = sample_entry(algorithm)
                parameters = {'book_code': self.book_code, 'entry': entry}
                encrypted_entry = process('encrypt', parameters, self.master, '')
                verifier = create_verifier(self.master, profile=encrypted_entry)
                self.assertEqual(set(verifier), {'algorithm', 'memory_kib', 'iterations', 'lanes', 'salt', 'data'})
                self.assertEqual({key: verifier[key] for key in ('algorithm', 'memory_kib', 'iterations', 'lanes')},
                                 {key: entry[key] for key in ('algorithm', 'memory_kib', 'iterations', 'lanes')})
                self.assertNotEqual(verifier['salt'], encrypted_entry['salt'])
                data = b64decode(verifier['data'])
                self.assertEqual(len(data), nonce_length + 18 + 16)
                self.assertNotEqual(data[:nonce_length], b64decode(encrypted_entry['data'])[:nonce_length])
                self.assertTrue(verify_master(verifier, self.master))
                with self.assertRaisesRegex(ValueError, '管理密码错误'):
                    verify_master(verifier, self.master + '!')
                damaged = data[:-1] + bytes([data[-1] ^ 1])
                with self.assertRaisesRegex(ValueError, '校验样本已被改动'):
                    verify_master({**verifier, 'data': b64encode(damaged).decode('ascii')}, self.master)
                with self.assertRaisesRegex(ValueError, '校验样本内容不正确'):
                    verify_master({key: encrypted_entry[key] for key in verifier}, self.master)

    def test_verifier_uses_config_defaults_when_no_profile_is_supplied(self):
        with patch.multiple('config', DEFAULT_ALGORITHM='CHACHA20-POLY1305', MEMORY_KIB=32, ITERATIONS=2, LANES=2):
            verifier = create_verifier(self.master)
        self.assertEqual((verifier['algorithm'], verifier['memory_kib'], verifier['iterations'], verifier['lanes']),
                         ('CHACHA20-POLY1305', 32, 2, 2))
        self.assertTrue(verify_master(verifier, self.master))

    def test_shared_pipeline_and_no_input_mutation(self):
        for algorithm in ('AES-256-GCM', 'CHACHA20-POLY1305', 'XCHACHA20-POLY1305'):
            entry = sample_entry(algorithm)
            parameters = {'book_code': self.book_code, 'entry': entry}
            original = deepcopy(parameters)
            for password in ('', '123456_qwerty', 'Oo0Iil', ' 中文🙂\n\t\\ ： '):
                with self.subTest(algorithm=algorithm, password=password):
                    encrypted = process('encrypt', parameters, self.master, password)
                    self.assertEqual(parameters, original)
                    self.assertEqual(process('decrypt', {'book_code': self.book_code, 'entry': encrypted}, self.master), password)
                    if password:
                        self.assertNotIn(password, encrypted.values())

    def test_reencrypt_refreshes_salt_and_nonce(self):
        parameters = {'book_code': self.book_code, 'entry': sample_entry()}
        first = process('encrypt', parameters, self.master, 'unchanged')
        second = process('encrypt', {'book_code': self.book_code, 'entry': first}, self.master, 'unchanged')
        self.assertNotEqual(first['salt'], second['salt'])
        self.assertNotEqual(b64decode(first['data'])[:24], b64decode(second['data'])[:24])
        self.assertEqual(process('decrypt', {'book_code': self.book_code, 'entry': second}, self.master), 'unchanged')

    def test_explicit_salt_is_used_but_nonce_is_always_fresh(self):
        salt = 'aB' * 16
        parameters = {'book_code': self.book_code, 'entry': sample_entry(), 'salt_override': salt}
        first = process('encrypt', parameters, self.master, 'original')
        second = process('encrypt', parameters, self.master, 'original')
        self.assertEqual(first['salt'], salt)
        self.assertEqual(second['salt'], salt)
        self.assertNotEqual(b64decode(first['data'])[:24], b64decode(second['data'])[:24])
        self.assertEqual(process('decrypt', {'book_code': self.book_code, 'entry': second}, self.master), 'original')
        with patch('core.argon2id_native.derive', side_effect=AssertionError('unexpected KDF')):
            for invalid in ('', 'zz' * 16, 'aa ' * 16):
                with self.subTest(salt=invalid), self.assertRaisesRegex(ValueError, '随机码'):
                    process('encrypt', {**parameters, 'salt_override': invalid}, self.master, 'original')
            with self.assertRaisesRegex(ValueError, 'salt_override'):
                process('decrypt', {**parameters, 'entry': first}, self.master)

    def test_wrong_master_and_altered_payload(self):
        for algorithm in ('AES-256-GCM', 'CHACHA20-POLY1305', 'XCHACHA20-POLY1305'):
            entry = process('encrypt', {'book_code': self.book_code, 'entry': sample_entry(algorithm)}, self.master, 'private-value')
            parameters = {'book_code': self.book_code, 'entry': entry}
            with self.assertRaises(ValueError):
                process('decrypt', parameters, 'wrong')
            self.assertEqual(process('decrypt', {**parameters, 'book_code': '00' * 16}, self.master), 'private-value')
            for key, value in (('salt', '00' * 16), ('iterations', 2)):
                with self.subTest(algorithm=algorithm, key=key), self.assertRaises(ValueError):
                    process('decrypt', {**parameters, 'entry': {**entry, key: value}}, self.master)
            data = bytearray(b64decode(entry['data']))
            for index in (0, len(data) // 2, len(data) - 1):
                changed = data.copy()
                changed[index] ^= 1
                with self.subTest(algorithm=algorithm, index=index), self.assertRaises(ValueError):
                    process('decrypt', {**parameters, 'entry': {**entry, 'data': b64encode(changed).decode('ascii')}}, self.master)

    def test_metadata_edits_swaps_and_deletes_are_permitted(self):
        first = process('encrypt', {'book_code': self.book_code, 'entry': sample_entry()}, self.master, 'first-password')
        second = process('encrypt', {'book_code': self.book_code, 'entry': sample_entry()}, self.master, 'second-password')
        first.update(service='改名', username='different-user', salt=second['salt'], data=second['data'])
        book = {'version': 1, 'book_code': self.book_code, 'entries': [first, second]}
        book['entries'].pop()
        text = text_process('encode', parameters=book)
        self.assertEqual(text_process('decrypt', text, 0, self.master), 'second-password')

    def test_text_pipeline_and_hidden_plaintext(self):
        text = text_process('new')
        book = text_process('decode', text)
        self.assertEqual(book['entries'], [])
        book['entries'].append(sample_entry())
        text = text_process('encode', parameters=book)
        encrypted = text_process('encrypt', text, 0, self.master, 'actual-site-secret')
        self.assertNotIn('actual-site-secret', encrypted)
        self.assertNotIn(self.master, encrypted)
        self.assertEqual(text_process('decrypt', encrypted, 0, self.master), 'actual-site-secret')
        self.assertEqual(text_process('decode', text)['entries'][0]['data'], '')
        with self.assertRaises(ValueError):
            text_process('decrypt', encrypted, -1, self.master)

    def test_generation_uses_minimum_satisfying_length(self):
        groups = ('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghjkmnpqrstuvwxyz', '123456789', '!@#')
        for allowed in ('U', 'D', 'LD', 'ULDS', 'S'):
            for minimum in (1, 8, 12):
                for count in range(1, len(allowed) + 1):
                    rules = {'length': minimum, 'categories': count, 'allowed': allowed, 'symbols': '!@#'}
                    enabled = [group for key, group in zip('ULDS', groups) if key in allowed]
                    for _ in range(5):
                        password = process('generate', rules)
                        self.assertEqual(len(password), max(minimum, count))
                        self.assertTrue(set(password) <= set(''.join(enabled)))
                        self.assertGreaterEqual(sum(bool(set(password) & set(group)) for group in enabled), count)

    def test_invalid_inputs_fail_before_derivation(self):
        parameters = {'book_code': self.book_code, 'entry': sample_entry()}
        with patch('core.argon2id_native.derive', side_effect=AssertionError('unexpected KDF')):
            for action in ('unknown', 'decrypt'):
                with self.assertRaises(ValueError):
                    process(action, parameters, self.master)
            with self.assertRaises(ValueError):
                process('encrypt', parameters, '', 'password')
            with self.assertRaises(ValueError):
                process('encrypt', parameters, self.master, 'a' * 65536)
            entry = {**parameters['entry'], 'salt': '00' * 16, 'data': b64encode(bytes(24 + 16 + 18 + 65536)).decode('ascii')}
            with self.assertRaises(ValueError):
                process('decrypt', {**parameters, 'entry': entry}, self.master)
            for field, value in (('lanes', 0), ('iterations', 0), ('memory_kib', 7), ('algorithm', 'unknown')):
                with self.subTest(field=field), self.assertRaises(ValueError):
                    process('encrypt', {**parameters, 'entry': {**parameters['entry'], field: value}}, self.master, 'password')
            text_process('decode', text_process('new'))

    def test_impossible_rules_rejected(self):
        rules = sample_entry()['rules']
        for field, value in (('length', 0), ('categories', 5), ('allowed', ''), ('allowed', 'UU'), ('symbols', 'a!'), ('symbols', '')):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                process('generate', {**rules, field: value})


if __name__ == '__main__':
    unittest.main()
