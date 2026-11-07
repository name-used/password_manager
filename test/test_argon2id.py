"""Fixed specification vectors; no third-party crypto dependency is needed."""

import unittest

from core.argon2id import blake2b, derive


class Blake2bTests(unittest.TestCase):
    def test_rfc7693_abc(self):
        # RFC 7693 appendix A: BLAKE2b-512("abc").
        expected = 'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1'
        expected += '7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923'
        self.assertEqual(blake2b(b'abc').hex(), expected)

    def test_empty(self):
        expected = '786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419'
        expected += 'd25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce'
        self.assertEqual(blake2b(b'').hex(), expected)

    def test_digest_length_changes_hash(self):
        self.assertEqual(blake2b(b'abc', 32).hex(), 'bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319')
        self.assertNotEqual(blake2b(b'abc', 32), blake2b(b'abc')[:32])

    def test_invalid_parameters(self):
        for length in (0, 65, 1.5, True):
            with self.subTest(length=length), self.assertRaises(ValueError):
                blake2b(b'abc', length)
        with self.assertRaises(TypeError):
            blake2b('abc')


class Argon2idTests(unittest.TestCase):
    def test_rfc9106_section_5_3(self):
        result = derive(bytes([1]) * 32, bytes([2]) * 16, 32, 3, 4, 32, bytes([3]) * 8, bytes([4]) * 12)
        self.assertEqual(result.hex(), '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659')

    def test_independent_regression_vectors(self):
        # Cross-checked against cryptography 50.0.1 / OpenSSL; these are not RFC test vectors.
        # Covers memory rounding, different lanes/passes, H' outputs >64 bytes and a second address block.
        cases = (
            (9, 2, 1, 32, '911a6d613e8875c27642fdf172411c317cd72b7f58760e5f097b06a15bdd97d4'),
            (33, 2, 3, 64,
             '2ff423e00d62a9d4b2fd0fdde36796d67b780d8b3f60c719c53f6a6931d9b4b0d6'
             '70a8dba114b5d01550bcc5e6c6ac9c9ed79dedeece00d73a3beb3618198cf4'),
            (49, 3, 4, 65,
             '647829e31c738e78e43390e5da3e3c9db380c7f7d7c20724d13c0e1bfc5636dff95'
             '43779456d4f855bf04aee8642df1f07e8e6364791ede08d93ae0f1f242a7c00'),
            (1024, 1, 1, 32, 'ec4ea35974a7736c8c4dad786327ba109182840784854b01ceb328445697456c'),
            (1031, 2, 2, 128,
             'e96313315069a0bf7b19160ab451ab39050d56a722be46857a2489e756dbe8c0adb6'
             '52be206c40885c28889e695b51da30fc988b449bd9b46073d5c6d9d2adfa3f254'
             '829963aee3cd8da850b027967dedcae013f7630eaccb0c4c8d42eab09ad199181ab'
             '6604495c46726a9e12d3c8417625ca74f6c0ed64a79394718fe466d2'),
        )
        for memory, iterations, lanes, length, expected in cases:
            with self.subTest(memory=memory, iterations=iterations, lanes=lanes, length=length):
                password = b'comparison-password' if length < 96 else bytes(range(131))
                secret = b'secret-input' if length >= 64 else b''
                ad = b'associated-data' if length >= 64 else b''
                self.assertEqual(derive(password, b'comparison-salt!', memory, iterations, lanes, length, secret, ad).hex(), expected)

    def test_salt_and_password_affect_key(self):
        arguments = dict(memory_kib=8, iterations=1, lanes=1)
        original = derive(b'password', b'0123456789abcdef', **arguments)
        self.assertNotEqual(original, derive(b'Password', b'0123456789abcdef', **arguments))
        self.assertNotEqual(original, derive(b'password', b'1123456789abcdef', **arguments))
        self.assertEqual(original, derive(b'password', b'0123456789abcdef', **arguments))

    def test_invalid_parameters(self):
        cases = ({'memory_kib': 7, 'lanes': 1}, {'iterations': 0}, {'lanes': 0}, {'length': 3}, {'memory_kib': 32.0})
        for arguments in cases:
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                derive(b'password', b'0123456789abcdef', **arguments)
        with self.assertRaises(TypeError):
            derive('password', b'0123456789abcdef')


if __name__ == '__main__':
    unittest.main()
