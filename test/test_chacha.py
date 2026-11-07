"""规范向量来自 RFC 8439 及 draft-irtf-cfrg-xchacha-03；无需第三方包。"""

import unittest
from unittest.mock import patch

from core.ciphers import _chacha as chacha
from core.ciphers import aes_gcm, chacha20_poly1305, xchacha20_poly1305


class ChaChaTest(unittest.TestCase):
    def test_rfc_block(self):
        expected = bytes.fromhex(
            '10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e'
            'd2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e'
        )
        self.assertEqual(chacha.chacha20_block(bytes(range(32)), bytes.fromhex('000000090000004a00000000'), 1), expected)

    def test_rfc_poly1305(self):
        key = bytes.fromhex('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b')
        self.assertEqual(chacha.poly1305(key, b'Cryptographic Forum Research Group'), bytes.fromhex('a8061dc1305136c6c22b8baf0c0127a9'))
        self.assertEqual(chacha.poly1305(key, b''), key[16:])

    def test_rfc_aead(self):
        # RFC 8439, section 2.8.2.
        key = bytes(range(0x80, 0xa0))
        nonce = bytes.fromhex('070000004041424344454647')
        aad = bytes.fromhex('50515253c0c1c2c3c4c5c6c7')
        plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
        expected = bytes.fromhex(
            'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6'
            '3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36'
            '92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc'
            '3ff4def08e4b7a9de576d26586cec64b6116'
            '1ae10b594f09e26a7e902ecbd0600691'
        )
        self.assertEqual(chacha.encrypt(key, nonce, plaintext, aad), expected)
        self.assertEqual(chacha.decrypt(key, nonce, expected, aad), plaintext)

    def test_draft_hchacha20(self):
        # draft-irtf-cfrg-xchacha-03, section 2.2.1.
        nonce = bytes.fromhex('000000090000004a0000000031415927')
        expected = bytes.fromhex('82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc')
        self.assertEqual(chacha.hchacha20(bytes(range(32)), nonce), expected)

    def test_draft_xchacha_aead(self):
        # draft-irtf-cfrg-xchacha-03, appendix A.3.1.
        key = bytes(range(0x80, 0xa0))
        nonce = bytes(range(0x40, 0x58))
        aad = bytes.fromhex('50515253c0c1c2c3c4c5c6c7')
        plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
        expected = bytes.fromhex(
            'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb'
            '731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452'
            '2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9'
            '21f9664c97637da9768812f615c68b13b52e'
            'c0875924c1c7987947deafd8780acf49'
        )
        self.assertEqual(chacha.encrypt(key, nonce, plaintext, aad), expected)
        self.assertEqual(chacha.decrypt(key, nonce, expected, aad), plaintext)

    def test_boundary_lengths_and_rejection(self):
        key = bytes(range(32))
        for nonce_size in (12, 24):
            for size in (0, 15, 16, 17, 63, 64, 65):
                for aad_size in (0, 15, 16, 17):
                    with self.subTest(nonce_size=nonce_size, size=size, aad_size=aad_size):
                        nonce = bytes(range(nonce_size))
                        plaintext, aad = bytes(range(size)), bytes(range(aad_size))
                        data = chacha.encrypt(key, nonce, plaintext, aad)
                        self.assertEqual(len(data), size + 16)
                        self.assertEqual(chacha.decrypt(key, nonce, data, aad), plaintext)
                        corrupted = data[:-1] + bytes([data[-1] ^ 1])
                        for bad_key, bad_nonce, bad_data, bad_aad in (
                            (key, nonce, corrupted, aad),
                            (key, nonce, data, aad + b'!'),
                            (bytes([key[0] ^ 1]) + key[1:], nonce, data, aad),
                            (key, bytes([nonce[0] ^ 1]) + nonce[1:], data, aad),
                        ):
                            with self.assertRaises(ValueError):
                                chacha.decrypt(bad_key, bad_nonce, bad_data, bad_aad)
                        if plaintext:
                            with self.assertRaises(ValueError):
                                chacha.decrypt(key, nonce, bytes([data[0] ^ 1]) + data[1:], aad)

    def test_verify_before_decrypt(self):
        key, nonce = bytes(32), bytes(12)
        data = chacha.encrypt(key, nonce, b'not released')
        corrupted = data[:-1] + bytes([data[-1] ^ 1])
        with patch('core.ciphers._chacha.chacha20_xor', side_effect=AssertionError('解密不应先于认证')):
            with self.assertRaises(ValueError):
                chacha.decrypt(key, nonce, corrupted)

    def test_invalid_inputs(self):
        for key_size in (0, 31, 33):
            with self.assertRaises(ValueError):
                chacha.encrypt(bytes(key_size), bytes(12), b'')
            with self.assertRaises(ValueError):
                chacha.poly1305(bytes(key_size), b'')
        for nonce_size in (0, 11, 13, 23, 25):
            with self.assertRaises(ValueError):
                chacha.encrypt(bytes(32), bytes(nonce_size), b'')
        for size in (0, 1, 15):
            with self.assertRaises(ValueError):
                chacha.decrypt(bytes(32), bytes(12), bytes(size))
        with self.assertRaises(ValueError):
            chacha.hchacha20(bytes(32), bytes(15))

    def test_counter_limit(self):
        key, nonce = bytes(32), bytes(12)
        self.assertEqual(chacha.chacha20_xor(key, nonce, bytes(64), 2 ** 32 - 1), chacha.chacha20_block(key, nonce, 2 ** 32 - 1))
        with self.assertRaises(ValueError):
            chacha.chacha20_xor(key, nonce, bytes(65), 2 ** 32 - 1)
        for counter in (-1, 2 ** 32, 1.5):
            with self.assertRaises(ValueError):
                chacha.chacha20_xor(key, nonce, b'', counter)
            with self.assertRaises(ValueError):
                chacha.chacha20_block(key, nonce, counter)


class CipherEntryTests(unittest.TestCase):
    def test_entry_nonce_sizes_and_roundtrips(self):
        for cipher, size in ((aes_gcm, 12), (chacha20_poly1305, 12), (xchacha20_poly1305, 24)):
            with self.subTest(cipher=cipher.__name__):
                self.assertEqual(cipher.NONCE_SIZE, size)
                key, nonce = bytes(range(32)), bytes(range(size))
                sealed = cipher.encrypt(key, nonce, b'entry test', b'context')
                self.assertEqual(cipher.decrypt(key, nonce, sealed, b'context'), b'entry test')
                for wrong_size in (0, 11, 12, 13, 23, 24, 25):
                    if wrong_size == size:
                        continue
                    with self.assertRaises(ValueError):
                        cipher.encrypt(key, bytes(wrong_size), b'entry test')
                    with self.assertRaises(ValueError):
                        cipher.decrypt(key, bytes(wrong_size), sealed)

    def test_chacha_entries_preserve_original_output(self):
        for cipher in (chacha20_poly1305, xchacha20_poly1305):
            with self.subTest(cipher=cipher.__name__):
                key, nonce = bytes(range(32)), bytes(range(cipher.NONCE_SIZE))
                self.assertEqual(cipher.encrypt(key, nonce, b'unchanged arithmetic'), chacha.encrypt(key, nonce, b'unchanged arithmetic'))


if __name__ == '__main__':
    unittest.main()
