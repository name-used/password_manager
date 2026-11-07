"""NIST known answers and adversarial inputs; no third-party test dependency.

Sources:
https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core256.pdf
https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf
"""

import unittest
from unittest.mock import patch

from core.ciphers import aes_gcm


class AESGCMTests(unittest.TestCase):
    def test_nist_aes256_blocks(self):
        key = bytes.fromhex('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4')
        plaintexts = [
            '6bc1bee22e409f96e93d7e117393172a', 'ae2d8a571e03ac9c9eb76fac45af8e51',
            '30c81c46a35ce411e5fbc1191a0a52ef', 'f69f2445df4f9b17ad2b417be66c3710',
        ]
        ciphertexts = [
            'f3eed1bdb5d2a03c064b5a7e3db181f8', '591ccb10d410ed26dc5ba74a31362870',
            'b6ed21b99ca6f4f9f153e7b1beafed1d', '23304b7a39f9f3ff067d8d8f9e24ecc7',
        ]
        for plaintext, ciphertext in zip(plaintexts, ciphertexts):
            with self.subTest(plaintext=plaintext):
                self.assertEqual(aes_gcm.encrypt_block(key, bytes.fromhex(plaintext)).hex(), ciphertext)

    def test_nist_gcm256_examples(self):
        key = bytes.fromhex('feffe9928665731c6d6a8f9467308308' * 2)
        nonce = bytes.fromhex('cafebabefacedbaddecaf888')
        plaintext = bytes.fromhex(
            'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72'
            '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255'
        )
        ciphertext = bytes.fromhex(
            '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa'
            '8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad'
        )
        aad = bytes.fromhex(
            '3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf'
            '43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4'
        )
        # NIST GCM-AES256 examples 1-5, all using complete 128-bit tags.
        cases = [
            (b'', b'', b'', 'fd2caa16a5832e76aa132c1453eeda7e'),
            (plaintext, b'', ciphertext, 'b094dac5d93471bdec1a502270e3cc6c'),
            (b'', aad, b'', 'de34b6dcd4cee2fdbec3cea01af1ee44'),
            (plaintext, aad, ciphertext, 'c06d76f31930fef37acae23ed465ae62'),
            (plaintext[:60], aad[:20], ciphertext[:60], 'e097195f4532da895fb917a5a55c6aa0'),
        ]
        for index, (plain, associated, cipher, tag) in enumerate(cases, 1):
            with self.subTest(example=index):
                expected = cipher + bytes.fromhex(tag)
                self.assertEqual(aes_gcm.encrypt(key, nonce, plain, associated), expected)
                self.assertEqual(aes_gcm.decrypt(key, nonce, expected, associated), plain)

    def test_boundaries_and_binary_contents(self):
        key = bytes(range(32))
        for size in (0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 256, 257):
            with self.subTest(size=size):
                nonce = size.to_bytes(12, 'big')
                plain = bytes(i % 256 for i in range(size))
                aad = b'\x00account\xff'
                sealed = aes_gcm.encrypt(key, nonce, plain, aad)
                self.assertEqual(len(sealed), size + 16)
                self.assertEqual(aes_gcm.decrypt(key, nonce, sealed, aad), plain)

    def test_reject_changes_before_decrypting(self):
        key, nonce, aad = bytes(range(32)), bytes(range(12)), b'public-fields'
        data = aes_gcm.encrypt(key, nonce, b'synthetic password', aad)
        variants = [(key, nonce, data, aad + b'!'), (bytes(32), nonce, data, aad), (key, bytes(12), data, aad)]
        for index in range(len(data)):
            changed = data[:index] + bytes([data[index] ^ 1]) + data[index + 1:]
            variants.append((key, nonce, changed, aad))
        variants.extend((key, nonce, changed, aad) for changed in (data[:-1], data + b'\x00', data[1:]))
        with patch.object(aes_gcm, '_crypt', side_effect=AssertionError('Decryption ran before authentication')):
            for index, values in enumerate(variants):
                with self.subTest(case=index), self.assertRaises(ValueError):
                    aes_gcm.decrypt(*values)

    def test_reject_invalid_sizes(self):
        for size in (0, 16, 24, 31, 33):
            with self.subTest(key_size=size), self.assertRaises(ValueError):
                aes_gcm.encrypt(bytes(size), bytes(12), b'')
        for size in (0, 8, 11, 13, 16):
            with self.subTest(nonce_size=size), self.assertRaises(ValueError):
                aes_gcm.encrypt(bytes(32), bytes(size), b'')
        for size in range(16):
            with self.subTest(tag_size=size), self.assertRaises(ValueError):
                aes_gcm.decrypt(bytes(32), bytes(12), bytes(size))
        with self.assertRaises(ValueError):
            aes_gcm.encrypt_block(bytes(32), bytes(15))
        with self.assertRaises(ValueError):
            aes_gcm._validate(bytes(12), (2 ** 32 - 2) * 16 + 1, 0)
        with self.assertRaises(ValueError):
            aes_gcm._validate(bytes(12), 0, 2 ** 61)


if __name__ == '__main__':
    unittest.main()
