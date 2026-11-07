/* Direct translations of this project's Python AEAD implementations.
 * RFC 8439, draft-irtf-cfrg-xchacha-03, FIPS 197 and NIST SP 800-38D.
 * Authentication is checked before plaintext is returned. BigInt and table
 * lookups do not provide a constant-time or secret-memory-erasure guarantee.
 * No file access, randomness, network or external crypto implementation.
 */
'use strict';

const VaultCiphers = (() => {
    const sboxHex =
        '637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0' +
        'b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275' +
        '09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf' +
        'd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2' +
        'cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb' +
        'e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08' +
        'ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e' +
        'e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16';
    const sbox = Uint8Array.from(sboxHex.match(/../g), value => parseInt(value, 16));

    function decrypt(algorithm, key, nonce, data, aad = new Uint8Array()) {
        for (const bytes of [key, nonce, data, aad]) {
            if (!(bytes instanceof Uint8Array)) throw new TypeError('加密输入必须是 Uint8Array');
        }
        if (key.length !== 32) throw new Error('密钥必须是 32 字节');
        if (data.length < 16) throw new Error('密文缺少完整的 16 字节认证码');
        if (algorithm === 'AES-256-GCM') {
            if (nonce.length !== 12) throw new Error('AES-GCM nonce 必须是 12 字节');
            return aesDecrypt(key, nonce, data, aad);
        }
        if (algorithm === 'XCHACHA20-POLY1305') {
            if (nonce.length !== 24) throw new Error('XChaCha20 nonce 必须是 24 字节');
            key = hchacha(key, nonce.subarray(0, 16));
            const shortNonce = new Uint8Array(12);
            shortNonce.set(nonce.subarray(16), 4);
            nonce = shortNonce;
        } else if (algorithm === 'CHACHA20-POLY1305') {
            if (nonce.length !== 12) throw new Error('ChaCha20 nonce 必须是 12 字节');
        } else {
            throw new Error(`未知加密算法：${algorithm}`);
        }
        return chachaDecrypt(key, nonce, data, aad);
    }

    function equalTag(actual, expected) {
        let difference = actual.length ^ expected.length;
        for (let index = 0; index < expected.length; ++index) difference |= actual[index] ^ expected[index];
        return difference === 0;
    }

    function readInteger(bytes, littleEndian = false) {
        let result = 0n;
        for (let index = 0; index < bytes.length; ++index) {
            result = (result << 8n) | BigInt(bytes[littleEndian ? bytes.length - index - 1 : index]);
        }
        return result;
    }

    function writeInteger(value, length, littleEndian = false) {
        const result = new Uint8Array(length);
        for (let index = 0; index < length; ++index) {
            result[littleEndian ? index : length - index - 1] = Number(value & 255n);
            value >>= 8n;
        }
        return result;
    }

    function xtime(value) {
        return ((value << 1) ^ (value & 0x80 ? 0x11b : 0)) & 255;
    }

    function expandKey(key) {
        const expanded = new Uint8Array(240);
        expanded.set(key);
        let rcon = 1;
        for (let offset = 32; offset < 240; offset += 4) {
            let word = expanded.slice(offset - 4, offset);
            if (offset % 32 === 0) {
                word = Uint8Array.of(sbox[word[1]] ^ rcon, sbox[word[2]], sbox[word[3]], sbox[word[0]]);
                rcon = xtime(rcon);
            } else if (offset % 32 === 16) {
                word = word.map(value => sbox[value]);
            }
            for (let index = 0; index < 4; ++index) expanded[offset + index] = expanded[offset + index - 32] ^ word[index];
        }
        return expanded;
    }

    function aesBlock(roundKeys, block) {
        let state = block.map((value, index) => value ^ roundKeys[index]);
        for (let round = 1; round <= 14; ++round) {
            const next = new Uint8Array(16);
            for (let column = 0; column < 4; ++column) {
                for (let row = 0; row < 4; ++row) next[4 * column + row] = sbox[state[4 * ((column + row) % 4) + row]];
            }
            if (round !== 14) {
                for (let index = 0; index < 16; index += 4) {
                    const [a, b, c, d] = next.subarray(index, index + 4);
                    const total = a ^ b ^ c ^ d;
                    next.set([a ^ total ^ xtime(a ^ b), b ^ total ^ xtime(b ^ c), c ^ total ^ xtime(c ^ d), d ^ total ^ xtime(d ^ a)], index);
                }
            }
            state = next.map((value, index) => value ^ roundKeys[round * 16 + index]);
        }
        return state;
    }

    function multiply128(x, y) {
        let result = 0n;
        for (let bit = 127n; bit >= 0n; --bit) {
            if ((x >> bit) & 1n) result ^= y;
            y = (y >> 1n) ^ ((y & 1n) ? 0xe1000000000000000000000000000000n : 0n);
        }
        return result;
    }

    function ghash(h, aad, ciphertext) {
        let value = 0n;
        for (const data of [aad, ciphertext]) {
            for (let offset = 0; offset < data.length; offset += 16) {
                const block = new Uint8Array(16);
                block.set(data.subarray(offset, offset + 16));
                value = multiply128(value ^ readInteger(block), h);
            }
        }
        const sizes = (BigInt(aad.length) * 8n << 64n) | BigInt(ciphertext.length) * 8n;
        return writeInteger(multiply128(value ^ sizes, h), 16);
    }

    function aesDecrypt(key, nonce, data, aad) {
        const ciphertext = data.subarray(0, -16), tag = data.subarray(-16);
        if (ciphertext.length > (2 ** 32 - 2) * 16 || aad.length >= 2 ** 61) throw new Error('AES-GCM 数据超出长度限制');
        const roundKeys = expandKey(key);
        const h = readInteger(aesBlock(roundKeys, new Uint8Array(16)));
        const counter = new Uint8Array(16);
        counter.set(nonce);
        counter[15] = 1;
        const mask = aesBlock(roundKeys, counter), hash = ghash(h, aad, ciphertext);
        const expected = mask.map((value, index) => value ^ hash[index]);
        if (!equalTag(tag, expected)) throw new Error('密文认证失败');
        const result = new Uint8Array(ciphertext.length);
        const view = new DataView(counter.buffer);
        for (let offset = 0; offset < ciphertext.length; offset += 16) {
            view.setUint32(12, 2 + offset / 16, false);
            const stream = aesBlock(roundKeys, counter);
            for (let index = 0; index < Math.min(16, ciphertext.length - offset); ++index) result[offset + index] = ciphertext[offset + index] ^ stream[index];
        }
        return result;
    }

    function chachaState(key, nonce, counter = 0) {
        const state = new Uint32Array(16);
        state.set([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
        const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
        for (let index = 0; index < 8; ++index) state[4 + index] = keyView.getUint32(4 * index, true);
        const nonceView = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
        if (nonce.length === 16) {
            for (let index = 0; index < 4; ++index) state[12 + index] = nonceView.getUint32(4 * index, true);
        } else {
            state[12] = counter;
            for (let index = 0; index < 3; ++index) state[13 + index] = nonceView.getUint32(4 * index, true);
        }
        return state;
    }

    function quarter(state, a, b, c, d) {
        state[a] += state[b]; state[d] ^= state[a]; state[d] = (state[d] << 16) | (state[d] >>> 16);
        state[c] += state[d]; state[b] ^= state[c]; state[b] = (state[b] << 12) | (state[b] >>> 20);
        state[a] += state[b]; state[d] ^= state[a]; state[d] = (state[d] << 8) | (state[d] >>> 24);
        state[c] += state[d]; state[b] ^= state[c]; state[b] = (state[b] << 7) | (state[b] >>> 25);
    }

    function chachaRounds(state) {
        for (let round = 0; round < 10; ++round) {
            quarter(state, 0, 4, 8, 12); quarter(state, 1, 5, 9, 13);
            quarter(state, 2, 6, 10, 14); quarter(state, 3, 7, 11, 15);
            quarter(state, 0, 5, 10, 15); quarter(state, 1, 6, 11, 12);
            quarter(state, 2, 7, 8, 13); quarter(state, 3, 4, 9, 14);
        }
    }

    function wordsToBytes(words) {
        const result = new Uint8Array(words.length * 4), view = new DataView(result.buffer);
        words.forEach((value, index) => view.setUint32(index * 4, value, true));
        return result;
    }

    function chachaBlock(key, nonce, counter) {
        const state = chachaState(key, nonce, counter), mixed = state.slice();
        chachaRounds(mixed);
        return wordsToBytes(mixed.map((value, index) => value + state[index]));
    }

    function hchacha(key, nonce) {
        const state = chachaState(key, nonce);
        chachaRounds(state);
        return wordsToBytes([...state.subarray(0, 4), ...state.subarray(12)]);
    }

    function poly1305(key, data) {
        const r = readInteger(key.subarray(0, 16), true) & 0x0ffffffc0ffffffc0ffffffc0fffffffn;
        const s = readInteger(key.subarray(16), true);
        let value = 0n;
        for (let offset = 0; offset < data.length; offset += 16) {
            const block = data.subarray(offset, offset + 16);
            const number = readInteger(block, true) | (1n << BigInt(block.length * 8));
            value = ((value + number) * r) % ((1n << 130n) - 5n);
        }
        return writeInteger((value + s) & ((1n << 128n) - 1n), 16, true);
    }

    function chachaDecrypt(key, nonce, data, aad) {
        const ciphertext = data.subarray(0, -16), tag = data.subarray(-16);
        if (ciphertext.length > (2 ** 32 - 1) * 64) throw new Error('ChaCha20 数据超出计数器限制');
        const aadSize = Math.ceil(aad.length / 16) * 16, ciphertextSize = Math.ceil(ciphertext.length / 16) * 16;
        const authenticated = new Uint8Array(aadSize + ciphertextSize + 16);
        authenticated.set(aad);
        authenticated.set(ciphertext, aadSize);
        authenticated.set(writeInteger(BigInt(aad.length), 8, true), aadSize + ciphertextSize);
        authenticated.set(writeInteger(BigInt(ciphertext.length), 8, true), aadSize + ciphertextSize + 8);
        const expected = poly1305(chachaBlock(key, nonce, 0).subarray(0, 32), authenticated);
        if (!equalTag(tag, expected)) throw new Error('密文认证失败');
        const result = new Uint8Array(ciphertext.length);
        for (let offset = 0; offset < ciphertext.length; offset += 64) {
            const stream = chachaBlock(key, nonce, 1 + offset / 64);
            for (let index = 0; index < Math.min(64, ciphertext.length - offset); ++index) result[offset + index] = ciphertext[offset + index] ^ stream[index];
        }
        return result;
    }

    return {decrypt};
})();

globalThis.VaultCiphers = VaultCiphers;
if (typeof module !== 'undefined') module.exports = VaultCiphers;
