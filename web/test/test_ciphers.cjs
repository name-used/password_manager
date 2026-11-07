'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const VaultCiphers = require('../core/ciphers.js');
const fromHex = value => Uint8Array.from(Buffer.from(value, 'hex'));
const hex = value => Buffer.from(value).toString('hex');

// Independent fixed answers from NIST AES_GCM examples and RFC 8439 / XChaCha draft.
const key = fromHex('feffe9928665731c6d6a8f9467308308'.repeat(2));
const nonce = fromHex('cafebabefacedbaddecaf888');
const plain = 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72' +
              '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255';
const cipher = '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa' +
               '8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad';
const aad = '3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf' +
            '43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4';
for (const [plaintext, associated, encrypted, tag] of [
    ['', '', '', 'fd2caa16a5832e76aa132c1453eeda7e'],
    [plain, '', cipher, 'b094dac5d93471bdec1a502270e3cc6c'],
    ['', aad, '', 'de34b6dcd4cee2fdbec3cea01af1ee44'],
    [plain, aad, cipher, 'c06d76f31930fef37acae23ed465ae62'],
    [plain.slice(0, 120), aad.slice(0, 40), cipher.slice(0, 120), 'e097195f4532da895fb917a5a55c6aa0'],
]) {
    assert.equal(hex(VaultCiphers.decrypt('AES-256-GCM', key, nonce, fromHex(encrypted + tag), fromHex(associated))), plaintext);
}

const chachaKey = Uint8Array.from({length: 32}, (_, index) => 0x80 + index);
const chachaAad = fromHex('50515253c0c1c2c3c4c5c6c7');
const chachaPlain = new TextEncoder().encode("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
const chachaCipher = fromHex(
    'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6' +
    '3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36' +
    '92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc' +
    '3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691');
assert.deepEqual(VaultCiphers.decrypt('CHACHA20-POLY1305', chachaKey, fromHex('070000004041424344454647'), chachaCipher, chachaAad), chachaPlain);
const xchachaCipher = fromHex(
    'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb' +
    '731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452' +
    '2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9' +
    '21f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780acf49');
assert.deepEqual(VaultCiphers.decrypt('XCHACHA20-POLY1305', chachaKey, Uint8Array.from({length: 24}, (_, i) => 0x40 + i),
                                    xchachaCipher, chachaAad), chachaPlain);

const fixtures = JSON.parse(fs.readFileSync(path.join(__dirname, 'cipher_fixtures.json'), 'utf8'));
let rejected = 0;
for (const item of fixtures) {
    const values = ['key', 'nonce', 'data', 'aad'].map(name => fromHex(item[name]));
    const original = values.map(value => value.slice());
    assert.equal(hex(VaultCiphers.decrypt(item.algorithm, ...values)), item.plaintext);
    values.forEach((value, index) => assert.deepEqual(value, original[index]));
    // Views with nonzero offsets ensure DataView never reads the surrounding buffer.
    const views = values.map(value => { const buffer = new Uint8Array(value.length + 7); buffer.set(value, 3); return buffer.subarray(3, 3 + value.length); });
    assert.equal(hex(VaultCiphers.decrypt(item.algorithm, ...views)), item.plaintext);
    if (item.plaintext.length > 512) continue;
    for (let changedIndex = 0; changedIndex < 4; ++changedIndex) {
        const changed = values.map(value => value.slice());
        if (changed[changedIndex].length) changed[changedIndex][0] ^= 1;
        else changed[changedIndex] = Uint8Array.of(1);
        assert.throws(() => VaultCiphers.decrypt(item.algorithm, ...changed));
        ++rejected;
    }
    const tampered = values.map(value => value.slice());
    tampered[2][tampered[2].length - 1] ^= 1;
    assert.throws(() => VaultCiphers.decrypt(item.algorithm, ...tampered));
    ++rejected;
}
for (const algorithm of ['AES-256-GCM', 'CHACHA20-POLY1305', 'XCHACHA20-POLY1305']) {
    const nonceSize = algorithm.startsWith('X') ? 24 : 12;
    for (const length of [0, 16, 24, 31, 33]) {
        assert.throws(() => VaultCiphers.decrypt(algorithm, new Uint8Array(length), new Uint8Array(nonceSize), new Uint8Array(16)));
    }
    for (const length of [0, nonceSize - 1, nonceSize + 1]) {
        assert.throws(() => VaultCiphers.decrypt(algorithm, new Uint8Array(32), new Uint8Array(length), new Uint8Array(16)));
    }
    for (let length = 0; length < 16; ++length) {
        assert.throws(() => VaultCiphers.decrypt(algorithm, new Uint8Array(32), new Uint8Array(nonceSize), new Uint8Array(length)));
    }
}
assert.throws(() => VaultCiphers.decrypt('UNKNOWN', new Uint8Array(32), new Uint8Array(12), new Uint8Array(16)));
assert.throws(() => VaultCiphers.decrypt('AES-256-GCM', [], new Uint8Array(12), new Uint8Array(16)));
console.log(`PASS: 7 published AEAD vectors; ${fixtures.length} Python cross-checks plus offset-view repeats; ${rejected} tampering cases rejected; invalid inputs rejected.`);
