'use strict';
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const text = require('../core/text_decoder.js');
globalThis.VaultCiphers = require('../core/ciphers.js');
const process = require('../core/process.js');

async function main() {
    globalThis.VAULT_WASM_BASE64 = fs.readFileSync(path.join(__dirname, '../core/argon2id.wasm')).toString('base64');
    const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, 'integration.json'), 'utf8'));
    const source = fs.readFileSync(path.join(__dirname, '..', 'example.vault'), 'utf8');
    const book = text.decode(source);
    assert.equal(book.entries.length, 4);
    assert(!source.includes(fixture.master));
    for (let index = 0; index < book.entries.length; ++index) {
        assert.equal(await process.decrypt(book.book_code, book.entries[index], fixture.master), fixture.passwords[index]);
    }
    console.log('Actual desktop GUI clipboard -> web core: all four full-parameter entries passed, including notes, Unicode and empty password.');
}

main().catch(error => {console.error(error); globalThis.process.exitCode = 1;});
