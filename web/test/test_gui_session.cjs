'use strict';
// Executes the shipped HTML and real Wasm with a small DOM substitute; does not launch a browser.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {performance} = require('node:perf_hooks');

class Element {
    constructor(tagName = 'div') {
        this.tagName = tagName;
        this.value = '';
        this.textContent = '';
        this.disabled = false;
        this.readOnly = false;
        this.checked = false;
        this.hidden = false;
        this.type = 'password';
        this.children = [];
        this.dataset = {};
        this.listeners = {};
        this.files = [];
        this.classList = {toggle() {}};
    }
    addEventListener(name, callback) { (this.listeners[name] ||= []).push(callback); }
    async emit(name, event = {}) {
        if (name === 'click' && this.disabled) return;
        await Promise.all((this.listeners[name] || []).map(callback => callback(event)));
    }
    setAttribute() {}
    append(...children) { this.children.push(...children); }
    remove() {}
    replaceChildren(...children) { this.children = children; }
    querySelectorAll(tagName) {
        return this.children.flatMap(child => [ ...(child.tagName === tagName ? [child] : []), ...child.querySelectorAll(tagName)]);
    }
    focus() {}
    select() {}
    setSelectionRange(start, end) { this.selection = [start, end]; }
    click() { return this.emit('click'); }
}

async function main() {
    const root = path.join(__dirname, '..');
    const html = fs.readFileSync(path.join(root, '..', 'password_viewer.html'), 'utf8');
    const template = fs.readFileSync(path.join(root, 'page.template.html'), 'utf8');
    // Exercise the shipped viewer after the encrypted entries have been copied to another book.
    const source = fs.readFileSync(path.join(__dirname, '..', 'example.vault'), 'utf8')
        .replace(/^校验码：[0-9a-f]{32}/im, '校验码：' + 'b2'.repeat(16));
    const sharedSource = source.replace(/^(?:内存KiB|迭代次数)：[^\r\n]*\r?\n/gm, '')
        .replace('格式：1', '格式：2\n内存KiB：65536\n迭代次数：3');
    const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, 'integration.json'), 'utf8'));
    const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]);
    assert.equal(ids.length, new Set(ids).size, 'HTML IDs must remain unique');
    assert(!ids.includes('book-kdf'), 'Encryption parameters belong to each entry detail');
    assert(template.indexOf('id="master"') < template.indexOf('class="workspace"'), 'Master input belongs to the book panel');
    assert(!html.includes('__GUI_SOURCE__'));
    const elements = Object.fromEntries(ids.map(id => [id, new Element()]));
    const downloads = [];
    let downloadBlob;
    const context = vm.createContext({
        document: {
            getElementById(id) { assert(id in elements, `Missing element: ${id}`); return elements[id]; },
            createElement(tagName) { return new Element(tagName); },
            body: {append(link) {
                link.addEventListener('click', () => downloads.push({name: link.download, blob: downloadBlob}));
            }},
        },
        Blob,
        URL: {
            createObjectURL(blob) { downloadBlob = blob; return 'blob:synthetic'; },
            revokeObjectURL() {},
        },
        navigator: {}, performance, setTimeout, confirm: () => true,
        TextEncoder, TextDecoder, Uint8Array, Uint32Array, ArrayBuffer, DataView, WebAssembly, atob, btoa,
    });
    const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
    vm.runInContext(script, context, {filename: 'password_viewer.html'});
    const process = context.VaultProcess;
    const calls = [];
    context.VaultProcess = {
        async verify(...args) {
            calls.push('verify');
            return process.verify(...args);
        },
        async decrypt(...args) {
            calls.push('decrypt');
            return process.decrypt(...args);
        },
    };
    const ui = elements;
    assert(!ids.includes('lock'));
    assert(template.indexOf('id="plaintext"') < template.indexOf('id="metadata"'), 'Password comes before public details');
    const verifierHeader = fs.readFileSync(path.join(__dirname, 'verifier.vault'), 'utf8');
    const verifiedSource = verifierHeader + '\n' + source.slice(source.indexOf('[条目]'));
    const typeMaster = async value => {
        assert(!ui.master.disabled && !ui['master-form'].hidden);
        ui.master.value = value;
        await ui.master.emit('input');
    };
    const showPassword = async checked => {
        assert(!ui['show-password'].disabled);
        ui['show-password'].checked = checked;
        await ui['show-password'].emit('change');
    };
    const assertPasswordCleared = () => {
        assert.equal(ui.plaintext.value, '');
        assert(!ui['show-password'].checked && ui['show-password'].disabled && ui['copy-password'].disabled);
    };
    const assertEntryCosts = () => {
        assert.equal(ui['crypto-info'].textContent, '加密算法 XCHACHA20-POLY1305 · 内存 64 MiB · 迭代 3 轮 · 并行通道 4');
    };

    assert(ui.master.disabled && ui.verify.disabled && ui['save-book'].disabled);
    assertPasswordCleared();
    ui.source.value = verifiedSource;
    await ui.load.click();
    assert(!ui.master.disabled && !ui['save-book'].disabled);
    await ui.entries.children[0].click();
    assert.deepEqual(calls, [], 'Reading and selecting before validation must not derive any keys');
    assert(!ui['public-details'].open);
    assertEntryCosts();

    await typeMaster('synthetic-wrong-password');
    await ui.verify.click();
    assert.deepEqual(calls, ['verify']);
    assert(!ui['master-form'].hidden && !ui.master.disabled);
    assertPasswordCleared();
    assert.match(ui.status.textContent, /管理密码验证失败/);

    await typeMaster(fixture.master);
    const pending = ui.verify.click();
    assert(ui.master.disabled && ui.source.disabled && ui.verify.disabled && ui['save-book'].disabled);
    await pending;
    assert.deepEqual(calls, ['verify', 'verify', 'decrypt'], 'Verify once, then decrypt the selected entry only');
    assert(ui['master-panel'].hidden && ui['master-form'].hidden && ui['change-master'].hidden);
    assert.equal(ui.plaintext.value, '••••••••');
    await ui['copy-password'].click();
    assert.equal(ui.plaintext.value, '••••••••', 'Clipboard failure must not reveal a masked password');
    assert.equal(ui.plaintext.selection, undefined);
    assert.match(ui.status.textContent, /显示密码/);
    await showPassword(true);
    assert.equal(ui.plaintext.value, fixture.passwords[0]);
    await showPassword(false);
    assert.equal(ui.plaintext.value, '••••••••');

    ui['public-details'].open = true;
    await ui.entries.children[1].click();
    assert.equal(calls.at(-1), 'decrypt');
    assert.equal(calls.length, 4);
    assert(!ui['public-details'].open && !ui['show-password'].checked);
    const clipboard = [];
    context.navigator.clipboard = {async writeText(value) { clipboard.push(value); }};
    await ui['copy-password'].click();
    assert.deepEqual(clipboard, [fixture.passwords[1]], 'Copy the original multiline string while masked');
    assert.equal(ui.plaintext.value, '••••••••');
    delete context.navigator.clipboard;
    await showPassword(true);
    await ui['copy-password'].click();
    assert.deepEqual(ui.plaintext.selection, [0, fixture.passwords[1].length]);

    const originalData = vm.runInContext('viewer.book.entries[2].data', context);
    vm.runInContext("viewer.book.entries[2].data = viewer.book.entries[2].data.replace(/^./, value => value === 'A' ? 'B' : 'A')", context);
    await ui.entries.children[2].click();
    assert(ui['master-form'].hidden);
    assertPasswordCleared();
    assert.match(ui.status.textContent, /^条目校验失败/);
    assert(!ui.retry.hidden && !ui.retry.disabled);
    vm.runInContext('viewer.book.entries[2].data = ' + JSON.stringify(originalData), context);
    await ui.retry.click();
    assert(ui.retry.hidden);
    await showPassword(true);
    assert.equal(ui.plaintext.value, fixture.passwords[2]);

    await ui['save-book'].click();
    assert.equal(downloads[0].name, '账本.txt');
    assert.equal(downloads[0].blob.type, 'text/plain;charset=utf-8');
    assert.deepEqual(Buffer.from(await downloads[0].blob.arrayBuffer()), Buffer.from(verifiedSource, 'utf8'));

    ui.source.value = source;
    await ui.source.emit('input');
    assert.equal(ui.master.value, '');
    assert(!ui['master-form'].hidden && ui.master.disabled && ui['save-book'].disabled);
    assertPasswordCleared();
    await ui.load.click();
    const beforeLegacy = calls.length;
    await typeMaster(fixture.master);
    await ui.verify.click();
    assert.deepEqual(calls.slice(beforeLegacy), ['decrypt']);
    assert(!ui['master-panel'].hidden && ui['master-form'].hidden && !ui['change-master'].hidden);
    assertPasswordCleared();
    await ui.entries.children[3].click();
    assert.equal(ui.plaintext.value, '');
    assert.equal(ui['plaintext-state'].textContent, '已解密（密码为空）');
    assert(!ui['copy-password'].disabled);
    await ui['change-master'].click();
    assert.equal(ui.master.value, '');
    assert(!ui['master-form'].hidden);
    assertPasswordCleared();

    await ui.entries.children[1].click();
    await typeMaster(fixture.master);
    const selectedLegacy = calls.length;
    await ui.verify.click();
    assert.deepEqual(calls.slice(selectedLegacy), ['decrypt'], 'Reuse authenticated plaintext for selected legacy entry');
    await showPassword(true);
    assert.equal(ui.plaintext.value, fixture.passwords[1]);

    ui.source.value = '[invalid]';
    await ui.load.click();
    assert.match(ui.status.textContent, /^无法读取粘贴内容。/);
    assert(!ui['master-form'].hidden && ui.master.disabled && ui['save-book'].disabled);
    assertPasswordCleared();
    ui.file.files = [new Blob(['[invalid]'])];
    await ui.file.emit('change');
    assert.match(ui.status.textContent, /^无法读取账本文件内容。/);
    ui.file.files = [{async arrayBuffer() { throw new Error('unavailable'); }}];
    await ui.file.emit('change');
    assert.match(ui.status.textContent, /^无法打开所选文件。/);

    const file = new Blob(['\uFEFF', sharedSource.replace(/^\uFEFF/, '').replace(/\r?\n/g, '\r\n')]);
    ui.file.files = [file];
    await ui.file.emit('change');
    assert.equal(ui.master.value, '');
    await ui['save-book'].click();
    assert.deepEqual(await downloads[1].blob.arrayBuffer(), await file.arrayBuffer(), 'Keep imported BOM and CRLF bytes');
    await ui.entries.children[0].click();
    assertEntryCosts();
    await typeMaster(fixture.master);
    await ui.verify.click();
    await showPassword(true);
    assert.equal(ui.plaintext.value, fixture.passwords[0]);
    await ui['clear-book'].click();
    assert.equal(ui.master.value, '');
    assert(!ui['master-form'].hidden && ui.master.disabled && ui['save-book'].disabled);
    assertPasswordCleared();

    // An independent verifier also works in an empty book without decrypting an entry.
    ui.source.value = verifierHeader;
    await ui.load.click();
    await typeMaster(fixture.master);
    const beforeEmpty = calls.length;
    await ui.verify.click();
    assert.deepEqual(calls.slice(beforeEmpty), ['verify']);
    assert(ui['master-form'].hidden);
    assertPasswordCleared();
    console.log('Shipped HTML session tests passed: verifier and legacy flows, automatic selected-entry decryption, masking, and byte-preserving downloads.');
}

main().catch(error => {console.error(error); process.exitCode = 1;});
