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
    const source = fs.readFileSync(path.join(__dirname, 'desktop_clipboard.vault'), 'utf8')
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
    context.VaultProcess = {async decrypt(...args) {
        calls.push({bookCode: args[0], service: args[1].service, master: args[2]});
        return process.decrypt(...args);
    }};
    const ui = elements;
    const defaultCryptoInfo = '加密算法 XCHACHA20-POLY1305 · 内存 64 MiB · 迭代 3 轮 · 并行通道 4';
    const typeMaster = async value => {
        assert(!ui.master.disabled && !ui.master.readOnly);
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

    assert(ui.master.disabled && ui['save-book'].disabled);
    assertPasswordCleared();
    ui.source.value = source;
    await ui.load.click();
    assert(!ui.master.disabled && !ui['save-book'].disabled);
    assert.equal(calls.length, 0, 'Load must not derive keys');
    await ui.entries.children[0].click();
    assert.equal(ui['crypto-info'].textContent, defaultCryptoInfo);
    assert.equal(calls.length, 0, 'Selection must not derive keys');
    await typeMaster('synthetic-wrong-password');
    await ui.decrypt.click();
    assert.equal(calls.length, 1);
    assertPasswordCleared();
    assert(!ui.master.readOnly, 'Failed first attempt must allow correction');
    await typeMaster(fixture.master);
    const pending = ui.decrypt.click();
    assert(ui.master.disabled && ui.source.disabled && ui.lock.disabled && ui['save-book'].disabled);
    await pending;
    assert.equal(calls.length, 2);
    assert.equal(ui.plaintext.value, '••••••••');
    await ui['copy-password'].click();
    assert.equal(ui.plaintext.value, '••••••••', 'Clipboard failure must not reveal a masked password');
    assert.equal(ui.plaintext.selection, undefined);
    assert.match(ui.status.textContent, /显示密码/);
    await showPassword(true);
    assert.equal(ui.plaintext.value, fixture.passwords[0]);
    await showPassword(false);
    assert.equal(ui.plaintext.value, '••••••••');
    await showPassword(true);
    assert(ui.master.readOnly);
    assert(!ui.master.disabled);
    await ui['save-book'].click();
    assert.equal(downloads.length, 1);
    assert.equal(downloads[0].name, '账本.txt');
    assert.equal(downloads[0].blob.type, 'text/plain;charset=utf-8');
    assert.deepEqual(Buffer.from(await downloads[0].blob.arrayBuffer()), Buffer.from(source, 'utf8'));
    await ui.entries.children[1].click();
    assert.equal(calls.length, 2);
    assert.equal(ui.master.value, fixture.master);
    assertPasswordCleared();
    assert(ui.master.readOnly);
    await ui.decrypt.click();
    assert.equal(calls.length, 3);
    assert.equal(ui.plaintext.value, '••••••••');
    const clipboard = [];
    context.navigator.clipboard = {async writeText(value) { clipboard.push(value); }};
    await ui['copy-password'].click();
    assert.deepEqual(clipboard, [fixture.passwords[1]], 'Copy the original multiline string while masked');
    assert.equal(ui.plaintext.value, '••••••••');
    delete context.navigator.clipboard;
    await showPassword(true);
    assert.equal(ui.plaintext.value, fixture.passwords[1]);
    await ui['copy-password'].click();
    assert.deepEqual(ui.plaintext.selection, [0, fixture.passwords[1].length]);
    assert.equal(calls[2].master, calls[1].master);

    // A broken or previously mixed record cannot silently select a different book password.
    vm.runInContext("viewer.book.entries[1].data = viewer.book.entries[1].data.replace(/^./, value => value === 'A' ? 'B' : 'A')", context);
    await ui.decrypt.click();
    assert.equal(calls.length, 4);
    assertPasswordCleared();
    assert.equal(ui.master.value, fixture.master);
    assert(ui.master.readOnly, 'An established session must remain fixed after another entry fails');
    await ui.lock.click();
    assert.equal(ui.master.value, '');
    assertPasswordCleared();
    assert(!ui.master.readOnly);

    ui.source.value = source;
    await ui.load.click();
    await ui.entries.children[2].click();
    await typeMaster(fixture.master);
    await ui.decrypt.click();
    assert.equal(ui.plaintext.value, '••••••••');
    await showPassword(true);
    assert.equal(ui.plaintext.value, fixture.passwords[2]);
    const beforeEdit = calls.length;
    ui.source.value = source + '\n';
    await ui.source.emit('input');
    assert.equal(calls.length, beforeEdit);
    assert.equal(ui.master.value, '');
    assert(!ui.master.readOnly);
    assert(ui.master.disabled && ui.decrypt.disabled && ui['save-book'].disabled);
    assertPasswordCleared();
    await ui.load.click();
    await ui.entries.children[3].click();
    await typeMaster(fixture.master);
    await ui.decrypt.click();
    assert.equal(ui.plaintext.value, '');
    assert.equal(ui['plaintext-state'].textContent, '已解密（密码为空）');
    assert(ui['show-password'].disabled && !ui['copy-password'].disabled);
    assert(ui.master.readOnly);

    // Applying any book, including the same text, clears the previous book session.
    await ui.load.click();
    assert.equal(ui.master.value, '');
    assert(!ui.master.readOnly);
    assertPasswordCleared();
    assert.equal(calls.length, beforeEdit + 1);
    await ui.entries.children[0].click();
    await typeMaster(fixture.master);
    await ui.decrypt.click();
    ui.source.value = '[invalid]';
    await ui.load.click();
    assert.match(ui.status.textContent, /^无法读取粘贴内容。/);
    assert.equal(ui.master.value, '');
    assert(!ui.master.readOnly);
    assertPasswordCleared();
    assert(ui.decrypt.disabled && ui['save-book'].disabled);

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
    assert(!ui.master.readOnly && !ui.master.disabled);
    await ui['save-book'].click();
    assert.equal(downloads.length, 2);
    assert.deepEqual(await downloads[1].blob.arrayBuffer(), await file.arrayBuffer(), 'Keep imported BOM and CRLF bytes');
    await ui.entries.children[0].click();
    assert.equal(ui['crypto-info'].textContent, defaultCryptoInfo);
    await typeMaster(fixture.master);
    await ui.decrypt.click();
    await showPassword(true);
    assert.equal(ui.plaintext.value, fixture.passwords[0]);
    await ui['clear-book'].click();
    assert.equal(ui.master.value, '');
    assertPasswordCleared();
    assert(!ui.master.readOnly && ui.master.disabled && ui['save-book'].disabled);
    ui.source.value = sharedSource;
    await ui.load.click();
    await ui.entries.children[0].click();
    assert.equal(ui['crypto-info'].textContent, defaultCryptoInfo);
    ui.source.value = source;
    await ui.load.click();
    await ui.entries.children[0].click();
    assert.equal(ui['crypto-info'].textContent, defaultCryptoInfo);
    assert.equal(calls.length, 8, 'Only eight explicit single-entry decrypt actions should have run');
    console.log('Shipped HTML session tests passed: format 1/2 display, password concealment and copy, file import and export; eight explicit full-parameter decrypts.');
}

main().catch(error => {console.error(error); process.exitCode = 1;});
