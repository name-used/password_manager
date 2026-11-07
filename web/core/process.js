/* One explicit decrypt call performs one Argon2 derivation. No network, storage, master-password or key cache. */
'use strict';

globalThis.VaultProcess = (() => {
    async function decrypt(bookCode, entry, master) {
        const text = globalThis.VaultText;
        text.validateCode(bookCode);
        text.validateEntry(entry);
        const {algorithm, memory_kib, iterations, lanes} = entry;
        if (typeof master !== 'string' || !master) throw new Error('请输入管理密码');
        // TextEncoder replaces isolated UTF-16 surrogates; Python's UTF-8 encoder rejects them.
        for (let index = 0; index < master.length; ++index) {
            const value = master.charCodeAt(index);
            if (value >= 0xD800 && value <= 0xDBFF) {
                const next = master.charCodeAt(++index);
                if (!(next >= 0xDC00 && next <= 0xDFFF)) throw new Error('管理密码含有无效字符，请重新输入。');
            } else if (value >= 0xDC00 && value <= 0xDFFF) {
                throw new Error('管理密码含有无效字符，请重新输入。');
            }
        }
        if (!entry.data) throw new Error('这条还没有加密密码。请在桌面管理端保存条目密码。');
        const nonceLength = algorithm === 'XCHACHA20-POLY1305' ? 24 : 12;
        const data = text.base64Bytes(entry.data);
        if (data.length < nonceLength + 16 + 18 || data.length > nonceLength + 16 + 18 + 65535) {
            throw new Error('条目的密码密文长度不正确。请检查账本内容是否完整。');
        }
        if (memory_kib >= 131072) throw new Error('这个条目无法在网页查看器的 128 MiB 内存上限内解密。请使用桌面管理端。');
        if (typeof globalThis.VaultCiphers?.decrypt !== 'function') throw new Error('解密组件未加载。请重新打开查看器。');
        if (typeof globalThis.VAULT_WASM_BASE64 !== 'string' || !globalThis.VAULT_WASM_BASE64) throw new Error('密钥计算组件未加载。请重新打开查看器。');
        const password = new TextEncoder().encode(master);
        const salt = Uint8Array.from(entry.salt.match(/../g), value => parseInt(value, 16));
        const binary = text.base64Bytes(globalThis.VAULT_WASM_BASE64);
        const {instance} = await WebAssembly.instantiate(binary, {});
        const core = instance.exports;
        const buffers = [];
        let key;
        function put(bytes) {
            const pointer = core.malloc(Math.max(1, bytes.length));
            if (!pointer) throw new Error('浏览器内存不足。请尝试在桌面管理端解密。');
            buffers.push(pointer);
            new Uint8Array(core.memory.buffer, pointer, bytes.length).set(bytes);
            return pointer;
        }
        try {
            const p = put(password), s = put(salt), output = put(new Uint8Array(32));
            const status = core.vault_argon2id(p, password.length, s, salt.length, memory_kib, iterations, lanes, output, 32, 0, 0, 0, 0);
            if (status === 1) throw new Error('条目的加密参数无效。请核对账本内容。');
            if (status === 2) throw new Error('浏览器无法分配解密所需的内存。请使用桌面管理端。');
            if (status !== 0) throw new Error(`密钥计算失败（错误代码 ${status}）。`);
            // The call may grow memory; copy the result from a new view before releasing the buffers.
            key = new Uint8Array(core.memory.buffer, output, 32).slice();
            let plaintext;
            try {
                plaintext = globalThis.VaultCiphers.decrypt(algorithm, key, data.subarray(0, nonceLength), data.subarray(nonceLength));
            } catch (error) {
                throw new Error('管理密码错误，或条目的密码密文、随机码或加密参数已更改。请核对管理密码和账本内容。');
            }
            if (plaintext.length < 18) throw new Error('解密后的密码数据长度不正确。');
            // 格式 1 前缀仅用于兼容既有密文，条目可在任意账本读取。
            const length = plaintext[16] * 256 + plaintext[17];
            if (plaintext.length !== 18 + length) throw new Error('解密后的密码数据长度不正确。');
            try {
                return new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(plaintext.subarray(18));
            } catch (error) {
                throw new Error('解密后的条目密码不是有效的 UTF-8 文本。');
            }
        } finally {
            for (const pointer of buffers) core.free(pointer);
            password.fill(0);
            if (key) key.fill(0);
        }
    }

    return {decrypt};
})();

if (typeof module !== 'undefined') module.exports = globalThis.VaultProcess;
