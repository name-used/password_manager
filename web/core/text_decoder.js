/* Read the same public ledger formats as the desktop application. No cryptographic work here. */
'use strict';

globalThis.VaultText = (() => {
    const sharedNumberFields = {'内存KiB': 'memory_kib', '迭代次数': 'iterations'};
    const sharedLabels = Object.keys(sharedNumberFields);
    const numberFields = {...sharedNumberFields, '并行通道': 'lanes'};
    const fields = {
        '服务名': 'service', '应用地址': 'addresses', '服务编码': 'code', '用户名': 'username', '昵称': 'nickname',
        '加密算法': 'algorithm', ...numberFields, '随机码': 'salt', '密码密文': 'data',
    };
    const entryLabels = [...Object.keys(fields), '密码规则', '可用符号'];
    const sharedEntryLabels = entryLabels.filter(label => !sharedLabels.includes(label));
    const bookLabels = ['格式', '校验码'];
    const sharedBookLabels = [...bookLabels, ...sharedLabels];
    const verifierBookLabels = ['格式', '校验样本'];
    const entryKeys = [...Object.values(fields), 'rules'];
    const textKeys = ['service', 'addresses', 'code', 'username', 'nickname', 'algorithm', 'salt', 'data'];
    const algorithms = ['AES-256-GCM', 'CHACHA20-POLY1305', 'XCHACHA20-POLY1305'];

    function decode(text) {
        if (typeof text !== 'string') throw new Error('请提供账本文本。');
        const sections = [];
        let current = null;
        const lines = text.replace(/^\uFEFF/, '').split('\n');
        for (let index = 0; index < lines.length; ++index) {
            const line = lines[index].replace(/\r$/, '');
            if (!line.trim()) continue;
            if (line === '[账本]' || line === '[条目]') {
                current = {type: line, fields: new Map(), line: index + 1};
                sections.push(current);
                continue;
            }
            if (!current) throw new Error(`第 ${index + 1} 行的字段前缺少 [账本] 或 [条目]。`);
            const separator = line.indexOf('：');
            if (separator < 0) throw new Error(`第 ${index + 1} 行缺少中文冒号（：）。请用中文冒号分隔字段名和内容。`);
            const label = line.slice(0, separator);
            const allowed = current.type === '[账本]' ? [...sharedBookLabels, '校验样本'] : [...entryLabels, '备注'];
            if (!allowed.includes(label)) throw new Error(`第 ${index + 1} 行有无法识别的字段“${label}”。`);
            if (current.fields.has(label)) throw new Error(`第 ${index + 1} 行的字段“${label}”重复。`);
            try {
                current.fields.set(label, unescape(line.slice(separator + 1)));
            } catch (error) {
                throw new Error(`请检查第 ${index + 1} 行。${error.message}`);
            }
        }
        if (!sections.length || sections[0].type !== '[账本]' || sections.slice(1).some(section => section.type === '[账本]')) {
            throw new Error('账本应以 [账本] 段开头，全文只能有一个 [账本] 段。请检查账本内容是否完整。');
        }
        const format = sections[0].fields.get('格式');
        if (format !== undefined && !['1', '2', '3'].includes(format)) throw new Error('此查看器只支持格式 1、2 和 3 的账本。');
        const shared = format === '2';
        const headerLabels = format === '3' ? verifierBookLabels : shared ? sharedBookLabels : bookLabels;
        const book = {version: Number(format ?? 1), book_code: '', entries: []};
        for (const section of sections) {
            const values = section.fields;
            const isHeader = section.type === '[账本]';
            const expected = isHeader ? headerLabels : shared ? sharedEntryLabels : entryLabels;
            const missing = expected.filter(label => !values.has(label));
            if (missing.length) throw new Error(`从第 ${section.line} 行开始的段落缺少字段 ${missing.map(label => `“${label}”`).join('、')}。`);
            const misplaced = [...values.keys()].find(label => !expected.includes(label) && label !== '备注');
            if (misplaced) throw new Error(`格式 ${book.version} 的 ${section.type} 段不能包含“${misplaced}”字段。请检查第 ${section.line} 行。`);
            try {
                if (isHeader) {
                    if (book.version === 3) {
                        book.book_code = '0'.repeat(32);
                        book.verifier = readVerifier(values.get('校验样本'));
                    } else {
                        book.book_code = values.get('校验码');
                        validateCode(book.book_code);
                    }
                    if (shared) {
                        for (const [label, key] of Object.entries(sharedNumberFields)) book[key] = readNumber(label, values.get(label));
                        validateCosts(book.memory_kib, book.iterations);
                    }
                } else {
                    const entry = shared ? {memory_kib: book.memory_kib, iterations: book.iterations} : {};
                    for (const [label, key] of Object.entries(fields)) {
                        if (values.has(label)) entry[key] = values.get(label);
                    }
                    if (values.has('备注')) entry.notes = values.get('备注');
                    for (const [label, key] of Object.entries(numberFields)) {
                        if (values.has(label)) entry[key] = readNumber(label, entry[key]);
                    }
                    const match = /^长度>=([0-9]+);类别>=([0-9]+);字符=([ULDS]+)$/.exec(values.get('密码规则'));
                    if (!match || match[0] !== values.get('密码规则')) throw new Error('“密码规则”格式不正确。请参照“长度>=8;类别>=3;字符=ULDS”。');
                    entry.rules = {length: Number(match[1]), categories: Number(match[2]), allowed: match[3], symbols: values.get('可用符号')};
                    validateEntry(entry);
                    book.entries.push(entry);
                }
            } catch (error) {
                throw new Error(`请检查从第 ${section.line} 行开始的段落。${error.message}`);
            }
        }
        return book;
    }

    function readNumber(label, value) {
        if (!value || /[^0-9]/.test(value)) throw new Error(`“${label}”应填写整数，只能包含数字 0 到 9。`);
        return Number(value);
    }

    function validateCode(value) {
        if (typeof value !== 'string' || value.length !== 32 || !/^[0-9a-fA-F]{32}$/.test(value)) {
            throw new Error('“校验码”必须是 32 个十六进制字符（0–9、A–F，不区分大小写）。');
        }
    }

    function validateCosts(memoryKib, iterations, lanes = 1) {
        const minimumMemory = 8 * lanes;
        if (!Number.isInteger(memoryKib) || memoryKib < minimumMemory || memoryKib >= 2 ** 32) {
            throw new Error(`“内存KiB”必须是 ${minimumMemory} 到 4294967295 之间的整数。`);
        }
        if (!Number.isInteger(iterations) || iterations < 1 || iterations >= 2 ** 32) throw new Error('“迭代次数”必须是 1 到 4294967295 之间的整数。');
    }

    function validateEncryptionParameters({algorithm, memory_kib, iterations, lanes}) {
        if (!algorithms.includes(algorithm)) throw new Error(`此查看器不支持加密算法“${algorithm}”。`);
        if (!Number.isInteger(lanes) || lanes < 1 || lanes >= 2 ** 24) throw new Error('“并行通道”必须是 1 到 16777215 之间的整数。');
        validateCosts(memory_kib, iterations, lanes);
    }

    function validateSalt(value) {
        if (typeof value !== 'string' || value.length !== 32 || !/^[0-9a-fA-F]{32}$/.test(value)) {
            throw new Error('“随机码”必须是 32 个十六进制字符（0–9、A–F，不区分大小写）。');
        }
    }

    function readVerifier(value) {
        const parts = value.split(',');
        if (parts.length !== 6) throw new Error('“校验样本”应包含算法、内存、迭代次数、并行通道、随机码和密文。');
        const [algorithm, memory, iterations, lanes, salt, data] = parts;
        const verifier = {algorithm, memory_kib: readNumber('内存KiB', memory), iterations: readNumber('迭代次数', iterations),
                          lanes: readNumber('并行通道', lanes), salt, data};
        validateVerifier(verifier);
        return verifier;
    }

    function validateVerifier(verifier) {
        if (!verifier || Object.keys(verifier).length !== 6 ||
            ['algorithm', 'memory_kib', 'iterations', 'lanes', 'salt', 'data'].some(key => !Object.prototype.hasOwnProperty.call(verifier, key))) {
            throw new Error('“校验样本”缺少所需字段。');
        }
        validateEncryptionParameters(verifier);
        validateSalt(verifier.salt);
        const nonceLength = verifier.algorithm === 'XCHACHA20-POLY1305' ? 24 : 12;
        if (base64Bytes(verifier.data).length !== nonceLength + 34) throw new Error('“校验样本”的密文长度不正确。');
    }

    function validateEntry(entry) {
        if (!entry || typeof entry !== 'object' || Array.isArray(entry) || entryKeys.some(key => !Object.prototype.hasOwnProperty.call(entry, key)) ||
            Object.keys(entry).some(key => !entryKeys.includes(key) && key !== 'notes')) {
            throw new Error('条目缺少必填字段，或包含无法识别的字段。请勿在账本中添加密码明文。');
        }
        if (textKeys.some(key => typeof entry[key] !== 'string') || (Object.prototype.hasOwnProperty.call(entry, 'notes') && typeof entry.notes !== 'string')) {
            throw new Error('服务资料、备注、加密算法、随机码和密码密文都应填写为文本。');
        }
        validateEncryptionParameters(entry);
        const rules = entry.rules;
        if (!rules || typeof rules !== 'object' || Array.isArray(rules) || Object.keys(rules).length !== 4 ||
            ['length', 'categories', 'allowed', 'symbols'].some(key => !Object.prototype.hasOwnProperty.call(rules, key))) {
            throw new Error('密码生成规则不完整。请核对最短长度、字符类型数量、可用类型和符号。');
        }
        if (typeof rules.allowed !== 'string' || !rules.allowed || /[^ULDS]/.test(rules.allowed) || new Set(rules.allowed).size !== rules.allowed.length) {
            throw new Error('可用字符类型应从 U、L、D、S 中至少选一种，且不能重复。');
        }
        if (!Number.isInteger(rules.length) || rules.length < 1 || rules.length > 65535) throw new Error('密码的最短长度必须是 1 到 65535 之间的整数。');
        if (!Number.isInteger(rules.categories) || rules.categories < 1 || rules.categories > rules.allowed.length) {
            throw new Error('密码至少要包含一种字符类型，所填的数量不能超过可用类型数。');
        }
        if (typeof rules.symbols !== 'string' || [...rules.symbols].some(char => char.charCodeAt(0) < 33 || char.charCodeAt(0) > 126 || /[A-Za-z0-9]/.test(char))) {
            throw new Error('可用符号只能包含半角标点或符号，不能包含字母、数字或空格。');
        }
        if (new Set(rules.symbols).size !== rules.symbols.length || (rules.allowed.includes('S') && !rules.symbols)) {
            throw new Error('可用符号不能重复。启用符号类型时，至少填写一个可用符号。');
        }
        if (Boolean(entry.salt) !== Boolean(entry.data)) throw new Error('已加密条目需要同时填写随机码和密码密文。未加密条目的这两个字段都应留空。');
        if (entry.salt) {
            validateSalt(entry.salt);
            base64Bytes(entry.data);
        }
    }

    function base64Bytes(value) {
        if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
            throw new Error('密码密文格式不正确。请检查密码密文是否完整。');
        }
        const bytes = atob(value);
        if (btoa(bytes) !== value) throw new Error('密码密文不是规范的 Base64 文本。请检查账本内容是否完整。');
        return Uint8Array.from(bytes, char => char.charCodeAt(0));
    }

    function unescape(value) {
        const escapes = {'\\': '\\', n: '\n', r: '\r', t: '\t'};
        let result = '';
        for (let index = 0; index < value.length; ++index) {
            let char = value[index];
            if (char === '\\') {
                ++index;
                if (index === value.length || !Object.prototype.hasOwnProperty.call(escapes, value[index])) throw new Error('反斜线后只能接另一个反斜线、n、r 或 t。');
                char = escapes[value[index]];
            } else if (char === '\r' || char === '\t') {
                throw new Error('字段中的回车和制表符请分别写作 \\r 和 \\t。');
            }
            result += char;
        }
        return result;
    }

    return {decode, validateCode, validateEntry, validateVerifier, base64Bytes};
})();

if (typeof module !== 'undefined') module.exports = globalThis.VaultText;
