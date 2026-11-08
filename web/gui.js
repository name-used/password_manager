'use strict';

const viewer = {book: null, index: null, loadedText: '', fileBytes: null, busy: false, plaintext: null, verified: false};
const ui = Object.fromEntries(['source-panel', 'source', 'load', 'open', 'save-book', 'clear-book', 'file', 'search', 'count', 'entries', 'no-selection',
    'detail', 'detail-title', 'detail-user', 'entry-state', 'public-details', 'metadata', 'crypto-info', 'master-panel', 'master-form', 'master',
    'show-master', 'verify', 'change-master', 'plaintext', 'plaintext-state', 'show-password', 'copy-password', 'retry', 'master-state',
    'status'].map(id => [id, document.getElementById(id)]));

function showStatus(message, error = false) {
    ui.status.textContent = message;
    ui.status.classList.toggle('error', error);
}

function renderPlaintext() {
    const password = viewer.plaintext ?? '';
    ui.plaintext.value = password && !ui['show-password'].checked ? '••••••••' : password;
}

function clearPlaintext(clearMaster = false) {
    viewer.plaintext = null;
    ui['show-password'].checked = false;
    renderPlaintext();
    ui['plaintext-state'].textContent = '未解密';
    if (clearMaster) {
        viewer.verified = false;
        ui.master.value = '';
        ui.master.type = 'password';
        ui['show-master'].checked = false;
    }
    refreshControls();
}

function refreshControls() {
    const loaded = viewer.book && ui.source.value === viewer.loadedText;
    for (const name of ['source', 'load', 'open', 'clear-book', 'file', 'change-master', 'retry']) ui[name].disabled = viewer.busy;
    ui.master.disabled = viewer.busy || !loaded;
    ui['save-book'].disabled = viewer.busy || !loaded;
    ui['master-panel'].hidden = viewer.verified && Boolean(viewer.book?.verifier);
    ui['master-form'].hidden = viewer.verified;
    ui['show-master'].disabled = ui.master.disabled;
    ui.verify.disabled = ui.master.disabled || viewer.verified || !ui.master.value || !verificationSample();
    ui['change-master'].hidden = !viewer.verified || Boolean(viewer.book?.verifier);
    ui['master-state'].textContent = viewer.verified ? '管理密码已验证。' : '';
    ui.search.disabled = viewer.busy || !loaded;
    ui['show-password'].disabled = viewer.busy || !viewer.plaintext;
    ui['copy-password'].disabled = viewer.busy || viewer.plaintext === null;
    ui.retry.hidden = !loaded || !viewer.verified || !selectedEntry()?.data || viewer.plaintext !== null;
    for (const button of ui.entries.querySelectorAll('button')) button.disabled = viewer.busy || !loaded;
}

function selectedEntry() {
    return viewer.book && viewer.index !== null ? viewer.book.entries[viewer.index] : null;
}

function verificationSample() {
    if (!viewer.book) return null;
    const entry = selectedEntry();
    return viewer.book.verifier ?? (entry?.data ? entry : viewer.book.entries.find(item => item.data));
}

function renderEntries() {
    ui.entries.replaceChildren();
    if (!viewer.book) {
        const placeholder = document.createElement('div');
        placeholder.className = 'empty';
        placeholder.textContent = '请打开账本文件，或粘贴账本文本。';
        ui.entries.append(placeholder);
        ui.count.textContent = '未读取账本';
        return;
    }
    const query = ui.search.value.toLocaleLowerCase();
    let count = 0;
    viewer.book.entries.forEach((entry, index) => {
        const searchable = [entry.service, entry.username, entry.addresses, entry.code, entry.nickname, entry.notes || ''].join(' ').toLocaleLowerCase();
        if (!searchable.includes(query)) return;
        ++count;
        const button = document.createElement('button');
        button.className = `entry${viewer.index === index ? ' selected' : ''}`;
        button.dataset.index = String(index);
        button.setAttribute('aria-pressed', String(viewer.index === index));
        const name = document.createElement('strong'), user = document.createElement('span');
        name.textContent = entry.service || '未命名服务';
        user.textContent = entry.username || '未填写用户名';
        button.append(name, user);
        button.addEventListener('click', () => selectEntry(index));
        ui.entries.append(button);
    });
    ui.count.textContent = `显示 ${count} / ${viewer.book.entries.length} 条`;
    if (!count) {
        const empty = document.createElement('div');
        empty.className = 'empty';
        empty.textContent = viewer.book.entries.length ? '没有匹配的条目。' : '账本中没有条目。';
        ui.entries.append(empty);
    }
    refreshControls();
}

function selectEntry(index) {
    if (viewer.busy || ui.source.value !== viewer.loadedText) return;
    viewer.index = index;
    clearPlaintext();
    const entry = viewer.book.entries[index];
    ui['no-selection'].hidden = true;
    ui.detail.hidden = false;
    ui['detail-title'].textContent = entry.service || '未命名服务';
    ui['detail-user'].textContent = entry.username || '未填写用户名';
    ui['entry-state'].textContent = entry.data ? '已加密' : '未加密';
    ui['public-details'].open = false;
    ui.metadata.replaceChildren();
    const groups = {U: '大写字母', L: '小写字母', D: '数字', S: '符号'};
    const rules = `至少 ${entry.rules.length} 个字符，包含下列字符类型中的至少 ${entry.rules.categories} 种（${Array.from(entry.rules.allowed, item => groups[item]).join('、')}）`;
    for (const [name, value] of [['用户名', entry.username], ['昵称', entry.nickname], ['应用地址', entry.addresses], ['服务编码', entry.code],
                               ['密码生成规则', rules], ['可用符号', entry.rules.symbols], ['公开备注', entry.notes || '']]) {
        const label = document.createElement('dt'), content = document.createElement('dd');
        label.textContent = name;
        content.textContent = value || '—';
        ui.metadata.append(label, content);
    }
    ui['crypto-info'].textContent = `加密算法 ${entry.algorithm} · 内存 ${entry.memory_kib / 1024} MiB · 迭代 ${entry.iterations} 轮 · 并行通道 ${entry.lanes}`;
    renderEntries();
    if (!entry.data) return showStatus('这条还没有加密密码。请在桌面管理端保存条目密码。');
    if (viewer.verified) return decryptSelected();
    showStatus('输入管理密码并验证后，即可解密所选条目。');
}

function loadBook(fileBytes = null, errorLabel = '无法读取粘贴内容') {
    if (viewer.busy) return;
    clearPlaintext(true);
    try {
        const book = VaultText.decode(ui.source.value);
        viewer.book = book;
        viewer.loadedText = ui.source.value;
        viewer.fileBytes = fileBytes;
        viewer.index = null;
        ui.search.value = '';
        ui.detail.hidden = true;
        ui['no-selection'].hidden = false;
        ui['source-panel'].open = false;
        renderEntries();
        showStatus(verificationSample() ? '已读取账本。请输入管理密码。' : '已读取账本。没有可用于验证管理密码的已加密条目。');
    } catch (error) {
        showStatus(`${errorLabel}。${error.message}`, true);
        refreshControls();
    }
}

function saveBook() {
    if (ui['save-book'].disabled) return;
    const file = new Blob([viewer.fileBytes ?? viewer.loadedText], {type: 'text/plain;charset=utf-8'});
    const url = URL.createObjectURL(file);
    const link = document.createElement('a');
    link.href = url;
    link.download = '账本.txt';
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    showStatus('已发起下载。请在浏览器的下载列表中查看“账本.txt”。');
}

function confirmCost({memory_kib, iterations, lanes}) {
    return (memory_kib <= 65536 && iterations <= 3 && lanes <= 4) || confirm('此次计算的参数较高，可能耗时较长或占用更多内存。继续吗？');
}

function showDecrypted(password, start) {
    viewer.plaintext = password;
    renderPlaintext();
    ui['plaintext-state'].textContent = password ? '已解密' : '已解密（密码为空）';
    showStatus(`解密成功，用时 ${((performance.now() - start) / 1000).toFixed(3)} 秒。`);
}

async function verifyMaster() {
    if (ui.verify.disabled) return;
    const {book} = viewer;
    const entry = selectedEntry();
    const sample = verificationSample();
    const master = ui.master.value;
    if (!confirmCost(sample)) return;
    viewer.busy = true;
    refreshControls();
    showStatus('正在验证管理密码。');
    try {
        await new Promise(resolve => setTimeout(resolve, 0));
        const start = performance.now();
        const result = book.verifier ? await VaultProcess.verify(sample, master) : await VaultProcess.decrypt(book.book_code, sample, master);
        if (viewer.book !== book || ui.source.value !== viewer.loadedText || ui.master.value !== master) return;
        viewer.verified = true;
        if (!book.verifier && sample === entry) showDecrypted(result, start);
        else showStatus('管理密码已验证。选择条目即可解密。');
    } catch (error) {
        showStatus(`管理密码验证失败。${error.message}`, true);
    } finally {
        viewer.busy = false;
        refreshControls();
    }
    if (viewer.verified && book.verifier && entry?.data) await decryptSelected();
}

async function decryptSelected() {
    const entry = selectedEntry();
    if (viewer.busy || !viewer.verified || !entry?.data || ui.source.value !== viewer.loadedText) return;
    const {book} = viewer;
    const master = ui.master.value;
    if (!confirmCost(entry)) return;
    viewer.busy = true;
    refreshControls();
    showStatus(`正在解密“${entry.service || '未命名服务'}”的密码。`);
    try {
        await new Promise(resolve => setTimeout(resolve, 0));
        const start = performance.now();
        const password = await VaultProcess.decrypt(book.book_code, entry, master);
        if (viewer.verified && viewer.book === book && ui.source.value === viewer.loadedText && ui.master.value === master) showDecrypted(password, start);
    } catch (error) {
        if (error.code === 'AUTHENTICATION_FAILED') {
            showStatus('条目校验失败。密码密文、随机码或加密参数可能已改动，或这条使用了其他管理密码。', true);
        } else {
            showStatus(`无法解密条目密码。${error.message}`, true);
        }
    } finally {
        viewer.busy = false;
        refreshControls();
    }
}

async function copyPassword() {
    const password = viewer.plaintext;
    if (password === null || viewer.busy) return;
    try {
        await navigator.clipboard.writeText(password);
        if (viewer.plaintext === password) showStatus('条目密码已复制。');
    } catch (_) {
        if (viewer.plaintext !== password || viewer.busy) return;
        if (!password) return showStatus('浏览器无法自动复制。条目密码为空。');
        if (!ui['show-password'].checked) return showStatus('浏览器无法自动复制。请勾选“显示密码”后手动复制。');
        ui.plaintext.focus();
        ui.plaintext.select();
        ui.plaintext.setSelectionRange(0, ui.plaintext.value.length);
        showStatus('浏览器无法自动复制。已选中条目密码，请手动复制。');
    }
}

ui.load.addEventListener('click', () => loadBook(ui.source.value === viewer.loadedText ? viewer.fileBytes : null));
ui['save-book'].addEventListener('click', saveBook);
ui.source.addEventListener('input', () => {
    clearPlaintext(true);
    if (viewer.book && ui.source.value !== viewer.loadedText) showStatus('粘贴内容已更改，请重新读取。');
});
ui.search.addEventListener('input', renderEntries);
ui.verify.addEventListener('click', verifyMaster);
ui.master.addEventListener('keydown', event => {if (event.key === 'Enter') verifyMaster();});
ui.master.addEventListener('input', () => {
    viewer.verified = false;
    clearPlaintext();
});
ui['show-master'].addEventListener('change', () => {ui.master.type = ui['show-master'].checked ? 'text' : 'password';});
ui['show-password'].addEventListener('change', renderPlaintext);
ui['copy-password'].addEventListener('click', copyPassword);
ui.retry.addEventListener('click', decryptSelected);
ui['change-master'].addEventListener('click', () => {
    if (viewer.busy) return;
    clearPlaintext(true);
    ui.master.focus();
    showStatus('请输入该条目使用的管理密码。');
});
ui.open.addEventListener('click', () => ui.file.click());
ui.file.addEventListener('change', async () => {
    const file = ui.file.files[0];
    if (!file || viewer.busy) return;
    viewer.busy = true;
    clearPlaintext(true);
    try {
        const fileBytes = await file.arrayBuffer();
        ui.source.value = new TextDecoder().decode(fileBytes);
        viewer.busy = false;
        loadBook(fileBytes, '无法读取账本文件内容');
    } catch {
        showStatus('无法打开所选文件。请检查文件是否仍可访问。', true);
    } finally {
        viewer.busy = false;
        ui.file.value = '';
        refreshControls();
    }
});
ui['clear-book'].addEventListener('click', () => {
    if (viewer.busy) return;
    viewer.book = null;
    viewer.index = null;
    viewer.loadedText = '';
    viewer.fileBytes = null;
    ui.source.value = '';
    ui.search.value = '';
    ui.detail.hidden = true;
    ui['no-selection'].hidden = false;
    ui['source-panel'].open = true;
    clearPlaintext(true);
    renderEntries();
    showStatus('页面已清空。');
});
refreshControls();
