'use strict';

const viewer = {book: null, index: null, loadedText: '', fileBytes: null, busy: false, plaintext: null, masterFixed: false};
const ui = Object.fromEntries(['source-panel', 'source', 'load', 'open', 'save-book', 'clear-book', 'file', 'search', 'count', 'entries', 'no-selection',
    'detail', 'detail-title', 'detail-user', 'entry-state', 'metadata', 'crypto-info', 'master', 'show-master', 'decrypt', 'plaintext',
    'plaintext-state', 'show-password', 'copy-password', 'lock', 'master-state', 'status'].map(id => [id, document.getElementById(id)]));

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
        viewer.masterFixed = false;
        ui.master.value = '';
        ui.master.type = 'password';
        ui['show-master'].checked = false;
    }
    refreshControls();
}

function refreshControls() {
    for (const name of ['source', 'load', 'open', 'clear-book', 'file', 'master', 'show-master', 'lock']) ui[name].disabled = viewer.busy;
    ui.master.disabled = viewer.busy || !viewer.book || ui.source.value !== viewer.loadedText;
    ui['save-book'].disabled = ui.master.disabled;
    ui.master.readOnly = viewer.masterFixed;
    ui['show-master'].disabled = ui.master.disabled;
    ui['master-state'].textContent = viewer.masterFixed ? '已保留管理密码。要换用其他密码，请先锁定账本。'
        : '首次解密成功后会保留管理密码。要换用其他密码，请先锁定账本。';
    ui.search.disabled = viewer.busy || !viewer.book;
    const entry = viewer.book && viewer.index !== null ? viewer.book.entries[viewer.index] : null;
    ui.decrypt.disabled = viewer.busy || !entry || !entry.data || ui.source.value !== viewer.loadedText;
    ui['show-password'].disabled = viewer.busy || !viewer.plaintext;
    ui['copy-password'].disabled = viewer.busy || viewer.plaintext === null;
    for (const button of ui.entries.querySelectorAll('button')) button.disabled = viewer.busy;
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
    if (viewer.busy) return;
    viewer.index = index;
    clearPlaintext();
    const entry = viewer.book.entries[index];
    ui['no-selection'].hidden = true;
    ui.detail.hidden = false;
    ui['detail-title'].textContent = entry.service || '未命名服务';
    ui['detail-user'].textContent = entry.username || '未填写用户名';
    ui['entry-state'].textContent = entry.data ? '已加密' : '未加密';
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
    showStatus(entry.data ? (ui.master.value ? '点击“解密密码”查看这条的密码。'
        : '输入管理密码，再点击“解密密码”。') : '这条还没有加密密码。请在桌面管理端保存条目密码。');
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
        showStatus(book.entries.length ? `已读取 ${book.entries.length} 个条目。请选择要查看的条目。` : '已读取账本。账本中没有条目。');
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

async function decryptSelected() {
    if (viewer.busy || viewer.index === null || !viewer.book) return;
    if (ui.source.value !== viewer.loadedText) return showStatus('粘贴内容已更改，请先点击“读取粘贴内容”。', true);
    clearPlaintext();
    const entry = viewer.book.entries[viewer.index];
    if (!ui.master.value) return showStatus('请输入管理密码。', true);
    if (entry.memory_kib > 65536 || entry.iterations > 3 || entry.lanes > 4) {
        if (!confirm('这个条目的解密参数较高，可能耗时较长或占用更多内存。继续解密吗？')) return;
    }
    viewer.busy = true;
    refreshControls();
    showStatus(`正在解密“${entry.service || '未命名服务'}”的密码。`);
    try {
        await new Promise(resolve => setTimeout(resolve, 0));
        const start = performance.now();
        const password = await VaultProcess.decrypt(viewer.book.book_code, entry, ui.master.value);
        viewer.masterFixed = true;
        viewer.plaintext = password;
        renderPlaintext();
        ui['plaintext-state'].textContent = password ? '已解密' : '已解密（密码为空）';
        showStatus(`解密成功，用时 ${((performance.now() - start) / 1000).toFixed(3)} 秒。`);
    } catch (error) {
        showStatus(`无法解密条目密码。${error.message}`, true);
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
ui.decrypt.addEventListener('click', decryptSelected);
ui.master.addEventListener('keydown', event => {if (event.key === 'Enter' && !ui.decrypt.disabled) decryptSelected();});
ui.master.addEventListener('input', () => clearPlaintext());
ui['show-master'].addEventListener('change', () => {ui.master.type = ui['show-master'].checked ? 'text' : 'password';});
ui['show-password'].addEventListener('change', renderPlaintext);
ui['copy-password'].addEventListener('click', copyPassword);
ui.lock.addEventListener('click', () => {clearPlaintext(true); showStatus('已锁定账本。管理密码和解密结果已清空。');});
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
