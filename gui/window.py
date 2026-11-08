"""桌面账本：文件与窗口状态由 Window 持有，密码计算只通过 core 的两个入口。"""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
from tempfile import NamedTemporaryFile
from time import monotonic
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

import config
from core import create_verifier, process, text_process, verify_master, with_verifier


def _cost_text(parameters):
    memory = parameters['memory_kib']
    size = f'{memory / 1024:g} MiB' if memory >= 1024 else f'{memory} KiB'
    return f"{size} · {parameters['iterations']} 轮"


def _reencrypt_book(book, old_master, new_master):
    # 原管理密码已经核验，这里只处理账本副本。
    verifier = book.get('verifier')
    entries = book['entries']
    profile = verifier
    for index, entry in enumerate(entries):
        if not entry['data']:
            continue
        if profile is None:
            profile = entry
        parameters = dict(book_code=book['book_code'], entry=entry)
        try:
            password = process('decrypt', parameters, old_master)
            entries[index] = process('encrypt', parameters, new_master, password)
        except (ValueError, TypeError) as error:
            raise ValueError(f'第 {index + 1} 条无法更换管理密码。{error}') from None
    return with_verifier(book, create_verifier(new_master, profile=profile)), new_master


def _verify_book_password(book_code, entry, verifier, master):
    if verifier is not None:
        verify_master(verifier, master)
    else:
        process('decrypt', dict(book_code=book_code, entry=entry), master, None)
    return master


def _unlock_book(book_code, entry, verifier, master):
    _verify_book_password(book_code, entry, verifier, master)
    if verifier is None:
        return create_verifier(master, profile=entry)


def _encrypt_entry(parameters, master, password, previous, generate, needs_verifier):
    if generate:
        password = process('generate', parameters['entry']['rules'])
    elif previous is not None:
        password = process('decrypt', dict(book_code=parameters['book_code'], entry=previous), master)
        if not password:
            raise ValueError('原来的条目密码为空。请生成或输入新密码后再保存条目。')
    entry = process('encrypt', parameters, master, password)
    verifier = create_verifier(master, profile=entry) if needs_verifier else None
    return entry, password, verifier


class _InputHistory:
    def __init__(self):
        self.reset('')

    def reset(self, value):
        self.values = [value]
        self.index = 0

    def record(self, value):
        if value != self.values[self.index]:
            del self.values[self.index + 1:]
            self.values.append(value)
            self.index += 1

    def move(self, step):
        index = self.index + step
        if 0 <= index < len(self.values):
            self.index = index
            return self.values[index]
        return None


class _NewMasterDialog(simpledialog.Dialog):
    def __init__(self, parent, old_master):
        self.old_master = old_master
        super().__init__(parent, '更换管理密码')

    def body(self, parent):
        tk.Label(parent, text='请输入新的管理密码。').pack(anchor='w')
        self.entry = tk.Entry(parent, show='•', width=36)
        self.entry.pack(fill='x', pady=(4, 6))
        visible = tk.BooleanVar(self, False)
        tk.Checkbutton(parent, text='显示新密码', variable=visible,
                       command=lambda: self.entry.configure(show='' if visible.get() else '•')).pack(anchor='w')
        return self.entry

    def validate(self):
        password = self.entry.get()
        if not password:
            messagebox.showerror(self.title(), '管理密码不能为空。', parent=self)
            return False
        if password == self.old_master:
            messagebox.showerror(self.title(), '请输入与旧管理密码不同的新密码。', parent=self)
            return False
        return True

    def apply(self):
        self.result = self.entry.get()


def run():
    root = tk.Tk()
    Window(root)
    root.mainloop()


class Window:
    def __init__(self, root):
        self.root = root
        self.path = None
        self.book = text_process('decode', text_process('new'))
        self.index = None
        self.dirty = False
        self.saved_password = None
        self.password_history = _InputHistory()
        self.salt_history = _InputHistory()
        self.replaying_input = False
        self.busy = False
        self.unlocked = False
        self.executor = None
        self.future = None
        self.book_text_window = None
        self.book_text = None
        self.book_text_snapshot = ''
        self.book_text_status = tk.StringVar(root)
        self.controls = []
        self.form_snapshot = ()
        self.fields = {name: tk.StringVar(root) for name in ('service', 'addresses', 'code', 'username', 'nickname')}
        self.length = tk.StringVar(root, str(config.DEFAULT_RULES['length']))
        self.categories = tk.StringVar(root, str(config.DEFAULT_RULES['categories']))
        self.allowed = {name: tk.BooleanVar(root, name in config.DEFAULT_RULES['allowed']) for name in 'ULDS'}
        self.symbols = tk.StringVar(root, config.DEFAULT_RULES['symbols'])
        self.algorithm = tk.StringVar(root, config.DEFAULT_ALGORITHM)
        self.memory_kib = tk.StringVar(root, str(config.MEMORY_KIB))
        self.iterations = tk.StringVar(root, str(config.ITERATIONS))
        self.encryption_fields = {'algorithm': self.algorithm, 'memory_kib': self.memory_kib, 'iterations': self.iterations}
        self.master = tk.StringVar(root)
        self.master_status = tk.StringVar(root, '未解锁')
        self.password = tk.StringVar(root)
        self.salt = tk.StringVar(root)
        self.visible = tk.BooleanVar(root, True)
        self.search = tk.StringVar(root)
        self.status = tk.StringVar(root, '可直接填写第一条，也可以打开已有账本。')
        self.file_label = tk.StringVar(root, '未保存的账本')
        self.count_label = tk.StringVar(root, '0 个条目')
        self.entry_title = tk.StringVar(root, '新建条目')
        self.crypto_label = tk.StringVar(root, '尚未加密')
        self.book_label = tk.StringVar(root)
        self._build()
        self.password.trace_add('write', self._password_changed)
        self.salt.trace_add('write', self._salt_changed)
        for variable in self.encryption_fields.values():
            variable.trace_add('write', self._encryption_settings_changed)
        self.search.trace_add('write', lambda *_: self._refresh_list())
        self.root.protocol('WM_DELETE_WINDOW', self.close)
        self.root.bind('<Control-s>', lambda _: self.save())
        self.root.bind('<Control-o>', lambda _: self.open_book())
        self.root.bind('<Escape>', lambda _: self.lock_book())
        self._show_entry(None)
        self._file_status()
        self._session_controls()

    def _build(self):
        self.root.title(config.TITLE)
        width, height = map(int, config.WINDOW_SIZE.split('x'))
        width = min(width, self.root.winfo_screenwidth())
        height = min(height, max(1, self.root.winfo_screenheight() - self.root.winfo_pixels('1i')))
        self.root.geometry(f'{width}x{height}')
        self.root.minsize(min(1020, width), min(620, height))
        self.root.configure(background=config.BACKGROUND)
        self.root.option_add('*Font', ('Microsoft YaHei UI', 10))
        style = ttk.Style(self.root)
        style.theme_use('clam')
        style.configure('.', background=config.PANEL, foreground=config.FOREGROUND, borderwidth=0, font=('Microsoft YaHei UI', 10))
        style.configure('TFrame', background=config.PANEL)
        style.configure('Root.TFrame', background=config.BACKGROUND)
        style.configure('TLabel', background=config.PANEL, foreground=config.FOREGROUND)
        style.configure('Muted.TLabel', foreground=config.MUTED)
        style.configure('Pending.TLabel', background='#4a252e', foreground='#ffb3bc', padding=(4, 2))
        style.configure('Saved.TLabel', background='#1c473e', foreground='#9cf3df', padding=(4, 2))
        style.configure('Title.TLabel', font=('Microsoft YaHei UI', 17, 'bold'))
        style.configure('Brand.TLabel', background=config.BACKGROUND, foreground=config.ACCENT, font=('Segoe UI', 22, 'bold'))
        style.configure('Root.TLabel', background=config.BACKGROUND, foreground=config.MUTED)
        style.configure('TButton', background='#24324d', padding=(10, 5), borderwidth=0)
        style.map('TButton', background=[('active', '#324767'), ('disabled', '#192237')], foreground=[('disabled', '#69748a')])
        style.configure('Accent.TButton', background=config.ACCENT, foreground='#082a2a')
        style.map('Accent.TButton', background=[('active', '#8cf0dc'), ('disabled', '#284c4b')], foreground=[('disabled', '#759491')])
        style.configure('TEntry', fieldbackground='#0e1628', foreground=config.FOREGROUND, insertcolor=config.FOREGROUND, padding=4)
        style.map('TEntry', fieldbackground=[('disabled', '#151d31')], foreground=[('disabled', '#69748a')])
        style.configure('TCombobox', fieldbackground='#0e1628', arrowcolor=config.ACCENT, padding=4)
        style.map('TCombobox', fieldbackground=[('readonly', '#0e1628')], foreground=[('readonly', config.FOREGROUND)])
        style.configure('TCheckbutton', background=config.PANEL, foreground=config.FOREGROUND, padding=2)
        style.map('TCheckbutton', background=[('active', config.PANEL)])
        style.configure('Treeview', background=config.PANEL, fieldbackground=config.PANEL, foreground=config.FOREGROUND, rowheight=43)
        style.map('Treeview', background=[('selected', '#284758')], foreground=[('selected', '#9cf3df')])
        style.configure('Treeview.Heading', background='#1c2942', foreground=config.MUTED, padding=8)
        style.configure('Horizontal.TProgressbar', troughcolor='#0e1628', background=config.ACCENT, thickness=4)
        style.configure('Card.TLabelframe', background=config.PANEL, bordercolor='#2a3851', borderwidth=1, relief='solid')
        style.configure('Card.TLabelframe.Label', background=config.PANEL, foreground=config.ACCENT, font=('Microsoft YaHei UI', 10, 'bold'))

        header = ttk.Frame(self.root, style='Root.TFrame', padding=(24, 17, 24, 8))
        header.pack(fill='x')
        ttk.Label(header, text='LOCAL VAULT', style='Brand.TLabel').pack(side='left')
        ttk.Label(header, text='  /  密码账本', style='Root.TLabel', font=('Microsoft YaHei UI', 15)).pack(side='left', pady=5)
        toolbar = ttk.Frame(self.root, style='Root.TFrame', padding=(24, 3, 24, 12))
        toolbar.pack(fill='x')
        for label, command in (('新建账本', self.new_book), ('打开账本', self.open_book), ('保存账本', self.save), ('另存为', lambda: self.save(True))):
            self._button(toolbar, label, command).pack(side='left', padx=(0, 7))
        self._button(toolbar, '编辑账本文本', self.show_book_text, accent=True).pack(side='left', padx=(0, 7))
        ttk.Label(toolbar, textvariable=self.file_label, style='Root.TLabel').pack(side='right')

        session = ttk.Frame(self.root, padding=(24, 7, 24, 10))
        session.pack(fill='x', padx=24, pady=(0, 10))
        ttk.Label(session, textvariable=self.master_status, style='Muted.TLabel').pack(side='right', padx=(12, 0))
        ttk.Label(session, text='管理密码').pack(side='left', padx=(0, 10))
        self.master_entry = ttk.Entry(session, textvariable=self.master, show='•', width=12)
        self.master_entry.pack(side='left', fill='x', expand=True)
        self.master_entry.bind('<Return>', lambda _: self.unlock_book())
        self.controls.append(self.master_entry)
        self.unlock_button = self._button(session, '解锁账本', self.unlock_book, accent=True, width=0)
        self.unlock_button.pack(side='left', padx=(10, 7))
        self._button(session, '更换管理密码', self.change_book_password, width=0).pack(side='left', padx=(0, 7))
        self._button(session, '锁定账本', self.lock_book, width=0).pack(side='left')

        footer = ttk.Frame(self.root, style='Root.TFrame', padding=(24, 10))
        footer.pack(side='bottom', fill='x')
        ttk.Label(footer, textvariable=self.status, style='Root.TLabel').pack(side='left')
        body = ttk.Frame(self.root, style='Root.TFrame', padding=(24, 0, 24, 0))
        body.pack(fill='both', expand=True)
        sidebar = ttk.Frame(body, padding=15, width=270)
        sidebar.pack(side='left', fill='y', padx=(0, 16))
        sidebar.pack_propagate(False)
        ttk.Label(sidebar, text='账本条目', style='Title.TLabel').pack(anchor='w')
        ttk.Label(sidebar, textvariable=self.count_label, style='Muted.TLabel').pack(anchor='w', pady=(2, 13))
        search_entry = ttk.Entry(sidebar, textvariable=self.search)
        search_entry.pack(fill='x')
        self.controls.append(search_entry)
        ttk.Label(sidebar, text='按服务名、用户名等搜索', style='Muted.TLabel').pack(anchor='w', pady=(4, 10))
        actions = ttk.Frame(sidebar)
        actions.pack(side='bottom', fill='x', pady=(13, 0))
        self._button(actions, '新增条目', self.new_entry, accent=True, width=0).pack(side='left')
        self._button(actions, '删除条目', self.delete_entry, width=0).pack(side='right')

        listing = ttk.Frame(sidebar)
        listing.pack(fill='both', expand=True)
        self.tree = ttk.Treeview(listing, columns=('user',), show='tree headings', selectmode='browse', height=6)
        list_scroll = ttk.Scrollbar(listing, orient='vertical', command=self.tree.yview)
        list_scroll.pack(side='right', fill='y')
        self.tree.configure(yscrollcommand=list_scroll.set)
        self.tree.heading('#0', text='服务名')
        self.tree.heading('user', text='用户名')
        self.tree.column('#0', width=117, minwidth=85)
        self.tree.column('user', width=107, minwidth=70)
        self.tree.pack(side='left', fill='both', expand=True)
        self.tree.bind('<<TreeviewSelect>>', self._select_entry)

        detail_panel = ttk.Frame(body)
        detail_panel.pack(side='right', fill='both', expand=True)
        canvas = self.detail_canvas = tk.Canvas(detail_panel, background=config.PANEL, highlightthickness=0)
        detail_scroll = ttk.Scrollbar(detail_panel, orient='vertical', command=canvas.yview)
        detail_scroll.pack(side='right', fill='y')
        canvas.configure(yscrollcommand=detail_scroll.set)
        canvas.pack(side='left', fill='both', expand=True)
        detail = ttk.Frame(canvas, padding=(19, 13))
        detail_window = canvas.create_window(0, 0, anchor='nw', window=detail)
        detail.bind('<Configure>', lambda _: canvas.configure(scrollregion=canvas.bbox(detail_window)))
        canvas.bind('<Configure>', lambda event: canvas.itemconfigure(detail_window, width=event.width))

        def scroll_detail(event):
            if event.widget is not canvas and not str(event.widget).startswith(f'{detail}.'):
                return
            if event.num in (4, 5):
                steps = -1 if event.num == 4 else 1
            elif event.delta:
                steps = -int(event.delta / 120) or (-1 if event.delta > 0 else 1)
            else:
                return
            canvas.yview_scroll(steps, 'units')

        self.root.bind('<MouseWheel>', scroll_detail, add='+')
        if self.root.tk.call('tk', 'windowingsystem') == 'x11':
            self.root.bind('<Button-4>', scroll_detail, add='+')
            self.root.bind('<Button-5>', scroll_detail, add='+')
        title_row = ttk.Frame(detail)
        title_row.pack(fill='x', pady=(0, 10))
        ttk.Label(title_row, textvariable=self.entry_title, style='Title.TLabel').pack(side='left')
        self._button(title_row, '应用资料', self.apply_metadata).pack(side='right')
        metadata = ttk.Frame(detail)
        metadata.pack(fill='x')
        metadata.columnconfigure(0, weight=1)
        metadata.columnconfigure(1, weight=1)
        for row, fields in enumerate(((('service', '服务名'), ('code', '服务编码')), (('username', '用户名'), ('nickname', '昵称')))):
            for column, (key, label) in enumerate(fields):
                field = ttk.Frame(metadata)
                field.grid(row=row, column=column, sticky='ew', padx=(0, 10 if column == 0 else 0), pady=(0, 6))
                ttk.Label(field, text=label, style='Muted.TLabel', width=8).pack(side='left')
                entry = ttk.Entry(field, textvariable=self.fields[key])
                entry.pack(side='left', fill='x', expand=True)
                self.controls.append(entry)
        address_row = ttk.Frame(metadata)
        address_row.grid(row=2, column=0, columnspan=2, sticky='ew')
        ttk.Label(address_row, text='应用地址', style='Muted.TLabel', width=8).pack(side='left')
        address_entry = ttk.Entry(address_row, textvariable=self.fields['addresses'])
        address_entry.pack(side='left', fill='x', expand=True)
        self.controls.append(address_entry)
        notes_row = ttk.Frame(metadata)
        notes_row.grid(row=3, column=0, columnspan=2, sticky='ew', pady=(6, 0))
        ttk.Label(notes_row, text='公开备注', style='Muted.TLabel', width=8).pack(side='left', anchor='n')
        self.notes = tk.Text(notes_row, height=2, wrap='word', bg='#0e1628', fg=config.FOREGROUND, insertbackground=config.FOREGROUND,
                             relief='flat', font=('Microsoft YaHei UI', 10), padx=6, pady=3)
        self.notes.pack(side='left', fill='x', expand=True)

        rules = ttk.LabelFrame(detail, text='  密码生成规则  ', style='Card.TLabelframe', padding=(12, 6))
        rules.pack(fill='x', pady=(12, 8))
        row = ttk.Frame(rules)
        row.pack(fill='x')
        for label, variable in (('最少字符数', self.length), ('最少字符类型', self.categories)):
            ttk.Label(row, text=label).pack(side='left', padx=(0, 5))
            entry = ttk.Entry(row, textvariable=variable, width=5)
            entry.pack(side='left', padx=(0, 12))
            self.controls.append(entry)
        for name, label in zip('ULDS', ('大写', '小写', '数字', '符号')):
            check = ttk.Checkbutton(row, text=label, variable=self.allowed[name])
            check.pack(side='left')
            self.controls.append(check)
        row = ttk.Frame(rules)
        row.pack(fill='x', pady=(6, 0))
        ttk.Label(row, text='可用符号').pack(side='left', padx=(0, 10))
        entry = ttk.Entry(row, textvariable=self.symbols)
        entry.pack(side='left', fill='x', expand=True)
        self.controls.append(entry)
        self.generate_button = self._button(row, '生成密码并保存', self.generate, width=0)
        self.generate_button.pack(side='right', padx=(10, 0))

        settings = ttk.LabelFrame(detail, text='  条目加密设置  ', style='Card.TLabelframe', padding=(12, 7))
        settings.pack(fill='x', pady=(0, 8))
        row = ttk.Frame(settings)
        row.pack(fill='x')
        ttk.Label(row, text='加密算法').pack(side='left', padx=(0, 12))
        algorithms = ('XCHACHA20-POLY1305', 'CHACHA20-POLY1305', 'AES-256-GCM')
        choice = ttk.Combobox(row, textvariable=self.algorithm, values=algorithms, state='readonly', width=28)
        choice.pack(side='left', fill='x', expand=True)
        self.controls.append(choice)
        self.encryption_badge = ttk.Label(row, width=8, anchor='center')
        self.encryption_badge.pack(side='left', padx=(8, 0))
        row = ttk.Frame(settings)
        row.pack(fill='x', pady=(6, 0))
        for label, variable in (('内存（KiB）', self.memory_kib), ('迭代次数', self.iterations)):
            ttk.Label(row, text=label).pack(side='left', padx=(0, 6))
            entry = ttk.Entry(row, textvariable=variable, width=11)
            entry.pack(side='left', padx=(0, 12))
            self.controls.append(entry)
        ttk.Label(row, text='65536 KiB = 64 MiB', style='Muted.TLabel').pack(side='left')
        ttk.Label(settings, textvariable=self.crypto_label, style='Muted.TLabel').pack(anchor='w', pady=(6, 0))

        secrets = ttk.LabelFrame(detail, text='  条目密码  ', style='Card.TLabelframe', padding=(12, 7))
        secrets.pack(fill='x')
        row = ttk.Frame(secrets)
        row.pack(fill='x')
        ttk.Label(row, text='密码', width=9).pack(side='left')
        self._button(row, '保存条目', self._save_entry, accent=True, width=0).pack(side='right', padx=(10, 0))
        self._button(row, '解密密码', lambda: self.compute('decrypt'), width=0).pack(side='right', padx=(10, 0))
        self.password_badge = ttk.Label(row, width=7, anchor='center')
        self.password_badge.pack(side='right', padx=(6, 0))
        self.password_entry = ttk.Entry(row, textvariable=self.password, width=8)
        self.password_entry.pack(side='left', fill='x', expand=True)
        self.controls.append(self.password_entry)
        self._bind_input_history(self.password_entry, self.password, self.password_history)
        row = ttk.Frame(secrets)
        row.pack(fill='x', pady=(7, 0))
        ttk.Label(row, text='随机码', width=9).pack(side='left')
        ttk.Label(row, text='留空则在保存条目时生成', style='Muted.TLabel').pack(side='right', padx=(8, 0))
        self.salt_badge = ttk.Label(row, width=7, anchor='center')
        self.salt_badge.pack(side='right', padx=(6, 0))
        salt_entry = ttk.Entry(row, textvariable=self.salt, width=24)
        salt_entry.pack(side='left', fill='x', expand=True)
        self.controls.append(salt_entry)
        self._bind_input_history(salt_entry, self.salt, self.salt_history)
        row = ttk.Frame(secrets)
        row.pack(fill='x', pady=(7, 0))
        check = ttk.Checkbutton(row, text='显示密码', variable=self.visible, command=self._visibility)
        check.pack(side='left')
        self.controls.append(check)
        self._button(row, '复制密码', self.copy_password).pack(side='left', padx=6)
        self._button(row, '隐藏并清空', lambda: self.clear_secret(hide=True)).pack(side='left')
        ttk.Label(row, text='密码加密后写入账本', style='Muted.TLabel').pack(side='right')
        self.progress = ttk.Progressbar(detail, mode='determinate', value=0)
        self.progress.pack(fill='x', pady=(10, 7))

        ttk.Label(detail, text='加密后的密码', style='Muted.TLabel').pack(anchor='w')
        self.ciphertext = tk.Text(detail, height=2, wrap='char', bg='#0e1628', fg='#a8bbd8', relief='flat', font=('Consolas', 9), padx=8, pady=7)
        self.ciphertext.pack(fill='both', expand=True, pady=(3, 6))
        self.ciphertext.configure(state='disabled')
        book_row = ttk.Frame(detail)
        book_row.pack(fill='x')
        ttk.Label(book_row, textvariable=self.book_label, style='Muted.TLabel').pack(side='left')

    def _button(self, parent, text, command, accent=False, **options):
        button = ttk.Button(parent, text=text, command=command, style='Accent.TButton' if accent else 'TButton', **options)
        self.controls.append(button)
        return button

    def _bind_input_history(self, entry, variable, history):
        entry.bind('<Control-z>', lambda _: self._move_input_history(variable, history, -1))
        entry.bind('<Control-r>', lambda _: self._move_input_history(variable, history, 1))

    def _move_input_history(self, variable, history, step):
        if not self.busy:
            value = history.move(step)
            if value is not None:
                self.replaying_input = True
                try:
                    variable.set(value)
                finally:
                    self.replaying_input = False
        return 'break'

    @property
    def secret_dirty(self):
        baseline = self.saved_password if self.saved_password is not None else ''
        return self.password.get() != baseline

    def _password_changed(self, *_):
        if not self.replaying_input:
            self.password_history.record(self.password.get())
        self._update_input_badge(self.password_badge, self.secret_dirty, self.saved_password is not None, '未显示')

    def _set_password(self, value, *, saved=False):
        self.saved_password = value if saved else None
        self.password.set(value)

    def _stored_salt(self):
        return self.book['entries'][self.index]['salt'] if self.index is not None else ''

    def _current_entry(self):
        return self.book['entries'][self.index] if self.index is not None else self._blank_entry()

    def _salt_changed(self, *_):
        if not self.replaying_input:
            self.salt_history.record(self.salt.get())
        stored = self._stored_salt()
        self._update_input_badge(self.salt_badge, self.salt.get() != stored, bool(stored), '未填写')

    def _encryption_settings_changed(self, *_):
        entry = self._current_entry()
        self._update_input_badge(self.encryption_badge, self._settings_pending(entry), bool(entry['data']), '')

    def _settings_pending(self, entry):
        return any(variable.get() != str(entry[key]) for key, variable in self.encryption_fields.items())

    def _show_encryption_settings(self, entry):
        for key, variable in self.encryption_fields.items():
            variable.set(str(entry[key]))

    def _update_input_badge(self, badge, dirty, saved, empty_text):
        if dirty:
            badge.configure(text='未保存', style='Pending.TLabel')
        elif saved:
            badge.configure(text='已保存', style='Saved.TLabel')
        else:
            badge.configure(text=empty_text, style='Muted.TLabel')

    def _visibility(self):
        self.password_entry.configure(show='' if self.visible.get() else '•')

    def clear_secret(self, *, hide=False):
        if self.busy:
            return
        self.password_history.reset('')
        self._set_password('')
        if hide:
            self.visible.set(False)
        self._visibility()

    def _session_controls(self):
        self.master_entry.state(['readonly'] if self.unlocked else ['!readonly'])
        self.unlock_button.state(['disabled'] if self.unlocked or self.busy else ['!disabled'])
        self.generate_button.state(['!disabled'] if self.unlocked and not self.busy else ['disabled'])
        self.master_status.set('已解锁' if self.unlocked else '未解锁')

    def unlock_book(self):
        if not self.busy and not self.unlocked:
            self.compute('unlock')

    def _use_book_password(self, master):
        self.clear_secret()
        self.master.set(master)
        self.unlocked = True
        self._session_controls()

    def change_book_password(self):
        if self.busy:
            return
        entry = next((entry for entry in self.book['entries'] if entry['data']), None)
        verifier = self.book.get('verifier')
        if verifier is None and entry is None:
            self._prompt_new_master(None)
            return
        old_master = simpledialog.askstring('更换管理密码', '请输入原管理密码。更换后，已加密条目都用新的管理密码解密，条目里的密码保持原样。',
                                            initialvalue=self.master.get(), show='•', parent=self.root)
        if old_master is None:
            return
        if not old_master:
            messagebox.showerror('更换管理密码', '旧管理密码不能为空。', parent=self.root)
            return
        if self._confirm_entry_cost(verifier if verifier is not None else entry):
            self._start_job('verify_rotate', _verify_book_password, self.book['book_code'], entry, verifier, old_master)

    def _prompt_new_master(self, old_master):
        new_master = _NewMasterDialog(self.root, old_master).result
        if new_master is None:
            self.status.set('已取消更换管理密码。')
            return
        entries = [entry for entry in self.book['entries'] if entry['data']]
        verifier = self.book.get('verifier')
        if any(self._expensive_entry(entry) for entry in entries + ([verifier] if verifier is not None else [])):
            message = '整本更换管理密码可能需要更长时间或占用较多内存。'
            if verifier is None and entries and entries[0]['memory_kib'] >= 128 * 1024:
                message += '\n新校验样本会沿用第一条密文的参数，整个账本将需要用桌面端验证。'
            if not messagebox.askyesno('更换管理密码', message + '\n继续吗？', parent=self.root):
                self.status.set('已取消更换管理密码。')
                return
        if self._pending_encryption() and not self._confirm_discard_secret():
            self.status.set('已取消更换管理密码。')
            return
        self._start_job('rotate', _reencrypt_book, deepcopy(self.book), old_master, new_master)

    def lock_book(self):
        if self.busy:
            return
        self.clear_secret()
        self.salt_history.reset(self.salt.get())
        self.master.set('')
        self.unlocked = False
        self._session_controls()
        self.status.set('账本已锁定。管理密码和密码框已清空。')

    def _snapshot(self):
        return tuple(value.get() for value in self.fields.values()) + (
            self.notes.get('1.0', 'end-1c'), self.length.get(), self.categories.get(), self.symbols.get(), *(value.get() for value in self.allowed.values())
        )

    def _blank_entry(self):
        return dict(service='新服务', addresses='', code='', username='', nickname='', rules=dict(config.DEFAULT_RULES),
                    algorithm=config.DEFAULT_ALGORITHM, memory_kib=config.MEMORY_KIB, iterations=config.ITERATIONS, lanes=config.LANES, salt='', data='')

    def _show_entry(self, index, *, reset_history=True):
        self.index = index
        entry = self.book['entries'][index] if index is not None else self._blank_entry()
        for name, variable in self.fields.items():
            variable.set(entry[name] if index is not None else '')
        self.notes.delete('1.0', 'end')
        self.notes.insert('1.0', entry.get('notes', '') if index is not None else '')
        rules = entry['rules']
        self.length.set(str(rules['length']))
        self.categories.set(str(rules['categories']))
        self.symbols.set(rules['symbols'])
        for name, variable in self.allowed.items():
            variable.set(name in rules['allowed'])
        self._show_encryption_settings(entry)
        self.entry_title.set(entry['service'] if index is not None else '新建条目')
        self._show_ciphertext(entry, reset_history=reset_history)
        self.form_snapshot = self._snapshot()
        if reset_history:
            self.clear_secret()

    def _show_ciphertext(self, entry, *, reset_history=True):
        if reset_history:
            self.salt_history.reset(entry['salt'])
        self.salt.set(entry['salt'])
        if entry['data']:
            cost = f"{_cost_text(entry)} · {entry['lanes']} 通道"
            self.crypto_label.set(f"当前条目使用 {entry['algorithm']}（{cost}）")
        else:
            self.crypto_label.set('条目尚未加密。')
        self.ciphertext.configure(state='normal')
        self.ciphertext.delete('1.0', 'end')
        self.ciphertext.insert('1.0', entry['data'] or '保存条目后，密文会显示在这里。')
        self.ciphertext.configure(state='disabled')

    def _refresh_list(self):
        query = self.search.get().casefold()
        self.tree.delete(*self.tree.get_children())
        for index, entry in enumerate(self.book['entries']):
            searchable = (' '.join(entry[name] for name in ('service', 'username', 'addresses', 'code', 'nickname')) + ' ' + entry.get('notes', '')).casefold()
            if query in searchable:
                self.tree.insert('', 'end', iid=str(index), text=entry['service'] or '未命名', values=(entry['username'],))
        if self.index is not None and self.tree.exists(str(self.index)):
            self.tree.selection_set(str(self.index))
        total = len(self.book['entries'])
        self.count_label.set(f'找到 {len(self.tree.get_children())} 条，共 {total} 条' if query else f'{total} 个条目')

    def _select_entry(self, _=None):
        selected = self.tree.selection()
        if not selected or int(selected[0]) == self.index:
            return
        next_index = int(selected[0])
        if self.busy or not self._leave_entry():
            if self.index is not None and self.tree.exists(str(self.index)):
                self.tree.selection_set(str(self.index))
            else:
                self.tree.selection_remove(*selected)
            return
        self._show_entry(next_index)
        self.tree.selection_set(str(next_index))

    def _read_rules(self):
        try:
            length = int(self.length.get())
        except ValueError:
            raise ValueError('请在“最少字符数”填写一个整数。') from None
        try:
            categories = int(self.categories.get())
        except ValueError:
            raise ValueError('请在“最少字符类型”填写一个整数。') from None
        return dict(length=length, categories=categories,
                    allowed=''.join(name for name, variable in self.allowed.items() if variable.get()), symbols=self.symbols.get())

    def _read_entry(self, encrypt=False):
        entry = self._blank_entry() if self.index is None else self.book['entries'][self.index].copy()
        entry.update({name: variable.get() for name, variable in self.fields.items()})
        notes = self.notes.get('1.0', 'end-1c')
        if notes:
            entry['notes'] = notes
        else:
            entry.pop('notes', None)
        entry['rules'] = self._read_rules()
        if encrypt:
            settings = {key: variable.get() for key, variable in self.encryption_fields.items()}
            for key, label in (('memory_kib', '内存（KiB）'), ('iterations', '迭代次数')):
                try:
                    settings[key] = int(settings[key])
                except ValueError:
                    raise ValueError(f'请在“{label}”填写一个整数。') from None
            entry.update(settings, salt='', data='')
        # 使用同一个文本边界校验，GUI 不另写一套账本规则。
        text_process('encode', parameters={**self.book, 'entries': [entry]})
        return entry

    def _book_with_entry(self, entry, index):
        entries = self.book['entries'].copy()
        if index is None:
            index = len(entries)
        entries[index:index + 1] = [entry]
        return {**self.book, 'entries': entries}, index

    def _sync_metadata(self):
        self.form_snapshot = self._snapshot()
        self.entry_title.set(self.book['entries'][self.index]['service'])
        self._refresh_list()

    def apply_metadata(self):
        if self.busy:
            return False
        if self._snapshot() == self.form_snapshot:
            return True
        try:
            entry = self._read_entry()
        except (ValueError, TypeError) as error:
            messagebox.showerror('无法应用条目资料', str(error), parent=self.root)
            return False
        self.book, self.index = self._book_with_entry(entry, self.index)
        self.dirty = True
        self._sync_metadata()
        self._file_status()
        self.status.set('已更新条目资料。点击“保存账本”写入文件。')
        return True

    def _leave_entry(self, *, parent=None):
        changed = self._snapshot() != self.form_snapshot
        apply = False
        if changed:
            apply = messagebox.askyesnocancel('条目资料有改动', '保留刚才修改的条目资料吗？\n选“否”将放弃这些修改。', parent=parent or self.root)
            if apply is None:
                return False
        pending = self._pending_encryption()
        if pending and not self._confirm_discard_secret(parent=parent):
            return False
        if apply and not self.apply_metadata():
            return False
        if changed and not apply:
            self._show_entry(self.index)
        elif pending:
            self.clear_secret()
            self.salt_history.reset(self._stored_salt())
            self.salt.set(self._stored_salt())
            self._show_encryption_settings(self._current_entry())
        return True

    def _pending_encryption(self):
        entry = self._current_entry()
        return self.secret_dirty or self.salt.get() != entry['salt'] or self._settings_pending(entry)

    def _confirm_discard_secret(self, *, parent=None):
        return messagebox.askyesno('条目有未保存的修改', '放弃密码、随机码或加密设置的修改，并继续吗？', parent=parent or self.root)

    def new_entry(self):
        if self.busy or not self._leave_entry():
            return
        self.book['entries'].append(self._blank_entry())
        self.dirty = True
        self.search.set('')
        self._show_entry(len(self.book['entries']) - 1)
        self._refresh_list()
        self._file_status()
        self.status.set('填写条目资料。解锁后可以生成密码，或手动输入密码再保存条目。')

    def delete_entry(self):
        if self.busy or self.index is None:
            return
        if self.book['entries'][self.index]['data']:
            if not messagebox.askyesno('删除条目', '删除这条记录和它的密码吗？点击“保存账本”后，删除才会写入文件。', parent=self.root):
                return
        del self.book['entries'][self.index]
        self.dirty = True
        self._show_entry(min(self.index, len(self.book['entries']) - 1) if self.book['entries'] else None)
        self._refresh_list()
        self._file_status()
        self.status.set('已删除条目。点击“保存账本”写入文件。')

    def generate(self):
        self._save_entry(generate=True)

    def _save_entry(self, *, generate=False):
        if self.busy:
            return
        try:
            master = self.master.get()
            if not self.unlocked or not master:
                raise ValueError('请先在顶部输入管理密码并解锁账本。')
            password = self.password.get()
            salt = '' if generate else self.salt.get()
            entry = self._read_entry(encrypt=True)
            previous = None
            if not generate and not password:
                current = self._current_entry()
                if not current['data'] or self.secret_dirty or (salt == current['salt'] and not self._settings_pending(current)):
                    raise ValueError('密码框为空。请输入密码，或点击“生成密码并保存”。')
                previous = deepcopy(current)
            if not self._confirm_save_cost(previous, entry):
                return
            parameters = dict(book_code=self.book['book_code'], entry=entry)
            if salt:
                parameters['salt_override'] = salt
        except (ValueError, TypeError) as error:
            messagebox.showerror('无法保存条目', str(error), parent=self.root)
            return
        self._start_job('encrypt', _encrypt_entry, parameters, master, password, previous, generate, 'verifier' not in self.book)

    def _expensive_entry(self, entry):
        return entry['memory_kib'] > config.MEMORY_KIB or entry['iterations'] > config.ITERATIONS or entry['lanes'] > config.LANES

    def _confirm_save_cost(self, previous, entry):
        details = []
        if previous is not None and self._expensive_entry(previous):
            details.append(f'读取原密码需要 {_cost_text(previous)}。')
        if self._expensive_entry(entry):
            details.append(f'保存新设置需要 {_cost_text(entry)}。')
        if entry['memory_kib'] >= 128 * 1024:
            details.append('这条记录将超过离线网页查看器的内存上限，需要用桌面端解密。')
            if 'verifier' not in self.book:
                details.append('本次保存还会用同样的参数创建校验样本，整个账本将需要用桌面端验证。')
        if not details:
            return True
        return messagebox.askyesno('确认加密设置', '\n'.join(details + ['继续保存条目吗？']), parent=self.root)

    def _confirm_entry_cost(self, entry, *, creates_verifier=False):
        if not self._expensive_entry(entry):
            return True
        cost = f"内存 {_cost_text(entry)} · {entry['lanes']} 通道。"
        message = f'这次密码计算可能需要较长时间或占用较多内存。\n{cost}'
        if creates_verifier and entry['memory_kib'] >= 128 * 1024:
            message += '\n保存用这些参数创建的校验样本后，整个账本将需要用桌面端验证。'
        message += '\n继续吗？'
        return messagebox.askyesno('解密可能需要更长时间', message, parent=self.root)

    def compute(self, action):
        if action == 'encrypt':
            self._save_entry()
            return
        if self.busy:
            return
        try:
            master = self.master.get()
            if not master:
                raise ValueError('请在顶部输入管理密码。')
            if action == 'unlock':
                if self.unlocked:
                    return
                verifier = self.book.get('verifier')
                # 旧账本尚无样本时，用一条已有密文验证输入。
                entry = None
                if verifier is None:
                    entries = self.book['entries']
                    entry = entries[self.index] if self.index is not None else None
                    if entry is None or not entry['data']:
                        entry = next((item for item in entries if item['data']), None)
                if entry is None and verifier is None:
                    self.unlocked = True
                    self._session_controls()
                    self.status.set('账本已解锁。接下来保存的条目会用这个管理密码加密。')
                    return
                if self._confirm_entry_cost(verifier if verifier is not None else entry, creates_verifier=verifier is None):
                    self._start_job('unlock', _unlock_book, self.book['book_code'], deepcopy(entry), deepcopy(verifier), master)
                return
            elif not self.unlocked:
                raise ValueError('请先点击顶部的“解锁账本”。')
            else:
                if self.index is None:
                    raise ValueError('这条还没有加密密码。请先保存条目。')
                entry = deepcopy(self.book['entries'][self.index])
                password = None
                if not entry['data']:
                    raise ValueError('这条还没有加密密码。请先保存条目。')
                if self.secret_dirty and not messagebox.askyesno('替换密码框里的内容', '解密成功后会替换密码框里尚未保存的内容。继续吗？', parent=self.root):
                    return
            if not self._confirm_entry_cost(entry):
                return
            parameters = dict(book_code=self.book['book_code'], entry=entry)
        except (ValueError, TypeError) as error:
            title = '无法解锁账本' if action == 'unlock' else '无法解密密码'
            messagebox.showerror(title, str(error), parent=self.root)
            return
        self._start_job(action, process, action, parameters, master, password)

    def _start_job(self, action, work, *args):
        self.busy = True
        self.job_action = action
        self.job_index = self.index
        self.job_started = monotonic()
        try:
            self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='vault')
            self.future = self.executor.submit(work, *args)
        except (RuntimeError, OSError):
            if self.executor is not None:
                self.executor.shutdown(wait=False)
            self.executor = None
            self.future = None
            self.busy = False
            self.status.set('无法开始密码操作。')
            messagebox.showerror('无法开始密码操作', '请关闭程序后重新打开，再试一次。', parent=self.root)
            return
        for widget in self.controls:
            widget.state(['disabled'])
        self.notes.configure(state='disabled')
        self.progress.configure(mode='indeterminate', value=0)
        self.progress.start(16)
        self._poll()

    def _poll(self):
        if not self.future.done():
            elapsed = monotonic() - self.job_started
            verb = {'unlock': '解锁账本', 'encrypt': '保存条目', 'decrypt': '解密密码',
                    'verify_rotate': '验证原管理密码', 'rotate': '更换管理密码'}[self.job_action]
            self.status.set(f'正在{verb} · 已用 {elapsed:.1f} 秒。')
            self.root.after(100, self._poll)
            return
        future, self.future = self.future, None
        self.executor.shutdown(wait=False)
        self.executor = None
        self.busy = False
        self.progress.stop()
        self.progress.configure(mode='determinate', value=0)
        for widget in self.controls:
            widget.state(['!disabled'])
        self._session_controls()
        self.notes.configure(state='normal')
        try:
            result = future.result()
        except Exception as error:
            title = {'unlock': '无法解锁账本', 'encrypt': '无法保存条目', 'decrypt': '无法解密密码',
                     'verify_rotate': '原管理密码验证失败', 'rotate': '无法更换管理密码'}[self.job_action]
            self.status.set(f'{title}。')
            detail = str(error)
            if self.job_action == 'decrypt' and isinstance(error, ValueError):
                detail = f'条目校验失败。{detail}\n如果这条来自使用其他管理密码的账本，请在来源账本查看。'
            messagebox.showerror(title, detail, parent=self.root)
            return
        if self.job_action == 'unlock':
            if result is not None:
                self.book = with_verifier(self.book, result)
                self.dirty = True
                self._file_status()
            self.unlocked = True
            self._session_controls()
            self.status.set('已核对旧账本。保存后将使用一个管理密码打开账本。' if result is not None else
                            '账本已解锁。可以解密条目或保存新密码。')
        elif self.job_action == 'verify_rotate':
            self.status.set('原管理密码已验证。')
            self._prompt_new_master(result)
        elif self.job_action == 'rotate':
            self.book, master = result
            self._use_book_password(master)
            self.dirty = True
            if self.index is not None:
                entry = self._current_entry()
                self._show_ciphertext(entry)
                self._show_encryption_settings(entry)
            else:
                self.salt.set('')
                self._show_encryption_settings(self._current_entry())
            self._file_status()
            self.status.set('管理密码已更换。点击“保存账本”写入文件。')
        elif self.job_action == 'encrypt':
            entry, password, verifier = result
            self.book, self.index = self._book_with_entry(entry, self.job_index)
            if verifier is not None:
                self.book = with_verifier(self.book, verifier)
            self.dirty = True
            self._show_entry(self.index, reset_history=False)
            self._set_password(password, saved=True)
            self._refresh_list()
            self._file_status()
            self.status.set('已加密并更新条目。点击“保存账本”写入文件。')
        else:
            self._set_password(result, saved=True)
            self.status.set('密码已解密。可以点击“复制密码”。')

    def copy_password(self):
        if self.busy:
            return
        if not self.password.get():
            self.status.set('密码框为空，没有可复制的密码。')
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(self.password.get())
        self.status.set('密码已复制。')

    def _file_status(self):
        name = self.path.name if self.path else '未保存的账本'
        if self.path is not None and self.dirty:
            name = f'{name}（未保存）'
        self.file_label.set(name)
        self.book_label.set('已设置账本校验样本' if 'verifier' in self.book else '尚未设置账本校验样本')
        self.root.title(f'{name} — {config.TITLE}')

    def show_book_text(self):
        if self.busy:
            return
        if self.book_text_window is not None:
            self.book_text_window.lift()
            self.book_text.focus_set()
            return
        if not self.apply_metadata():
            return
        dialog = tk.Toplevel(self.root)
        self.book_text_window = dialog
        dialog.title('编辑账本文本')
        dialog.geometry('1020x680')
        dialog.minsize(760, 450)
        dialog.configure(background=config.PANEL)
        dialog.transient(self.root)
        dialog.protocol('WM_DELETE_WINDOW', self.close_book_text)
        dialog.bind('<Control-s>', lambda _: self.save_book_text())
        toolbar = ttk.Frame(dialog, padding=12)
        toolbar.pack(fill='x')
        ttk.Button(toolbar, text='保存当前文本', command=self.save_book_text, style='Accent.TButton').pack(side='left', padx=(0, 8))
        ttk.Button(toolbar, text='粘贴并追加…', command=self.show_append_text).pack(side='left')
        ttk.Button(toolbar, text='关闭', command=self.close_book_text).pack(side='right')
        ttk.Label(dialog, text='可直接编辑账本文本。要复制整本，按 Ctrl+A 全选，再按 Ctrl+C。',
                  style='Muted.TLabel', padding=(12, 0, 12, 10)).pack(anchor='w')
        self.book_text = self._text_editor(dialog)
        ttk.Label(dialog, textvariable=self.book_text_status, style='Muted.TLabel', padding=12).pack(
            side='bottom', fill='x', before=self.book_text.master)
        self._show_book_text(text_process('encode', parameters=self.book))
        self.book_text_status.set('点击“保存当前文本”写入账本文件。')
        self.book_text.bind('<<Modified>>', self._book_text_edited)
        dialog.grab_set()
        self.book_text.focus_set()

    def _text_editor(self, dialog):
        frame = ttk.Frame(dialog, padding=(12, 0, 12, 0))
        frame.pack(fill='both', expand=True)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        editor = tk.Text(frame, wrap='none', undo=True, bg='#0e1628', fg=config.FOREGROUND, insertbackground=config.FOREGROUND,
                         relief='flat', font=('Consolas', 10), padx=10, pady=10)
        editor.grid(row=0, column=0, sticky='nsew')
        vertical = ttk.Scrollbar(frame, orient='vertical', command=editor.yview)
        horizontal = ttk.Scrollbar(frame, orient='horizontal', command=editor.xview)
        vertical.grid(row=0, column=1, sticky='ns')
        horizontal.grid(row=1, column=0, sticky='ew')
        editor.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)

        def select_all(event):
            event.widget.tag_add('sel', '1.0', 'end-1c')
            return 'break'

        editor.bind('<Control-a>', select_all)
        return editor

    def _show_book_text(self, text):
        self.book_text.delete('1.0', 'end')
        self.book_text.insert('1.0', text)
        self.book_text.edit_reset()
        self.book_text.edit_modified(False)
        self.book_text_snapshot = text

    def _book_text_edited(self, _event):
        if self.book_text.edit_modified():
            self.book_text.edit_modified(False)
            if self.book_text.get('1.0', 'end-1c') != self.book_text_snapshot:
                self.book_text_status.set('文本有改动。点击“保存当前文本”写入文件。')
            else:
                self.book_text_status.set('点击“保存当前文本”写入账本文件。')

    def save_book_text(self):
        if self.busy or self.book_text is None:
            return False
        dialog = self.book_text_window
        text = self.book_text.get('1.0', 'end-1c')
        try:
            book, writable = text_process('portable', text)
            self._check_text_crypto(book)
        except (ValueError, TypeError) as error:
            messagebox.showerror('无法保存账本文本', str(error), parent=dialog)
            return False
        changed = book != self.book
        if changed and self._pending_encryption() and not self._confirm_discard_secret(parent=dialog):
            return False
        path = self.path or self._choose_book_path(dialog)
        if path is None or not self._write_book_file(path, writable, dialog):
            return False
        was_unlocked = self.unlocked
        if changed:
            self._set_book(book, path)
        else:
            self.path, self.dirty = path, False
            self._file_status()
        if text != writable:
            self._show_book_text(writable)
        else:
            self.book_text_snapshot = text
            self.book_text.edit_modified(False)
        status = f'已保存到“{path.name}”。'
        if changed and was_unlocked:
            status += '账本已锁定，请重新解锁。'
        self.book_text_status.set(status)
        self.status.set(status)
        return True

    def _check_text_crypto(self, book):
        fields = (*self.encryption_fields, 'lanes')
        saved_settings = {}
        for entry in self.book['entries']:
            if entry['data']:
                saved_settings.setdefault(entry['data'], set()).add(tuple(entry[key] for key in fields))
        for entry in book['entries']:
            settings = saved_settings.get(entry['data'])
            if settings and tuple(entry[key] for key in fields) not in settings:
                raise ValueError('现有密文的加密设置被改动了。请恢复原值。要更换设置，请在条目界面重新保存条目。')
        verifier = self.book.get('verifier')
        if verifier is not None and verifier != book.get('verifier'):
            retains_ciphertext = any(entry['data'] in saved_settings for entry in book['entries'])
            if retains_ciphertext or not saved_settings:
                raise ValueError('校验样本已被改动。请恢复原样本。要更换管理密码，请使用管理端的“更换管理密码”。')

    def show_append_text(self):
        if self.busy or self.book_text is None:
            return
        parent = self.book_text_window
        if self.book_text.get('1.0', 'end-1c') != self.book_text_snapshot:
            messagebox.showinfo('账本文本有改动', '请先点击“保存当前文本”，再追加条目。', parent=parent)
            return
        dialog = tk.Toplevel(parent)
        dialog.title('粘贴并追加条目')
        dialog.geometry('760x420')
        dialog.minsize(580, 300)
        dialog.configure(background=config.PANEL)
        dialog.transient(parent)
        ttk.Label(dialog, text='把完整的 [条目] 段粘贴到下方。粘贴整本账本时，只追加其中的条目。',
                  wraplength=520, padding=12).pack(anchor='w')
        editor = self._text_editor(dialog)

        def close_dialog():
            dialog.grab_release()
            dialog.destroy()
            parent.grab_set()
            self.book_text.focus_set()

        def append():
            if self.append_book_text(editor.get('1.0', 'end-1c'), dialog):
                close_dialog()

        toolbar = ttk.Frame(dialog, padding=12)
        toolbar.pack(side='bottom', fill='x', before=editor.master)
        ttk.Button(toolbar, text='追加到当前账本', command=append, style='Accent.TButton').pack(side='left')
        ttk.Button(toolbar, text='取消', command=close_dialog).pack(side='right')
        dialog.protocol('WM_DELETE_WINDOW', close_dialog)
        dialog.grab_set()
        editor.focus_set()

    def append_book_text(self, text, dialog):
        if self.busy or self.book_text is None:
            return False
        if not text.strip():
            messagebox.showinfo('还没有粘贴内容', '请先把要追加的条目粘贴到这个窗口。', parent=dialog)
            return False
        try:
            merged = text_process('append', text, parameters=self.book)
            addition = text_process('decode', merged)['entries'][len(self.book['entries']):]
        except (ValueError, TypeError) as error:
            messagebox.showerror('无法追加条目', str(error), parent=dialog)
            return False
        if not addition:
            messagebox.showinfo('没有可追加的条目', '这段文本里没有 [条目]。请粘贴要追加的条目。', parent=dialog)
            return False
        prior_entries = self.book['entries']
        if not self._leave_entry(parent=dialog):
            return False
        entries = self.book['entries']
        current_text = self.book_text_snapshot if entries is prior_entries else text_process('encode', parameters=self.book)
        if 'verifier' not in self.book and not any(entry['data'] for entry in entries) and any(entry['data'] for entry in addition):
            self.lock_book()
        self.book['entries'] = entries + addition
        self.dirty = True
        self._show_entry(len(entries))
        self.search.set('')
        self._file_status()
        _, _, appended_text = text_process('encode', parameters={**self.book, 'entries': addition}).partition('\n\n')
        separator = '\n' if current_text.endswith('\n') else '\n\n'
        self._show_book_text(current_text + separator + appended_text)
        self.book_text_status.set(f'已追加 {len(addition)} 条。点击“保存当前文本”写入文件。')
        self.status.set(f'已追加 {len(addition)} 条。点击“保存账本”写入文件。')
        return True

    def _confirm_close_book_text(self):
        if self.book_text is not None and self.book_text.get('1.0', 'end-1c') != self.book_text_snapshot:
            return messagebox.askyesno('账本文本尚未保存', '放弃在此窗口对文本的修改并关闭？', parent=self.book_text_window)
        return True

    def close_book_text(self):
        if self.book_text_window is None:
            return True
        if not self._confirm_close_book_text():
            return False
        self.book_text_window.grab_release()
        self.book_text_window.destroy()
        self.book_text_window = None
        self.book_text = None
        self.book_text_snapshot = ''
        return True

    def _leave_book(self):
        changed = self._snapshot() != self.form_snapshot
        if not changed and (not self.dirty or (self.path is None and not self.book['entries'] and 'verifier' not in self.book)):
            return not self._pending_encryption() or self._confirm_discard_secret()
        message = '要先把修改保存到账本文件吗？\n选“否”将放弃未保存的修改。'
        if self._pending_encryption():
            message += '\n密码、随机码或加密设置还有改动。请取消，然后先点击“保存条目”。'
        answer = messagebox.askyesnocancel('账本尚未保存', message, parent=self.root)
        return answer is not None and (not answer or self.save(confirm_secret=False))

    def _set_book(self, book, path=None, dirty=False):
        self.lock_book()
        self.book = book
        self.path = path
        self.dirty = dirty
        self._show_entry(0 if book['entries'] else None)
        self.search.set('')
        self._file_status()

    def new_book(self):
        if self.busy or not self._leave_book():
            return
        self._set_book(text_process('decode', text_process('new')))
        self.status.set('已新建账本。可以直接填写第一条。')

    def open_book(self):
        if self.busy:
            return
        name = filedialog.askopenfilename(parent=self.root, title='打开账本', filetypes=[('密码账本', '*.vault'), ('文本文件', '*.txt'), ('全部文件', '*')])
        if not name:
            return
        path = Path(name)
        try:
            book = text_process('decode', path.read_text(encoding='utf-8-sig'))
            if not self._leave_book():
                return
            if self.path is not None and path.resolve() == self.path.resolve():
                # 保存当前账本可能刚替换了要打开的文件。
                book = text_process('decode', path.read_text(encoding='utf-8-sig'))
        except UnicodeError:
            messagebox.showerror('无法打开账本', '请选择用 UTF-8 保存的账本文本文件。', parent=self.root)
            return
        except OSError:
            messagebox.showerror('无法打开账本', f'无法读取“{path.name}”。请检查文件是否还在，或是否有权限读取。', parent=self.root)
            return
        except (ValueError, TypeError) as error:
            messagebox.showerror('无法读取账本内容', str(error), parent=self.root)
            return
        self._set_book(book, path)
        self.status.set('账本已打开。解锁后可以查看条目密码。')

    def save(self, as_new=False, *, confirm_secret=True):
        if self.busy:
            return False
        if confirm_secret and self._pending_encryption():
            message = '密码、随机码或加密设置还有改动。\n继续保存账本文件时，这些改动会留在编辑框里。'
            if not messagebox.askyesno('条目有未保存的修改', message, parent=self.root):
                return False
        path = self.path
        if path is None or as_new:
            path = self._choose_book_path(self.root)
            if path is None:
                return False
        book, index = self.book, self.index
        changed = self._snapshot() != self.form_snapshot
        try:
            if changed:
                book, index = self._book_with_entry(self._read_entry(), self.index)
            text = text_process('encode', parameters=book)
        except (ValueError, TypeError) as error:
            messagebox.showerror('无法保存账本', str(error), parent=self.root)
            return False
        if not self._write_book_file(path, text, self.root):
            return False
        self.book, self.index = book, index
        if changed:
            self._sync_metadata()
        self.path = path
        self.dirty = False
        self._file_status()
        self.status.set(f'账本已保存到“{path.name}”。')
        return True

    def _choose_book_path(self, parent):
        name = filedialog.asksaveasfilename(parent=parent, title='保存账本', defaultextension='.vault',
                                             filetypes=[('密码账本', '*.vault'), ('文本文件', '*.txt')])
        return Path(name) if name else None

    def _write_book_file(self, path, text, parent):
        temporary = None
        try:
            with NamedTemporaryFile(mode='w', encoding='utf-8', newline='\n', dir=path.parent, prefix=f'.{path.name}.', suffix='.tmp', delete=False) as output:
                temporary = Path(output.name)
                output.write(text)
            temporary.replace(path)
        except (OSError, ValueError, TypeError) as error:
            if isinstance(error, PermissionError):
                detail = f'无法写入“{path.name}”。请检查文件是否被占用，或另选一个可写入的位置。'
            elif isinstance(error, FileNotFoundError):
                detail = '保存位置已不存在，请另选一个位置。'
            else:
                detail = f'无法写入“{path.name}”。请检查保存位置后重试。'
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    detail += f'\n未能删除临时文件“{temporary.name}”。'
            messagebox.showerror('无法保存账本', detail, parent=parent)
            return False
        return True

    def close(self):
        if self.busy:
            messagebox.showinfo('密码操作正在进行', '请等本次操作完成后再关闭窗口。', parent=self.root)
            return
        if self._confirm_close_book_text() and self._leave_book():
            self.lock_book()
            self.root.destroy()
