"""实际 Tk 控件与状态转换测试；测试专用低成本参数，不修改发布配置。"""

from pathlib import Path
from copy import deepcopy
from tempfile import TemporaryDirectory
from time import monotonic, sleep
from unittest.mock import patch
import unittest

from core import process, text_process, verify_master

try:
    import tkinter as tk
except ImportError:
    tk = None
if tk is not None:
    from gui.window import Window, _NewMasterDialog


@unittest.skipIf(tk is None, '当前 Python 未提供 Tkinter')
class GuiTests(unittest.TestCase):
    def setUp(self):
        try:
            self.root = tk.Tk()
        except tk.TclError as error:
            self.skipTest(f'当前环境没有可用的 Tk 桌面：{error}')
        self.parameters = patch.multiple('config', MEMORY_KIB=32, ITERATIONS=1, LANES=1)
        self.parameters.start()
        self.window = Window(self.root)
        self.root.update()
        self.errors = patch('gui.window.messagebox.showerror')
        self.error_message = self.errors.start()

    def tearDown(self):
        if not hasattr(self, 'window'):
            return
        if self.window.executor is not None:
            self.window.executor.shutdown(wait=True)
        self.errors.stop()
        self.parameters.stop()
        self.root.destroy()

    def _wait(self):
        deadline = monotonic() + 10
        while self.window.busy and monotonic() < deadline:
            self.root.update()
            sleep(.005)
        self.assertFalse(self.window.busy)

    def _encrypt(self):
        window = self.window
        window.new_entry()
        window.fields['service'].set('百度')
        window.fields['username'].set('jassor')
        window.password.set('Synthetic-site-pass1!')
        window.master.set('Synthetic-master-1!')
        window.unlock_book()
        self.assertTrue(window.unlocked)

        def delayed_process(*args, **kwargs):
            sleep(.05)
            return process(*args, **kwargs)

        with patch('gui.window.process', side_effect=delayed_process):
            window.compute('encrypt')
            self.assertTrue(window.busy)
            self.assertEqual(window.master.get(), 'Synthetic-master-1!')
            self.assertTrue(all(widget.instate(['disabled']) for widget in window.controls))
            window.lock_book()
            self.assertTrue(window.unlocked)
            self._wait()
        self.error_message.assert_not_called()
        self.assertTrue(window.book['entries'][0]['data'])
        self.assertEqual(window.password.get(), 'Synthetic-site-pass1!')
        self.assertFalse(window.secret_dirty)
        self.assertIsNone(window.executor)
        self.assertTrue(all(not widget.instate(['disabled']) for widget in window.controls if widget is not window.unlock_button))
        self.assertTrue(window.master_entry.instate(['readonly']))
        self.assertTrue(window.unlock_button.instate(['disabled']))

    def test_layout_and_new_book_do_not_derive(self):
        with patch('gui.window.process') as compute, patch('gui.window.messagebox.askyesnocancel') as ask:
            self.window.new_book()
            self.assertTrue(self.window.apply_metadata())
            self.assertTrue(self.window._leave_book())
            self.assertEqual(self.window.book['entries'], [])
            self.assertEqual(self.window.entry_title.get(), '新建条目')
            self.root.update()
            compute.assert_not_called()
            ask.assert_not_called()

    def test_short_window_keeps_sidebar_actions_and_scrolls_detail(self):
        window = self.window
        self.root.geometry('1100x640')
        window.book['entries'] = [window._blank_entry() for _ in range(20)]
        window._refresh_list()
        self.root.update()
        for button in (item for item in window.controls if item.winfo_class() == 'TButton'):
            if button.cget('text') in ('新增条目', '删除条目', '更换管理密码'):
                self.assertTrue(button.winfo_ismapped())
                self.assertEqual(button.winfo_height(), button.winfo_reqheight())
                self.assertEqual(button.winfo_width(), button.winfo_reqwidth())
        self.assertLess(window.tree.yview()[1], 1)
        window.tree.yview_moveto(1)
        self.assertGreater(window.tree.yview()[0], 0)
        canvas = window.detail_canvas
        self.assertLess(canvas.yview()[1], 1)
        canvas.yview_moveto(1)
        self.root.update()
        last_row = window.ciphertext.master.winfo_children()[-1]
        self.assertLessEqual(last_row.winfo_rooty() + last_row.winfo_height(), canvas.winfo_rooty() + canvas.winfo_height())

    def test_blank_password_does_not_overwrite_ciphertext(self):
        self._encrypt()
        window = self.window
        original = deepcopy(window.book)
        window.clear_secret()
        window.compute('encrypt')
        self.assertFalse(window.busy)
        self.assertEqual(window.book, original)
        self.assertIn('密码框为空', self.error_message.call_args.args[1])

    def test_change_book_password_preserves_passwords_and_replaces_all_ciphertexts(self):
        self._encrypt()
        window = self.window
        old_master, new_master = 'Synthetic-master-1!', 'new synthetic master'
        second = process('encrypt', dict(book_code=window.book['book_code'], entry=window._blank_entry()), old_master, '保留原密码')
        draft = window._blank_entry()
        window.book['entries'].extend([second, draft])
        original = deepcopy(window.book)
        window.fields['nickname'].set('尚未应用的资料')
        with patch('gui.window.simpledialog.askstring', return_value='wrong old master') as old_prompt, \
                patch('gui.window._NewMasterDialog') as new_prompt:
            window.change_book_password()
            self._wait()
        old_prompt.assert_called_once()
        new_prompt.assert_not_called()
        self.assertEqual(window.master.get(), old_master)
        self.assertEqual(window.book, original)
        self.error_message.assert_called_once()
        self.assertEqual(self.error_message.call_args.args[0], '原管理密码验证失败')
        self.error_message.reset_mock()
        with patch('gui.window.simpledialog.askstring', return_value=old_master) as old_prompt, \
                patch('gui.window._NewMasterDialog') as new_prompt:
            new_prompt.return_value.result = new_master
            window.change_book_password()
            self._wait()
        old_prompt.assert_called_once()
        new_prompt.assert_called_once_with(self.root, old_master)
        self.error_message.assert_not_called()
        self.assertTrue(window.dirty and window.unlocked)
        self.assertEqual(window.master.get(), new_master)
        self.assertTrue(verify_master(window.book['verifier'], new_master))
        self.assertNotEqual(window.book['verifier']['salt'], original['verifier']['salt'])
        with self.assertRaises(ValueError):
            verify_master(window.book['verifier'], old_master)
        self.assertEqual(window.fields['nickname'].get(), '尚未应用的资料')
        self.assertEqual(window.book['entries'][2], draft)
        for index, expected in enumerate(('Synthetic-site-pass1!', '保留原密码')):
            entry = window.book['entries'][index]
            old = original['entries'][index]
            self.assertNotEqual(entry['salt'], old['salt'])
            self.assertNotEqual(entry['data'], old['data'])
            self.assertEqual({**entry, 'salt': old['salt'], 'data': old['data']}, old)
            parameters = dict(book_code=window.book['book_code'], entry=entry)
            self.assertEqual(process('decrypt', parameters, new_master), expected)
            with self.assertRaisesRegex(ValueError, '管理密码错误'):
                process('decrypt', parameters, old_master)
        with TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            window.path = Path(directory) / 'rotated.vault'
            self.assertTrue(window.save())
            text = window.path.read_text(encoding='utf-8')
            self.assertEqual(text_process('decrypt', text, 0, new_master), 'Synthetic-site-pass1!')
            self.assertNotIn(new_master, text)
            self.assertEqual(text_process('decode', text)['entries'][0]['nickname'], '尚未应用的资料')

    def test_change_book_password_keeps_every_entry_on_mixed_password_failure(self):
        self._encrypt()
        window = self.window
        foreign = process('encrypt', dict(book_code=window.book['book_code'], entry=window._blank_entry()), 'other master', 'other password')
        window.book['entries'].append(foreign)
        window.dirty = False
        original = deepcopy(window.book)
        with patch('gui.window.simpledialog.askstring', return_value='Synthetic-master-1!'), \
                patch('gui.window._NewMasterDialog') as new_prompt:
            new_prompt.return_value.result = 'new master'
            window.change_book_password()
            self._wait()
        new_prompt.assert_called_once_with(self.root, 'Synthetic-master-1!')
        self.assertEqual(window.book, original)
        self.assertFalse(window.dirty)
        self.assertEqual(window.master.get(), 'Synthetic-master-1!')
        self.assertIn('第 2 条', self.error_message.call_args.args[1])

    def test_legacy_change_password_checks_first_encrypted_entry_before_prompt(self):
        window = self.window
        code = window.book['book_code']
        draft = window._blank_entry()
        first = process('encrypt', dict(book_code=code, entry=draft), 'first synthetic master', 'first synthetic site password')
        selected = process('encrypt', dict(book_code=code, entry=draft), 'selected synthetic master', 'selected synthetic site password')
        book = dict(version=1, book_code=code, entries=[draft, first, selected])
        window._set_book(book)
        window._show_entry(2)

        with patch('gui.window.simpledialog.askstring', return_value='selected synthetic master'), \
                patch('gui.window._NewMasterDialog') as new_prompt:
            window.change_book_password()
            self._wait()
        new_prompt.assert_not_called()
        self.error_message.assert_called_once()
        self.assertEqual(self.error_message.call_args.args[0], '原管理密码验证失败')
        self.assertEqual(window.book, book)
        self.assertFalse(window.unlocked)

    def test_cancel_new_master_after_verification_preserves_current_state(self):
        self._encrypt()
        window = self.window
        old_master = window.master.get()
        original = deepcopy(window.book)
        window.dirty = False
        window.password.set('unsaved synthetic site password')
        window.salt.set('ab' * 16)
        with patch('gui.window.simpledialog.askstring', return_value=old_master), \
                patch('gui.window.verify_master', wraps=verify_master) as authenticate, \
                patch('gui.window._NewMasterDialog') as new_prompt, \
                patch('gui.window._reencrypt_book') as rotate:
            def cancel_new_prompt(_parent, _old_master):
                authenticate.assert_called_once_with(original['verifier'], old_master)
                return new_prompt.return_value

            new_prompt.side_effect = cancel_new_prompt
            new_prompt.return_value.result = None
            window.change_book_password()
            self._wait()
        new_prompt.assert_called_once_with(self.root, old_master)
        rotate.assert_not_called()
        self.error_message.assert_not_called()
        self.assertEqual(window.book, original)
        self.assertEqual(window.master.get(), old_master)
        self.assertEqual(window.password.get(), 'unsaved synthetic site password')
        self.assertEqual(window.salt.get(), 'ab' * 16)
        self.assertTrue(window.unlocked)
        self.assertFalse(window.dirty)

    def test_new_master_dialog_has_one_masked_input_and_reveals_without_editing(self):
        password = ' synthetic new master 🙂 '
        observations = {}

        def exercise_dialog():
            dialog = next(child for child in self.root.winfo_children() if isinstance(child, _NewMasterDialog))
            try:
                widgets = dialog.entry.master.winfo_children()
                observations['inputs'] = sum(isinstance(widget, tk.Entry) for widget in widgets)
                toggle = next(widget for widget in widgets if isinstance(widget, tk.Checkbutton))
                observations['masked'] = dialog.entry.cget('show')
                dialog.entry.insert(0, password)
                toggle.invoke()
                observations['revealed'] = dialog.entry.cget('show')
                observations['visible_value'] = dialog.entry.get()
                toggle.invoke()
                observations['hidden_again'] = dialog.entry.cget('show')
                observations['hidden_value'] = dialog.entry.get()
            except Exception as error:
                observations['error'] = error
            finally:
                if 'error' in observations:
                    dialog.cancel()
                else:
                    dialog.ok()

        self.root.after(50, exercise_dialog)
        dialog = _NewMasterDialog(self.root, 'synthetic old master')
        self.assertNotIn('error', observations)
        self.assertEqual(observations, dict(inputs=1, masked='•', revealed='', visible_value=password,
                                            hidden_again='•', hidden_value=password))
        self.assertEqual(dialog.result, password)

    def test_async_encrypt_decrypt_and_wrong_master(self):
        self._encrypt()
        window = self.window
        window.compute('decrypt')
        self._wait()
        self.assertEqual(window.password.get(), 'Synthetic-site-pass1!')
        self.assertFalse(window.secret_dirty)
        ciphertext = window.book['entries'][0]['data']
        window.lock_book()
        window.master.set('incorrect')
        window.unlock_book()
        self._wait()
        self.assertEqual(window.password.get(), '')
        self.assertFalse(window.unlocked)
        self.assertFalse(window.master_entry.instate(['readonly']))
        self.assertEqual(window.book['entries'][0]['data'], ciphertext)
        self.error_message.assert_called_once()
        self.error_message.reset_mock()
        window.compute('encrypt')
        self.assertFalse(window.busy)
        self.error_message.assert_called_once()
        self.assertEqual(window.book['entries'][0]['data'], ciphertext)

    def test_save_on_leave_includes_form_metadata_and_keeps_cipher_algorithm(self):
        self._encrypt()
        window = self.window
        original = window.book['entries'][0].copy()
        window.algorithm.set('AES-256-GCM')
        window.fields['nickname'].set('大马')
        self.assertTrue(window.apply_metadata())
        self.assertEqual(window.book['entries'][0]['algorithm'], original['algorithm'])
        self.assertEqual(window.book['entries'][0]['data'], original['data'])
        window.fields['service'].set('待保存的资料')
        with TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            window.path = Path(directory) / 'ledger.vault'
            with patch('gui.window.messagebox.askyesnocancel', return_value=True) as ask:
                self.assertTrue(window._leave_book())
            ask.assert_called_once()
            decoded = text_process('decode', window.path.read_text(encoding='utf-8'))
            self.assertEqual(decoded['entries'][0]['service'], '待保存的资料')
            self.assertEqual(decoded['entries'][0]['algorithm'], original['algorithm'])
            self.assertEqual(decoded['entries'][0]['data'], original['data'])
            self.assertFalse(window.dirty)

    def test_cancel_preserves_secret_and_current_book(self):
        window = self.window
        window.new_entry()
        window.fields['service'].set('尚未应用')
        window.password.set('unsaved secret')
        with patch('gui.window.messagebox.askyesnocancel', return_value=False), patch('gui.window.messagebox.askyesno', return_value=False):
            self.assertFalse(window._leave_entry())
        self.assertEqual(window.fields['service'].get(), '尚未应用')
        self.assertEqual(window.password.get(), 'unsaved secret')
        window.clear_secret()
        window.fields['service'].set('改名后取消打开')
        original = window.book
        with patch('gui.window.messagebox.askyesnocancel') as ask, patch('gui.window.filedialog.askopenfilename', return_value=''):
            window.open_book()
        ask.assert_not_called()
        self.assertIs(window.book, original)
        self.assertEqual(window.fields['service'].get(), '改名后取消打开')
        self.assertNotEqual(window._snapshot(), window.form_snapshot)
        self.assertTrue(window.dirty)

    def test_empty_book_draft_generates_and_encrypts_without_manual_entry(self):
        window = self.window
        window.fields['service'].set('直接填写的服务')
        self.assertTrue(window.generate_button.instate(['disabled']))
        self.assertEqual(window.password_entry.cget('show'), '')
        window.generate()
        self.assertEqual(window.book['entries'], [])
        self.assertEqual(window.password.get(), '')
        self.error_message.assert_called_once()
        self.error_message.reset_mock()
        window.master.set('test draft master')
        window.unlock_book()
        self.assertFalse(window.generate_button.instate(['disabled']))
        window.generate()
        self._wait()
        generated = window.password.get()
        salt = window.salt.get()
        self.assertTrue(generated)
        self.assertEqual(len(salt), 32)
        self.assertFalse(window.secret_dirty)
        self.assertEqual(window.password_badge.cget('style'), 'Saved.TLabel')
        self.assertEqual(window.salt_badge.cget('style'), 'Saved.TLabel')
        self.assertEqual(window.index, 0)
        self.assertEqual(len(window.book['entries']), 1)
        self.assertEqual(window.book['entries'][0]['service'], '直接填写的服务')
        self.assertEqual(window.book['entries'][0]['salt'], salt)
        window.compute('decrypt')
        self._wait()
        self.assertEqual(window.password.get(), generated)
        self.error_message.assert_not_called()

    def test_save_entry_uses_current_salt_and_can_preserve_existing_password(self):
        self._encrypt()
        window = self.window
        window.salt.set('a0' * 16)
        window.salt.set('b1' * 16)
        window.compute('decrypt')
        self._wait()
        self.assertEqual(window.password.get(), 'Synthetic-site-pass1!')
        self.assertEqual(window.salt_badge.cget('style'), 'Pending.TLabel')
        window.clear_secret()
        window._save_entry()
        self._wait()
        entry = window.book['entries'][0]
        self.assertEqual(entry['salt'], 'b1' * 16)
        self.assertEqual(window.salt.get(), entry['salt'])
        self.assertEqual(window.salt_badge.cget('style'), 'Saved.TLabel')
        self.assertEqual(process('decrypt', dict(book_code=window.book['book_code'], entry=entry), window.master.get()), 'Synthetic-site-pass1!')
        window.password.set('manually edited password')
        window.salt.set('C2' * 16)
        window._save_entry()
        self._wait()
        entry = window.book['entries'][0]
        self.assertEqual(entry['salt'], 'C2' * 16)
        self.assertEqual(process('decrypt', dict(book_code=window.book['book_code'], entry=entry), window.master.get()), 'manually edited password')
        window.salt.set('aB' * 16)
        window.generate()
        self._wait()
        self.assertNotEqual(window.book['entries'][0]['salt'], entry['salt'])
        self.assertNotEqual(window.book['entries'][0]['salt'], 'aB' * 16)
        self.assertEqual(window.salt.get(), window.book['entries'][0]['salt'])
        previous_salt = window.salt.get()
        window.generate()
        self._wait()
        self.assertNotEqual(window.salt.get(), previous_salt)
        self.error_message.assert_not_called()

    def test_input_history_survives_save_and_clears_at_lock(self):
        self._encrypt()
        window = self.window
        old_password = window.password.get()
        old_salt = window.salt.get()
        for index in range(150):
            window.password.set(f'edit {index}')
        window.salt.set('ab' * 16)
        window._save_entry()
        self._wait()
        saved = deepcopy(window.book)
        for _ in range(150):
            window._move_input_history(window.password, window.password_history, -1)
        self.assertEqual(window.password.get(), old_password)
        self.assertEqual(window.password_badge.cget('style'), 'Pending.TLabel')
        self.assertEqual(window.salt_badge.cget('style'), 'Saved.TLabel')
        for _ in range(150):
            window._move_input_history(window.password, window.password_history, 1)
        self.assertEqual(window.password.get(), 'edit 149')
        self.assertEqual(window.password_badge.cget('style'), 'Saved.TLabel')
        window._move_input_history(window.salt, window.salt_history, -1)
        self.assertEqual(window.salt.get(), old_salt)
        self.assertEqual(window.salt_badge.cget('style'), 'Pending.TLabel')
        self.assertEqual(window.book, saved)
        window._move_input_history(window.salt, window.salt_history, 1)
        self.assertEqual(window.salt.get(), 'ab' * 16)
        self.assertEqual(window.salt_badge.cget('style'), 'Saved.TLabel')
        window.lock_book()
        window._move_input_history(window.password, window.password_history, -1)
        window._move_input_history(window.salt, window.salt_history, -1)
        self.assertEqual(window.password.get(), '')
        self.assertEqual(window.salt.get(), 'ab' * 16)

    def test_save_entry_failure_preserves_pending_password_and_salt(self):
        self._encrypt()
        window = self.window
        original = deepcopy(window.book)
        window.password.set('pending manual password')
        window.salt.set('invalid salt')
        window._save_entry()
        self._wait()
        self.assertEqual(window.book, original)
        self.assertEqual(window.password.get(), 'pending manual password')
        self.assertEqual(window.salt.get(), 'invalid salt')
        self.assertEqual(window.password_badge.cget('style'), 'Pending.TLabel')
        self.assertEqual(window.salt_badge.cget('style'), 'Pending.TLabel')
        self.assertIn('随机码', self.error_message.call_args.args[1])
        with patch('gui.window.process', side_effect=ValueError('模拟生成失败')):
            window.generate()
            self._wait()
        self.assertEqual(window.book, original)
        self.assertEqual(window.password.get(), 'pending manual password')
        self.assertEqual(window.salt.get(), 'invalid salt')

    def test_switch_book_keeps_draft_until_save_succeeds(self):
        window = self.window
        window.fields['service'].set('未提交的首条')
        window.password.set('pending clear text')
        current = window.book
        with TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            new_path = Path(directory) / 'another.vault'
            new_book = dict(version=1, book_code='ab' * 16, entries=[
                dict(window._blank_entry(), service='第一条'),
                dict(window._blank_entry(), service='第二条'),
            ])
            new_path.write_text(text_process('encode', parameters=new_book), encoding='utf-8')
            save_path = Path(directory) / 'draft.vault'
            with patch('gui.window.filedialog.askopenfilename', return_value=str(new_path)):
                with patch('gui.window.messagebox.askyesnocancel', return_value=None):
                    window.open_book()
                self.assertIs(window.book, current)
                self.assertEqual(window.fields['service'].get(), '未提交的首条')
                self.assertEqual(window.password.get(), 'pending clear text')
                with patch('gui.window.messagebox.askyesnocancel', return_value=True), patch('gui.window.filedialog.asksaveasfilename', return_value=''):
                    window.open_book()
                self.assertIs(window.book, current)
                self.assertEqual(window.password.get(), 'pending clear text')
                with patch('gui.window.messagebox.askyesnocancel', return_value=True) as ask, patch('gui.window.filedialog.asksaveasfilename', return_value=str(save_path)):
                    window.open_book()
                ask.assert_called_once()
            saved = save_path.read_text(encoding='utf-8')
            self.assertNotIn('pending clear text', saved)
            self.assertEqual(text_process('decode', saved)['entries'][0]['service'], '未提交的首条')
            self.assertEqual(window.book, new_book)
            self.assertEqual(window.index, 0)
            self.assertEqual(window.fields['service'].get(), '第一条')
            self.assertEqual(window.password.get(), '')
            with patch('gui.window.messagebox.askyesnocancel') as ask:
                window.new_book()
            ask.assert_not_called()
            self.assertEqual(window.book['entries'], [])

    def test_reopen_same_file_and_save_last_entry_deletion(self):
        window = self.window
        window.fields['service'].set('初次保存')
        with TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            window.path = Path(directory) / 'ledger.vault'
            self.assertTrue(window.save())
            window.fields['service'].set('重新打开前保存')
            with patch('gui.window.filedialog.askopenfilename', return_value=str(window.path)), patch('gui.window.messagebox.askyesnocancel', return_value=True):
                window.open_book()
            self.assertEqual(window.fields['service'].get(), '重新打开前保存')
            with patch('gui.window.messagebox.askyesno') as confirm:
                window.delete_entry()
            confirm.assert_not_called()
            self.assertEqual(window.entry_title.get(), '新建条目')
            self.assertEqual(window.book['entries'], [])
            with patch('gui.window.messagebox.askyesnocancel', return_value=True) as ask:
                window.new_book()
            ask.assert_called_once()
            saved = Path(directory, 'ledger.vault').read_text(encoding='utf-8')
            self.assertEqual(text_process('decode', saved)['entries'], [])

    def test_delete_encrypted_entry_requires_confirmation(self):
        self._encrypt()
        window = self.window
        original = deepcopy(window.book)
        with patch('gui.window.messagebox.askyesno', return_value=False) as confirm:
            window.delete_entry()
        confirm.assert_called_once()
        self.assertEqual(window.book, original)
        with patch('gui.window.messagebox.askyesno', return_value=True) as confirm:
            window.delete_entry()
        confirm.assert_called_once()
        self.assertEqual(window.book['entries'], [])

    def test_atomic_save_contains_no_secrets_and_failure_retains_original(self):
        self._encrypt()
        window = self.window
        with TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            window.path = Path(directory) / 'ledger.vault'
            self.assertTrue(window.save())
            saved = window.path.read_text(encoding='utf-8')
            self.assertEqual(text_process('decode', saved), window.book)
            self.assertNotIn('Synthetic-site-pass1!', saved)
            self.assertNotIn('Synthetic-master-1!', saved)
            window.fields['nickname'].set('修改')
            with patch('pathlib.Path.replace', side_effect=OSError('模拟替换失败')):
                self.assertFalse(window.save())
            self.assertEqual(window.path.read_text(encoding='utf-8'), saved)
            self.assertEqual(window.book, text_process('decode', saved))
            self.assertEqual(window.fields['nickname'].get(), '修改')
            self.assertNotEqual(window._snapshot(), window.form_snapshot)
            self.assertEqual(list(Path(directory).glob('*.tmp')), [])

    def test_expensive_record_confirmation_precedes_worker(self):
        self._encrypt()
        window = self.window
        window.book['entries'][0]['memory_kib'] = 64
        window.master.set('Synthetic-master-1!')
        with patch('gui.window.messagebox.askyesno', return_value=False) as ask, patch('gui.window.process') as compute:
            window.compute('decrypt')
        ask.assert_called_once()
        compute.assert_not_called()
        self.assertFalse(window.busy)
        self.assertEqual(window.master.get(), 'Synthetic-master-1!')

    def test_thread_start_failure_restores_idle_state(self):
        window = self.window
        window.new_entry()
        window.master.set('Synthetic-master-1!')
        window.unlock_book()
        window.password.set('Synthetic-site-pass1!')
        with patch('gui.window.ThreadPoolExecutor', side_effect=RuntimeError('模拟线程启动失败')):
            window.compute('encrypt')
        self.assertFalse(window.busy)
        self.assertIsNone(window.executor)
        self.assertIsNone(window.future)
        self.assertEqual(window.master.get(), 'Synthetic-master-1!')
        self.assertEqual(window.password.get(), 'Synthetic-site-pass1!')
        self.assertTrue(window.unlocked)
        self.assertTrue(window.master_entry.instate(['readonly']))
        self.error_message.assert_called_once()

    def test_one_unlock_covers_multiple_entries_and_clear_only_hides_site_password(self):
        self._encrypt()
        window = self.window
        window.new_entry()
        window.fields['service'].set('第二个服务')
        window.password.set('second site password')
        self.assertEqual(window.master.get(), 'Synthetic-master-1!')
        window.compute('encrypt')
        self._wait()
        self.assertEqual(len(window.book['entries']), 2)
        for index, expected in enumerate(('Synthetic-site-pass1!', 'second site password')):
            window._show_entry(index)
            self.assertEqual(window.password.get(), '')
            self.assertTrue(window.unlocked)
            window.compute('decrypt')
            self._wait()
            self.assertEqual(window.password.get(), expected)
            window.clear_secret()
            self.assertEqual(window.password.get(), '')
            self.assertEqual(window.master.get(), 'Synthetic-master-1!')
        self.error_message.assert_not_called()

    def test_legacy_unlock_checks_selected_entry_before_creating_verifier(self):
        self._encrypt()
        window = self.window
        window._set_book(dict(version=1, book_code='bc' * 16, entries=window.book['entries']))
        master = 'another synthetic master'
        source_code = 'ab' * 16
        entry = process('encrypt', dict(book_code=source_code, entry=window._blank_entry()), master, 'imported secret')
        text = text_process('encode', parameters=dict(version=1, book_code=source_code, entries=[entry]))
        window.show_book_text()
        self.assertTrue(window.append_book_text(text[text.index('[条目]'):], window.book_text_window))
        self.assertTrue(window.close_book_text())
        self.assertEqual(window.book['entries'][1], entry)
        self.assertEqual(window.index, 1)
        window.lock_book()
        window.master.set('wrong password')
        window.unlock_book()
        self._wait()
        self.assertFalse(window.unlocked)
        self.assertNotIn('verifier', window.book)
        self.error_message.assert_called_once()
        self.error_message.reset_mock()
        window.master.set(master)
        with patch('gui.window.process', wraps=process) as compute:
            window.unlock_book()
            self._wait()
        compute.assert_called_once()
        self.assertEqual(compute.call_args.args[0], 'decrypt')
        self.assertEqual(compute.call_args.args[1]['entry'], entry)
        self.assertTrue(window.unlocked)
        self.assertEqual(window.book['version'], 3)
        self.assertEqual(window.book['entries'][1], entry)
        self.assertTrue(verify_master(window.book['verifier'], master))
        self.assertEqual(window.password.get(), '')
        self.assertEqual(window.index, 1)
        window.compute('decrypt')
        self._wait()
        self.assertEqual(window.password.get(), 'imported secret')
        self.error_message.assert_not_called()

    def test_new_format_uses_header_with_a_foreign_or_damaged_selected_entry(self):
        self._encrypt()
        window = self.window
        entry = process('encrypt', dict(book_code='ab' * 16, entry=window._blank_entry()), 'foreign master', 'foreign password')
        window.book['entries'].append(entry)
        window._show_entry(1)
        window.lock_book()
        window.master.set('foreign master')
        window.unlock_book()
        self._wait()
        self.assertFalse(window.unlocked)
        self.assertEqual(window.password.get(), '')
        window.master.set('Synthetic-master-1!')
        with patch('gui.window.process', side_effect=AssertionError('解锁新版账本不应解密条目')):
            window.unlock_book()
            self._wait()
        self.assertTrue(window.unlocked)
        self.assertEqual(window.password.get(), '')
        window.compute('decrypt')
        self._wait()
        self.assertIn('条目校验失败', self.error_message.call_args.args[1])
        self.assertTrue(window.unlocked)
        window.lock_book()
        sample = window.book['verifier']
        first = 'A' if sample['data'][0] != 'A' else 'B'
        sample['data'] = first + sample['data'][1:]
        window.master.set('Synthetic-master-1!')
        with patch('gui.window.process', side_effect=AssertionError('校验样本失败也不能回退到条目')):
            window.unlock_book()
            self._wait()
        self.assertFalse(window.unlocked)
        self.assertIn('校验样本', self.error_message.call_args.args[1])

    def test_empty_book_can_set_and_persist_an_independent_verifier(self):
        window = self.window
        master = 'explicit synthetic master'
        with patch('gui.window.simpledialog.askstring') as old_prompt, patch('gui.window._NewMasterDialog') as new_prompt:
            new_prompt.return_value.result = master
            window.change_book_password()
            self._wait()
        old_prompt.assert_not_called()
        new_prompt.assert_called_once_with(self.root, None)
        self.assertTrue(window.unlocked)
        self.assertTrue(window.dirty)
        self.assertEqual(window.book['entries'], [])
        self.assertTrue(verify_master(window.book['verifier'], master))
        with patch('gui.window.messagebox.askyesnocancel', return_value=None) as leave:
            window.new_book()
        leave.assert_called_once()
        with TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            window.path = Path(directory) / 'empty.vault'
            self.assertTrue(window.save())
            book = text_process('decode', window.path.read_text(encoding='utf-8'))
            self.assertEqual(book, window.book)
        window.lock_book()
        window.master.set('wrong password')
        window.unlock_book()
        self._wait()
        self.assertFalse(window.unlocked)
        window.master.set(master)
        window.unlock_book()
        self._wait()
        self.assertTrue(window.unlocked)

    def test_empty_book_unlock_does_not_compute_and_lock_clears_session(self):
        window = self.window
        window.master.set('fresh book master')
        with patch('gui.window.process') as compute:
            window.unlock_book()
            window.new_entry()
            compute.assert_not_called()
        self.assertTrue(window.unlocked)
        self.assertEqual(window.master.get(), 'fresh book master')
        window.password.set('temporary site password')
        window.lock_book()
        self.assertEqual(window.master.get(), '')
        self.assertEqual(window.password.get(), '')
        self.assertFalse(window.unlocked)
        self.assertFalse(window.master_entry.instate(['readonly']))

    def test_new_open_cancel_and_failed_open_have_correct_session_scope(self):
        self._encrypt()
        window = self.window
        with patch('gui.window.messagebox.askyesnocancel', return_value=None):
            window.new_book()
        self.assertTrue(window.unlocked)
        window.dirty = False
        with patch('gui.window.filedialog.askopenfilename', return_value=''):
            window.open_book()
        self.assertTrue(window.unlocked)
        with TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            path = Path(directory) / 'another.vault'
            path.write_text('invalid book', encoding='utf-8')
            with patch('gui.window.filedialog.askopenfilename', return_value=str(path)):
                window.open_book()
            self.assertTrue(window.unlocked)
            self.assertEqual(window.master.get(), 'Synthetic-master-1!')
            path.write_text(text_process('encode', parameters=window.book), encoding='utf-8')
            with patch('gui.window.filedialog.askopenfilename', return_value=str(path)):
                window.open_book()
            self.assertFalse(window.unlocked)
            self.assertEqual(window.master.get(), '')
            self.assertEqual(window.salt.get(), window.book['entries'][0]['salt'])
            self.assertEqual(window.salt_badge.cget('style'), 'Saved.TLabel')
            self.assertFalse(window._pending_encryption())
        window.master.set('Synthetic-master-1!')
        window.unlock_book()
        self._wait()
        window.new_book()
        self.assertFalse(window.unlocked)
        self.assertEqual(window.master.get(), '')
        self.assertEqual(window.salt.get(), '')

    def test_append_window_starts_blank_and_only_adds_pasted_entries(self):
        self._encrypt()
        window = self.window
        window.show_book_text()
        original_text = window.book_text.get('1.0', 'end-1c')
        source = dict(version=1, book_code='ab' * 16, entries=[dict(window._blank_entry(), service='粘贴来的条目')])
        text = text_process('encode', parameters=source)

        def widgets(widget):
            for child in widget.winfo_children():
                yield child
                yield from widgets(child)

        def button(parent, label):
            return next(child for child in widgets(parent) if child.winfo_class() == 'TButton' and child.cget('text') == label)

        parent = window.book_text_window
        button(parent, '粘贴并追加…').invoke()
        child = parent.grab_current()
        self.assertIsNot(child, parent)
        editor = next(widget for widget in widgets(child) if isinstance(widget, tk.Text))
        self.assertEqual(editor.get('1.0', 'end-1c'), '')
        self.assertEqual(window.book_text.get('1.0', 'end-1c'), original_text)
        self.assertEqual(len(window.book['entries']), 1)
        with patch('gui.window.messagebox.showinfo') as info:
            button(child, '追加到当前账本').invoke()
        info.assert_called_once()
        self.assertTrue(child.winfo_exists())
        self.assertEqual(len(window.book['entries']), 1)
        editor.insert('1.0', text)
        with patch('gui.window.process') as compute:
            button(child, '追加到当前账本').invoke()
        compute.assert_not_called()
        self.assertFalse(child.winfo_exists())
        self.assertIs(parent.grab_current(), parent)
        self.assertTrue(window.unlocked)
        self.assertEqual(window.master.get(), 'Synthetic-master-1!')
        self.assertEqual(len(window.book['entries']), 2)
        self.assertEqual(window.book['entries'][1], source['entries'][0])
        self.assertEqual(window.book['book_code'], text_process('decode', original_text)['book_code'])
        self.assertEqual(window.book['verifier'], text_process('decode', original_text)['verifier'])
        self.assertEqual(window.book_text.get('1.0', 'end-1c').count('[条目]'), 2)
        button(parent, '粘贴并追加…').invoke()
        child = parent.grab_current()
        button(child, '取消').invoke()
        self.assertEqual(len(window.book['entries']), 2)
        self.assertIs(parent.grab_current(), parent)

    def test_save_book_text_writes_current_text_and_keeps_edits_on_failure(self):
        self._encrypt()
        window = self.window
        window.show_book_text()
        original_book = deepcopy(window.book)
        text = window.book_text.get('1.0', 'end-1c').replace('服务名：百度', '服务名：改过的服务')
        text = '\n' + text + '\n\n'
        window.book_text.delete('1.0', 'end')
        window.book_text.insert('1.0', text)
        with patch('gui.window.messagebox.showinfo') as info:
            window.show_append_text()
        info.assert_called_once()
        self.assertIs(window.book_text_window.grab_current(), window.book_text_window)
        with TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            path = Path(directory) / 'text.vault'
            with patch('gui.window.filedialog.asksaveasfilename', return_value=''):
                self.assertFalse(window.save_book_text())
            with patch('gui.window.filedialog.asksaveasfilename', return_value=str(path)):
                with patch('pathlib.Path.replace', side_effect=OSError('模拟替换失败')):
                    self.assertFalse(window.save_book_text())
                self.assertFalse(path.exists())
                self.assertEqual(window.book, original_book)
                self.assertTrue(window.unlocked)
                self.assertEqual(window.book_text.get('1.0', 'end-1c'), text)
                self.assertTrue(window.save_book_text())
            self.assertEqual(path.read_bytes(), text.encode('utf-8'))
            self.assertEqual(window.path, path)
            self.assertFalse(window.dirty)
            self.assertEqual(window.book['entries'][0]['service'], '改过的服务')
            window.book_text.insert('end', '这行无效')
            self.assertFalse(window.save_book_text())
            self.assertEqual(path.read_bytes(), text.encode('utf-8'))
            self.assertEqual(window.book['entries'][0]['service'], '改过的服务')
        self.assertFalse(window.unlocked)
        self.assertEqual(window.master.get(), '')

    def test_saving_changed_parameters_keeps_the_existing_password(self):
        self._encrypt()
        window = self.window
        before = window.book['entries'][0]
        master = window.master.get()
        password = window.password.get()
        window.clear_secret()
        window.algorithm.set('AES-256-GCM')
        window.memory_kib.set('64')
        window.iterations.set('2')
        self.assertTrue(window._pending_encryption())
        self.assertEqual(window.encryption_badge.cget('style'), 'Pending.TLabel')
        with patch('gui.window.messagebox.askyesno', return_value=True) as confirm:
            window.compute('encrypt')
            self._wait()
        confirm.assert_called_once()
        self.assertEqual(window.password.get(), password)
        after = window.book['entries'][0]
        self.assertEqual((after['algorithm'], after['memory_kib'], after['iterations']), ('AES-256-GCM', 64, 2))
        self.assertNotEqual(after['data'], before['data'])
        self.assertEqual(after['salt'], before['salt'])
        self.assertEqual(window.encryption_badge.cget('style'), 'Saved.TLabel')
        self.assertFalse(window._pending_encryption())
        window.new_entry()
        self.assertEqual((window.memory_kib.get(), window.iterations.get()), ('32', '1'))
        window.generate()
        self._wait()
        text = text_process('encode', parameters=window.book)
        self.assertEqual(text.count('内存KiB：'), 2)
        self.assertEqual(text.count('迭代次数：'), 2)
        self.assertEqual(text_process('decrypt', text, 0, master), password)
        self.assertEqual(text_process('decrypt', text, 1, master), window.password.get())

    def test_generation_uses_editable_settings_and_confirms_expensive_choices(self):
        window = self.window
        window.master.set('synthetic master for generation')
        window.unlock_book()
        window.memory_kib.set('无效')
        window.generate()
        self.assertFalse(window.busy)
        self.assertIn('内存', self.error_message.call_args.args[1])
        window.memory_kib.set('131072')
        with patch('gui.window.messagebox.askyesno', return_value=False) as confirm:
            window.generate()
        self.assertIn('离线网页查看器', confirm.call_args.args[1])
        self.assertEqual(window.book['entries'], [])
        self.assertEqual(window.memory_kib.get(), '131072')
        window.algorithm.set('CHACHA20-POLY1305')
        window.memory_kib.set('16')
        window.iterations.set('2')
        with patch('gui.window.messagebox.askyesno', return_value=True):
            window.generate()
            self._wait()
        entry = window.book['entries'][0]
        self.assertEqual((entry['algorithm'], entry['memory_kib'], entry['iterations']), ('CHACHA20-POLY1305', 16, 2))
        self.assertEqual(process('decrypt', dict(book_code=window.book['book_code'], entry=entry), window.master.get()), window.password.get())

    def test_open_shared_format_recovers_parameters_and_saves_portable_entries(self):
        window = self.window
        master = 'synthetic master for compatibility'
        old_entry = dict(window._blank_entry(), memory_kib=16, iterations=2)
        old_entry = process('encrypt', dict(book_code=window.book['book_code'], entry=old_entry), master, 'original password')
        original = text_process('encode', parameters={**window.book, 'entries': [old_entry]})
        header, separator, entries = original.partition('\n\n')
        entries = '\n'.join(line for line in entries.split('\n') if not line.startswith(('内存KiB：', '迭代次数：')))
        temporary_format = header.replace('格式：1', '格式：2') + '\n内存KiB：16\n迭代次数：2' + separator + entries
        with TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            path = Path(directory) / 'temporary-format.vault'
            path.write_text(temporary_format, encoding='utf-8')
            with patch('gui.window.filedialog.askopenfilename', return_value=str(path)):
                window.open_book()
            self.assertEqual(path.read_text(encoding='utf-8'), temporary_format)
            self.assertEqual(window.book['entries'][0], old_entry)
            self.assertEqual((window.memory_kib.get(), window.iterations.get()), ('16', '2'))
            self.assertTrue(window.save())
            text = path.read_text(encoding='utf-8')
            self.assertEqual(text, original)
            self.assertEqual(text_process('decrypt', text, 0, master), 'original password')

    def test_text_editor_does_not_change_parameters_on_existing_ciphertext(self):
        self._encrypt()
        window = self.window
        with TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as directory:
            path = Path(directory) / 'existing.vault'
            with patch('gui.window.filedialog.asksaveasfilename', return_value=str(path)):
                self.assertTrue(window.save())
            entry = window.book['entries'][0]
            saved = path.read_bytes()
            window.show_book_text()
            editor = window.book_text
            editor.replace('1.0', 'end-1c', editor.get('1.0', 'end-1c').replace('迭代次数：1', '迭代次数：2'))
            self.assertFalse(window.save_book_text())
            self.assertEqual(path.read_bytes(), saved)
            self.assertEqual(window.book['entries'][0], entry)
            self.assertIn('恢复原值', self.error_message.call_args.args[1])

    def test_first_ciphertext_append_requires_new_authentication(self):
        window = self.window
        window.master.set('draft master')
        window.unlock_book()
        window.new_entry()
        entry = process('encrypt', dict(book_code=window.book['book_code'], entry=window._blank_entry()), 'imported master', 'imported password')
        addition = dict(version=1, book_code=window.book['book_code'], entries=[entry])
        window.show_book_text()
        with patch('gui.window.process') as compute:
            self.assertTrue(window.append_book_text(text_process('encode', parameters=addition), window.book_text_window))
            compute.assert_not_called()
        self.assertFalse(window.unlocked)
        self.assertEqual(window.master.get(), '')
        window.master.set('imported master')
        window.unlock_book()
        self._wait()
        self.assertTrue(window.unlocked)

    def test_failed_entry_decrypt_keeps_book_session_and_does_not_rewrite_mixed_legacy(self):
        self._encrypt()
        window = self.window
        entry = process('encrypt', dict(book_code=window.book['book_code'], entry=window._blank_entry()), 'legacy other master', 'legacy password')
        window.book['entries'].append(entry)
        window._show_entry(1)
        original = deepcopy(window.book)
        window.compute('decrypt')
        self._wait()
        self.assertTrue(window.unlocked)
        self.assertEqual(window.master.get(), 'Synthetic-master-1!')
        self.assertEqual(window.password.get(), '')
        self.assertEqual(window.book, original)
        self.assertIn('其他管理密码', self.error_message.call_args.args[1])

    def test_unlock_start_failure_keeps_locked_editable_input(self):
        self._encrypt()
        window = self.window
        window.lock_book()
        window.master.set('Synthetic-master-1!')
        with patch('gui.window.ThreadPoolExecutor', side_effect=RuntimeError('模拟线程启动失败')):
            window.unlock_book()
        self.assertFalse(window.busy)
        self.assertFalse(window.unlocked)
        self.assertFalse(window.master_entry.instate(['readonly']))
        self.assertEqual(window.master.get(), 'Synthetic-master-1!')
        self.assertIsNone(window.executor)
        self.error_message.assert_called_once()


if __name__ == '__main__':
    unittest.main()
