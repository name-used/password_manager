"""备注与账本剪贴板交换：验证真实的格式边界、状态变化和拒绝后的数据保留。"""

from copy import deepcopy
from unittest.mock import patch
import unittest

from core import process, text_process
from test.test_process import sample_entry

try:
    import tkinter as tk
except ImportError:
    tk = None
if tk is not None:
    from gui.window import Window


class TextExchangeTests(unittest.TestCase):
    def setUp(self):
        self.book = {'version': 1, 'book_code': '0123456789abcdef0123456789abcdef', 'entries': [sample_entry()]}

    def test_optional_notes_roundtrip_and_ciphertext_unchanged(self):
        entry = process('encrypt', {'book_code': self.book['book_code'], 'entry': self.book['entries'][0]}, 'master', 'site-password')
        original = entry['data']
        entry['notes'] = '中文第一行\n第二行：反斜杠\\和制表\t 🙂'
        self.book['entries'][0] = entry
        text = text_process('encode', parameters=self.book)
        self.assertIn('备注：中文第一行\\n第二行', text)
        restored = text_process('decode', text)
        self.assertEqual(restored, self.book)
        self.assertEqual(restored['entries'][0]['data'], original)
        self.assertEqual(text_process('decrypt', text, 0, 'master'), 'site-password')
        entry.pop('notes')
        self.assertNotIn('备注：', text_process('encode', parameters=self.book))
        entry['notes'] = ''
        self.assertNotIn('备注：', text_process('encode', parameters=self.book))
        entry['notes'] = 123
        with self.assertRaisesRegex(ValueError, '备注'):
            text_process('encode', parameters=self.book)

    def test_append_book_and_fragments_is_atomic_and_never_derives(self):
        addition = deepcopy(self.book)
        addition['entries'][0].update(service='追加中文服务', notes='多行\n备注')
        addition['entries'].append(sample_entry('AES-256-GCM'))
        complete = text_process('encode', parameters=addition)
        fragment = '\ufeff\n  \n' + complete[complete.index('[条目]'):]
        original = deepcopy(self.book)
        with patch('core.argon2id_native.derive', side_effect=AssertionError('文本追加不应派生')):
            for text in (complete, fragment):
                result = text_process('decode', text_process('append', text, parameters=self.book))
                self.assertEqual(len(result['entries']), 3)
                self.assertEqual(result['entries'][1:], addition['entries'])
                self.assertEqual(self.book, original)
            for invalid in (complete.replace(addition['book_code'], 'bad-code'), fragment + '密码明文：不许保存\n', None):
                with self.subTest(text=invalid), self.assertRaises(ValueError):
                    text_process('append', invalid, parameters=self.book)
                self.assertEqual(self.book, original)

    def test_portable_ciphertexts_are_preserved_by_paste_and_direct_text_edit(self):
        master = 'synthetic shared master'
        source_code = 'ff' * 16
        source_entries = [
            process('encrypt', {'book_code': source_code, 'entry': sample_entry(algorithm)}, master, password)
            for algorithm, password in (('XCHACHA20-POLY1305', 'first'), ('AES-256-GCM', 'second'))
        ]
        source = text_process('encode', parameters=dict(self.book, book_code=source_code, entries=source_entries))
        target = text_process('encode', parameters=self.book)
        fragment = source[source.index('[条目]'):]
        for combined in (text_process('append', source, parameters=self.book),
                         text_process('append', fragment, parameters=self.book),
                         target + '\n' + fragment):
            book = text_process('decode', combined)
            self.assertEqual(book['book_code'], self.book['book_code'])
            self.assertEqual(book['entries'], self.book['entries'] + source_entries)
            self.assertEqual(text_process('decrypt', combined, 1, master), 'first')
            self.assertEqual(text_process('decrypt', combined, 2, master), 'second')
            with self.assertRaisesRegex(ValueError, '管理密码错误'):
                text_process('decrypt', combined, 1, 'wrong master')


@unittest.skipIf(tk is None, '当前 Python 未提供 Tkinter')
class TextWindowTests(unittest.TestCase):
    def setUp(self):
        try:
            self.root = tk.Tk()
        except tk.TclError as error:
            self.skipTest(f'当前环境没有可用的 Tk 桌面：{error}')
        self.window = Window(self.root)
        self.errors = patch('gui.window.messagebox.showerror')
        self.error_message = self.errors.start()
        self.root.update()

    def tearDown(self):
        if hasattr(self, 'window'):
            self.errors.stop()
            self.root.destroy()

    def _set_text(self, text):
        self.window.book_text.delete('1.0', 'end')
        self.window.book_text.insert('1.0', text)

    def test_select_all_applies_notes_but_excludes_secrets_and_does_not_compute(self):
        window = self.window
        window.new_entry()
        window.notes.insert('1.0', '可以公开的中文备注\n第二行')
        window.master.set('never-copy-master')
        window.password.set('never-copy-password')
        with patch('gui.window.process', side_effect=AssertionError('打开或全选文本不应计算')):
            window.show_book_text()
            self.assertEqual(window.book_text_window.grab_current(), window.book_text_window)
            self.root.update()
            window.book_text.focus_force()
            self.root.update()
            window.book_text.event_generate('<Control-a>')
        selected = window.book_text.get('sel.first', 'sel.last')
        self.assertEqual(selected, window.book_text.get('1.0', 'end-1c'))
        self.assertNotIn('never-copy-master', selected)
        self.assertNotIn('never-copy-password', selected)
        self.assertEqual(text_process('decode', selected)['entries'][0]['notes'], '可以公开的中文备注\n第二行')
        self.assertEqual(window.password.get(), 'never-copy-password')
        self._set_text(selected + '密码明文：不应保存\n')
        self.assertFalse(window.save_book_text())
        self.error_message.assert_called_once()

    def test_save_text_protects_unsaved_password_and_respects_cancel(self):
        window = self.window
        window.new_entry()
        window.show_book_text()
        original = deepcopy(window.book)
        new_book = text_process('decode', text_process('new'))
        new_book['entries'] = [sample_entry()]
        self._set_text(text_process('encode', parameters=new_book))
        window.password.set('pending-password')
        with patch('gui.window.messagebox.askyesno', return_value=False):
            self.assertFalse(window.save_book_text())
        self.assertEqual(window.book, original)
        with patch('gui.window.messagebox.askyesno', return_value=True), patch('gui.window.filedialog.asksaveasfilename', return_value=''):
            self.assertFalse(window.save_book_text())
        self.assertEqual(window.book, original)
        self.assertEqual(window.password.get(), 'pending-password')
        self.assertIsNone(window.path)

    def test_append_protects_unsaved_password_and_keeps_target_header(self):
        window = self.window
        window.new_entry()
        window.password.set('pending-password')
        window.show_book_text()
        addition = deepcopy(window.book)
        addition['entries'][0]['service'] = '追加条目'
        text = text_process('encode', parameters=addition)
        fragment = text[text.index('[条目]'):]
        with patch('gui.window.messagebox.askyesno', return_value=False):
            self.assertFalse(window.append_book_text(fragment, window.book_text_window))
        self.assertEqual(len(window.book['entries']), 1)
        self.assertEqual(window.password.get(), 'pending-password')
        with patch('gui.window.messagebox.askyesno', return_value=True):
            self.assertTrue(window.append_book_text(fragment, window.book_text_window))
        self.assertEqual(len(window.book['entries']), 2)
        self.assertEqual(window.index, 1)
        self.assertEqual(window.password.get(), '')
        self.assertTrue(window.append_book_text(text.replace(addition['book_code'], 'ab' * 16), window.book_text_window))
        self.assertEqual(window.book['book_code'], addition['book_code'])
        self.assertEqual(len(window.book['entries']), 3)

    def test_append_keeps_first_draft_applied_during_import(self):
        window = self.window
        window.show_book_text()
        window.fields['service'].set('首条草稿')
        addition = dict(window.book, entries=[dict(sample_entry(), service='追加条目')])
        text = text_process('encode', parameters=addition)
        with patch('gui.window.messagebox.askyesnocancel', return_value=True):
            self.assertTrue(window.append_book_text(text, window.book_text_window))
        self.assertEqual([entry['service'] for entry in window.book['entries']], ['首条草稿', '追加条目'])
        self.assertEqual(text_process('decode', window.book_text.get('1.0', 'end-1c')), window.book)
        self.assertEqual(window.index, 1)

    def test_close_and_busy_guards_preserve_edited_text(self):
        window = self.window
        window.busy = True
        window.show_book_text()
        self.assertIsNone(window.book_text_window)
        window.busy = False
        window.show_book_text()
        self._set_text('unloaded edits')
        with patch('gui.window.messagebox.askyesno', return_value=False):
            self.assertFalse(window.close_book_text())
        self.assertEqual(window.book_text.get('1.0', 'end-1c'), 'unloaded edits')
        window.busy = True
        self.assertFalse(window.save_book_text())
        self.assertFalse(window.append_book_text('unused', window.book_text_window))
        window.busy = False
        with patch('gui.window.messagebox.askyesno', return_value=True):
            self.assertTrue(window.close_book_text())
        self.assertIsNone(window.book_text_window)


if __name__ == '__main__':
    unittest.main()
