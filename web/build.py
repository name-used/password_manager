"""把网页源码、自有加密核心和许可通知合成为独立离线 HTML。"""

import base64
from pathlib import Path


def main():
    root = Path(__file__).resolve().parent
    source = (root / 'page.template.html').read_text(encoding='utf-8')
    parts = {
        '__STANDARD_LIBRARY_NOTICES__': root / 'core/THIRD_PARTY_NOTICES.txt',
        '__CIPHER_SOURCE__': root / 'core/ciphers.js',
        '__TEXT_SOURCE__': root / 'core/text_decoder.js',
        '__PROCESS_SOURCE__': root / 'core/process.js',
        '__GUI_SOURCE__': root / 'gui.js',
    }
    for marker, path in parts.items():
        source = source.replace(marker, path.read_text(encoding='utf-8'))
    source = source.replace('__WASM_BASE64__', base64.b64encode((root / 'core/argon2id.wasm').read_bytes()).decode('ascii'))
    target = root.parent / 'password_viewer.html'
    target.write_text(source, encoding='utf-8')
    print(f'{target}: {target.stat().st_size} bytes')


if __name__ == '__main__':
    main()
