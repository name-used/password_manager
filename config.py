"""界面与新一次加密的默认配置；解密使用账本中记录的实际参数。"""

TITLE = '密码账本 · LOCAL VAULT'
DEFAULT_ALGORITHM = 'XCHACHA20-POLY1305'
MEMORY_KIB = 65536
ITERATIONS = 3
LANES = 4
DEFAULT_RULES = {'length': 8, 'categories': 3, 'allowed': 'ULDS', 'symbols': '!@#$%^&*_-+=.?'}

BACKGROUND = '#0b1020'
PANEL = '#151d31'
ACCENT = '#59e1c5'
FOREGROUND = '#e7edf9'
MUTED = '#98a7c2'
WINDOW_SIZE = '1180x880'
