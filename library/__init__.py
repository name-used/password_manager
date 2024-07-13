import os
from pathlib import Path

from .lord import load_lord, Lord
# from .password import load_password
# from .rule import load_rule
# from .history import load_history


class Library(object):
    def __init__(self, root: Path):
        os.makedirs(name=root, exist_ok=True)
        self.lords: Lord = load_lord(root / 'lord.txt')
        # self.passwords: Password = load_password(root / 'password.txt')
        # self.rules: Rule = load_rule(root / 'rule.txt')
        # self.histories: History = load_history(root / 'history.txt')

    def close(self):
        self.lords.close()
        # self.passwords.close()
        # self.rules.close()
        # self.histories.close()
