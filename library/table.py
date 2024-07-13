import os
from typing import Dict, List
from pathlib import Path

from .file import load, write


class Table(object):
    columns = None

    def __init__(self):
        self.data: List[Dict[str, str]] = []
        self.file = None

    def synchronize(self, path: Path) -> None:
        mode = 'r+' if os.path.exists(path) else 'w+'
        self.file = open(path, mode=mode)
        self.data = load(file=self.file, columns=self.columns)

    def close(self) -> None:
        write(file=self.file, columns=self.columns, data=self.data)
        self.file.close()

    def add(self, item: Dict[str, str]) -> None:
        item['index'] = str(len(self.data))
        self.data.append(item)

    def select(self, index: int) -> Dict[str, str]:
        return self.data[index]

    def update(self, index: int, item: Dict[str, str]) -> None:
        self.data[index] = item
