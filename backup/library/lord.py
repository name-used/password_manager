from pathlib import Path

from .table import Table


class Lord(Table):
    columns = ['index', 'password', 'salt']


def load_lord(path: Path) -> Lord:
    lord = Lord()
    lord.synchronize(path)
    return lord
