from io import TextIOWrapper
from typing import Dict, List
from pathlib import Path


def load(file: TextIOWrapper, columns: List[str]) -> List[Dict[str, str]]:
    content = file.read().strip()
    groups = content.split('\n\n')
    data = []
    for group in groups:
        if not group: continue
        print([group])
        lines = group.split('\n')
        item = {}
        for i, column in enumerate(columns):
            item[column] = lines[i]
        data.append(item)
    return data


def write(file: TextIOWrapper, columns: List[str], data: List[Dict[str, str]]) -> None:
    file.seek(0)
    file.truncate()
    for item in data:
        file.write('\n')
        for column in columns:
            line = item[column]
            file.write(line)
            file.write('\n')
