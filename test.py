from pathlib import Path
from library import Library

lib = Library(root=Path('./lib'))
lib.lords.add({
    'password': '123456',
    'salt': '123456',
})
lib.close()
