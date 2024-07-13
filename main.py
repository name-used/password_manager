import os
from pathlib import Path
import traceback

from library import Library
from frame import Frame
from security import Security
from service import Service


def main():
    # root 表示数据表单的存储位置
    root = Path(os.getcwd()) / 'lib'
    # static_salt 是本项目的一个静态盐
    static_salt = 'f1treaqt518r7eq1f54'

    # security 负责加解密算法的实现
    security = Security(static_salt=static_salt)
    # lib 负责数据读写
    lib = Library(root=root)
    # service 负责业务功能实现
    service = Service(lib=lib, security=security)
    # frame 负责 ui 交互
    frame = Frame(service=service)

    # noinspection PyBroadException
    try:
        frame.start()
    except Exception as e:
        traceback.print_exc()
    lib.close()


main()
