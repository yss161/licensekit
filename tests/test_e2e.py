# -*- coding: utf-8 -*-
"""端到端：两个项目的密钥互不通用。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _util
from _util import Sandbox


def main():
    box = Sandbox()
    box.project("app_one", "应用一号", spec=120)
    box.project("app_two", "应用二号", spec=120)

    key_one = box.issue("app_one")
    key_two = box.issue("app_two", edition="professional", days=30)
    key_short = box.issue("app_one", spec=24)

    client_one = box.client("app_one", 120)
    client_two = box.client("app_two", 120)

    print("== 客户端 app_one ==")
    cases = [
        ("项目名正确", lambda: client_one.PROJECT == "app_one"),
        ("接受本项目的密钥", lambda: client_one.verify(key_one)[0]),
        ("拒绝另一个项目的密钥",
         lambda: not client_one.verify(key_two)[0]),
        ("拒绝空密钥", lambda: not client_one.verify("")[0]),
        ("拒绝乱码", lambda: not client_one.verify("AAAAAA-BBBBBB")[0]),
        ("拒绝 24 字符密钥（本项目是 120）",
         lambda: not client_one.verify(key_short)[0]),
    ]
    ok1 = _util.run(cases)

    print("== 客户端 app_two ==")
    cases = [
        ("项目名正确", lambda: client_two.PROJECT == "app_two"),
        ("接受本项目的密钥", lambda: client_two.verify(key_two)[0]),
        ("拒绝另一个项目的密钥",
         lambda: not client_two.verify(key_one)[0]),
        ("两个项目公钥不同",
         lambda: client_one.PUBLIC_KEY != client_two.PUBLIC_KEY),
        ("机器码算法一致",
         lambda: client_one.machine_code() == client_two.machine_code()),
    ]
    ok2 = _util.run(cases)
    return ok1 and ok2


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
