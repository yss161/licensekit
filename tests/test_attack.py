# -*- coding: utf-8 -*-
"""攻击面：拿到全部客户端源码后，能否伪造或篡改密钥。"""

import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _util
from _util import Sandbox

import ed25519


def main():
    box = Sandbox()
    box.project("demo", "演示", spec=120)
    client = box.client("demo", 120)
    key = box.issue("demo", days=30, machine=client.machine_code())

    raw = bytearray(client.b32decode(key))
    print("原始密钥载荷：", bytes(raw[:7]).hex())

    def tampered(mutate):
        body = mutate(bytearray(raw))
        return client.verify(client.format_key(client.b32encode(bytes(body))))

    def set_forever(b):
        b[3], b[4] = 0xFF, 0xFF
        return b

    def set_internal(b):
        b[2] = (4 << 4) | 2
        return b

    def unbind(b):
        b[5] = b[6] = 0
        return b

    def change_serial(b):
        b[0] = (b[0] + 1) % 256
        return b

    def random_signature():
        """用随机字节冒充签名，试 200 次。"""
        msg = b"LKV4|demo|" + bytes(raw[:7])
        for _ in range(200):
            if ed25519.verify(client.PUBLIC_KEY, msg, secrets.token_bytes(64)):
                return False
        return True

    cases = [
        ("基线：原密钥有效", lambda: client.verify(key)[0]),
        ("改到期日为永久 -> 被拒", lambda: not tampered(set_forever)[0]),
        ("改版本为内部版 -> 被拒", lambda: not tampered(set_internal)[0]),
        ("去掉机器绑定 -> 被拒", lambda: not tampered(unbind)[0]),
        ("改流水号 -> 被拒", lambda: not tampered(change_serial)[0]),
        ("随机猜 200 次签名全失败", random_signature),
        ("换成别的项目名 -> 被拒", lambda: _with_project(client, "其他", key)),
    ]
    return _util.run(cases)


def _with_project(client, other, key):
    original = client.PROJECT
    client.PROJECT = other
    try:
        return not client.verify(key)[0]
    finally:
        client.PROJECT = original


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
