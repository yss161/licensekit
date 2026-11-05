# -*- coding: utf-8 -*-
"""根据项目记录生成客户端文件（licensing.py + ed25519.py）。

CLI 和交互菜单都调用这里，避免两份重复的替换逻辑。
"""

from __future__ import annotations

import os
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TEMPLATE = os.path.join(ROOT, "client_template", "licensing.py")
ED25519 = os.path.join(HERE, "ed25519.py")


def generate_client(record: dict, spec: int, out_dir: str,
                    compact_secret: bytes, template: str = "",
                    ed25519_src: str = "") -> str:
    """把模板填好项目名、公钥、密钥规格，写到 out_dir。返回 licensing.py 路径。"""
    template = template or TEMPLATE
    ed25519_src = ed25519_src or ED25519

    with open(template, "r", encoding="utf-8") as handle:
        body = handle.read()

    body = body.replace('PROJECT = "myapp"', 'PROJECT = "{}"'.format(record["name"]))
    body = body.replace('PRODUCT = "我的程序"',
                        'PRODUCT = "{}"'.format(record.get("title", record["name"])))
    body = body.replace('KEY_SPEC = 120', 'KEY_SPEC = {}'.format(int(spec)))
    body = body.replace('PUBLIC_KEY = bytes.fromhex("00" * 32)',
                        'PUBLIC_KEY = bytes.fromhex("{}")'.format(
                            record["ed25519_public"]))
    # 强签名模式下不会用到对称密钥，不把它写进客户端
    if int(spec) != 120 and compact_secret:
        body = body.replace('COMPACT_SECRET = bytes.fromhex("00" * 32)',
                            'COMPACT_SECRET = bytes.fromhex("{}")'.format(
                                compact_secret.hex()))

    os.makedirs(out_dir, exist_ok=True)
    target = os.path.join(out_dir, "licensing.py")
    with open(target, "w", encoding="utf-8") as handle:
        handle.write(body)
    shutil.copyfile(ed25519_src, os.path.join(out_dir, "ed25519.py"))
    return target
