#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""运行全部测试。

    python selftest.py
"""

from __future__ import annotations

import os
import runpy
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = [
    ("核心库单元测试", "test_core.py"),
    ("密钥长度规格", "test_specs.py"),
    ("客户端端到端", "test_e2e.py"),
    ("攻击面模拟", "test_attack.py"),
]


def run(filename: str) -> bool:
    path = os.path.join(HERE, "tests", filename)
    old_argv, old_cwd = sys.argv[:], os.getcwd()
    sys.argv = [path]
    try:
        os.chdir(os.path.dirname(path))
        runpy.run_path(path, run_name="__main__")
        return True
    except SystemExit as exc:
        return not exc.code
    except Exception as exc:                       # noqa: BLE001
        print("异常：{}: {}".format(type(exc).__name__, exc))
        return False
    finally:
        sys.argv, _ = old_argv, os.chdir(old_cwd)


def main() -> int:
    print("LicenseKit 自检")
    print()
    results = []
    for title, filename in TESTS:
        print("=" * 52)
        print(" " + title)
        print("=" * 52)
        results.append((title, run(filename)))
        print()

    print("=" * 52)
    failed = [t for t, ok in results if not ok]
    for title, ok in results:
        print("  {}  {}".format("通过" if ok else "失败", title))
    print()
    print("全部通过" if not failed else "{} 项失败".format(len(failed)))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
