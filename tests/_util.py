# -*- coding: utf-8 -*-
"""测试公用工具：在临时目录里造项目、生成客户端。"""

import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
NATIVE = os.path.join(ROOT, "native")
if NATIVE not in sys.path:
    sys.path.insert(0, NATIVE)

import client_builder          # noqa: E402
import license_core as L       # noqa: E402


class Sandbox:
    """一次性测试环境：临时目录 + 项目库 + 客户端模块。"""

    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="licensekit-test-")
        self.store = L.ProjectStore(os.path.join(self.dir, "projects.json"))

    def project(self, name, title="", spec=None):
        record = self.store.add(name, title or name)
        if spec is not None:
            record["spec"] = spec
            self.store.save()
        return record

    def client(self, name, spec=120):
        """生成客户端并导入，返回模块对象。"""
        out = os.path.join(self.dir, "client_" + name)
        client_builder.generate_client(
            self.store.get(name), spec, out, self.store.compact_secret(name))
        mod_name = "cl_" + name + "_" + str(spec)
        sys.modules.pop(mod_name, None)
        spec_obj = importlib.util.spec_from_file_location(
            mod_name, os.path.join(out, "licensing.py"))
        mod = importlib.util.module_from_spec(spec_obj)
        sys.modules[mod_name] = mod
        spec_obj.loader.exec_module(mod)
        return mod

    def issue(self, name, spec=120, **kwargs):
        record = self.store.get(name)
        if spec == 120:
            return L.issue_v4(self.store.private_key(name), name, **kwargs)
        return L.issue_compact(self.store.compact_secret(name), name, spec, **kwargs)


def run(cases):
    """依次跑 (名称, 可调用) 断言列表，返回是否全部通过。"""
    ok = fail = 0
    for label, func in cases:
        try:
            result = func()
            bad = result is False
            extra = "" if result is True or result is None else str(result)
        except Exception as exc:                       # noqa: BLE001
            bad, extra = True, "{}: {}".format(type(exc).__name__, exc)
        if bad:
            fail += 1
            print("  FAIL " + label + ("  -> " + extra if extra else ""))
        else:
            ok += 1
            print("  OK   " + label)
    print()
    print("通过 {} / 失败 {}".format(ok, fail))
    return fail == 0
