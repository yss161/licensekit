#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
LicenseKit · 管理端
===================

你是唯一持有这个工具的人。它能：
    · 为不同项目生成**互不相同**的密钥对（Ed25519）
    · 签发许可证（永久 / 指定到期日 / N 天 / 绑定机器）
    · 签发原版 v1 兼容密钥（24 字符，可直接给原版程序用）
    · 查看密钥内容、吊销密钥、生成客户端片段

用法示例
--------
    python licensekit.py projects                 # 列出项目
    python licensekit.py add myapp --title 我的程序
    python licensekit.py client myapp --out ./out # 生成可直接用的客户端文件
    python licensekit.py issue myapp --days 365
    python licensekit.py issue myapp --machine MZF5IPEE --edition pro
    python licensekit.py issue myapp --v1         # 原版 24 字符格式
    python licensekit.py inspect myapp XXXX-...
    python licensekit.py revoke myapp XXXX-...
    python licensekit.py banlist myapp
"""

from __future__ import annotations

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "native"))

try:
    import client_builder
    import license_core as L
except ImportError as exc:
    print("无法加载核心库：{}".format(exc))
    print("请确认 native/license_core.py 与 native/ed25519.py 存在。")
    raise SystemExit(2)

STORE_PATH = os.path.join(HERE, "license_projects.json")


def _store() -> "L.ProjectStore":
    return L.ProjectStore(STORE_PATH)


def _need(name: str):
    store = _store()
    record = store.get(name)
    if record is None:
        names = ", ".join(p["name"] for p in store.list_projects()) or "（还没有任何项目）"
        print("项目 {} 不存在。现有项目：{}".format(name, names))
        raise SystemExit(1)
    return store, record


# ==========================================================
# 命令
# ==========================================================
def cmd_projects(args) -> int:
    store = _store()
    items = store.list_projects()
    if not items:
        print("还没有项目。用 python licensekit.py add <项目名> 新建一个。")
        return 0
    print("{:<18} {:<20} {:<8} {:>8}  公钥".format(
        "项目", "名称", "命名空间", "已签发"))
    print("-" * 92)
    for record in items:
        print("{:<18} {:<20} {:<8} {:>8}  {}".format(
            record["name"], record.get("title", ""), record.get("namespace", ""),
            len(record.get("issued", [])), str(record["ed25519_public"])[:24] + "..."))
    return 0


def cmd_add(args) -> int:
    store = _store()
    try:
        record = store.add(args.name, args.title or args.name,
                           create_v1=not args.no_v1)
    except L.LicenseError as exc:
        print("添加失败：{}".format(exc))
        return 1
    print("已创建项目：{}".format(record["name"]))
    print("  显示名称     ：{}".format(record["title"]))
    print("  命名空间     ：{}".format(record["namespace"]))
    print("  Ed25519 公钥 ：{}".format(record["ed25519_public"]))
    print("  v1 兼容密钥  ：{}".format(record["v1_secret"] or "（未生成）"))
    print()
    print("下一步：python licensekit.py client {} --out ./out".format(record["name"]))
    return 0


def cmd_remove(args) -> int:
    store = _store()
    store.remove(args.name)
    print("已删除项目：{}".format(args.name))
    return 0


def cmd_client(args) -> int:
    """生成可直接放进项目的客户端文件（只含公钥）。"""
    store, record = _need(args.name)
    out_dir = args.out or os.path.join(HERE, "out", args.name)
    os.makedirs(out_dir, exist_ok=True)

    template = os.path.join(HERE, "client_template", "licensing.py")
    if not os.path.isfile(template):
        print("找不到模板：{}".format(template))
        return 1

    spec = args.spec or int(record.get("spec") or L.DEFAULT_SPEC)

    client_builder.generate_client(
        record, spec, out_dir,
        store.compact_secret(str(record["name"])), template=template,
        ed25519_src=os.path.join(HERE, "native", "ed25519.py"))

    # 记住该项目选定的规格，后续 issue 默认沿用
    if record.get("spec") != spec:
        record["spec"] = spec
        store.save()

    print("已生成客户端文件到：{}".format(out_dir))
    print("  licensing.py   （项目名 = {}，密钥规格 = {} 字符）".format(
        record["name"], spec))
    print("  ed25519.py     （签名实现，一起复制进你的项目）")
    print()
    print("接入方式：")
    print("    import licensing")
    print("    licensing.require()        # 未激活时自动退出")
    return 0


def cmd_issue(args) -> int:
    store, record = _need(args.name)
    edition = {"std": "standard", "pro": "professional",
               "int": "internal", "trial": "trial"}[args.edition]

    machine = ""
    if args.machine:
        machine = L.machine_code() if args.machine.upper() == "THIS" else args.machine

    # 三种有效期写法互斥：--forever > --expires > --days（默认永久）
    days = None
    expires_on = None
    if args.expires:
        expires_on = args.expires
    elif args.days and not args.forever:
        days = args.days

    spec = args.spec or int(record.get("spec") or L.DEFAULT_SPEC)

    try:
        if args.v1:
            secret = store.v1_secret(args.name)
            if not secret:
                print("该项目没有生成 v1 兼容密钥，创建时用了 --no-v1。")
                return 1
            key = L.issue_v1(secret, edition, expires_on=expires_on,
                             days=days, machine=machine)
            fmt = "v1（24 字符，原版兼容）"
        elif spec == 120:
            key = L.issue_v4(store.private_key(args.name), args.name, edition,
                             expires_on=expires_on, days=days, machine=machine)
            fmt = "v4（120 字符，Ed25519 强签名）"
        else:
            key = L.issue_compact(store.compact_secret(args.name), args.name,
                                  spec, edition, expires_on=expires_on,
                                  days=days, machine=machine)
            fmt = "v2（{} 字符，紧凑 HMAC）".format(spec)
    except L.LicenseError as exc:
        print("签发失败：{}".format(exc))
        return 1

    store.record_issue(args.name, key, {
        "edition": edition,
        "expires": expires_on or ("%d 天" % days if days else "永久"),
        "machine": machine or "不绑机",
        "format": "v1" if args.v1 else ("v4" if spec == 120 else "v2"),
        "spec": spec,
    })

    # 回读校验，确保签出来的一定能用
    if args.v1:
        good, message, _ = L.verify_v1(key, store.v1_secret(args.name),
                                       machine=machine)
    elif spec == 120:
        good, message, _ = L.verify_v4(key, args.name, store.public_key(args.name),
                                       machine=machine)
    else:
        good, message, _ = L.verify_compact(key, store.compact_secret(args.name),
                                            args.name, machine=machine)

    print()
    print("  项目    ：{}".format(record.get("title", args.name)))
    print("  格式    ：{}".format(fmt))
    print("  内容    ：{}".format(message))
    print("  签发结果：{}{}".format("OK" if good else "失败", "" if good else " <- 请检查"))
    print()
    print("  许可证：")
    print("  " + L.format_key(key, 6 if not args.v1 else 6))
    print()
    return 0 if good else 1


def cmd_inspect(args) -> int:
    store, record = _need(args.name)
    info = L.describe(args.key, args.name, store.public_key(args.name),
                      store.v1_secret(args.name))
    if not info.get("ok"):
        print("无法解析：{}".format(info.get("reason")))
        return 1
    print("  格式      ：v{}".format(info.get("format")))
    print("  版本类型  ：{}".format(L.EDITION_LABELS.get(
        str(info.get("edition")), info.get("edition"))))
    print("  流水号    ：{}".format(info.get("serial")))
    print("  到期日    ：{}".format(info.get("expires_on") or "永久"))
    bound = info.get("machine_bound")
    print("  机器绑定  ：{}".format("是（指纹 %04x）" % info.get("machine_fp")
                                     if bound else "否"))
    print("  规范化    ：{}".format(info.get("normalized")))
    if info.get("format") == L.FORMAT_V4:
        ok, message, _ = L.verify_v4(args.key, args.name,
                                     store.public_key(args.name))
        print("  当前校验  ：{} {}".format("通过" if ok else "不通过", message))
    return 0


def cmd_revoke(args) -> int:
    store, record = _need(args.name)
    if store.revoke(args.name, args.key, args.reason or ""):
        print("已吊销该密钥。")
        print("把它同步到客户端：python licensekit.py banlist {}".format(args.name))
        return 0
    print("吊销失败：签发记录里没有找到这枚密钥（可能不是本工具签发的）。")
    return 1


def cmd_banlist(args) -> int:
    store, record = _need(args.name)
    print(store.banlist_literal(args.name))
    return 0


def cmd_keys(args) -> int:
    store, record = _need(args.name)
    print("  项目        ：{}".format(record.get("title", args.name)))
    print("  命名空间    ：{}".format(record.get("namespace")))
    print("  Ed25519 私钥：{}".format(record["ed25519_private"]))
    print("  Ed25519 公钥：{}".format(record["ed25519_public"]))
    print("  v1 兼容密钥 ：{}".format(record.get("v1_secret") or "（无）"))
    print()
    print("  ⚠ 私钥 = 造钥匙的模具。只能自己留着，绝不要放进客户端。")
    return 0


def cmd_history(args) -> int:
    store, record = _need(args.name)
    items = record.get("issued", [])
    if not items:
        print("还没有签发记录。")
        return 0
    for entry in items:
        flag = "  [已吊销]" if entry.get("revoked") else ""
        print("{:<20} {:<6} {:<10} {:<14} {}{}".format(
            entry.get("issued_at", ""), entry.get("format", "v4"),
            entry.get("edition", ""), entry.get("expires", ""),
            L.format_key(str(entry.get("key", "")))[:32] + "...", flag))
    return 0


# ==========================================================
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="licensekit",
        description="LicenseKit —— 多项目离线许可证签发工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="不带参数运行会进入数字菜单；带子命令则直接执行对应操作。")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("projects", help="列出所有项目")
    p.set_defaults(func=cmd_projects)

    p = sub.add_parser("add", help="新建项目（自动生成独立密钥对）")
    p.add_argument("name")
    p.add_argument("--title", default="", help="显示名称")
    p.add_argument("--no-v1", action="store_true", help="不生成 v1 兼容密钥")
    p.set_defaults(func=cmd_add)

    p = sub.add_parser("remove", help="删除项目")
    p.add_argument("name")
    p.set_defaults(func=cmd_remove)

    p = sub.add_parser("client", help="生成客户端接入文件")
    p.add_argument("name")
    p.add_argument("--out", default="", help="输出目录")
    p.add_argument("--spec", type=int, default=0,
                   choices=[0, 24, 32, 40, 120],
                   help="密钥长度：24/32/40 紧凑，120 强签名（默认取项目设置）")
    p.set_defaults(func=cmd_client)

    p = sub.add_parser("issue", help="签发许可证")
    p.add_argument("name")
    p.add_argument("--days", type=int, default=0, help="有效天数（默认永久）")
    p.add_argument("--forever", action="store_true", help="永久有效")
    p.add_argument("--expires", default="", help="指定到期日 YYYY-MM-DD")
    p.add_argument("--edition", default="std",
                   choices=["std", "pro", "int", "trial"], help="版本类型")
    p.add_argument("--machine", default="", help="绑定机器码；THIS = 本机")
    p.add_argument("--v1", action="store_true", help="签发原版 24 字符格式")
    p.add_argument("--spec", type=int, default=0,
                   choices=[0, 24, 32, 40, 120],
                   help="密钥长度：24/32/40 紧凑，120 强签名（默认取项目设置）")
    p.set_defaults(func=cmd_issue)

    p = sub.add_parser("inspect", help="查看密钥内容")
    p.add_argument("name")
    p.add_argument("key")
    p.set_defaults(func=cmd_inspect)

    p = sub.add_parser("revoke", help="吊销密钥")
    p.add_argument("name")
    p.add_argument("key")
    p.add_argument("--reason", default="")
    p.set_defaults(func=cmd_revoke)

    p = sub.add_parser("banlist", help="输出作废名单片段")
    p.add_argument("name")
    p.set_defaults(func=cmd_banlist)

    p = sub.add_parser("keys", help="查看项目密钥对")
    p.add_argument("name")
    p.set_defaults(func=cmd_keys)

    p = sub.add_parser("history", help="查看签发历史")
    p.add_argument("name")
    p.set_defaults(func=cmd_history)

    return parser


def launch_menu() -> int:
    """进入交互式控制台（数字菜单）。"""
    try:
        import menu
    except ImportError as exc:
        print("无法加载菜单模块：{}".format(exc))
        print("请确认 menu.py 与本文件在同一目录。")
        return 2
    return menu.main_menu(STORE_PATH)


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # 没有任何参数 -> 直接进菜单；显式 --menu 也一样
    if not argv or argv[0] in ("-m", "--menu", "menu"):
        return launch_menu()

    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        return launch_menu()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
