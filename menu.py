# -*- coding: utf-8 -*-
"""
LicenseKit · 交互式控制台
=========================

全部操作都用「数字选择」完成，不必记命令。

    python licensekit.py          ← 直接进菜单

也保留了原来的命令行用法（脚本/批量时用）：

    python licensekit.py issue demo_app --days 30
"""

from __future__ import annotations

import os
import subprocess
import sys
import unicodedata
from datetime import date

HERE = os.path.dirname(os.path.abspath(__file__))
if os.path.join(HERE, "native") not in sys.path:
    sys.path.insert(0, os.path.join(HERE, "native"))

import client_builder
import license_core as L

if os.name == "nt":
    os.system("")

EDITION_MENU = [
    ("standard", "标准版"),
    ("professional", "专业版"),
    ("internal", "内部版"),
    ("trial", "试用版"),
]

# 密钥长度规格
SPEC_MENU = [
    (24, "24 字符 · 极简（最好抄，对称加密）"),
    (32, "32 字符 · 简洁（对称加密）"),
    (40, "40 字符 · 中等（对称加密）"),
    (120, "120 字符 · 强签名（Ed25519，源码公开也造不出）"),
]


def pick_spec(current: int = 120) -> int:
    """选密钥长度，返回字符数。"""
    default = 1
    for index, (chars, _label) in enumerate(SPEC_MENU, 1):
        if chars == current:
            default = index
    print()
    print("  " + bold("密钥长度"))
    print(dim("   24/32/40 是对称格式：短、好抄，但客户端里有密钥，"))
    print(dim("   源码被看到就能自己造。120 是非对称，源码公开也造不出。"))
    picked = choose("选择", [(label, chars) for chars, label in SPEC_MENU], default)
    return SPEC_MENU[picked - 1][0]


# ==========================================================
# 终端美化
# ==========================================================
def paint(text: str, code: str) -> str:
    return "\033[" + code + "m" + text + "\033[0m"


def green(t):  return paint(t, "32")
def red(t):    return paint(t, "31")
def yellow(t): return paint(t, "33")
def cyan(t):   return paint(t, "36")
def bold(t):   return paint(t, "1")
def dim(t):    return paint(t, "90")


def width(text: str) -> int:
    return sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1
               for ch in text)


def pad(text: str, size: int, right: bool = False) -> str:
    gap = max(0, size - width(text))
    return (" " * gap + text) if right else (text + " " * gap)


def rule(char: str = "─", size: int = 62) -> str:
    return char * size


def clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def pause(tip: str = "按回车返回") -> None:
    try:
        input("\n" + dim("  " + tip + " ..."))
    except (EOFError, KeyboardInterrupt):
        print()


def banner() -> None:
    print()
    print(cyan("  ╔" + "═" * 58 + "╗"))
    print(cyan("  ║") + bold(pad("  LicenseKit 授权管理控制台", 58)) + cyan("║"))
    print(cyan("  ║") + dim(pad("  数字选择 · 不用记命令", 58)) + cyan("║"))
    print(cyan("  ╚" + "═" * 58 + "╝"))


def title(text: str) -> None:
    print()
    print(bold("  " + text))
    print("  " + rule("─", width(text) + 2))


# ==========================================================
# 输入工具
# ==========================================================
def ask(prompt: str, default: str = "") -> str:
    """读一行；直接回车用默认值。EOF 抛 KeyboardInterrupt 交给上层。"""
    tail = dim(" [{}]".format(default)) if default else ""
    try:
        value = input("  " + prompt + tail + "：").strip()
    except EOFError:
        raise KeyboardInterrupt
    return value or default


def choose(prompt: str, options, default: int = 1) -> int:
    """数字选择，返回 1 起的序号。"""
    for index, (label, _value) in enumerate(options, 1):
        mark = green("●") if index == default else dim("○")
        print("   {} {} {}".format(mark, cyan(str(index)), label))
    print()
    while True:
        raw = ask(prompt, str(default))
        try:
            picked = int(raw)
        except ValueError:
            print("  " + red("请输入数字。"))
            continue
        if 1 <= picked <= len(options):
            return picked
        print("  " + red("请输入 1 ~ {} 之间的数字。".format(len(options))))


def confirm(prompt: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    raw = ask("{} ({})".format(prompt, hint), "").lower()
    if not raw:
        return default
    return raw.startswith("y")


def pause_or_quit() -> bool:
    """回车继续 / 输入 q 回主菜单。返回 False 表示要回主菜单。"""
    try:
        raw = input("\n" + dim("  回车继续，输入 q 返回主菜单 ...")).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return raw != "q"


# ==========================================================
# 剪贴板
# ==========================================================
def copy_to_clipboard(text: str) -> bool:
    try:
        if os.name == "nt":
            proc = subprocess.Popen("clip", stdin=subprocess.PIPE, shell=True)
            proc.communicate(text.encode("utf-16le"))
        elif sys.platform == "darwin":
            proc = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
            proc.communicate(text.encode("utf-8"))
        else:
            proc = subprocess.Popen(["xclip", "-selection", "clipboard"],
                                    stdin=subprocess.PIPE)
            proc.communicate(text.encode("utf-8"))
        return True
    except Exception:
        return False


# ==========================================================
# 密钥展示
# ==========================================================
def show_key(key: str) -> None:
    body = L.format_key(key)
    groups = body.split("-")
    print()
    print(green("  ┌" + "─" * 58 + "┐"))
    # 每行放 3 组
    for start in range(0, len(groups), 3):
        chunk = "-".join(groups[start:start + 3])
        print(green("  │ ") + bold(pad(chunk, 56)) + green("│"))
    print(green("  └" + "─" * 58 + "┘"))
    print(dim("   共 {} 个字符".format(len(L.normalize(key)))))

    if copy_to_clipboard(key):
        print("   " + green("✓ 已复制到剪贴板"))
    else:
        print(dim("   （剪贴板不可用，请手动选中复制）"))


# ==========================================================
# 选项目
# ==========================================================
def pick_project(store: "L.ProjectStore", prompt: str = "请选择项目",
                 auto_single: bool = True):
    """列出项目让用户选序号。返回项目记录，没有则返回 None。"""
    items = store.list_projects()
    if not items:
        print()
        print(yellow("  还没有任何项目。"))
        if confirm("现在新建一个？", True):
            return action_add_project(store)
        return None

    if auto_single and len(items) == 1:
        print(dim("  项目：{}（仅有一个，自动选中）".format(items[0]["title"])))
        return items[0]

    print()
    print("  " + bold("可用项目"))
    print("  " + rule("─", 58))
    for index, record in enumerate(items, 1):
        issued = len(record.get("issued", []))
        print("   {} {}  {}".format(
            cyan(str(index)),
            pad(str(record.get("title", "")), 20),
            dim("已签发 {} 枚".format(issued))))
    print("   {} 返回".format(cyan("0")))
    print()
    while True:
        raw = ask(prompt, "1")
        try:
            picked = int(raw)
        except ValueError:
            print("  " + red("请输入数字。"))
            continue
        if picked == 0:
            return None
        if 1 <= picked <= len(items):
            return items[picked - 1]
        print("  " + red("请输入 0 ~ {} 之间的数字。".format(len(items))))


# ==========================================================
# 功能 1：签发
# ==========================================================
def action_issue(store: "L.ProjectStore") -> None:
    while True:
        clear()
        banner()
        title("签发许可证")

        record = pick_project(store)
        if record is None:
            return
        name = str(record["name"])

        print()
        print("  " + bold("有效期"))
        picked = choose("选择", [
            ("永久有效", "forever"),
            ("指定天数", "days"),
            ("指定日期", "date"),
        ], 1)
        expires_on = None
        days = None
        if picked == 2:
            while True:
                raw = ask("多少天", "30")
                try:
                    days = int(raw)
                    if days > 0:
                        break
                except ValueError:
                    pass
                print("  " + red("请输入正整数。"))
        elif picked == 3:
            while True:
                raw = ask("到期日期（YYYY-MM-DD）", "")
                try:
                    expires_on = date.fromisoformat(raw).isoformat()
                    if date.fromisoformat(raw) <= date.today():
                        print("  " + red("这个日期已经过去了，请换一个。"))
                        continue
                    break
                except ValueError:
                    print("  " + red("格式不对，应形如 2027-06-30"))

        spec = pick_spec(int(record.get("spec") or L.DEFAULT_SPEC))

        print()
        print("  " + bold("版本类型"))
        picked = choose("选择", [(label, value) for value, label in EDITION_MENU], 1)
        edition = EDITION_MENU[picked - 1][0]

        print()
        print("  " + bold("机器绑定"))
        picked = choose("选择", [
            ("不绑定（换电脑也能用）", "none"),
            ("绑定本机（推荐）", "this"),
            ("输入其他机器码", "manual"),
        ], 1)
        machine = ""
        if picked == 2:
            machine = L.machine_code()
            print(dim("  本机机器码：{}".format(machine)))
        elif picked == 3:
            machine = ask("请输入机器码", "").strip().upper()

        # 签发
        try:
            if spec == 120:
                key = L.issue_v4(store.private_key(name), name, edition,
                                 expires_on=expires_on, days=days, machine=machine)
            else:
                key = L.issue_compact(store.compact_secret(name), name, spec,
                                      edition, expires_on=expires_on,
                                      days=days, machine=machine)
        except L.LicenseError as exc:
            print()
            print("  " + red("签发失败：{}".format(exc)))
            if not pause_or_quit():
                return
            continue

        if spec == 120:
            ok, message, _info = L.verify_v4(key, name, store.public_key(name),
                                             machine=machine)
        else:
            ok, message, _info = L.verify_compact(
                key, store.compact_secret(name), name, machine=machine)

        store.record_issue(name, key, {
            "edition": edition,
            "expires": expires_on or ("{} 天".format(days) if days else "永久"),
            "machine": machine or "不绑机",
            "format": "v4" if spec == 120 else "v2",
            "spec": spec,
        })

        print()
        print("  " + green("✓ 签发成功") + "  " + dim(message))
        show_key(key)

        if not confirm("再签一枚？", False):
            return


# ==========================================================
# 功能 2：生成客户端
# ==========================================================
def action_client(store: "L.ProjectStore") -> None:
    clear()
    banner()
    title("生成客户端接入文件")

    record = pick_project(store)
    if record is None:
        return
    name = str(record["name"])

    spec = pick_spec(int(record.get("spec") or L.DEFAULT_SPEC))

    default_out = os.path.join(HERE, "out", name)
    out_dir = ask("输出目录", default_out)

    template = os.path.join(HERE, "client_template", "licensing.py")
    if not os.path.isfile(template):
        print(red("  找不到模板：{}".format(template)))
        return

    try:
        client_builder.generate_client(
            record, spec, out_dir, store.compact_secret(name), template=template,
            ed25519_src=os.path.join(HERE, "native", "ed25519.py"))
    except OSError as exc:
        print(red("  生成失败：{}".format(exc)))
        pause()
        return

    # 记住这个项目选的规格，下次签发默认用它
    if record.get("spec") != spec:
        record["spec"] = spec
        store.save()

    print()
    print("  " + green("✓ 已生成") + dim("（密钥规格：{} 字符）".format(spec)))
    print("    " + os.path.join(out_dir, "licensing.py"))
    print("    " + os.path.join(out_dir, "ed25519.py"))
    print()
    print(dim("  把这两个文件复制进你的项目目录，然后在入口加："))
    print(dim("      import licensing"))
    print(dim("      licensing.require()"))
    pause()


# ==========================================================
# 功能 3：项目管理
# ==========================================================
def action_add_project(store: "L.ProjectStore"):
    title_text = ask("项目名称（英文/数字，签发时要用）", "")
    if not title_text:
        print(red("  已取消。"))
        return None
    if store.get(title_text):
        print(red("  项目 {} 已存在。".format(title_text)))
        return None
    show = ask("显示名称（可中文，直接回车同上）", title_text)
    try:
        record = store.add(title_text, show)
    except L.LicenseError as exc:
        print(red("  创建失败：{}".format(exc)))
        return None
    print()
    print("  " + green("✓ 项目已创建：{}".format(record["title"])))
    print("    项目名  ：" + str(record["name"]))
    print("    命名空间：" + str(record["namespace"]))
    print("    公钥    ：" + str(record["ed25519_public"])[:32] + "...")
    print()
    print(yellow("  ⚠ 这个项目的密钥已经生成并保存在 license_projects.json 中。"))
    return record


def action_projects(store: "L.ProjectStore") -> None:
    while True:
        clear()
        banner()
        title("项目管理")

        print("   {} 查看项目列表".format(cyan("1")))
        print("   {} 新建项目".format(cyan("2")))
        print("   {} 查看项目密钥对".format(cyan("3")))
        print("   {} 删除项目".format(cyan("4")))
        print("   {} 返回主菜单".format(cyan("0")))
        print()

        raw = ask("请选择", "1")
        if raw == "0":
            return

        if raw == "1":
            items = store.list_projects()
            print()
            if not items:
                print(yellow("  还没有任何项目。"))
            else:
                print("  " + pad("项目名", 18) + pad("显示名", 20)
                      + pad("命名空间", 10) + "已签发")
                print("  " + rule("─", 58))
                for record in items:
                    print("  " + pad(str(record["name"]), 18)
                          + pad(str(record.get("title", "")), 20)
                          + pad(str(record.get("namespace", "")), 10)
                          + str(len(record.get("issued", []))))
            pause()

        elif raw == "2":
            action_add_project(store)
            pause()

        elif raw == "3":
            record = pick_project(store, "选择要查看的项目", auto_single=False)
            if record:
                print()
                print("  " + bold(str(record.get("title"))))
                print("  " + rule("─", 58))
                print("  项目名    ：" + str(record["name"]))
                print("  命名空间  ：" + str(record.get("namespace")))
                print("  公钥      ：" + str(record["ed25519_public"]))
                print("  私钥      ：" + str(record["ed25519_private"]))
                print()
                print(yellow("  ⚠ 私钥能签出任意密钥，只留给自己，别放进客户端。"))
            pause()

        elif raw == "4":
            items = store.list_projects()
            if not items:
                print(yellow("  没有项目可删。"))
                pause()
                continue
            record = pick_project(store, "选择要删除的项目", auto_single=False)
            if record:
                print()
                print(red("  即将删除项目：{}（含 {} 条签发记录）".format(
                    record.get("title"), len(record.get("issued", [])))))
                print(red("  这个操作不可撤销，已发出的密钥将无法再验证。"))
                if confirm("确定删除？", False):
                    store.remove(str(record["name"]))
                    print(green("  已删除。"))
                else:
                    print(dim("  已取消。"))
            pause()
        else:
            print(red("  请输入 0 ~ 4。"))
            pause()


# ==========================================================
# 功能 4：查看 / 校验密钥
# ==========================================================
def action_inspect(store: "L.ProjectStore") -> None:
    clear()
    banner()
    title("查看 / 校验密钥")

    print(dim("  把密钥粘贴进来，我告诉你是谁签的、什么时候到期。"))
    print()
    key = ask("密钥", "")
    if not key:
        print(red("  已取消。"))
        pause()
        return

    items = store.list_projects()
    if not items:
        print(red("  还没有项目，无法校验。"))
        pause()
        return

    print()
    print("  " + bold("用哪个项目来校验？"))
    record = pick_project(store, "选择项目", auto_single=False)
    if record is None:
        return
    name = str(record["name"])

    compact_sec = store.compact_secret(name)
    info = L.describe(key, name, store.public_key(name), compact_sec)
    print()
    if not info.get("ok"):
        print("  " + red("✗ 无法解析"))
        print("    " + str(info.get("reason")))
        pause()
        return

    fmt = info.get("format")
    if fmt == L.FORMAT_V4:
        ok, message, _ = L.verify_v4(key, name, store.public_key(name),
                                     check_machine=False)
    elif fmt == L.FORMAT_V2:
        ok, message, _ = L.verify_compact(key, compact_sec, name,
                                          check_machine=False)
    else:
        ok, message, _ = L.verify_v1(key, store.v1_secret(name),
                                     check_machine=False)

    edition_raw = str(info.get("edition"))
    edition_cn = {"standard": "标准版", "professional": "专业版",
                  "internal": "内部版", "trial": "试用版"}.get(edition_raw, edition_raw)

    print("  " + (green("✓ 有效") if ok else red("✗ 无效")) + "  " + message)
    print("  " + rule("─", 58))
    print("  所属项目  ：{}（{}）".format(record.get("title"), name))
    print("  格式      ：v{}（{} 字符）".format(
        info.get("format"), len(L.normalize(key))))
    print("  版本类型  ：" + edition_cn)
    print("  流水号    ：" + str(info.get("serial")))
    print("  到期日期  ：" + str(info.get("expires_on") or "永久"))
    print("  机器绑定  ：" + ("是（指纹 {}）".format(info.get("machine_fp"))
                              if info.get("machine_bound") else "否"))
    pause()


# ==========================================================
# 功能 5：吊销
# ==========================================================
def action_revoke(store: "L.ProjectStore") -> None:
    clear()
    banner()
    title("吊销密钥")

    record = pick_project(store)
    if record is None:
        return
    name = str(record["name"])

    issued = [e for e in record.get("issued", []) if not e.get("revoked")]
    if not issued:
        print()
        print(yellow("  这个项目还没有可吊销的密钥。"))
        pause()
        return

    print()
    print("  " + bold("最近签发的密钥"))
    print("  " + rule("─", 62))
    recent = issued[-10:][::-1]
    for index, entry in enumerate(recent, 1):
        print("   {}  {}  {}".format(
            cyan(str(index)),
            pad(str(entry.get("issued_at", ""))[:16], 18),
            dim(L.format_key(str(entry.get("key", "")))[:28] + "...")))
    print("   {}  手动输入密钥".format(cyan("0")))
    print()

    raw = ask("请选择", "1")
    if raw == "0":
        key = ask("粘贴要吊销的密钥", "")
        if not key:
            return
    else:
        try:
            key = str(recent[int(raw) - 1]["key"])
        except (ValueError, IndexError):
            print(red("  选择无效。"))
            pause()
            return

    if store.revoke(name, key, "手动吊销"):
        print()
        print("  " + green("✓ 已吊销"))
        print()
        print(dim("  还要让它对客户端生效，需要把作废名单贴进去："))
        print()
        print(dim(store.banlist_literal(name)))
    else:
        print(red("  吊销失败：签发记录里没有这枚密钥。"))
    pause()


# ==========================================================
# 功能 6：签发历史
# ==========================================================
def action_history(store: "L.ProjectStore") -> None:
    clear()
    banner()
    title("签发历史")

    record = pick_project(store)
    if record is None:
        return

    items = record.get("issued", [])
    if not items:
        print()
        print(yellow("  这个项目还没有签发记录。"))
        pause()
        return

    print()
    labels = {"standard": "标准版", "professional": "专业版",
              "internal": "内部版", "trial": "试用版"}
    print("  " + pad("时间", 20) + pad("版本", 8) + pad("期限", 14)
          + pad("绑机", 8) + "状态")
    print("  " + rule("─", 62))
    for entry in items:
        state = red("已吊销") if entry.get("revoked") else green("有效")
        edition = labels.get(str(entry.get("edition", "")),
                             str(entry.get("edition", "")))
        machine = str(entry.get("machine", "不绑机"))
        if machine != "不绑机":
            machine = "是"
        print("  " + pad(str(entry.get("issued_at", "")), 20)
              + pad(edition, 8)
              + pad(str(entry.get("expires", "")), 14)
              + pad(machine, 8) + state)
    print()
    print(dim("  共 {} 枚".format(len(items))))
    pause()


# ==========================================================
# 主菜单
# ==========================================================
def main_menu(store_path: str) -> int:
    store = L.ProjectStore(store_path)

    while True:
        clear()
        banner()

        items = store.list_projects()
        print()
        if items:
            print(dim("  已有 {} 个项目 · 共签发 {} 枚密钥".format(
                len(items), sum(len(p.get("issued", [])) for p in items))))
        else:
            print(yellow("  还没有项目，先选 3 新建一个。"))

        print()
        print("   {}  签发许可证".format(cyan("1")) + green("   ← 最常用"))
        print("   {}  生成客户端接入文件".format(cyan("2")))
        print("   {}  项目管理".format(cyan("3")))
        print("   {}  查看 / 校验密钥".format(cyan("4")))
        print("   {}  吊销密钥".format(cyan("5")))
        print("   {}  签发历史".format(cyan("6")))
        print()
        print("   {}  退出".format(cyan("0")))
        print()

        try:
            raw = ask("请选择", "1")
        except KeyboardInterrupt:
            print()
            print(dim("  再见。"))
            return 0

        try:
            if raw == "0":
                print()
                print(dim("  再见。"))
                return 0
            elif raw == "1":
                action_issue(store)
            elif raw == "2":
                action_client(store)
            elif raw == "3":
                action_projects(store)
            elif raw == "4":
                action_inspect(store)
            elif raw == "5":
                action_revoke(store)
            elif raw == "6":
                action_history(store)
            else:
                print(red("  请输入 0 ~ 6。"))
                pause("按回车继续")
        except KeyboardInterrupt:
            print()
            print(dim("  已返回主菜单。"))
            continue

    return 0
