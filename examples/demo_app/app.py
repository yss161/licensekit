#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
文本体检工具 · 授权演示
=======================

这是一个**真实可跑的小工具**，只是为了演示授权系统怎么接进一个程序。

它做两件事：
    1. 启动时检查授权，没激活就进激活页
    2. 激活后提供文本统计功能

运行的三种状态你可以亲自试：
    · 没激活  → 看到机器码，要求输入密钥
    · 输错了  → 立刻告诉你**具体错在哪**（格式 / 别的程序 / 过期 / 绑错机器 / 已作废）
    · 输对了  → 写 license.key，进入主菜单

调试用选项：
    python app.py --reset      清除激活，回到激活页
    python app.py --status     只看当前授权状态
    python app.py --machine    只显示本机机器码
"""

from __future__ import annotations

import os
import sys
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import licensing

VERSION = "1.0.0"
PRODUCT = licensing.PRODUCT
MAX_TRIES = 3

# ==========================================================
# 终端着色（Windows 10+ / macOS / Linux 都支持）
# ==========================================================
if os.name == "nt":
    os.system("")          # 打开 ANSI 转义支持


def paint(text: str, code: str) -> str:
    return "\033[" + code + "m" + text + "\033[0m"


def width(text: str) -> int:
    """显示宽度：中文/全角算 2 格。"""
    return sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1
               for ch in text)


def pad(text: str, size: int, right: bool = False) -> str:
    """按显示宽度补空格（不能用 ljust，中文会歪）。"""
    gap = max(0, size - width(text))
    return (" " * gap + text) if right else (text + " " * gap)


def green(t):    return paint(t, "32")
def red(t):      return paint(t, "31")
def yellow(t):   return paint(t, "33")
def cyan(t):     return paint(t, "36")
def bold(t):     return paint(t, "1")
def dim(t):      return paint(t, "90")


def line(char: str = "─", width: int = 60) -> str:
    return char * width


def banner() -> None:
    print()
    print(cyan("  ╔" + "═" * 58 + "╗"))
    print(cyan("  ║") + bold(pad("  文本体检工具  v" + VERSION, 58)) + cyan("║"))
    print(cyan("  ║") + dim(pad("  授权系统演示 · LicenseKit", 58)) + cyan("║"))
    print(cyan("  ╚" + "═" * 58 + "╝"))


# ==========================================================
# 错误诊断：把校验结果翻译成「人话 + 下一步怎么办」
# ==========================================================
def diagnose(key: str, message: str) -> str:
    """根据 verify() 返回的原因，给出更具体、可操作的提示。"""
    body = licensing.normalize(key)
    length = len(body)

    # 空输入
    if "空的" in message:
        return "你没有粘贴任何内容。请把作者给你的整串密钥复制过来。"

    # 旧版 v1 密钥（24 字符）
    if "v1" in message:
        return ("这是**旧版 v1 格式**的 24 字符密钥。\n"
                "     本程序用的是 **v4 格式**（120 字符），两者签名算法不同，不能通用。\n"
                "     请向作者索取本程序的 v4 密钥。")

    # 长度不对
    if "长度不对" in message:
        if length == 24:
            return "密钥只有 24 个字符，本程序需要 120 个字符（20 组）。"
        return ("密钥长度是 {} 个字符，本程序需要 **120 个字符**（20 组，每组 6 位）。\n"
                "     常见原因：复制时漏了一截、末尾多了空格，或者混进了中文标点。".format(length))

    # 含非法字符
    if "格式不对" in message:
        return ("密钥里出现了不属于它的字符。base32 只允许 **A-Z 和 2-7**，\n"
                "     常见情况：把数字 0 输成了字母 O，或把 1 输成了 I。\n"
                "     建议直接重新复制粘贴，不要手打。")

    # 别的程序的密钥
    if "不是本程序签发" in message or "本程序不匹配" in message:
        return ("签名对不上，说明这枚密钥不是发给「{}」的。\n"
                "     如果你有多个程序，检查一下是不是拿错了另一个程序的密钥。\n"
                "     也可能是复制过程中改动了某个字符。".format(licensing.PROJECT))

    # 过期
    if "过期" in message:
        return "授权已到期，请联系作者续期（续期后需要重新输入新密钥）。"

    # 绑定别的机器
    if "另一台电脑" in message or "机器码" in message:
        return ("这枚密钥绑定了别的电脑。\n"
                "     本机机器码：{}".format(bold(licensing.machine_code())) + "\n"
                "     把上面这行发给作者，换一枚绑定本机的密钥。")

    # 作废
    if "作废" in message:
        return "这枚密钥已被作者吊销（可能是退款、泄露或换机后重发）。请联系作者。"

    return "校验没有通过，请检查密钥是否完整、是否为本程序专用。"


def show_failure(key: str, message: str, attempt: int) -> None:
    print()
    print("  " + red("✗ 激活失败"))
    print("  " + line("─", 56))
    print("  原因：" + yellow(message))
    print()
    print("  " + diagnose(key, message))
    left = MAX_TRIES - attempt
    if left > 0:
        print()
        print(dim("  还可以再试 {} 次".format(left)))
    print()


def show_success(message: str) -> None:
    ok, msg, info = licensing.current_status()
    print()
    print("  " + green("✓ 激活成功！"))
    print("  " + line("─", 56))
    print("  授权内容：" + green(message))
    print("  授权文件：" + dim(licensing.license_path()))
    print()


# ==========================================================
# 激活页
# ==========================================================
def activation_screen() -> bool:
    banner()
    print()
    print(yellow("  ⚠  本程序尚未激活"))
    print("  " + line("─", 56))
    print("  本机机器码：" + bold(cyan(licensing.machine_code())))
    print()
    print(dim("  把这行机器码发给作者，换取一串本机专用的授权密钥。"))
    print(dim("  密钥形如：AB3DEF-7H2KLM-...（共 120 字符，横杠可有可无）"))
    print()

    for attempt in range(1, MAX_TRIES + 1):
        try:
            key = input("  请输入授权密钥" + dim("（直接回车退出）") + "：").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return False

        if not key:
            print()
            print(dim("  已取消。"))
            return False

        ok, message, info = licensing.verify(key)
        if ok:
            saved, save_msg, _ = licensing.activate(key)
            if not saved:
                print()
                print("  " + red("✗ 密钥有效，但写入授权文件失败："))
                print("    " + save_msg)
                print("    " + dim("可能是程序目录没有写权限，试试把程序放到桌面再运行。"))
                continue
            show_success(message)
            return True

        show_failure(key, message, attempt)

    print("  " + red("尝试次数已用完。"))
    print(dim("  请确认密钥无误后重新启动程序。"))
    print()
    return False


# ==========================================================
# 功能：文本体检
# ==========================================================
def text_report(text: str) -> None:
    if not text:
        print(yellow("  没有输入内容。"))
        return

    total = len(text)
    lines = text.count("\n") + 1
    chinese = sum(1 for ch in text if "\u4e00" <= ch <= "\u9fff")
    letters = sum(1 for ch in text if ch.isalpha() and not ("\u4e00" <= ch <= "\u9fff"))
    digits = sum(1 for ch in text if ch.isdigit())
    spaces = sum(1 for ch in text if ch.isspace())
    others = total - chinese - letters - digits - spaces

    words = len([w for w in text.replace("\n", " ").split(" ") if w.strip()])

    print()
    print("  " + bold("文本体检报告"))
    print("  " + line("─", 50))
    rows = [
        ("总字符数", total),
        ("行数", lines),
        ("词数（按空格）", words),
        ("中文字符", chinese),
        ("英文字母", letters),
        ("数字", digits),
        ("空白字符", spaces),
        ("其他符号", others),
    ]
    for label, value in rows:
        bar = "█" * min(20, int(value / max(total, 1) * 20))
        print("  " + pad(label, 14) + pad(str(value), 6, right=True)
              + "   " + (cyan(bar) if bar else ""))
    print()


def feature_text_check() -> None:
    print()
    print(dim("  粘贴或输入要分析的文本，输入空行结束："))
    print()
    chunks = []
    while True:
        try:
            one = input("  > ")
        except (EOFError, KeyboardInterrupt):
            break
        if not one.strip():
            break
        chunks.append(one)
    if chunks:
        text_report("\n".join(chunks))
    else:
        print(yellow("  没有输入内容。"))


def feature_license_info() -> None:
    ok, message, info = licensing.current_status()
    print()
    print("  " + bold("授权详情"))
    print("  " + line("─", 50))
    print("  状态      ：" + (green("已激活") if ok else red("未激活")))
    print("  说明      ：" + message)
    if info:
        edition = {"standard": "标准版", "professional": "专业版",
                   "internal": "内部版", "trial": "试用版"}.get(
                       str(info.get("edition")), str(info.get("edition")))
        print("  版本类型  ：" + edition)
        print("  到期日期  ：" + (str(info.get("expires_on")) if info.get("expires_on") else "永久"))
        print("  机器绑定  ：" + ("是" if info.get("machine_bound") else "否"))
        print("  流水号    ：" + str(info.get("serial")))
    print("  本机机器码：" + licensing.machine_code())
    print("  授权文件  ：" + dim(licensing.license_path()))
    print()


def feature_reset() -> None:
    path = licensing.license_path()
    if os.path.isfile(path):
        try:
            os.remove(path)
            print()
            print("  " + green("已清除激活。") + " 下次启动会重新要求输入密钥。")
            print()
        except OSError as exc:
            print(red("  删除失败：{}".format(exc)))
    else:
        print(yellow("  当前本来就没有激活文件。"))


def main_menu() -> None:
    while True:
        print()
        print(line())
        print("  " + bold("主菜单"))
        print(line())
        print("  1  文本体检")
        print("  2  查看授权详情")
        print("  3  更换授权密钥")
        print("  4  清除激活（演示用）")
        print("  0  退出")
        print()
        try:
            choice = input("  请选择：").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if choice == "1":
            feature_text_check()
        elif choice == "2":
            feature_license_info()
        elif choice == "3":
            print()
            print(dim("  输入新的授权密钥："))
            try:
                key = input("  > ").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if not key:
                continue
            ok, message, _ = licensing.verify(key)
            if ok:
                licensing.activate(key)
                show_success(message)
            else:
                show_failure(key, message, 1)
        elif choice == "4":
            feature_reset()
            print(dim("  重新进入激活页..."))
            if not activation_screen():
                return
        elif choice == "0":
            print()
            print(dim("  再见。"))
            return
        else:
            print(yellow("  无效选项，请输入 0-4。"))


# ==========================================================
# 入口
# ==========================================================
def main(argv=None) -> int:
    argv = argv or sys.argv[1:]

    if "--machine" in argv:
        print(licensing.machine_code())
        return 0

    if "--status" in argv:
        ok, message, info = licensing.current_status()
        print(("已激活：" if ok else "未激活：") + message)
        return 0 if ok else 3

    if "--reset" in argv:
        path = licensing.license_path()
        if os.path.isfile(path):
            os.remove(path)
            print("已清除激活文件：{}".format(path))
        else:
            print("没有找到激活文件。")
        return 0

    # 正常启动流程
    ok, message, info = licensing.current_status()
    if ok:
        licensing.touch()
        banner()
        print()
        print("  " + green("✓ 已授权  ") + dim(message))
        main_menu()
        return 0

    # 没激活
    if not activation_screen():
        print(dim("  程序未激活，已退出。"))
        return 3

    main_menu()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
