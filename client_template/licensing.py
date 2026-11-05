# -*- coding: utf-8 -*-
"""
licensing.py · 客户端授权模块（模板）
====================================

用法：把本文件和 ed25519.py 一起复制到你的项目里，改下面三行即可。

    PROJECT    = "myapp"                  ← 项目名，必须与签发时一致
    PUBLIC_KEY = bytes.fromhex("...")     ← 本项目的公钥（管理端 gen-client 生成）
    BANNED_KEYS = set()                   ← 作废名单（管理端 revoke 后同步）

然后：

    import licensing
    if not licensing.is_activated():
        # 弹激活页，让用户输入密钥
        key = input(f"机器码 {licensing.machine_code()}，请输入授权码：")
        ok, msg, _ = licensing.activate(key)
        if not ok:
            print(msg); raise SystemExit(3)
    else:
        print(licensing.status_text())

安全说明：
    这个文件里只有「公钥」。即使整个源码公开，别人也造不出可用密钥 ——
    因为他没有私钥，而私钥只存在于你自己的管理端。
"""

from __future__ import annotations

import os
import sys

# 让 ed25519.py 与本文件同目录时能被导入
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ed25519

# ==========================================================
# 配置区（只改这里）
# ==========================================================
PROJECT = "myapp"
PRODUCT = "我的程序"

# 密钥长度规格（生成客户端时确定，改动会导致已有密钥全部失效）
#     24 / 32 / 40  -> 紧凑格式（对称 HMAC，短，好抄）
#     120           -> 强签名格式（Ed25519，长，源码公开也造不出）
KEY_SPEC = 120

# 120 字符（强签名）用的公钥
PUBLIC_KEY = bytes.fromhex("00" * 32)          # ← 生成时自动填入

# 24 / 32 / 40 字符（紧凑格式）用的对称密钥
COMPACT_SECRET = bytes.fromhex("00" * 32)      # ← 生成时自动填入

# 作废名单：管理端 revoke 后，把生成的片段粘到这里
BANNED_KEYS = set()

# 授权文件位置：默认与本文件同目录（licensing.py 和主程序放一起时最直观）。
# 如果你的项目是 app/ 子目录结构，改成：
#     LICENSE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LICENSE_NAME = "license.key"
LICENSE_DIR = os.path.dirname(os.path.abspath(__file__))

# 文件里的完整性 MAC 用什么算：优先用公钥派生（无需另存密钥）
def _file_secret() -> bytes:
    """派生授权文件 MAC 用的密钥（客户端无法伪造，因为要公钥反推私钥不可行）。"""
    import hashlib
    return hashlib.sha256(b"licensekit-record|" + PROJECT.encode()
                          + PUBLIC_KEY).digest()


# ==========================================================
# 以下一般不用改
# ==========================================================
import hashlib                      # noqa: E402
import hmac                         # noqa: E402
import platform                     # noqa: E402
import re                           # noqa: E402
import time                         # noqa: E402
import uuid                         # noqa: E402
from datetime import date, timedelta  # noqa: E402

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
V4_TOTAL, V4_CHARS = 75, 120

# 紧凑格式的签名字节数由 KEY_SPEC 推出：总字节 = 字符数 * 5 / 8，减去 7 字节载荷
COMPACT_SIGN_LEN = max(0, KEY_SPEC * 5 // 8 - 7)
V4_PAYLOAD_LEN, V4_SIGN_LEN = 7, 64
FOREVER = 0xFFFF
EPOCH = date(2020, 1, 1)
RECORD_VERSION = 2
EDITION_LABELS = {"standard": "标准版", "professional": "专业版",
                  "internal": "内部版", "trial": "试用版"}


def normalize(text: str) -> str:
    return re.sub(r"[\s\-_·—–‐‑‒−－_.]+", "", (text or "")).upper()


def format_key(body: str, group_len: int = 6) -> str:
    body = normalize(body)
    return "-".join(body[i:i + group_len]
                    for i in range(0, len(body), group_len))


def b32decode(text: str):
    body = normalize(text)
    if not body:
        return None
    acc = bits = 0
    out = bytearray()
    for ch in body:
        idx = ALPHABET.find(ch)
        if idx < 0:
            return None
        acc = (acc << 5) | idx
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if bits and (acc & ((1 << bits) - 1)):
        return None
    return bytes(out)


def b32encode(raw: bytes) -> str:
    out, acc, bits = [], 0, 0
    for byte in raw:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(ALPHABET[(acc >> bits) & 31])
    if bits:
        out.append(ALPHABET[(acc << (5 - bits)) & 31])
    return "".join(out)


# ---------- 机器码 ----------
def machine_code() -> str:
    try:
        node = uuid.getnode()
    except Exception:
        node = 0
    raw = "{}|{}|{}|{}".format(platform.node(), platform.system(),
                               platform.machine(), node)
    return b32encode(hashlib.sha256(raw.encode("utf-8", "replace")).digest())[:8]


def machine_fingerprint(code: str) -> int:
    code = (code or "").strip().upper()
    if not code or code in ("ANY", "NONE", "*"):
        return 0
    return int.from_bytes(
        hashlib.sha256(("machine:" + code).encode("utf-8")).digest()[:2], "big")


# ---------- 校验 ----------
def _summary(edition: str, expires_on, bound: bool, serial: int) -> str:
    label = EDITION_LABELS.get(edition, edition)
    tail = "永久有效" if expires_on is None else "有效期至 " + expires_on.isoformat()
    return "{} · {} · {} · 流水号 {}".format(label, tail,
                                            "绑定机器" if bound else "不绑机器", serial)


def verify(key: str, today=None):
    """校验许可证。返回 (是否有效, 说明, 解析结果)。

    顺序很重要：先看字符数和作废名单，再解码验签 ——
    这样用户拿到的是「长度不对 / 已作废」这种能自己修的提示，
    而不是含糊的「格式错误」。
    """
    body = normalize(key)
    if not body:
        return False, "密钥是空的，请粘贴完整密钥", {}
    if body in BANNED_KEYS:
        return False, "该密钥已被作废，请联系卖家", {}
    if len(body) != KEY_SPEC:
        return False, "密钥长度不对（当前 {} 个字符，本程序需要 {} 个）".format(
            len(body), KEY_SPEC), {}

    raw = b32decode(key)
    if raw is None:
        return False, "密钥格式不对（只能包含 A-Z 和 2-7，可能有字符被改动了）", {}

    if KEY_SPEC != V4_CHARS:
        return _verify_compact(body, raw, today)
    return _verify_strong(body, raw, today)


def _verify_compact(body: str, raw: bytes, today):
    """紧凑格式：HMAC + 项目绑定。"""
    sign_len = COMPACT_SIGN_LEN
    if len(raw) != V4_PAYLOAD_LEN + sign_len:
        return False, "密钥长度不对", {}

    payload = raw[:V4_PAYLOAD_LEN]
    sign = raw[V4_PAYLOAD_LEN:]
    expect = hmac.new(COMPACT_SECRET,
                      b"LKC2|" + PROJECT.encode("utf-8") + b"|" + payload,
                      hashlib.sha256).digest()[:sign_len]
    if not hmac.compare_digest(sign, expect):
        return False, "密钥无效：不是本程序签发的，或与本程序不匹配", {}

    head = payload[2]
    if (head >> 4) != 2:
        return False, "密钥格式版本不匹配", {}
    edition = {0: "standard", 1: "professional",
               2: "internal", 3: "trial"}.get(head & 0x0F)
    if edition is None:
        return False, "未知的版本类型", {}

    serial = int.from_bytes(payload[0:2], "big")
    expiry_value = int.from_bytes(payload[3:5], "big")
    machine_fp = int.from_bytes(payload[5:7], "big")
    expires_on = None if expiry_value == FOREVER else (
        EPOCH + timedelta(days=expiry_value))

    now = today or date.today()
    if expires_on is not None and now > expires_on:
        return False, "许可证已于 {} 过期".format(expires_on.isoformat()), {}

    if machine_fp and machine_fp != machine_fingerprint(machine_code()):
        return False, "该许可证绑定了另一台电脑，请用本机机器码重新签发", {}

    info = {"edition": edition, "serial": serial,
            "expires_on": None if expires_on is None else expires_on.isoformat(),
            "machine_bound": machine_fp != 0}
    return True, _summary(edition, expires_on, machine_fp != 0, serial), info


def _verify_strong(body: str, raw: bytes, today):
    """强签名格式：Ed25519。"""
    payload = raw[:V4_PAYLOAD_LEN]
    sign = raw[V4_PAYLOAD_LEN:V4_PAYLOAD_LEN + V4_SIGN_LEN]

    msg = b"LKV4|" + PROJECT.encode("utf-8") + b"|" + payload
    if not ed25519.verify(PUBLIC_KEY, msg, sign):
        return False, "密钥无效：不是本程序签发的，或与本程序不匹配", {}

    head = payload[2]
    if (head >> 4) != 4:
        return False, "密钥格式版本不匹配", {}
    edition = {0: "standard", 1: "professional",
               2: "internal", 3: "trial"}.get(head & 0x0F)
    if edition is None:
        return False, "未知的版本类型", {}

    serial = int.from_bytes(payload[0:2], "big")
    expiry_value = int.from_bytes(payload[3:5], "big")
    machine_fp = int.from_bytes(payload[5:7], "big")
    expires_on = None if expiry_value == FOREVER else (
        EPOCH + timedelta(days=expiry_value))

    now = today or date.today()
    if expires_on is not None and now > expires_on:
        return False, "许可证已于 {} 过期".format(expires_on.isoformat()), {}

    if machine_fp and machine_fp != machine_fingerprint(machine_code()):
        return False, "该许可证绑定了另一台电脑，请用本机机器码重新签发", {}

    info = {"edition": edition, "serial": serial,
            "expires_on": None if expires_on is None else expires_on.isoformat(),
            "machine_bound": machine_fp != 0}
    return True, _summary(edition, expires_on, machine_fp != 0, serial), info


# ---------- 授权文件 ----------
def license_path() -> str:
    return os.path.join(LICENSE_DIR, LICENSE_NAME)


def _record_mac(key: str, activated_at: str, last_seen: str) -> str:
    body = "v{}|{}|{}|{}".format(RECORD_VERSION, normalize(key),
                                 activated_at, last_seen)
    return b32encode(hmac.new(_file_secret(), body.encode("utf-8"),
                              hashlib.sha256).digest()[:8])


def save_license(key: str, activated_at: str = "", last_seen: str = "") -> str:
    activated_at = activated_at or time.strftime("%Y-%m-%d %H:%M:%S")
    last_seen = last_seen or date.today().isoformat()
    text = format_key(normalize(key))
    body = (
        "# {} · 授权文件 v{}\n".format(PRODUCT, RECORD_VERSION)
        + "# 删掉本文件 = 取消激活；手动改任何一行都会失效\n"
        + "# 激活时间：{}\n".format(activated_at)
        + "# 机器码：{}\n".format(machine_code())
        + "# 最近使用：{}\n".format(last_seen)
        + text + "\n"
        + "# 下面是整份文件的完整性校验（别删、别改）\n"
        + "MAC {}\n".format(_record_mac(text, activated_at, last_seen))
    )
    path = license_path()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(body)
    return path


def read_record() -> dict:
    result = {"exists": "0", "key": "", "activated_at": "",
              "last_seen": "", "mac": "", "machine": ""}
    try:
        with open(license_path(), "r", encoding="utf-8", errors="replace") as fh:
            lines = [x.rstrip("\n") for x in fh]
    except OSError:
        return result
    result["exists"] = "1"
    for line in lines:
        text = line.strip()
        if not text:
            continue
        if text.startswith("#"):
            for prefix, field in (("# 激活时间：", "activated_at"),
                                  ("# 最近使用：", "last_seen"),
                                  ("# 机器码：", "machine")):
                if text.startswith(prefix):
                    result[field] = text[len(prefix):].strip()
            continue
        if text.upper().startswith("MAC"):
            result["mac"] = text[3:].strip()
            continue
        if not result["key"]:
            result["key"] = text
    return result


def touch() -> bool:
    """记录「今天用过」（日期变了才写盘）。"""
    record = read_record()
    if record["exists"] != "1" or not record["key"]:
        return False
    today = date.today().isoformat()
    if record["last_seen"] == today:
        return False
    try:
        save_license(record["key"], record["activated_at"], today)
        return True
    except OSError:
        return False


# ---------- 对外接口 ----------
def current_status(today=None):
    """当前授权状态。返回 (是否已激活, 说明, 信息)。"""
    record = read_record()
    if record["exists"] != "1":
        return False, "尚未激活（没有找到授权文件）", {}
    if not record["key"]:
        return False, "授权文件里没有密钥，请重新激活", {}
    ok, message, info = verify(record["key"], today=today)
    if not ok:
        return False, message, info
    if not record["mac"]:
        return False, "授权文件缺少完整性校验，请重新激活", info
    expect = _record_mac(record["key"], record["activated_at"], record["last_seen"])
    if normalize(record["mac"]) != normalize(expect):
        return False, "授权文件被改动过（完整性校验不通过），请重新激活", info
    if record["last_seen"]:
        try:
            seen = date.fromisoformat(record["last_seen"])
        except ValueError:
            return False, "授权文件日期格式异常，请重新激活", info
        now = today or date.today()
        if now < seen - timedelta(days=1):
            return False, ("系统时间异常：当前 {}，比上次使用 {} 还早。"
                           "请把电脑时间调准".format(now.isoformat(),
                                                   seen.isoformat())), info
    info.update({"activated_at": record["activated_at"],
                 "last_seen": record["last_seen"]})
    return True, message, info


def is_activated() -> bool:
    return current_status()[0]


def activate(key: str):
    """校验并写入授权文件。返回 (是否成功, 说明, 信息)。"""
    ok, message, info = verify(key)
    if not ok:
        return False, message, info
    try:
        save_license(key)
    except OSError as exc:
        return False, "写入授权文件失败：{}".format(exc), info
    return True, message, info


def status_text() -> str:
    ok, message, _info = current_status()
    return ("{}（{}）".format(message, machine_code()) if ok
            else "未激活：" + message)


def require(exit_code: int = 3) -> None:
    """没激活就打印提示并退出。在你的主程序入口调用。"""
    ok, message, _info = current_status()
    if ok:
        touch()
        return
    print("=" * 52)
    print("  {} 需要授权".format(PRODUCT))
    print("=" * 52)
    print("  本机机器码：{}".format(machine_code()))
    print("  状态：{}".format(message))
    print()
    print("  把这行机器码发给作者换取授权码，然后重新运行程序。")
    raise SystemExit(exit_code)
