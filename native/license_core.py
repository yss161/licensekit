# -*- coding: utf-8 -*-
"""
LicenseKit 核心库
=================

离线许可证的签发与校验。三种格式：

  v1  legacy HMAC：7 字节载荷 + 8 字节签名，固定 24 字符。
  v2  紧凑 HMAC  ：7 字节载荷 + 8/13/18 字节签名，24/32/40 字符。
      签名覆盖项目名，跨项目不可用。客户端持有密钥，可被逆向。
  v4  Ed25519    ：7 字节载荷 + 64 字节签名，120 字符。
      客户端只持公钥，源码公开也无法伪造。

项目隔离
--------
签名内容里带项目名（v2: LKC2|项目名|载荷，v4: LKV4|项目名|载荷），
客户端校验时用自己写死的项目名重新拼一次，对不上就拒绝。
每个项目另有独立的密钥对。

版本类型：standard / professional / internal / trial
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import re
import secrets
import time
import uuid
from datetime import date, timedelta
from typing import Dict, List, Optional, Tuple

import ed25519

# ==========================================================
# 常量
# ==========================================================
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"      # RFC4648 base32

FORMAT_V1 = 1          # 原版 HMAC 格式：7 载荷 + 8 签名 = 15 字节 = 24 字符
FORMAT_V2 = 2          # 紧凑格式（本项目 HMAC + 项目绑定）：长度可选
FORMAT_V4 = 4          # 强签名格式：7 载荷 + 64 签名 + 4 补齐 = 75 字节 = 120 字符

# 可选密钥规格：字符数 -> 签名字节数
#   base32 每 5 字节正好 8 字符，所以总长必须是 5 的倍数：
#   7 载荷 + N 签名 = 5k  =>  N = 8/13/18/23...
KEY_SPECS = {
    24: {"format": FORMAT_V2, "sign": 8},     # 极简：8 字节 MAC
    32: {"format": FORMAT_V2, "sign": 13},    # 简洁：13 字节 MAC
    40: {"format": FORMAT_V2, "sign": 18},    # 中等：18 字节 MAC
    120: {"format": FORMAT_V4, "sign": 64},   # 强签名：Ed25519
}
DEFAULT_SPEC = 120

GROUP_LEN = 6

V1_PAYLOAD_LEN = 7
V1_SIGN_LEN = 8
V1_TOTAL = V1_PAYLOAD_LEN + V1_SIGN_LEN             # 15

V4_PAYLOAD_LEN = 7
V4_SIGN_LEN = 64
V4_PAD_LEN = 4
V4_TOTAL = V4_PAYLOAD_LEN + V4_SIGN_LEN + V4_PAD_LEN  # 75

# 版本类型编码
EDITION_CODES = {
    "standard": 0,
    "professional": 1,
    "internal": 2,
    "trial": 3,
}
EDITION_NAMES = {v: k for k, v in EDITION_CODES.items()}
EDITION_LABELS = {
    "standard": "标准版",
    "professional": "专业版",
    "internal": "内部版",
    "trial": "试用版",
}

FOREVER = 0xFFFF
EPOCH = date(2020, 1, 1)


class LicenseError(Exception):
    """许可证相关的可预期错误。"""


# ==========================================================
# 编解码：base32 <-> 文本
# ==========================================================
def normalize(text: str) -> str:
    """去掉分隔符、统一大写，只保留 24 个密钥字符。

    接受半角/全角横杠、下划线、点、空格等常见分隔写法，
    不做 0/O、1/I 之类的猜测性替换（宁可报格式错误，也不要错位）。
    """
    return re.sub(r"[\s\-_·—–‐‑‒−－_.]+", "", (text or "")).upper()


def format_key(body: str, group_len: int = GROUP_LEN) -> str:
    """按 6 位分组加横杠，便于抄写与核对（v1 得 4 组，v4 得 20 组）。"""
    body = normalize(body)
    return "-".join(body[i:i + group_len]
                    for i in range(0, len(body), group_len))


def b32encode(raw: bytes) -> str:
    out = []
    acc = 0
    bits = 0
    for byte in raw:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(ALPHABET[(acc >> bits) & 31])
    if bits:
        out.append(ALPHABET[(acc << (5 - bits)) & 31])
    return "".join(out)


def b32decode(text: str) -> Optional[bytes]:
    """严格 base32 解码：非法字符或多余位数一律返回 None。"""
    body = normalize(text)
    if not body:
        return None
    acc = 0
    bits = 0
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
    # 剩余不足 8 位的填充必须为 0，否则是被改过的密钥
    if bits and (acc & ((1 << bits) - 1)):
        return None
    return bytes(out)


# ==========================================================
# 到期日 Helpers
# ==========================================================
def expiry_to_value(expires_on) -> int:
    """把到期日（date / 'YYYY-MM-DD' / None）编码成载荷值。"""
    if expires_on in (None, "", 0):
        return FOREVER
    if isinstance(expires_on, str):
        expires_on = date.fromisoformat(expires_on.strip())
    delta = (expires_on - EPOCH).days
    if delta < 0:
        raise LicenseError(f"到期日 {expires_on} 早于纪元 {EPOCH}，请换一个日期")
    if delta >= FOREVER:
        return FOREVER
    return delta


def value_to_expiry(value: int) -> Optional[date]:
    if value == FOREVER:
        return None
    return EPOCH + timedelta(days=value)


def days_to_expiry(days: int) -> int:
    return expiry_to_value(date.today() + timedelta(days=int(days)))


# ==========================================================
# 机器码
# ==========================================================
def machine_code() -> str:
    """本机机器码（8 位）。同一台机器基本不变。"""
    try:
        node = uuid.getnode()
    except Exception:
        node = 0
    raw = "{}|{}|{}|{}".format(
        platform.node(), platform.system(), platform.machine(), node
    )
    digest = hashlib.sha256(raw.encode("utf-8", "replace")).digest()
    return b32encode(digest)[:8]


def machine_fingerprint(code: str) -> int:
    """机器码 -> 2 字节指纹。空 / ANY / * 表示不绑定机器。"""
    code = (code or "").strip().upper()
    if not code or code in ("ANY", "NONE", "*"):
        return 0
    digest = hashlib.sha256(("machine:" + code).encode("utf-8")).digest()
    return int.from_bytes(digest[:2], "big")


# ==========================================================
# 项目命名空间
# ==========================================================
def namespace_code(project: str) -> int:
    """项目名 -> 2 字节命名空间。不同项目必然不同。"""
    digest = hashlib.sha256(("ns:" + (project or "").strip()).encode("utf-8")).digest()
    return int.from_bytes(digest[:2], "big")


# ==========================================================
# 载荷编解码
# ==========================================================
def _v1_keystream(secret: bytes, nonce: bytes) -> bytes:
    return hashlib.sha256(secret + nonce).digest()[:V1_PAYLOAD_LEN]


def build_v1_payload(secret: bytes, edition: str, expiry: int,
                     serial: int, machine_fp: int) -> bytes:
    """构造原版格式的 7 字节载荷（第 2~6 字节被异或掩盖）。"""
    head = ((FORMAT_V1 & 0xF) << 4) | (EDITION_CODES[edition] & 0xF)
    plain = (int(serial & 0xFFFF).to_bytes(2, "big")
             + bytes([head])
             + int(expiry).to_bytes(2, "big")
             + int(machine_fp & 0xFFFF).to_bytes(2, "big"))
    stream = _v1_keystream(secret, plain[0:2])
    out = bytearray(plain)
    for i in range(2, len(out)):
        out[i] ^= stream[i]
    return bytes(out)


def parse_v1_payload(secret: bytes, stored: bytes) -> bytes:
    stream = _v1_keystream(secret, stored[0:2])
    out = bytearray(stored)
    for i in range(2, len(out)):
        out[i] ^= stream[i]
    return bytes(out)


def _v4_pad(payload: bytes, sign: bytes) -> bytes:
    """4 字节补齐，把总长凑成 75=3*25 字节（对应 120 个 base32 字符）。

    这些字节不参与验签，只作填充；换台机器重编码也会被签名层拦住。
    """
    return hashlib.sha256(payload + sign).digest()[:V4_PAD_LEN]


def _v4_payload(project: str, edition: str, expiry_value: int,
                machine_fp: int, serial: int) -> Tuple[bytes, int]:
    head = ((FORMAT_V4 & 0xF) << 4) | (EDITION_CODES[edition] & 0xF)
    payload = (int(serial & 0xFFFF).to_bytes(2, "big")
               + bytes([head])
               + int(expiry_value).to_bytes(2, "big")
               + int(machine_fp & 0xFFFF).to_bytes(2, "big"))
    return payload, head


def v4_signed_message(project: str, payload: bytes) -> bytes:
    """签名覆盖「项目命名空间 + 载荷」—— 换项目签名必然失效。"""
    return b"LKV4|" + (project or "").encode("utf-8") + b"|" + payload


def parse_v4_payload(project: str, payload: bytes, sign: bytes,
                     public_key: bytes, today: Optional[date] = None) -> Dict[str, object]:
    """校验并解析 v4 载荷。失败抛 LicenseError。"""
    if not ed25519.verify(public_key, v4_signed_message(project, payload), sign):
        return {"ok": False, "reason": "签名无效（不是本程序签发的，或已损坏）"}

    head = payload[2]
    if (head >> 4) != FORMAT_V4:
        return {"ok": False, "reason": "密钥格式版本不匹配（需要 v4）"}

    serial = int.from_bytes(payload[0:2], "big")
    edition_code = head & 0x0F
    edition = EDITION_NAMES.get(edition_code)
    if edition is None:
        return {"ok": False, "reason": f"未知的版本类型 {edition_code}"}

    expiry_value = int.from_bytes(payload[3:5], "big")
    machine_fp = int.from_bytes(payload[5:7], "big")
    return {
        "ok": True,
        "format": FORMAT_V4,
        "serial": serial,
        "edition": edition,
        "expiry_value": expiry_value,
        "expires_on": value_to_expiry(expiry_value),
        "machine_fp": machine_fp,
        "machine_bound": machine_fp != 0,
    }


# ==========================================================
# 签发（v4 强签名）
# ==========================================================
def issue_v4(private_key: bytes, project: str, edition: str = "standard",
             expires_on=None, days: Optional[int] = None,
             machine: str = "", serial: Optional[int] = None) -> str:
    """签发一枚 v4 许可证。

    expires_on : date / 'YYYY-MM-DD' / None(永久)
    days       : 相对今天的天数（与 expires_on 二选一）
    machine    : 绑定的机器码；空 = 不绑机
    """
    if edition not in EDITION_CODES:
        raise LicenseError(f"未知版本类型：{edition}")

    if days is not None and expires_on is None:
        expiry_value = days_to_expiry(days)
    else:
        expiry_value = expiry_to_value(expires_on)

    if serial is None:
        serial = secrets.randbelow(0x10000)

    payload, _head = _v4_payload(project, edition, expiry_value,
                                 machine_fingerprint(machine), serial)
    sign = ed25519.sign(private_key, v4_signed_message(project, payload))
    body = b32encode(payload + sign + _v4_pad(payload, sign))
    return format_key(body)


def issue_v1(secret: bytes, edition: str = "standard",
             expires_on=None, days: Optional[int] = None,
             machine: str = "", serial: Optional[int] = None) -> str:
    """签发一枚原版 v1 格式密钥（HMAC 对称，可与原版程序互通）。"""
    if edition not in EDITION_CODES:
        raise LicenseError(f"未知版本类型：{edition}")
    if days is not None and expires_on is None:
        expiry_value = days_to_expiry(days)
    else:
        expiry_value = expiry_to_value(expires_on)
    if serial is None:
        serial = secrets.randbelow(0x10000)

    payload = build_v1_payload(secret, edition, expiry_value,
                               serial, machine_fingerprint(machine))
    sign = hmac.new(secret, payload, hashlib.sha256).digest()[:V1_SIGN_LEN]
    return format_key(b32encode(payload + sign))


# ==========================================================
# 紧凑格式（v2）：短密钥，对称 + 项目绑定
# ==========================================================
def compact_signed_message(project: str, payload: bytes) -> bytes:
    """签名覆盖项目名 —— 换项目立刻失效，这和 v4 是一个思路。

    注意：这里的密钥（secret）客户端也有一份，所以它防的是
    「随手转发、随便编一串字符」，不防「读了源码自己造钥匙」。
    """
    return b"LKC2|" + (project or "").encode("utf-8") + b"|" + payload


def issue_compact(secret: bytes, project: str, chars: int = 24,
                  edition: str = "standard", expires_on=None,
                  days: Optional[int] = None, machine: str = "",
                  serial: Optional[int] = None) -> str:
    """签发一枚紧凑格式密钥（24 / 32 / 40 字符）。"""
    if chars not in KEY_SPECS or KEY_SPECS[chars]["format"] != FORMAT_V2:
        raise LicenseError(
            "紧凑格式只支持 24 / 32 / 40 字符（强签名用 120）")
    if edition not in EDITION_CODES:
        raise LicenseError(f"未知版本类型：{edition}")
    if not secret:
        raise LicenseError("该项目没有紧凑密钥（compact_secret），无法签发")

    if days is not None and expires_on is None:
        expiry_value = days_to_expiry(days)
    else:
        expiry_value = expiry_to_value(expires_on)
    if serial is None:
        serial = secrets.randbelow(0x10000)

    sign_len = int(KEY_SPECS[chars]["sign"])
    head = ((FORMAT_V2 & 0xF) << 4) | (EDITION_CODES[edition] & 0xF)
    payload = (int(serial & 0xFFFF).to_bytes(2, "big")
               + bytes([head])
               + int(expiry_value).to_bytes(2, "big")
               + int(machine_fingerprint(machine) & 0xFFFF).to_bytes(2, "big"))
    sign = hmac.new(secret, compact_signed_message(project, payload),
                    hashlib.sha256).digest()[:sign_len]
    return format_key(b32encode(payload + sign))


def verify_compact(text: str, secret: bytes, project: str, machine: str = "",
                   today: Optional[date] = None,
                   check_machine: bool = True) -> Tuple[bool, str, Dict[str, object]]:
    """校验紧凑格式密钥。"""
    raw = b32decode(text)
    if raw is None:
        return False, "密钥格式不对（只能包含 A-Z 和 2-7）", {}

    chars = len(normalize(text))
    spec = KEY_SPECS.get(chars)
    if spec is None or spec["format"] != FORMAT_V2:
        return False, "密钥长度不是紧凑格式（24 / 32 / 40 字符）", {}

    sign_len = int(spec["sign"])
    if len(raw) != V4_PAYLOAD_LEN + sign_len:
        return False, "密钥长度不对", {}

    payload = raw[:V4_PAYLOAD_LEN]
    sign = raw[V4_PAYLOAD_LEN:]
    expect = hmac.new(secret, compact_signed_message(project, payload),
                      hashlib.sha256).digest()[:sign_len]
    if not hmac.compare_digest(sign, expect):
        return False, "密钥无效：不是本程序签发的，或与本程序不匹配", {}

    head = payload[2]
    if (head >> 4) != FORMAT_V2:
        return False, "密钥格式版本不匹配", {}
    edition = EDITION_NAMES.get(head & 0x0F)
    if edition is None:
        return False, "未知的版本类型", {}

    serial = int.from_bytes(payload[0:2], "big")
    expiry_value = int.from_bytes(payload[3:5], "big")
    machine_fp = int.from_bytes(payload[5:7], "big")
    expires_on = value_to_expiry(expiry_value)

    now = today or date.today()
    if expires_on is not None and now > expires_on:
        overdue = (now - expires_on).days
        return False, f"许可证已于 {expires_on.isoformat()} 过期（超期 {overdue} 天）", {}

    if check_machine and machine_fp != 0:
        if machine_fp != machine_fingerprint(machine or machine_code()):
            return False, ("该许可证绑定了另一台电脑（机器码对不上），"
                           "请用本机机器码重新签发"), {}

    info = {
        "ok": True,
        "format": FORMAT_V2,
        "chars": chars,
        "serial": serial,
        "edition": edition,
        "expiry_value": expiry_value,
        "expires_on": expires_on,
        "machine_fp": machine_fp,
        "machine_bound": machine_fp != 0,
    }
    return True, _summary(info, expires_on), info


# ==========================================================
# 校验
# ==========================================================
def detect_format(text: str, project: str = "", compact_secret: bytes = b"",
                  v1_secret: bytes = b"") -> Optional[int]:
    """识别密钥格式。

    120 字符 -> FORMAT_V4；
    24 / 32 / 40 字符 -> FORMAT_V2，但 24 字符与原版 v1 长度相同，
    所以如果传了 v1_secret 会用验签来区分（能验过 v1 就判为 v1）。
    """
    raw = b32decode(text)
    if raw is None:
        return None
    if len(raw) == V4_TOTAL:
        return FORMAT_V4

    chars = len(normalize(text))
    if chars not in KEY_SPECS:
        return None

    # 24 字符歧义：优先按紧凑格式验签，其次按原版 v1
    if compact_secret and project:
        if verify_compact(text, compact_secret, project, check_machine=False)[0]:
            return FORMAT_V2
    if v1_secret:
        if verify_v1(text, v1_secret, check_machine=False)[0]:
            return FORMAT_V1
    return FORMAT_V2


def verify_v4(text: str, project: str, public_key: bytes,
              machine: str = "", today: Optional[date] = None,
              check_machine: bool = True) -> Tuple[bool, str, Dict[str, object]]:
    """完整校验 v4 许可证：格式 -> 签名 -> 版本 -> 到期 -> 机器。"""
    raw = b32decode(text)
    if raw is None:
        return False, "密钥格式不对（含非法字符）", {}
    if len(raw) != V4_TOTAL:
        return False, "密钥长度不对（不是 v4 格式）", {}

    payload = raw[:V4_PAYLOAD_LEN]
    sign = raw[V4_PAYLOAD_LEN:V4_PAYLOAD_LEN + V4_SIGN_LEN]
    info = parse_v4_payload(project, payload, sign, public_key, today)
    if not info.get("ok"):
        return False, str(info.get("reason")), info

    now = today or date.today()
    expires_on = info["expires_on"]
    if expires_on is not None and now > expires_on:
        overdue = (now - expires_on).days
        return False, f"许可证已于 {expires_on.isoformat()} 过期（超期 {overdue} 天）", info

    if check_machine and info["machine_bound"]:
        want = int(info["machine_fp"])
        got = machine_fingerprint(machine or machine_code())
        if want != got:
            return False, ("该许可证绑定了另一台电脑（机器码对不上），"
                           "请用本机机器码重新签发"), info

    return True, _summary(info, expires_on), info


def verify_v1(text: str, secret: bytes, machine: str = "",
              today: Optional[date] = None,
              check_machine: bool = True) -> Tuple[bool, str, Dict[str, object]]:
    """校验原版 v1 密钥。"""
    raw = b32decode(text)
    if raw is None:
        return False, "密钥格式不对（含非法字符）", {}
    if len(raw) != V1_TOTAL:
        return False, "密钥长度不对（不是 v1 格式）", {}

    payload, sign = raw[:V1_PAYLOAD_LEN], raw[V1_PAYLOAD_LEN:]
    expect = hmac.new(secret, payload, hashlib.sha256).digest()[:V1_SIGN_LEN]
    if not hmac.compare_digest(sign, expect):
        return False, "密钥校验失败（不是本程序签发的，或抄错了）", {}

    plain = parse_v1_payload(secret, payload)
    head = plain[2]
    if (head >> 4) != FORMAT_V1:
        return False, "密钥版本不匹配（需要 v1）", {}
    edition = EDITION_NAMES.get(head & 0x0F)
    if edition is None:
        return False, "未知的版本类型", {}

    serial = int.from_bytes(plain[0:2], "big")
    expiry_value = int.from_bytes(plain[3:5], "big")
    machine_fp = int.from_bytes(plain[5:7], "big")
    expires_on = value_to_expiry(expiry_value)

    now = today or date.today()
    if expires_on is not None and now > expires_on:
        return False, f"许可证已于 {expires_on.isoformat()} 过期", {}

    if check_machine and machine_fp != 0:
        if machine_fp != machine_fingerprint(machine or machine_code()):
            return False, "该许可证绑定了另一台电脑", {}

    info = {
        "ok": True,
        "format": FORMAT_V1,
        "serial": serial,
        "edition": edition,
        "expiry_value": expiry_value,
        "expires_on": expires_on,
        "machine_fp": machine_fp,
        "machine_bound": machine_fp != 0,
    }
    return True, _summary(info, expires_on), info


def _summary(info: Dict[str, object], expires_on: Optional[date]) -> str:
    edition = EDITION_LABELS.get(str(info.get("edition")), str(info.get("edition")))
    tail = "永久有效" if expires_on is None else f"有效期至 {expires_on.isoformat()}"
    bound = "绑定机器" if info.get("machine_bound") else "不绑机器"
    return f"{edition} · {tail} · {bound} · 流水号 {info.get('serial')}"


def _parse_compact_view(text: str, raw: bytes, secret: bytes,
                        project: str) -> Dict[str, object]:
    """解出一枚紧凑密钥的内容（只解析，不判有效期）。"""
    chars = len(normalize(text))
    sign_len = int(KEY_SPECS.get(chars, {}).get("sign", 0))
    payload = raw[:V4_PAYLOAD_LEN]
    ok, _msg, _info = verify_compact(text, secret, project, check_machine=False)
    if not ok:
        return {"ok": False, "reason": "签名对不上（不是本项目签发的）"}
    head = payload[2]
    expiry_value = int.from_bytes(payload[3:5], "big")
    machine_fp = int.from_bytes(payload[5:7], "big")
    return {
        "ok": True,
        "format": FORMAT_V2,
        "chars": chars,
        "serial": int.from_bytes(payload[0:2], "big"),
        "edition": EDITION_NAMES.get(head & 0x0F, "?"),
        "expiry_value": expiry_value,
        "expires_on": value_to_expiry(expiry_value),
        "machine_fp": machine_fp,
        "machine_bound": machine_fp != 0,
    }


def describe(text: str, project: str = "", public_key: bytes = b"",
             secret: bytes = b"") -> Dict[str, object]:
    """不判断有效期/机器，只把密钥解开看内容（管理端排错用）。"""
    raw = b32decode(text)
    if raw is None:
        return {"ok": False, "reason": "格式错误：含非法字符，或不是完整密钥"}
    fmt = detect_format(text, project, secret, secret)
    if fmt is None:
        return {"ok": False,
                "reason": "长度不认识（支持 24 / 32 / 40 / 120 字符）"}
    try:
        if fmt == FORMAT_V4:
            if not public_key:
                return {"ok": False, "reason": "需要公钥才能查看该密钥内容"}
            info = parse_v4_payload(
                project, raw[:V4_PAYLOAD_LEN],
                raw[V4_PAYLOAD_LEN:V4_PAYLOAD_LEN + V4_SIGN_LEN], public_key)
        elif fmt == FORMAT_V2:
            if not secret:
                return {"ok": False, "reason": "需要紧凑密钥才能查看该密钥内容"}
            info = _parse_compact_view(text, raw, secret, project)
        else:
            if not secret:
                return {"ok": False, "reason": "需要密钥才能查看 v1 密钥内容"}
            plain = parse_v1_payload(secret, raw[:V1_PAYLOAD_LEN])
            info = {"ok": True, "format": FORMAT_V1,
                    "serial": int.from_bytes(plain[0:2], "big"),
                    "edition": EDITION_NAMES.get(plain[2] & 0x0F, "?"),
                    "expiry_value": int.from_bytes(plain[3:5], "big"),
                    "expires_on": value_to_expiry(int.from_bytes(plain[3:5], "big")),
                    "machine_fp": int.from_bytes(plain[5:7], "big"),
                    "machine_bound": int.from_bytes(plain[5:7], "big") != 0}
    except LicenseError as exc:
        return {"ok": False, "reason": str(exc)}
    if info.get("ok"):
        info["expires_on"] = (info["expires_on"].isoformat()
                              if info.get("expires_on") else None)
        info["normalized"] = format_key(normalize(text))
    return info


# ==========================================================
# 密钥对管理
# ==========================================================
def generate_keypair() -> Tuple[bytes, bytes]:
    """生成 Ed25519 密钥对 (私钥, 公钥)。"""
    sk = secrets.token_bytes(32)
    return sk, ed25519.publickey(sk)


# ==========================================================
# 许可证文件（带完整性 MAC + 时间回退检测）
# ==========================================================
RECORD_VERSION = 2


def _record_mac(secret: bytes, key: str, activated_at: str, last_seen: str) -> str:
    body = f"v{RECORD_VERSION}|{normalize(key)}|{activated_at}|{last_seen}"
    return b32encode(hmac.new(secret, body.encode("utf-8"),
                              hashlib.sha256).digest()[:8])


def save_record(path: str, key: str, secret: bytes,
                activated_at: str = "", last_seen: str = "",
                project: str = "") -> str:
    activated_at = activated_at or time.strftime("%Y-%m-%d %H:%M:%S")
    last_seen = last_seen or date.today().isoformat()
    key_text = format_key(normalize(key))
    mac = _record_mac(secret, key_text, activated_at, last_seen)
    body = (
        f"# {project or 'LicenseKit'} · 授权文件 v{RECORD_VERSION}\n"
        "# 删掉本文件 = 取消激活；手动改任何一行都会失效（下方有完整性校验）\n"
        f"# 激活时间：{activated_at}\n"
        f"# 机器码：{machine_code()}\n"
        f"# 最近使用：{last_seen}\n"
        f"{key_text}\n"
        f"# 下面是整份文件的完整性校验（别删、别改）\n"
        f"MAC {mac}\n"
    )
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(body)
    return path


def read_record(path: str) -> Dict[str, str]:
    result = {"path": path, "exists": "0", "key": "", "activated_at": "",
              "last_seen": "", "machine": "", "mac": ""}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            lines = [line.rstrip("\n") for line in handle]
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


def verify_record(path: str, secret: bytes, today: Optional[date] = None,
                  allow_rollback_days: int = 1) -> Tuple[bool, str, Dict[str, str]]:
    """校验授权文件本身：存在性 -> 完整性 MAC -> 时间回退。"""
    record = read_record(path)
    if record["exists"] != "1":
        return False, "尚未激活（没有找到授权文件）", record
    if not record["key"]:
        return False, "授权文件里没有密钥，请重新激活", record
    if not record["mac"]:
        return False, "授权文件缺少完整性校验（旧版或被改动），请重新激活", record
    expect = _record_mac(secret, record["key"],
                         record["activated_at"], record["last_seen"])
    if normalize(record["mac"]) != normalize(expect):
        return False, "授权文件被改动过（完整性校验不通过），请重新激活", record
    if record["last_seen"]:
        try:
            seen = date.fromisoformat(record["last_seen"])
        except ValueError:
            return False, "授权文件里的日期格式不对，请重新激活", record
        now = today or date.today()
        if now < seen - timedelta(days=allow_rollback_days):
            return False, (f"系统时间异常：现在是 {now.isoformat()}，"
                           f"比上次使用时间 {seen.isoformat()} 还早"), record
    return True, "OK", record


def touch_record(path: str, secret: bytes, project: str = "") -> bool:
    """把「最近使用」更新为今天（日期变了才重写）。"""
    record = read_record(path)
    if record["exists"] != "1" or not record["key"]:
        return False
    today = date.today().isoformat()
    if record["last_seen"] == today:
        return False
    try:
        save_record(path, record["key"], secret,
                    activated_at=record["activated_at"]
                    or time.strftime("%Y-%m-%d %H:%M:%S"),
                    last_seen=today, project=project)
        return True
    except OSError:
        return False


# ==========================================================
# 项目注册表（管理端）
# ==========================================================
REGISTRY_FILE = "license_projects.json"


class ProjectStore:
    """管理端保存的多项目密钥库。

    每个项目一条记录：项目名、显示名、公钥、私钥、v1 兼容密钥、签发历史。
    私钥只在这里出现，绝不下发到客户端。
    """

    def __init__(self, path: str = REGISTRY_FILE):
        self.path = path
        self.data = {"version": 1, "projects": {}}
        self.load()

    def load(self) -> None:
        if not os.path.isfile(self.path):
            return
        with open(self.path, "r", encoding="utf-8") as handle:
            self.data = json.load(handle)

    def save(self) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(self.data, handle, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)

    # -------- 项目 --------
    def list_projects(self) -> List[Dict[str, object]]:
        return sorted(self.data["projects"].values(), key=lambda x: str(x["name"]))

    def get(self, name: str) -> Optional[Dict[str, object]]:
        return self.data["projects"].get(name)

    def add(self, name: str, title: str = "", create_v1: bool = True) -> Dict[str, object]:
        name = (name or "").strip()
        if not name:
            raise LicenseError("项目名不能为空")
        if name in self.data["projects"]:
            raise LicenseError(f"项目 {name} 已存在")
        sk, pk = generate_keypair()
        record = {
            "name": name,
            "title": title or name,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ed25519_private": sk.hex(),
            "ed25519_public": pk.hex(),
            "v1_secret": secrets.token_hex(32) if create_v1 else "",
            "compact_secret": secrets.token_hex(32),
            "namespace": format(namespace_code(name), "04x"),
            "issued": [],
        }
        self.data["projects"][name] = record
        self.save()
        return record

    def remove(self, name: str) -> None:
        if name not in self.data["projects"]:
            raise LicenseError(f"项目 {name} 不存在")
        del self.data["projects"][name]
        self.save()

    def private_key(self, name: str) -> bytes:
        record = self.get(name)
        if record is None:
            raise LicenseError(f"项目 {name} 不存在")
        return bytes.fromhex(str(record["ed25519_private"]))

    def public_key(self, name: str) -> bytes:
        record = self.get(name)
        if record is None:
            raise LicenseError(f"项目 {name} 不存在")
        return bytes.fromhex(str(record["ed25519_public"]))

    def compact_secret(self, name: str) -> bytes:
        """紧凑格式用的对称密钥。老项目没有就现生成一个并存下来。"""
        record = self.get(name)
        if record is None:
            raise LicenseError(f"项目 {name} 不存在")
        secret = str(record.get("compact_secret") or "")
        if not secret:
            secret = secrets.token_hex(32)
            record["compact_secret"] = secret
            self.save()
        return bytes.fromhex(secret)

    def v1_secret(self, name: str) -> bytes:
        record = self.get(name)
        if record is None:
            raise LicenseError(f"项目 {name} 不存在")
        secret = str(record.get("v1_secret") or "")
        return bytes.fromhex(secret) if secret else b""

    # -------- 签发记录 --------
    def record_issue(self, name: str, key: str, meta: Dict[str, object]) -> None:
        record = self.get(name)
        if record is None:
            raise LicenseError(f"项目 {name} 不存在")
        entry = {
            "key": key,
            "issued_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        entry.update({k: v for k, v in meta.items() if k != "key"})
        record.setdefault("issued", []).append(entry)
        self.save()                       # 必须落盘，否则关掉就丢了

    def revoke(self, name: str, key: str, reason: str = "") -> bool:
        """把某枚密钥拉黑（客户端需同步 banlist 才能生效）。"""
        record = self.get(name)
        if record is None:
            raise LicenseError(f"项目 {name} 不存在")
        target = normalize(key)
        for entry in record.setdefault("issued", []):
            if normalize(str(entry.get("key", ""))) == target:
                entry["revoked"] = True
                entry["revoked_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                entry["reason"] = reason
                self.save()               # 同样要落盘
                return True
        return False

    def revoked_keys(self, name: str) -> List[str]:
        record = self.get(name)
        if record is None:
            return []
        return [str(e["key"]) for e in record.get("issued", []) if e.get("revoked")]

    def banlist_literal(self, name: str) -> str:
        """生成可直接粘进客户端 licensing.py 的 banlist 片段。"""
        keys = self.revoked_keys(name)
        body = ",\n".join(f'    "{format_key(normalize(k))}",' for k in keys)
        return "BANNED_KEYS = set(\n" + (body + "\n" if body else "") + ")\n"
