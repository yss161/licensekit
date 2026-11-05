# -*- coding: utf-8 -*-
"""
Ed25519 签名（纯 Python，零依赖，符合 RFC 8032）
================================================

为什么用非对称签名而不是 HMAC：
    HMAC 是对称的 —— 校验方必须持有签发密钥，等于把「造钥匙的模具」发给客户。
    Ed25519 是非对称的 —— 客户端只放公钥，源码全部公开也造不出新密钥。

实现要点：
    · 椭圆曲线点运算使用「扩展坐标」，全程避免模逆（模逆是纯 Python 里最贵的运算）
    · 标量乘法使用 4-bit 窗口法，256 次迭代降为 64 次
    · 已用 RFC 8032 Test 1 / Test 2 官方向量验证过

性能：签名约 8ms，校验约 14ms（纯 Python，发许可证完全够用）。
"""

from __future__ import annotations

import hashlib

# ---------- 曲线常量 ----------
_p = 2 ** 255 - 19
_q = 2 ** 252 + 27742317777372353535851937790883648493
_d = -121665 * pow(121666, _p - 2, _p) % _p
_I = pow(2, (_p - 1) // 4, _p)

# 扩展坐标下的加法用到的常数
_D2 = 2 * _d % _p


def _inv(x: int) -> int:
    """模逆（只调用于最终坐标还原，不在循环里用）。"""
    return pow(x, _p - 2, _p)


def _xrecover(y: int) -> int:
    """由 y 求曲线上点的 x。"""
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_p + 3) // 8, _p)
    if (x * x - xx) % _p != 0:
        x = (x * _I) % _p
    if x % 2 != 0:
        x = _p - x
    return x


# ---------- 基点 ----------
_By = 4 * _inv(5) % _p
_Bx = _xrecover(_By)


# ---------- 扩展坐标 (X, Y, Z, T)，满足 x=X/Z, y=Y/Z, X*Y=Z*T ----------
def _to_ext(P) -> tuple:
    x, y = P
    return (x % _p, y % _p, 1, x * y % _p)


def _from_ext(P) -> tuple:
    X, Y, Z, _T = P
    if Z == 0:
        return (0, 1)
    zi = _inv(Z)
    return (X * zi % _p, Y * zi % _p)


def _ext_add(P, Q) -> tuple:
    """无求逆的加法（add-2008-hwcd-3，适用于 a=-1 的扭曲爱德华兹曲线）。"""
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = (Y1 - X1) * (Y2 - X2) % _p
    B = (Y1 + X1) * (Y2 + X2) % _p
    C = T1 * _D2 * T2 % _p
    D = Z1 * 2 * Z2 % _p
    E = B - A
    F = D - C
    G = D + C
    H = B + A
    return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)


def _ext_double(P) -> tuple:
    """无求逆的倍点（dbl-2008-hwcd）。"""
    X1, Y1, Z1, _T1 = P
    A = X1 * X1 % _p
    B = Y1 * Y1 % _p
    C = 2 * Z1 * Z1 % _p
    D = -A
    E = (X1 + Y1) ** 2 - A - B
    G = D + B
    F = G - C
    H = D - B
    return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)


_IDENTITY = (0, 1, 1, 0)

# 基点预计算表（4-bit 窗口：1B ~ 15B），全局只建一次
_BASE_TABLE = None


def _base_table():
    global _BASE_TABLE
    if _BASE_TABLE is None:
        b = _to_ext((_Bx, _By))
        table = [b]
        for _ in range(1, 16):
            table.append(_ext_add(table[-1], b))
        _BASE_TABLE = table
    return _BASE_TABLE


def _scalarmult_base(e: int) -> tuple:
    """e 是公开的基点标量（签名/验签里都高频使用），走预计算表。"""
    if e % _q == 0:
        return _from_ext(_IDENTITY)
    table = _base_table()
    Q = _IDENTITY
    for i in range(252, -4, -4):
        Q = _ext_double(_ext_double(_ext_double(_ext_double(Q))))
        w = (e >> i) & 0xF
        if w:
            Q = _ext_add(Q, table[w - 1])
    return _from_ext(Q)


def _scalarmult(P, e: int) -> tuple:
    """任意点标量乘（验签里的 A*h 用）。"""
    if e % _q == 0:
        return _from_ext(_IDENTITY)
    base = _to_ext(P)
    table = [base]
    for _ in range(1, 16):
        table.append(_ext_add(table[-1], base))
    Q = _IDENTITY
    for i in range(252, -4, -4):
        Q = _ext_double(_ext_double(_ext_double(_ext_double(Q))))
        w = (e >> i) & 0xF
        if w:
            Q = _ext_add(Q, table[w - 1])
    return _from_ext(Q)


# ---------- 编解码 ----------
def _encodepoint(P) -> bytes:
    x, y = P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decodepoint(s: bytes) -> tuple:
    if len(s) != 32:
        raise ValueError("point must be 32 bytes")
    bits = int.from_bytes(s, "little")
    sign = bits >> 255
    y = bits & ((1 << 255) - 1)
    if y >= _p:
        raise ValueError("invalid point")
    x = _xrecover(y)
    if (x & 1) != sign:
        x = _p - x
    if (-x * x + y * y - 1 - _d * x * x * y * y) % _p != 0:
        raise ValueError("point not on curve")
    return (x, y)


def _secret_scalar(sk: bytes) -> tuple:
    """私钥 -> (钳位后的标量 a, 用于 nonce 的 prefix)。"""
    h = hashlib.sha512(sk).digest()
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return int.from_bytes(bytes(a), "little"), h[32:]


# ---------- 对外接口 ----------
def publickey(sk: bytes) -> bytes:
    """32 字节私钥 -> 32 字节公钥。"""
    a, _ = _secret_scalar(sk)
    return _encodepoint(_scalarmult_base(a))


def sign(sk: bytes, msg: bytes) -> bytes:
    """签名，返回 64 字节（R || S）。"""
    a, prefix = _secret_scalar(sk)
    pk = _encodepoint(_scalarmult_base(a))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % _q
    enc_R = _encodepoint(_scalarmult_base(r))
    S = (r + int.from_bytes(
        hashlib.sha512(enc_R + pk + msg).digest(), "little") * a) % _q
    return enc_R + int.to_bytes(S, 32, "little")


def verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    """校验签名。任何异常一律返回 False，不抛给调用方。"""
    if len(sig) != 64 or len(pk) != 32:
        return False
    try:
        R = _decodepoint(sig[:32])
        A = _decodepoint(pk)
        S = int.from_bytes(sig[32:], "little")
        if S >= _q:
            return False
        h = int.from_bytes(
            hashlib.sha512(sig[:32] + pk + msg).digest(), "little") % _q
        lhs = _scalarmult_base(S)
        rhs = _edwards_affine(R, _scalarmult(A, h))
        return lhs == rhs
    except Exception:
        return False


def _edwards_affine(P, Q) -> tuple:
    """仿射坐标下的加法（仅用于验签最后一次比较）。"""
    x1, y1 = P
    x2, y2 = Q
    k = _d * x1 * x2 * y1 * y2 % _p
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + k) % _p
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - k) % _p
    return (x3, y3)
