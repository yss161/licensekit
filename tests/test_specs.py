# -*- coding: utf-8 -*-
import sys, os, tempfile, secrets
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "native"))
import license_core as L
from datetime import date, timedelta

ok = fail = 0
def chk(n, c, e=""):
    global ok, fail
    if c: ok += 1; print("  OK   " + n)
    else: fail += 1; print("  FAIL " + n + ("  -> " + str(e) if e else ""))

sk, pk = L.generate_keypair()
proj = "demo"
sec = secrets.token_bytes(32)

print("== 各长度签发 ==")
for chars in (24, 32, 40, 120):
    if chars == 120:
        key = L.issue_v4(sk, proj, "standard")
        good, msg, info = L.verify_v4(key, proj, pk)
    else:
        key = L.issue_compact(sec, proj, chars, "standard")
        good, msg, info = L.verify_compact(key, sec, proj)
    chk("%d 字符（实得 %d）" % (chars, len(L.normalize(key))), 
        len(L.normalize(key)) == chars and good, msg)
    print("      ", L.format_key(key)[:60] + ("..." if chars > 60 else ""))

print()
print("== 项目隔离（同长度）==")
secA = secrets.token_bytes(32); secB = secrets.token_bytes(32)
kA = L.issue_compact(secA, "项目A", 24)
chk("A 的紧凑密钥在 A 有效", L.verify_compact(kA, secA, "项目A")[0])
chk("A 的紧凑密钥在 B 无效", not L.verify_compact(kA, secA, "项目B")[0])
chk("换 secret 无效", not L.verify_compact(kA, secB, "项目A")[0])

print()
print("== 篡改检测 ==")
body = list(L.normalize(kA)); body[10] = "A" if body[10] != "A" else "B"
chk("改一位失效", not L.verify_compact(L.format_key("".join(body)), secA, "项目A")[0])

print()
print("== 到期 / 绑机 ==")
e7 = L.issue_compact(secA, "项目A", 32, "standard", days=7)
chk("7 天现在有效", L.verify_compact(e7, secA, "项目A")[0])
chk("8 天后失效", not L.verify_compact(e7, secA, "项目A",
        today=date.today()+timedelta(days=8))[0])
mc = L.machine_code()
b = L.issue_compact(secA, "项目A", 40, "professional", machine=mc)
chk("绑本机有效", L.verify_compact(b, secA, "项目A")[0])
chk("换机失效", not L.verify_compact(b, secA, "项目A", machine="ZZZZZZZZ")[0])

print()
print("== 交叉误用 ==")
long_key = L.issue_v4(sk, proj, "standard")
chk("v4 密钥不被紧凑校验接受", not L.verify_compact(long_key, secA, "项目A")[0])
chk("紧凑密钥不被 v4 校验接受", not L.verify_v4(kA, "项目A", pk)[0])

print()
print("通过 %d / 失败 %d" % (ok, fail))
sys.exit(1 if fail else 0)
