# -*- coding: utf-8 -*-
import sys, os, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "native"))
import license_core as L
from datetime import date, timedelta

ok = fail = 0
def check(name, cond, extra=""):
    global ok, fail
    if cond: ok += 1; print("  OK   " + name)
    else: fail += 1; print("  FAIL " + name + ("  -> " + str(extra) if extra else ""))

print("== 1. 基本格式 ==")
sk, pk = L.generate_keypair()
key = L.issue_v4(sk, "demo", "standard")
print("   密钥示例:", key)
check("v4 为 120 字符", len(L.normalize(key)) == 120, len(L.normalize(key)))
check("v4 为 20 组", key.count("-") == 19, key.count("-"))
check("格式识别为 v4", L.detect_format(key) == L.FORMAT_V4)

print("== 2. v4 校验正确性 ==")
good, msg, info = L.verify_v4(key, "demo", pk)
check("正常密钥通过", good, msg)
check("可解出版本类型", info.get("edition") == "standard", info)
check("永久有效", info.get("expires_on") is None)

print("== 3. 篡改检测 ==")
body = list(L.normalize(key)); body[10] = "A" if body[10] != "A" else "B"
broken = L.format_key("".join(body))
check("改一位立即失效", not L.verify_v4(broken, "demo", pk)[0])
check("空密钥失效", not L.verify_v4("", "demo", pk)[0])

print("== 4. 项目隔离（核心需求）==")
bad_p, _b = L.generate_keypair()
skA, pkA = L.generate_keypair(); skB, pkB = L.generate_keypair()
keyA = L.issue_v4(skA, "项目A", "standard")
keyB = L.issue_v4(skB, "项目B", "standard")
check("A 的密钥在 A 项目有效", L.verify_v4(keyA, "项目A", pkA)[0])
check("A 的密钥在 B 项目无效", not L.verify_v4(keyA, "项目B", pkA)[0])
check("B 的密钥在 A 项目无效", not L.verify_v4(keyB, "项目A", pkA)[0])
check("两个项目密钥不同", keyA != keyB)

print("== 5. 换密钥对后失效 ==")
check("别的密钥对签的同名项目密钥无效",
      not L.verify_v4(keyA, "项目A", bad_p)[0])

print("== 6. 到期控制 ==")
expired = L.issue_v4(skA, "项目A", "standard", days=7)
check("7 天密钥现在有效", L.verify_v4(expired, "项目A", pkA)[0])
check("8 天后失效",
      not L.verify_v4(expired, "项目A", pkA, today=date.today()+timedelta(days=8))[0])
check("永久密钥不受时间影响",
      L.verify_v4(L.issue_v4(skA, "项目A"), "项目A", pkA,
                  today=date.today()+timedelta(days=9999))[0])

print("== 7. 机器绑定 ==")
mc = L.machine_code()
print("   本机机器码:", mc)
bound = L.issue_v4(skA, "项目A", "standard", machine=mc)
check("绑定本机通过", L.verify_v4(bound, "项目A", pkA)[0])
check("换台机器失效", not L.verify_v4(bound, "项目A", pkA, machine="ZZZZZZZZ")[0])
check("不绑机的密钥换机器仍可用",
      L.verify_v4(L.issue_v4(skA, "项目A"), "项目A", pkA, machine="ZZZZZZZZ")[0])

print("== 8. 版本类型 ==")
for ed in ("standard", "professional", "internal", "trial"):
    k = L.issue_v4(skA, "项目A", ed)
    g, m, i = L.verify_v4(k, "项目A", pkA)
    check(f"{ed} 往返一致", g and i["edition"] == ed, m)

print("== 9. v1 兼容原版格式 ==")
v1sk = b"legacy-v1-test-secret"
k1 = L.issue_v1(v1sk, "standard")
print("   v1 密钥:", k1)
check("v1 长度也是 24", len(L.normalize(k1)) == 24)
check("v1 识别正确（给密钥可区分）",
      L.detect_format(k1, v1_secret=v1sk) == L.FORMAT_V1)
check("v1 自校验通过", L.verify_v1(k1, v1sk)[0])
check("v1 换密钥失效", not L.verify_v1(k1, b"other-secret")[0])
check("v1 会被当 v4 拒绝", not L.verify_v4(k1, "x", pk)[0])

print("== 10. 容错解析 ==")
dirty = " " + key.lower().replace("-", " ") + " "
check("空格/小写/无横杠也能识别", L.verify_v4(dirty, "demo", pk)[0])
check("全角横杠可识别", L.verify_v4(key.replace("-", "－"), "demo", pk)[0])
check("长度不对报错", not L.verify_v4("AAAAAA-BBBBBB", "demo", pk)[0])

print("== 11. describe 排错 ==")
d = L.describe(key, "demo", pk)
check("describe 能解开 v4", d.get("ok") and d.get("serial") is not None, d)

print("== 12. 管理端项目库 ==")
tmp = tempfile.mkdtemp()
store = L.ProjectStore(os.path.join(tmp, "p.json"))
store.add("app1", "应用一号"); store.add("app2", "应用二号"); store.save()
store2 = L.ProjectStore(os.path.join(tmp, "p.json"))
check("项目持久化", len(store2.list_projects()) == 2)
check("两项目公钥不同", store2.public_key("app1") != store2.public_key("app2"))
k2 = L.issue_v4(store2.private_key("app2"), "app2")
check("从库签发可用", L.verify_v4(k2, "app2", store2.public_key("app2"))[0])
store2.record_issue("app2", k2, {"edition": "standard"}); store2.revoke("app2", k2, "测试")
check("吊销记录生效", len(store2.revoked_keys("app2")) == 1)
check("banlist 可生成", "BANNED_KEYS" in store2.banlist_literal("app2"))

print("== 13. 授权文件完整性 ==")
p = os.path.join(tmp, "license.key")
L.save_record(p, key, b"filesecret", project="demo")
check("授权文件可读", L.read_record(p)["key"] != "")
check("完整性校验通过", L.verify_record(p, b"filesecret")[0])
with open(p, "r", encoding="utf-8") as fh: txt = fh.read()
with open(p, "w", encoding="utf-8") as fh: fh.write(txt.replace("激活时间", "激活年代"))
check("手改文件被发现", not L.verify_record(p, b"filesecret")[0])

print()
print("通过 %d / 失败 %d" % (ok, fail))
sys.exit(1 if fail else 0)
