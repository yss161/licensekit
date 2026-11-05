# LicenseKit

离线许可证系统，用于给 Python 项目加授权校验。不联网，不依赖第三方库。

- 每个项目有独立的密钥对，密钥跨项目不可用
- v4 格式使用 Ed25519 非对称签名，客户端只持有公钥
- 支持永久 / 限期 / 绑定机器
- 授权文件带完整性 MAC，改动任意一行即失效
- 纯标准库实现，含 Ed25519（已用 RFC 8032 测试向量验证）

## 快速开始

运行管理端：

```
python licensekit.py
```

不带参数会进入菜单，全部操作用数字选择：

```
1  签发许可证
2  生成客户端接入文件
3  项目管理
4  查看 / 校验密钥
5  吊销密钥
6  签发历史
0  退出
```

### 接入一个项目

**1. 新建项目**（菜单 3 → 2）

输入项目名，如 `mytool`。系统为它生成独立的密钥对。

**2. 生成客户端文件**（菜单 2）

选项目、选密钥长度、确认输出目录，得到：

```
out/mytool/
├── licensing.py    授权模块，已填好项目名和公钥
└── ed25519.py      签名实现
```

把这两个文件复制到你的程序目录。

**3. 在程序入口调用**

```python
import licensing
licensing.require()      # 未激活时打印机器码并退出
```

**4. 签发密钥**（菜单 1）

按提示选有效期、长度、版本、是否绑定机器，密钥生成后自动复制到剪贴板。

## 密钥格式

| 格式 | 长度 | 算法 | 源码公开后能否伪造 |
|---|---|---|---|
| v1 | 24 字符 | HMAC-SHA256 | 能 |
| v2 | 24 / 32 / 40 字符 | HMAC-SHA256 + 项目绑定 | 能 |
| v4 | 120 字符 | Ed25519 | 不能 |

v4 的签名固定 64 字节，无法压缩，所以短密钥只能用对称算法。
v1 和 v2 的客户端持有密钥，被逆向即可自行签发；v4 客户端只有公钥,数学上无法伪造。

密钥长度在生成客户端时确定，之后该程序只接受这一种长度。更换长度会使已发出的密钥全部失效。

## 项目隔离

签名内容包含项目名：

```
v2:  b"LKC2|" + PROJECT + b"|" + payload
v4:  b"LKV4|" + PROJECT + b"|" + payload
```

客户端把项目名写死，校验时重新拼一次。项目名不同则签名不匹配。
因此 A 项目的密钥无法激活 B 项目，即使两者使用同一份代码。

## 安全边界

能挡住的：

- 编造或抄错的密钥
- 把别的项目的密钥拿来用
- 手工修改 license.key（有完整性 MAC）
- 改名系统时间延长限期授权（有回退检测）
- 把密钥转发给别人（可绑定机器）

挡不住的：

- 拿到源码后直接修改客户端，删掉 `licensing.require()` 或把 `verify()` 改成返回 True。
  任何纯脚本的授权方案都无法阻止这一点。要防逆向需要编译成 exe 并加壳。

因此这套方案的定位是：防止密钥被分享和伪造，而不是防止客户端被篡改。

## 目录结构

```
licensekit/
├── licensekit.py           命令行入口
├── menu.py                 交互式菜单
├── selftest.py             运行全部测试
├── native/
│   ├── license_core.py     签发与校验
│   ├── ed25519.py          Ed25519 实现
│   └── client_builder.py   生成客户端文件
├── client_template/
│   └── licensing.py        客户端模板
├── tests/                  测试用例
└── examples/demo_app/      演示程序
```

## 关于 license_projects.json

该文件保存所有项目的私钥，是唯一能签发密钥的凭据。

- 丢失后无法再签发新密钥（已发出的密钥仍可使用）
- 泄露后他人可签发任意密钥

已在 `.gitignore` 中排除，请自行备份。客户端 `licensing.py` 只含公钥，可以公开。

## 测试

```
python selftest.py
```

包含四组：核心库单测（40 项）、密钥长度规格（14 项）、客户端端到端（5 项）、攻击面模拟（7 项）。

## 命令行

菜单之外也可直接用子命令，适合脚本和批量操作。

```
python licensekit.py add myapp --title 我的程序
python licensekit.py client myapp --out ./out/myapp --spec 120
python licensekit.py issue myapp --days 30
python licensekit.py issue myapp --expires 2027-12-31 --edition pro
python licensekit.py issue myapp --machine THIS
python licensekit.py inspect myapp <密钥>
python licensekit.py revoke myapp <密钥>
python licensekit.py banlist myapp
```

`--spec` 取值 24 / 32 / 40 / 120，默认沿用该项目上次生成客户端时的选择。