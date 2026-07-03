#  免杀技术套件skills ( AV Evasion Skill)

**作者：bluechips**
**版本：V4.0**
**更新日期：2026-06-26**
**状态：已验证成功**

一套完整的免杀解决方案，涵盖 Shellcode 处理与 Loader 编写，结合 IPv4 混淆、XOR 加密、Module Stomping、Fiber 执行、间接 Syscall 等技术，用于绕过主流杀软和 EDR 检测。

> ⚠️ **法律声明**：本工具仅用于授权的安全测试、CTF 比赛和渗透评估。严禁用于任何非法用途，使用本工具产生的任何后果由使用者自行承担。

---

## 目录

- [核心特性](#核心特性)
- [项目结构](#项目结构)
- [技术架构](#技术架构)
- [快速开始](#快速开始)
- [使用指南](#使用指南)
- [编译说明](#编译说明)
- [脚本说明](#脚本说明)
- [问题排查](#问题排查)
- [版本历史](#版本历史)
- [注意事项](#注意事项)

---

## 核心特性

### Shellcode 处理
- ✅ **Shellcode Patch**：同义指令替换 + 花指令注入，破坏静态特征码
- ✅ **XOR 加密**：自定义密钥，加密后数据与随机数据不可区分
- ✅ **IPv4 地址混淆**：将 Shellcode 伪装成 IPv4 地址数组，无字节序问题

### Loader 免杀技术
- ✅ **Module Stomping**：覆写合法微软签名 DLL 的 `.text` 段，零 VirtualAlloc 执行内存
- ✅ **HeapAlloc 解密缓冲**：使用堆分配而非 VirtualAlloc，行为与正常应用一致
- ✅ **RW→RX 内存权限翻转**：VirtualProtect 作用于签名 DLL 内存，非匿名页
- ✅ **Fiber 执行**：CreateFiber + SwitchToFiber，非 CreateThread
- ✅ **回调备用执行**：EnumSystemLocalesW 回调路径
- ✅ **零显式反沙箱**：不查 CPU、内存、VM 进程等（检测行为本身即特征）
- ✅ **零系统指纹**：不调 GetUserNameW、GetComputerName 等
- ✅ **手动 IPv4 解析**：不用 sscanf，减少 CRT 导入特征
- ✅ **DLL 分离加载**：Loader 不含敏感数据，静态免杀更优
- ✅ **无窗口静默**：-mwindows 编译为 GUI 程序

---

## 项目结构

```
ai-av-evasion-optimized/
├── README.md                          # 项目说明文档
├── SKILL.md                           # Skill 技术文档
└── scripts/
    ├── shellcode-patch.py             # Shellcode Patch 工具
    ├── shellcode-encrypt.py           # Shellcode XOR 加密工具
    ├── shellcode-obfuscate-ipv4.py    # IPv4 混淆工具
    ├── payload_dll.c                  # Payload DLL 源码模板
    └── loader_v4.c                    # v4.0 Module Stomping Loader
```

---

## 技术架构

### 1. Shellcode 处理流程

```
原始 Shellcode
      │
      ▼
┌─────────────────┐
│  shellcode-patch │  同义指令替换 + 花指令注入
└────────┬────────┘
         ▼
┌─────────────────┐
│ shellcode-encrypt│  XOR 加密 (自定义密钥)
└────────┬────────┘
         ▼
┌─────────────────────┐
│ shellcode-obfuscate  │  IPv4 地址混淆
│      -ipv4           │
└────────┬────────────┘
         ▼
   IPv4 数组 (C 格式)
         │
         ▼
   填入 payload_dll.c
```

### 2. Loader 执行流程 (v4.0)

```
程序启动 (WinMain / main)
      │
      ▼
  LoadLibrary("helper.dll")        ← 加载 Payload DLL
      │
      ▼
  GetPayloadData/Size/Key()       ← 获取 IPv4 数组 + 密钥
      │
      ▼
  HeapAlloc(堆分配) + IPv4 反混淆   ← 手动解析，不用 sscanf
      │
      ▼
  XOR 解密还原 Shellcode
      │
      ▼
  FreeLibrary(helper.dll)          ← 立即释放 DLL
      │
      ▼
  LoadLibrary("msimg32.dll")       ← 加载合法签名 DLL
      │
      ▼
  解析 PE 找到 .text 段
      │
      ▼
  VirtualProtect(.text → RW)       ← 签名 DLL 内存改为可写
      │
      ▼
  memcpy(.text, shellcode)         ← 覆写 .text 为 Shellcode
      │
      ▼
  VirtualProtect(.text → RX)       ← 翻转为可执行 (非 RWX!)
      │
      ▼
  SecureZeroMemory + HeapFree      ← 擦除堆中明文
      │
      ▼
  CreateFiber(.text)               ← Fiber 执行 (主路径)
      │
      ▼
  EnumSystemLocalesW(.text)        ← 回调执行 (备用路径)
```

### 3. v4.0 行为隐匿对比

| 行为 | 传统 Loader (被检出) | v4.0 (隐匿) |
|------|---------------------|-------------|
| 执行内存 | VirtualAlloc 匿名 RWX/RX | **Module Stomping** (签名 DLL 的 .text) |
| 解密缓冲 | VirtualAlloc | **HeapAlloc** (正常堆操作) |
| 反沙箱 | CPU/内存/VM 进程检查 | **零显式检测** |
| 系统指纹 | GetUserNameW/GetComputerName | **零查询** |
| 线程创建 | CreateThread/NtCreateThreadEx | **CreateFiber** |
| 调用栈 | 匿名内存 → 可疑 | **msimg32.dll!text → 合法** |
| ETW | 无处理或 Patch | 无 (Patch 本身也是特征) |
| 导入 DLL | 4+ (含 ADVAPI32/psapi) | **仅 2** (KERNEL32 + msvcrt) |

---

## 快速开始

### 环境要求

- 操作系统：Windows 10/11 (x64)
- Python：3.8+
- 编译器：GCC (MinGW-w64)
- Shellcode：64 位原始 Shellcode

### 一键处理 Shellcode

```bash
# 将你的 shellcode 放到 scripts 目录下
cp your_shellcode.bin scripts/shellcode_raw.bin
cd scripts/

# 步骤1: Patch Shellcode
python shellcode-patch.py shellcode_raw.bin

# 步骤2: XOR 加密
python shellcode-encrypt.py shellcode_patched.bin "你的密钥"

# 步骤3: IPv4 混淆
python shellcode-obfuscate-ipv4.py shellcode_encrypted.bin
```

---

## 使用指南

### 唯一方案：DLL 分离加载 (loader_v4.c)

Loader 本身不含敏感数据，运行时动态加载 `helper.dll` 获取 IPv4 数组和密钥。

1. 查看生成的 `shellcode_obfuscated_ipv4.c` 中的 IPv4 数组
2. 将 IPv4 数组复制到 `payload_dll.c` 的 `ipv4_array[]`
3. 将加密密钥填入 `payload_dll.c` 的 `GetEncryptionKey()` 返回值
4. Loader 代码无需修改（已内置完整 Module Stomping 逻辑）

**优势：**
- 静态免杀：Loader 不含 Shellcode 特征
- 灵活性：更换 Shellcode 只需重新编译 DLL
- 行为隐匿：Module Stomping 避开 VirtualAlloc 执行内存检测

---

## 编译说明

```bash
# 步骤1: 编译 Payload DLL
gcc -shared -o helper.dll payload_dll.c -s

# 步骤2: 编译 v4.0 Loader
gcc -mwindows -o loader.exe loader_v4.c -s

# 输出文件
# loader.exe + helper.dll 同目录放置即可
```

| 参数 | 说明 |
|------|------|
| `-shared` | 编译为 DLL |
| `-mwindows` | GUI 程序，无控制台窗口 |
| `-s` | 去除符号表，减小体积 |

**零额外链接库**：v4.0 不需要 `-lpsapi`，不依赖任何额外静态库。

---

## 脚本说明

### shellcode-patch.py

Shellcode 字节特征修改工具。

```bash
python shellcode-patch.py <shellcode_file>
```

输出：`shellcode_patched.bin`

### shellcode-encrypt.py

Shellcode XOR 加密工具。

```bash
python shellcode-encrypt.py <shellcode_file> <key>
```

| 参数 | 说明 |
|------|------|
| `shellcode_file` | 待加密的 Shellcode 文件 |
| `key` | 加密密钥（任意长度字符串） |

输出：`shellcode_encrypted.bin` + `shellcode_encrypted.c`

### shellcode-obfuscate-ipv4.py

IPv4 地址混淆工具。

```bash
python shellcode-obfuscate-ipv4.py <shellcode_file>
```

输出：`shellcode_obfuscated_ipv4.c`（C 语言 IPv4 数组格式）

---

## 问题排查

### 问题 1：解密后无法执行
**排查步骤：**
1. 对比解密后字节与原始 Shellcode（前 50 字节）
2. 确认 payload_dll.c 中的密钥与加密时一致
3. 确认 IPv4 数组完整复制（无截断）

### 问题 2：Shellcode 架构不匹配
**原因**：Loader 编译架构与 Shellcode 架构不一致。
**解决**：
- 64 位 Shellcode → GCC 默认编译（64 位）
- 32 位 Shellcode → 需 32 位 GCC 环境（MinGW32）

### 问题 3：虚拟机中无反应
**原因**：没有反沙箱退出逻辑 — v4.0 设计为在任何环境都运行。
**验证**：在真实 Windows 机器上测试。

### 问题 4：Stomping 的 DLL 崩溃
**原因**：`msimg32.dll` 的 `.text` 段小于 Shellcode。
**解决**：Loader 内置回退逻辑，自动尝试 `dcomp.dll` → `dwmapi.dll`。

### 问题 5：找不到 helper.dll
**原因**：DLL 与 EXE 不在同一目录。
**解决**：确保 `loader.exe` 和 `helper.dll` 同目录。

---

## 版本历史

**V4.0 (2026-06-26) — 当前版本**
- 🆕 Module Stomping：覆写签名 DLL .text 段替代 VirtualAlloc 执行内存
- 🆕 HeapAlloc 替代 VirtualAlloc 用于解密缓冲
- 🔴 移除所有反沙箱检测（检测行为本身即特征）
- 🔴 移除所有系统指纹查询
- 🔴 移除 ETW Patch（Patch 行为也是特征）
- 🆕 Fiber 执行 + EnumSystemLocalesW 回调备用
- 🆕 手动 IPv4 解析（零 sscanf 导入）
- 🆕 导入 DLL 从 4 个减至 2 个

**V3.0 (2026-06-07)** — 行为隐匿版
- RW→RX 分阶段内存 + 零反VM + ETW 绕过 + 回调执行

**V2.1 (2026-04-05)** — DLL 分离加载
- DLL 分离方案 + 时间延迟检测

**V2.0 (2026-04-04)** — IPv4 混淆
- IPv4 混淆替代 UUID + 6 层反沙箱 + Syscall 绕过

**V1.0** — 初始版本
- UUID 混淆 + 基础反沙箱

---

## 注意事项

1. **合法性**：本工具仅用于授权的安全测试、CTF 比赛和渗透评估
2. **时效性**：免杀技术会随杀软更新失效，需定期更新策略
3. **DLL 命名**：避免使用 `payload.dll`、`shellcode.dll` 等敏感名称
4. **密钥管理**：建议使用高强度随机密钥，避免弱密钥
5. **测试验证**：每次使用前应在目标环境等效的测试环境中验证
6. **Module Stomping**：若 `msimg32.dll` 不可用，Loader 自动回退到其他 DLL

---

## 赞赏码

如果这个项目帮你节省了一些时间，了解了一些技术，欢迎打赏支持 ❤️

你的支持是我持续维护和更新的动力。
每一份鼓励都很珍贵，谢谢！

💰 赞赏码见下方链接

https://img.remit.ee/api/file/BQACAgUAAyEGAASHRsPbAAEWSRFqQdZ84zinoByzmBI3yShdjaWbAQACnyIAAv6GEFbeygfRJhnU9zwE.png


## Star History

## Star History

<a href="https://www.star-history.com/?repos=bluechips-zhao%2Fav-evasion-skills&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=bluechips-zhao/av-evasion-skills&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=bluechips-zhao/av-evasion-skills&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=bluechips-zhao/av-evasion-skills&type=date&legend=top-left" />
 </picture>
</a>
---

**作者：bluechips**
**版本：V4.0**
**最后更新：2026-06-26**
**测试环境：Windows 10/11 Pro x64**
