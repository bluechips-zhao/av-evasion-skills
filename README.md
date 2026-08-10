# AV Evasion Skills

**作者：bluechips**
**版本：V5.2**
**更新日期：2026-08-10**
**状态：已通过沙箱验证**

一套完整的免杀解决方案，涵盖 Shellcode 处理与 Loader 编写，综合运用 Indirect Syscall、ETW 补丁、Module Stomping、字符串加密、IPv4 混淆等技术，用于绕过主流杀软和 EDR 检测。

> ⚠️ **法律声明**：本工具仅用于授权的安全测试、CTF 比赛和渗透评估。严禁用于任何非法用途，使用本工具产生的任何后果由使用者自行承担。

***

## 目录

- [版本演进](#版本演进)
- [核心特性](#核心特性)
- [项目结构](#项目结构)
- [技术架构](#技术架构)
- [快速开始](#快速开始)
- [使用指南](#使用指南)
- [编译说明](#编译说明)
- [脚本说明](#脚本说明)
- [问题排查](#问题排查)
- [注意事项](#注意事项)

***

## 版本演进

| 版本       | 核心思路              | 关键技术                                       |
| -------- | ----------------- | ------------------------------------------ |
| v4.1     | 让杀软"看不懂"（行为伪装）    | WriteProcessMemory、HeapAlloc、直接函数指针调用      |
| v5.0     | 让杀软"看不见"（绕过 Hook） | Indirect Syscall + Halo's Gate、ETW 补丁      |
| v5.1     | 让杀软"查不到"（消除特征）    | 字符串编译期 XOR 加密、.text Code Cave              |
| **v5.2** | **单文件极简部署**       | **内嵌 Payload 数据、IPv4 编译期加密、消除 helper.dll** |

### v5.2 改进（基于沙箱报告）

1. **内嵌 Payload 数据**：将 IPv4 数组和密钥直接编译进 Loader，消除 `LoadLibraryA("helper.dll")` 调用
   - 减少 `NtQuerySystemInformation` 内部调用（6→4）
   - 单文件部署，无需 helper.dll
2. **IPv4 编译期加密**：每个 IPv4 字符串用 XOR 0x5A 加密，二进制中不存在任何明文 IP 地址
3. **密钥栈上解密 + 即时擦除**：密钥解密到栈上，使用后 `SecureZeroMemory` 擦除

***

## 核心特性

### Shellcode 处理

- ✅ **Shellcode Patch**：同义指令替换，破坏静态特征码
- ✅ **XOR 加密**：自定义密钥，加密后数据与随机数据不可区分
- ✅ **IPv4 地址混淆**：将 Shellcode 伪装成 IPv4 地址数组，无字节序问题

### Loader 免杀技术

- ✅ **Indirect Syscall**：跳转到 ntdll 中的 syscall;ret 指令，绕过用户态 Hook
- ✅ **Halo's Gate**：处理被 Hook 的 Nt\* 函数，从邻近存根推算 SSN
- ✅ **ETW 补丁**：通过 Indirect Syscall 致盲 EDR 事件收集
- ✅ **.text Code Cave**：利用自身 .text 段 padding 存放 syscall stub，零额外可执行内存
- ✅ **Module Stomping**：覆写合法微软签名 DLL 的 `.text` 段作为执行内存
- ✅ **字符串编译期加密**：所有敏感字符串 XOR 加密，运行时解密到栈上
- ✅ **HeapAlloc 解密缓冲**：使用堆分配而非 VirtualAlloc
- ✅ **直接函数指针调用**：无 CreateFiber、无回调 API
- ✅ **零反沙箱/零系统指纹**：不查 CPU、内存、VM 进程等
- ✅ **手动 IPv4 解析**：不用 sscanf，减少 CRT 导入
- ✅ **Stub 自清理**：执行后恢复 .text padding 原始内容
- ✅ **SecureZeroMemory**：堆/栈明文即时擦除
- ✅ **单文件部署**：无需 helper.dll，一个 exe 即可
- ✅ **无窗口静默**：-mwindows 编译为 GUI 程序

***

## 项目结构

```
av-evasion-skills/
├── README.md                          # 项目说明文档
├── SKILL.md                           # Skill 技术文档
└── scripts/
    ├── shellcode-patch.py             # Shellcode Patch 工具
    ├── shellcode-encrypt.py           # Shellcode XOR 加密工具
    ├── shellcode-obfuscate-ipv4.py    # IPv4 混淆工具
    ├── gen_embed_data.py              # 内嵌数据生成脚本
    ├── loader_v5.c                    # Loader 主源码
    ├── payload_data.h                 # 加密数据头文件（由 gen_embed_data.py 生成）
    └── tcp_windows_amd64.bin          # 示例 Shellcode
```

***

## 技术架构

### 1. Shellcode 处理流程

```
原始 Shellcode
      │
      ▼
┌─────────────────┐
│ shellcode-patch │  同义指令替换（破坏字节特征）
└────────┬────────┘
         ▼
┌─────────────────┐
│shellcode-encrypt│  XOR 加密 (自定义密钥)
└────────┬────────┘
         ▼
┌─────────────────────┐
│shellcode-obfuscate  │  IPv4 地址混淆
│     -ipv4           │
└────────┬────────────┘
         ▼
   IPv4 数组 (C 格式)
         │
         ▼
┌─────────────────────┐
│  gen_embed_data.py  │  生成 payload_data.h（XOR 加密）
└────────┬────────────┘
         ▼
   #include "payload_data.h"  ←  编译进 loader_v5.c
```

### 2. Loader 执行流程

```
程序启动 (main)
      │
      ▼
  PatchETW()                        ← Indirect Syscall 补丁 EtwEventWrite
      │
      ▼
  解密内嵌密钥到栈上                  ← DecryptStr(enc_key)
      │
      ▼
  HeapAlloc(堆分配) + IPv4 反混淆     ← 从 enc_ipv4[] 解密+解析
      │
      ▼
  XOR 解密还原 Shellcode
      │
      ▼
  SecureZeroMemory(key)             ← 擦除栈上密钥明文
      │
      ▼
  LoadLibrary("msimg32.dll")        ← 加载合法签名 DLL
      │                            (失败回退: dcomp.dll → dwmapi.dll)
      ▼
  解析 PE 找到 .text 段
      │
      ▼
  Indirect Syscall 写入 .text        ← BuildSyscallStub → NtWriteVirtualMemory
      │                            (回退: WriteProcessMemory)
      ▼
  FlushInstructionCache             ← 刷新指令缓存
      │
      ▼
  SecureZeroMemory + HeapFree       ← 擦除堆中明文
      │
      ▼
  CleanupSyscallStubs()             ← 恢复 .text padding 原始内容
      │
      ▼
  函数指针调用(.text)                ← 直接调用执行
```

### 3. 关键特性

| 维度              | 实现方式                                  |
| --------------- | ------------------------------------- |
| 执行内存来源          | 签名 DLL 的 .text 段（Module Stomping）     |
| 代码写入方式          | Indirect Syscall / WriteProcessMemory |
| Syscall Stub 存储 | .text Code Cave（零额外可执行内存）             |
| 解密缓冲区           | HeapAlloc（堆分配）                        |
| 执行方式            | 直接函数指针调用                              |
| 字符串保护           | 编译期 XOR 加密，运行时栈上解密                    |
| 系统信息查询          | 零查询                                   |
| IPv4 解析         | 手动解析（零 CRT 导入）                        |
| 执行地址栈回溯         | msimg32.dll!text（合法模块）                |
| 导入 DLL          | 仅 KERNEL32 + msvcrt                   |
| 内存清理            | SecureZeroMemory + HeapFree           |
| 部署方式            | 单文件（无需 helper.dll）                    |

### 4. DLL 回退链

```
msimg32.dll  →  dcomp.dll  →  dwmapi.dll
```

***

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

# 步骤4: 生成加密数据头文件
python gen_embed_data.py

# 步骤5: 编译 Loader
gcc -mwindows -o loader.exe loader_v5.c -s
```

***

## 使用指南

### 单文件部署 (loader\_v5.c)

v5.2 采用内嵌数据架构，所有 Payload 数据编译进 Loader，无需额外 DLL。

1. 运行 `gen_embed_data.py` 生成 `payload_data.h`
2. `payload_data.h` 包含加密后的 IPv4 数组和密钥
3. `loader_v5.c` 通过 `#include "payload_data.h"` 引入数据
4. 编译即可，无需其他文件

**优势：**

- 单文件部署，无需 helper.dll
- 减少 LoadLibraryA 调用，降低 NtQuerySystemInformation 触发
- 所有敏感数据编译期加密，二进制中无明文

***

## 编译说明

```bash
# 编译 Loader（单文件，零额外依赖）
gcc -mwindows -o loader.exe loader_v5.c -s
```

| 参数          | 说明            |
| ----------- | ------------- |
| `-mwindows` | GUI 程序，无控制台窗口 |
| `-s`        | 去除符号表，减小体积    |

**零额外链接库**：不需要 `-lpsapi`，不依赖任何额外静态库。

***

## 脚本说明

### shellcode-patch.py

Shellcode 字节特征修改工具。扫描已知等价指令模式进行替换，不改变指令长度和语义。

```bash
python shellcode-patch.py <shellcode_file>
```

输出：`shellcode_patched.bin`

### shellcode-encrypt.py

Shellcode XOR 加密工具。

```bash
python shellcode-encrypt.py <shellcode_file> <key>
```

| 参数               | 说明                 |
| ---------------- | ------------------ |
| `shellcode_file` | 待加密的 Shellcode 文件  |
| `key`            | 加密密钥（任意长度字符串，不可为空） |

输出：`shellcode_encrypted.bin` + `shellcode_encrypted.c`

### shellcode-obfuscate-ipv4.py

IPv4 地址混淆工具。

```bash
python shellcode-obfuscate-ipv4.py <shellcode_file>
```

输出：`shellcode_obfuscated_ipv4.c`

### gen\_embed\_data.py

内嵌数据生成脚本。从 `shellcode_obfuscated_ipv4.c`（或 payload\_dll.c）提取 IPv4 数组和密钥，生成编译期 XOR 加密的 C 头文件。

```bash
python gen_embed_data.py
```

输出：`payload_data.h`

***

## 问题排查

### 问题 1：解密后无法执行

**排查步骤：**

1. 对比解密后字节与原始 Shellcode（前 50 字节）
2. 确认 gen\_embed\_data.py 提取的密钥与加密时一致
3. 确认 IPv4 数组完整（无截断）

### 问题 2：Shellcode 架构不匹配

**原因**：Loader 编译架构与 Shellcode 架构不一致。
**解决**：

- 64 位 Shellcode → GCC 默认编译（64 位）
- 32 位 Shellcode → 需 32 位 GCC 环境（MinGW32）

### 问题 3：虚拟机中无反应

**原因**：没有反沙箱退出逻辑 — 本版本设计为在任何环境都运行。
**验证**：在真实 Windows 机器上测试。

### 问题 4：Stomping 的 DLL 崩溃

**原因**：`msimg32.dll` 的 `.text` 段小于 Shellcode。
**解决**：Loader 内置回退逻辑，自动尝试 `dcomp.dll` → `dwmapi.dll`。

### 问题 5：编译报错找不到 payload\_data.h

**原因**：未运行 gen\_embed\_data.py 生成头文件。
**解决**：先运行 `python gen_embed_data.py`，再编译。

***

## 注意事项

1. **合法性**：本工具仅用于授权的安全测试、CTF 比赛和渗透评估
2. **时效性**：免杀技术会随杀软更新失效，需定期更新策略
3. **密钥管理**：建议使用高强度随机密钥，密钥不可为空
4. **测试验证**：每次使用前应在目标环境等效的测试环境中验证
5. **Module Stomping**：若 `msimg32.dll` 不可用，Loader 自动回退到其他 DLL
6. **Indirect Syscall**：syscall number 随 Windows 版本变化，Loader 运行时动态解析

***

## 赞赏码

如果这个项目帮你节省了一些时间，了解了一些技术，欢迎打赏支持 ❤️

你的支持是我持续维护和更新的动力。
每一份鼓励都很珍贵，谢谢！

💰 赞赏码见下方链接

<https://img.remit.ee/api/file/BQACAgUAAyEGAASHRsPbAAEWSRFqQdZ84zinoByzmBI3yShdjaWbAQACnyIAAv6GEFbeygfRJhnU9zwE.png>

***

**作者：bluechips**
**版本：V5.2**
**最后更新：2026-08-10**
**测试环境：Windows 10/11 Pro x64**

<img width="2560" height="1248" alt="image" src="https://github.com/user-attachments/assets/97b621af-775b-47e7-b82c-5b9e2eb6beaf" />

<img width="2560" height="1248" alt="image" src="https://github.com/user-attachments/assets/40c18ab7-4d58-484e-8861-8d8cbc46e74c" />
