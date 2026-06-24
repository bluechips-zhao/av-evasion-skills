<!--
  Author: bluechips
  Version: V3.5
  Project: AI AV Evasion Skill (免杀技术套件)
  Date: 2026-06-24
-->

# AI 免杀技术套件 (AI AV Evasion Skill)

> **作者**：bluechips\
> **版本**：V3.5\
> **更新日期**：2026-06-24\
> **状态**：已验证成功

一套完整的免杀解决方案，涵盖 Shellcode 处理与 Loader 编写，结合 IPv4 混淆、RC4 加密、9 层反沙箱、栈字符串、ETW 绕过、RW→RX 翻转、间接 Syscall 等技术，用于绕过主流杀软和 EDR 检测。

> ⚠️ **法律声明**：本工具仅用于授权的安全测试、CTF 比赛和渗透评估。严禁用于任何非法用途，使用本工具产生的任何后果由使用者自行承担。

***

## 目录

- [核心特性](#核心特性)
- [项目结构](#项目结构)
- [技术架构](#技术架构)
- [快速开始](#快速开始)
- [使用指南](#使用指南)
- [编译说明](#编译说明)
- [脚本说明](#脚本说明)
- [测试结果](#测试结果)
- [问题排查](#问题排查)
- [版本历史](#版本历史)
- [注意事项](#注意事项)

***

## 核心特性

### Shellcode 处理

- ✅ **Shellcode Patch**：NOP sled 前缀 + NOP 等效指令变异 + 随机尾随填充
- ✅ **RC4 加密**：16 字节随机密钥，更高熵值，无已知明文攻击
- ✅ **XOR 加密**：兼容旧版的简单加密方案
- ✅ **IPv4 地址混淆**：将 Shellcode 伪装成 IPv4 地址数组，无字节序问题

### Loader 免杀技术

- ✅ **栈字符数组构造 API 名**：静态扫描看不到 API 明文
- ✅ **VEH 异常处理**：绕过内存扫描
- ✅ **间接 Syscall**：绕过用户层 API Hook
- ✅ **9 层反沙箱检测**：综合评分 ≥4 项才判定
- ✅ **ETW 遥测绕过**：EtwEventWrite → ret 补丁
- ✅ **RW→RX 内存权限翻转**：避免 RWX 内存扫描红旗
- ✅ **NtDelayExecution 随机延迟**：绕过 Sleep Hook（2-5s 随机抖动）
- ✅ **原生 GUI 入口**：WinMainCRTStartup，自动无窗口
- ✅ **DLL 分离加载**：Loader 不含敏感数据，静态免杀更优

***

## 项目结构

```
免杀skill/
├── README.md                          # 项目说明文档
├── SKILL.md                           # Skill 技术文档
├── shellcodes_raws.bin                # 原始 Shellcode (64位)
└── scripts/
    ├── shellcode-patch.py             # Shellcode Patch 工具
    ├── shellcode-encrypt.py           # Shellcode 加密工具 (RC4/XOR)
    ├── shellcode-obfuscate-ipv4.py    # IPv4 混淆工具 (推荐)
    ├── shellcode-obfuscate.py         # UUID 混淆工具 (已弃用)
    ├── loader_full.c                  # 完整 Loader (数据内嵌, v2.1)
    ├── loader_full_v3.c               # 完整 Loader v3.0 (数据内嵌)
    ├── loader_dll.c                   # DLL 分离加载 Loader (v2.1)
    ├── loader_dll_v3.c                # DLL 分离加载 Loader v3.0 (推荐⭐)
    ├── payload_dll.c                  # Payload DLL 源码 (v2.1)
    └── payload_dll_v3.c               # Payload DLL 源码 v3.0
```

***

## 技术架构

### 1. Shellcode 处理流程

```
原始 Shellcode
      │
      ▼
┌─────────────────┐
│  shellcode-patch │  NOP sled + 指令变异 + 尾随填充
└────────┬────────┘
         ▼
┌─────────────────┐
│ shellcode-encrypt│  RC4 加密 (16字节随机密钥)
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
   嵌入 Loader / DLL
```

### 2. Loader 执行流程

```
程序启动 (WinMainCRTStartup)
      │
      ▼
  9 层反沙箱检测 (≥4 项判定退出)
      │
      ▼
  ETW 遥测绕过 (EtwEventWrite 补丁)
      │
      ▼
  NtDelayExecution 随机延迟 (2-5s)
      │
      ▼
  加载 Payload DLL (DLL分离版) / 读取内嵌数据
      │
      ▼
  IPv4 反混淆 (sscanf 解析还原字节)
      │
      ▼
  RC4 解密还原 Shellcode
      │
      ▼
  分配内存 (PAGE_READWRITE)
      │
      ▼
  写入 Shellcode + VEH 异常处理注册
      │
      ▼
  权限翻转 RW → RX (避开 RWX 红旗)
      │
      ▼
  间接 Syscall 创建线程执行
      │
      ▼
  FreeLibrary 释放 DLL (DLL分离版)
```

### 3. 9 层反沙箱检测

| 层级 | 检测项     | 判定条件              |
| -- | ------- | ----------------- |
| 1  | CPU 核心数 | ≤2 核              |
| 2  | 内存大小    | <2GB              |
| 3  | 虚拟机进程   | 检测 10 个 VM 进程名    |
| 4  | 用户交互    | >5 分钟无输入          |
| 5  | 调试器     | IsDebuggerPresent |
| 6  | 时间延迟    | Sleep 加速（实际<理论）   |
| 7  | 磁盘容量    | <60GB             |
| 8  | 屏幕分辨率   | <800×600          |
| 9  | 开机时间    | <30 分钟            |

> **评分机制**：≥4 项命中才判定为沙箱环境，避免单项误杀真实机器。

***

## 快速开始

### 环境要求

- **操作系统**：Windows 10/11 (x64)
- **Python**：3.8+
- **编译器**：GCC (MinGW-w64)
- **Shellcode**：64 位原始 Shellcode（如 msfvenom 生成）

### 一键处理 Shellcode

```bash
cd scripts/

# 步骤1: Patch Shellcode (修改字节特征)
python shellcode-patch.py ../shellcodes_raws.bin --aggressive

# 步骤2: RC4 加密 (自动生成16字节随机密钥)
python shellcode-encrypt.py shellcodes_raws_patched.bin --genkey

# 步骤3: IPv4 混淆
python shellcode-obfuscate-ipv4.py shellcodes_raws_patched_encrypted.bin
```

***

## 使用指南

### 方案 A：数据内嵌版本（loader\_full\_v3.c）

适用于单文件部署场景。

1. 将生成的 `shellcode_obfuscated_ipv4.c` 中的 IPv4 数组复制到 `loader_full_v3.c` 的 `ipv4_array[]`
2. 确认 RC4 密钥一致（将 `shellcode-encrypt.py` 生成的密钥填入）
3. 确认 `SHELLCODE_SIZE` 正确

### 方案 B：DLL 分离加载版本（loader\_dll\_v3.c）⭐ 推荐

静态免杀效果更优，Loader 本身不含敏感数据。

1. 将 IPv4 数组复制到 `payload_dll_v3.c` 的 `ipv4_array[]`
2. 将 RC4 密钥填入 `payload_dll_v3.c`
3. Loader 代码无需修改（已内置动态加载逻辑）
4. 更换 Shellcode 只需重新编译 DLL，无需修改 Loader

***

## 编译说明

### v3.0 编译（推荐）

```bash
# 方案A：数据内嵌版 — WinMainCRTStartup 自带无窗口
gcc -o loader_v3.exe loader_full_v3.c -lpsapi

# 方案B：DLL分离版 (推荐⭐)
gcc -shared -o helper.dll payload_dll_v3.c
gcc -o loader_v3.exe loader_dll_v3.c -lpsapi

# 可选优化
strip loader_v3.exe                    # 去除符号表
```

生成：PE32+ executable (GUI) — 自动无窗口，无需 `-mwindows`

### v2.1 编译（兼容旧版）

```bash
gcc -mwindows -o loader_final.exe loader_full.c -lpsapi
gcc -shared -o helper.dll payload_dll.c
gcc -mwindows -o loader_final.exe loader_dll.c -lpsapi
```

### 其他优化（可选）

- **添加资源**：合法图标、版本信息（ResHacker）
- **签名伪造**：SigThief 窃取合法签名
- **编译器选项**：`-Os` 优化体积，`-s` 去除符号

***

## 脚本说明

### shellcode-patch.py

Shellcode 字节特征修改工具。

```bash
python shellcode-patch.py <shellcode_file> [--light | --aggressive]
```

| 参数             | 说明                       |
| -------------- | ------------------------ |
| `--light`      | 仅添加 NOP sled（最安全，推荐）     |
| `--aggressive` | NOP sled + NOP 变异 + 尾随填充 |

### shellcode-encrypt.py

Shellcode 加密工具，支持 RC4 和 XOR。

```bash
python shellcode-encrypt.py <shellcode_file> <key> [--xor] [--genkey]
```

| 参数         | 说明               |
| ---------- | ---------------- |
| `--rc4`    | 使用 RC4 加密（默认，推荐） |
| `--xor`    | 使用 XOR 加密（兼容旧版）  |
| `--genkey` | 自动生成 16 字节随机密钥   |

### shellcode-obfuscate-ipv4.py

IPv4 地址混淆工具（推荐）。

```bash
python shellcode-obfuscate-ipv4.py <shellcode_file>
```

### shellcode-obfuscate.py

UUID 混淆工具（已弃用，存在字节序问题）。

```bash
python shellcode-obfuscate.py <shellcode_file>
```

***

## 测试结果

### 测试环境

- **系统**：Windows 10 Pro 10.0.19045
- **架构**：64 位 (x86-64)
- **Shellcode**：510 字节反向连接 Shell
- **编译器**：GCC (MinGW-w64)

### 测试版本

| 文件                               | 大小            | 类型          | 功能                | 状态   |
| -------------------------------- | ------------- | ----------- | ----------------- | ---- |
| loader\_raw\.exe                 | 54KB          | Console     | 直接加载原始 Shellcode  | ✅ 成功 |
| test\_decrypt.exe                | 54KB          | Console     | XOR 解密测试          | ✅ 成功 |
| loader\_ipv4.exe                 | 59KB          | Console     | IPv4 混淆+解密        | ✅ 成功 |
| loader\_full.exe                 | 63KB          | Console     | 完整功能（数据内嵌）        | ✅ 成功 |
| loader\_final.exe (内嵌版)          | 63KB          | GUI         | 完整功能+无窗口          | ✅ 成功 |
| **loader\_dll.exe + helper.dll** | **61KB+42KB** | **GUI+DLL** | **DLL 分离加载+完整功能** | ✅ 成功 |

### 功能验证

- ✅ IPv4 反混淆正确还原字节
- ✅ RC4/XOR 解密还原原始 Shellcode
- ✅ 反沙箱检测通过（真实机器）
- ✅ 间接 Syscall 绕过 API Hook 成功
- ✅ VEH 异常处理生效
- ✅ ETW 遥测绕过生效
- ✅ 无窗口静默运行
- ✅ 成功反弹 Shell 连接

***

## 问题排查

### 问题 1：UUID 反混淆失败

**原因**：Windows `UuidFromStringA` 字节序与 Python `uuid.UUID` 不一致。\
**解决**：改用 IPv4 混淆方案，直接按字节顺序转换。

### 问题 2：反沙箱导致真实机器退出

**原因**：检测逻辑有误（如检测不存在的文件）。\
**解决**：采用综合评分机制，需 ≥4 项才判定沙箱。

### 问题 3：解密后无法执行

**排查步骤**：

1. 测试 `test_decrypt.exe` 验证解密正确性
2. 对比解密后字节与原始 Shellcode
3. 确认密钥一致（RC4 密钥需逐字节核对）

### 问题 4：Shellcode 架构不匹配

**原因**：Loader 编译架构与 Shellcode 架构不一致。\
**解决**：

- 64 位 Shellcode → GCC 默认编译（64 位）
- 32 位 Shellcode → 需 32 位 GCC 环境（MinGW32）

### 问题 5：有黑色弹窗

**原因**：编译为 Console 程序。\
**解决**：v3.0 使用 `WinMainCRTStartup` 自动无窗口；v2.1 使用 `-mwindows` 参数。

***

## 版本历史

### V3.5 (2026-06-24) — 当前版本

- 整理项目文档，新增 README.md
- 完善 Shellcode 处理脚本说明
- 基于 v3.0 技术架构整合

### v3.0 (2026-06-07)

- 加密算法从 XOR 升级为 **RC4**（16 字节随机密钥）
- 内存权限从 RWX 改为 **RW→RX 翻转**
- API 字符串全部改用 **栈字符数组构造**
- 新增 **ETW 遥测绕过**
- 沙箱检测从 6 层扩展到 **9 层**
- 延时从 Sleep 改为 **NtDelayExecution + 随机抖动**
- shellcode-patch.py 实现为 **NOP sled + 等效指令变异**
- 入口函数改用 **WinMainCRTStartup**
- payload\_dll 新增 **GetKeySize** 导出

### v2.1 (2026-04-05)

- 新增 DLL 分离加载方案（loader\_dll.c）
- 添加时间延迟检测（第 6 层反沙箱）
- DLL 使用隐蔽命名（helper.dll）

### v2.0 (2026-04-04)

- 修复 UUID 字节序问题，改用 IPv4 混淆
- 添加 6 层反沙箱检测（综合评分机制）
- 实现 Syscall 绕过 Hook
- 添加无窗口编译选项

### v1.0

- UUID 混淆方案（存在字节序问题）
- 基础反沙箱检测
- 初步 Loader 框架

***

## 注意事项

1. **合法性**：本工具仅用于授权的安全测试、CTF 比赛和渗透评估
2. **安全性**：使用后请及时清理测试环境，避免造成安全隐患
3. **时效性**：免杀技术会随着杀软的更新而失效，需要定期更新免杀策略
4. **字节序**：优先使用 IPv4 混淆方案，避免 UUID 字节序问题
5. **反沙箱**：使用综合评分机制，避免单项检测误杀真实环境
6. **DLL 分离**：推荐使用 DLL 分离方案，静态免杀效果更优，注意 DLL 名称不要使用明显的 payload 相关命名
7. **密钥管理**：RC4 密钥建议使用 `--genkey` 生成随机密钥，避免使用弱密钥

***

## 技术参考

- 免杀技术原理与实践
- AI 在网络安全中的应用
- 现代 EDR 检测机制分析
- 系统底层安全编程技术
- Windows Syscall 编程指南
- 反沙箱检测技术研究

***

**作者**：bluechips\
**版本**：V1.5\
**最后更新**：2026-06-24\
**测试环境**：Windows 10 Pro x64
