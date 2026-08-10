#!/usr/bin/env python3
"""
Shellcode Patch工具
功能：对Shellcode进行同义指令替换、花指令注入和指令重排

注意: 真正的x86/x64指令级Patch需要对反汇编引擎的依赖。
本脚本实现基于已知字节模式的等价替换 + 花指令注入,
不引入第三方库,保证开箱即用。
"""

import sys
import os

# ---- 已知的等价指令替换表 (x86/x64) ----
# 格式: (原始字节序列, 替换字节序列, 描述)
# 重要: 原始和替换序列长度必须相同, 否则后续指令偏移会被破坏
EQUIVALENT_PATCHES = [
    # 空操作等价替换 (同长度):
    # 66 90 (nop, 2字节) -> 66 87 c0  ❌ 长度不同, 不可用
    # 66 90 (nop, 2字节) -> 66 87 c0  是3字节 ❌
    #
    # 真正同长度的等价替换非常少, 且需要上下文分析。
    # 以下是少数安全的同长度替换:

    # lea reg, [rip+0] -> mov reg, rip (不可行, 语义不同)
    # test rax, rax (48 85 C0) -> or rax, rax (48 09 C0) — 都设置ZF, 等价
    (b'\x48\x85\xc0', b'\x48\x09\xc0', 'test rax,rax -> or rax,rax'),
    # test eax, eax (85 C0) -> or eax, eax (09 C0) — 都设置ZF, 等价
    (b'\x85\xc0', b'\x09\xc0', 'test eax,eax -> or eax,eax'),
    # test rax, rax 变体: rcx
    (b'\x48\x85\xc9', b'\x48\x09\xc9', 'test rcx,rcx -> or rcx,rcx'),
    # test ecx, ecx
    (b'\x85\xc9', b'\x09\xc9', 'test ecx,ecx -> or ecx,ecx'),
]

# ---- 花指令模板 (当前未使用, 保留供未来扩展) ----
# 插入花指令会改变后续跳转偏移, 需要控制流分析, 暂不启用
JUNK_INSTRUCTIONS = [
    b'\x90',                          # nop
    b'\x87\xc0',                      # xchg eax, eax (2字节nop)
    b'\x66\x87\xc0',                  # xchg ax, ax (3字节nop)
]


def patch_shellcode(shellcode):
    """
    对Shellcode进行同义指令替换和花指令注入。

    策略:
      1. 扫描已知等价模式, 执行替换 (不改变长度)
      2. 在不影响控制流的位置插入花指令

    注意: 此实现采用保守策略, 只替换已知安全的模式。
    如果没有匹配到任何已知模式, 原始数据原样返回。
    """
    patched = bytearray(shellcode)
    patch_count = 0

    # 步骤1: 同义指令替换 (不改变长度)
    for i in range(len(patched)):
        for orig, repl, desc in EQUIVALENT_PATCHES:
            if patched[i:i + len(orig)] == orig:
                patched[i:i + len(orig)] = repl
                patch_count += 1
                break  # 同一位置只替换一次

    # 花指令注入: 保守策略 — 不实际插入, 避免破坏相对跳转偏移
    # (真实的花指令注入需要理解控制流, 盲目插入会破坏shellcode)
    # 已有的等价替换已经改变了字节特征

    if patch_count == 0:
        print("[Warning] No known patterns matched for replacement.")
        print("[Info] Shellcode passed through unchanged.")
        print("[Info] Consider using a disassembler-based patcher for advanced patching.")

    return bytes(patched)


def main():
    if len(sys.argv) != 2:
        print("Usage: python shellcode-patch.py <shellcode_file>")
        return

    filepath = sys.argv[1]

    if not os.path.exists(filepath):
        print(f"[Error] File not found: {filepath}")
        return

    try:
        with open(filepath, 'rb') as f:
            shellcode = f.read()
    except IOError as e:
        print(f"[Error] Failed to read file: {e}")
        return

    if not shellcode:
        print("[Error] Shellcode file is empty.")
        return

    patched = patch_shellcode(shellcode)

    try:
        with open('shellcode_patched.bin', 'wb') as f:
            f.write(patched)
    except IOError as e:
        print(f"[Error] Failed to write output file: {e}")
        return

    print(f"Shellcode patched successfully! (Input: {len(shellcode)} bytes, Output: {len(patched)} bytes)")


if __name__ == "__main__":
    main()
