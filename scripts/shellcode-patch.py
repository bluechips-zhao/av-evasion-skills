#!/usr/bin/env python3
"""
Shellcode Patch 工具 v2.0
在不破坏功能的前提下改动 Shellcode 字节特征
技术: NOP sled 前缀 + NOP 等效指令变异 + 随机尾随填充
"""

import sys
import os
import secrets

def add_nop_sled(shellcode: bytes, count: int = None) -> bytes:
    """在 shellcode 前添加随机长度 NOP (0x90) 滑板"""
    if count is None:
        count = secrets.randbelow(24) + 4
    return b'\x90' * count + shellcode

def add_random_padding(shellcode: bytes, count: int = None) -> bytes:
    """末尾添加随机填充 (不破坏执行)"""
    if count is None:
        count = secrets.randbelow(32) + 8
    return shellcode + secrets.token_bytes(count)

def mutate_nop_pairs(shellcode: bytes) -> bytes:
    """
    将连续 NOP 对替换为等效无操作指令:
    0x90 0x90 → 0x87 0xC0 (xchg eax,eax, 2 bytes)
    0x90 0x90 → 0x66 0x90 (xchg ax,ax, 2 bytes)
    """
    result = bytearray(shellcode)
    i = 0
    while i < len(result) - 1:
        if result[i] == 0x90 and result[i+1] == 0x90:
            choice = secrets.randbelow(3)
            if choice == 0:
                result[i] = 0x87; result[i+1] = 0xC0
            elif choice == 1:
                result[i] = 0x66; result[i+1] = 0x90
            i += 2
        else:
            i += 1
    return bytes(result)

def main():
    if len(sys.argv) < 2:
        print("Usage: python shellcode-patch.py <shellcode_file> [--aggressive]")
        print("  --light       仅添加 NOP sled (最安全，推荐)")
        print("  --aggressive  NOP sled + NOP变异 + 尾随填充")
        sys.exit(1)

    path = sys.argv[1]
    mode = "aggressive" if "--aggressive" in sys.argv else "light"

    with open(path, 'rb') as f:
        original = f.read()

    result = original
    if mode == "aggressive":
        result = mutate_nop_pairs(result)
        result = add_random_padding(result)
    result = add_nop_sled(result)

    basename = os.path.splitext(os.path.basename(path))[0]
    out_path = f"{basename}_patched.bin"
    with open(out_path, 'wb') as f:
        f.write(result)

    changed = sum(1 for a, b in zip(original, result[:len(original)]) if a != b)
    print(f"[+] Mode:     {mode}")
    print(f"[+] Original: {len(original)} bytes")
    print(f"[+] Patched:  {len(result)} bytes (~{changed} bytes mutated)")
    print(f"[+] Output:   {out_path}")

if __name__ == "__main__":
    main()
