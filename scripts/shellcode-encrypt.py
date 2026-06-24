#!/usr/bin/env python3
"""
Shellcode 加密工具 v2.0
支持 RC4 (推荐) 和 XOR 两种加密算法
用法: python shellcode-encrypt.py <shellcode_file> <key> [--xor]
"""

import sys
import os
import secrets

def rc4_ksa(key: bytes) -> list:
    """RC4 密钥调度算法"""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def rc4_crypt(data: bytes, key: bytes) -> bytes:
    """RC4 加密/解密 (对称)"""
    S = rc4_ksa(key)
    i = j = 0
    result = bytearray(len(data))
    for n in range(len(data)):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result[n] = data[n] ^ S[(S[i] + S[j]) % 256]
    return bytes(result)

def xor_crypt(data: bytes, key: bytes) -> bytes:
    """XOR 加密"""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def format_c_array(data: bytes, name: str = "shellcode") -> str:
    """格式化为 C 数组"""
    lines = []
    line = []
    for i, b in enumerate(data):
        line.append(f"0x{b:02X}")
        if len(line) == 12 or i == len(data) - 1:
            lines.append("    " + ",".join(line))
            line = []
    return f"unsigned char {name}[] = {{\n" + ",\n".join(lines) + "\n};"

def format_key_c_array(key: bytes, name: str = "rc4key") -> str:
    """格式化为 C 密钥数组"""
    return format_c_array(key, name)

def main():
    if len(sys.argv) < 3:
        print("Usage: python shellcode-encrypt.py <shellcode_file> <key> [--xor] [--genkey]")
        print("  --rc4    使用 RC4 加密 (默认，推荐)")
        print("  --xor    使用 XOR 加密 (兼容旧版)")
        print("  --genkey 自动生成 16 字节随机密钥")
        sys.exit(1)

    shellcode_path = sys.argv[1]
    use_xor = "--xor" in sys.argv
    use_genkey = "--genkey" in sys.argv

    with open(shellcode_path, 'rb') as f:
        shellcode = f.read()

    if use_genkey:
        key = secrets.token_bytes(16)
        print(f"[+] 生成随机密钥: {key.hex().upper()}")
    else:
        key = sys.argv[2].encode()

    basename = os.path.splitext(os.path.basename(shellcode_path))[0]

    if use_xor:
        method = "XOR"
        encrypted = xor_crypt(shellcode, key)
        key_c_name = f'const char* xor_key = "{sys.argv[2]}";'
    else:
        method = "RC4"
        encrypted = rc4_crypt(shellcode, key)
        key_c_name = format_key_c_array(key, "rc4key")

    # 写入加密后的二进制
    enc_bin = f"{basename}_encrypted.bin"
    with open(enc_bin, 'wb') as f:
        f.write(encrypted)

    # 写入 C 语言头文件 (.h)
    enc_h = f"{basename}_encrypted.h"
    with open(enc_h, 'w') as f:
        f.write(f"/* Shellcode encrypted with {method}, {len(encrypted)} bytes */\n")
        f.write(format_c_array(encrypted, "encrypted_shellcode"))
        f.write(";\n")
        f.write(f"const unsigned int ENC_SHELLCODE_SIZE = {len(encrypted)};\n\n")
        f.write(f"/* RC4 decryption key ({len(key)} bytes) */\n")
        f.write(key_c_name)
        f.write(";\n")
        f.write(f"const unsigned int ENC_KEY_SIZE = {len(key)};\n")

    print(f"[+] Algorithm:   {method}")
    print(f"[+] Shellcode:   {len(shellcode)} bytes → {len(encrypted)} bytes encrypted")
    print(f"[+] Key:         {len(key)} bytes")
    print(f"[+] Binary:      {enc_bin}")
    print(f"[+] C header:    {enc_h}")

if __name__ == "__main__":
    main()
