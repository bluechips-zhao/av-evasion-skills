#!/usr/bin/env python3
"""
Shellcode IPv4混淆工具
功能：将Shellcode伪装成IPv4地址数组
"""

import sys
import os


def obfuscate_as_ipv4(shellcode):
    """
    将Shellcode每4字节转换为一个IPv4地址。

    参数:
      shellcode: bytes, 原始shellcode

    返回:
      list[str], IPv4地址字符串列表
    """
    ipv4_list = []
    for i in range(0, len(shellcode), 4):
        chunk = shellcode[i:i + 4]
        if len(chunk) < 4:
            chunk = chunk.ljust(4, b'\x00')
        # 直接按字节顺序转换：chunk[0].chunk[1].chunk[2].chunk[3]
        ipv4 = f"{chunk[0]}.{chunk[1]}.{chunk[2]}.{chunk[3]}"
        ipv4_list.append(ipv4)
    return ipv4_list


def format_c_array(ipv4_list, ips_per_line=5):
    """
    生成格式化的C语言IPv4数组, 每行固定数量的IP。

    参数:
      ipv4_list: list[str], IPv4地址列表
      ips_per_line: int, 每行IP数量

    返回:
      str, C语言数组字符串
    """
    lines = []
    lines.append("char* ipv4_array[] = {")

    for i in range(0, len(ipv4_list), ips_per_line):
        chunk = ipv4_list[i:i + ips_per_line]
        # 每个IP用引号包裹, 逗号分隔, 末尾不加逗号(最后一个)
        is_last_chunk = (i + ips_per_line) >= len(ipv4_list)
        line_ips = ", ".join([f'"{ip}"' for ip in chunk])
        # 如果不是最后一组, 加上逗号
        if not is_last_chunk:
            line_ips += ","
        lines.append(f"    {line_ips}")

    lines.append("};")
    return "\n".join(lines)


def main():
    if len(sys.argv) != 2:
        print("Usage: python shellcode-obfuscate-ipv4.py <shellcode_file>")
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

    ipv4_list = obfuscate_as_ipv4(shellcode)

    # 生成格式化的C语言数组
    c_array = format_c_array(ipv4_list)

    try:
        with open('shellcode_obfuscated_ipv4.c', 'w') as f:
            f.write(c_array)
    except IOError as e:
        print(f"[Error] Failed to write output file: {e}")
        return

    print(f"Shellcode obfuscated as IPv4 successfully! Total: {len(ipv4_list)} IPs")


if __name__ == "__main__":
    main()
