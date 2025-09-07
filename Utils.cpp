#include "Utils.h"
#include <windows.h>
#include <vector>
#include <algorithm>
#include <psapi.h>
#include <cmath>

bool IsAddressInModule(void* address, DWORD pid) {
    HMODULE hMods[1024];
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return false;
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i) {
            MODULEINFO mi;
            if (GetModuleInformation(hProcess, hMods[i], &mi, sizeof(mi))) {
                if ((BYTE*)address >= (BYTE*)mi.lpBaseOfDll &&
                    (BYTE*)address < (BYTE*)mi.lpBaseOfDll + mi.SizeOfImage) {
                    CloseHandle(hProcess);
                    return true;
                }
            }
        }
    }
    CloseHandle(hProcess);
    return false;
}

unsigned long long GetThreadStartAddress(DWORD threadId) {
    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
    if (!hThread) return 0;
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        CloseHandle(hThread);
        return 0;
    }
#ifdef _M_X64
    unsigned long long addr = ctx.Rip;
#else
    unsigned long long addr = ctx.Eip;
#endif
    CloseHandle(hThread);
    return addr;
}

double CalculateEntropy(const std::vector<unsigned char>& buffer) {
    if (buffer.empty()) return 0.0;
    int counts[256] = { 0 };
    for (unsigned char b : buffer) counts[b]++;
    double entropy = 0.0;
    const double size = (double)buffer.size();
    for (int i = 0; i < 256; i++) {
        if (counts[i] == 0) continue;
        double p = counts[i] / size;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

bool IsPEHeader(const std::vector<unsigned char>& buffer) {
    if (buffer.size() < 0x1000) return false;
    if (buffer[0] != 'M' || buffer[1] != 'Z') return false;
    DWORD peOffset = *(DWORD*)&buffer[0x3C];
    if (peOffset + 4 >= buffer.size()) return false;
    return buffer[peOffset] == 'P' && buffer[peOffset + 1] == 'E' && buffer[peOffset + 2] == 0 && buffer[peOffset + 3] == 0;
}
