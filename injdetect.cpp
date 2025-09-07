#include <windows.h>
#include <psapi.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <iomanip>
#include <cmath>

struct MemoryRegion {
    LPVOID base;
    SIZE_T size;
    std::string protect;
    double entropy;
};

// Calculate Shannon entropy
double calculateEntropy(BYTE* data, SIZE_T size) {
    int counts[256] = { 0 };
    for (SIZE_T i = 0; i < size; ++i)
        counts[data[i]]++;

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] == 0) continue;
        double p = (double)counts[i] / size;
        entropy -= p * log2(p);
    }
    return entropy;
}

// Convert memory protection flags to string
std::string protectToString(DWORD protect) {
    switch (protect) {
    case PAGE_EXECUTE: return "X";
    case PAGE_EXECUTE_READ: return "RX";
    case PAGE_EXECUTE_READWRITE: return "RWX";
    case PAGE_READWRITE: return "RW";
    case PAGE_READONLY: return "R";
    case PAGE_WRITECOPY: return "WC";
    default: return "OTHER";
    }
}

int main() {
    DWORD pid;
    std::cout << "Enter PID to scan: ";
    std::cin >> pid;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Failed to open process.\n";
        return 1;
    }

    SYSTEM_INFO si;
    GetSystemInfo(&si);

    std::vector<MemoryRegion> suspiciousRegions;
    std::ofstream logFile("injdetect_log.txt");

    for (LPBYTE addr = (LPBYTE)si.lpMinimumApplicationAddress; addr < si.lpMaximumApplicationAddress;) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == 0)
            break;

        addr += mbi.RegionSize;

        if (mbi.State != MEM_COMMIT) continue;

        std::string protectStr = protectToString(mbi.Protect);
        if (protectStr == "R" || protectStr == "WC") continue;

        std::vector<BYTE> buffer(mbi.RegionSize);
        SIZE_T bytesRead;
        if (!ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead))
            continue;

        double entropy = calculateEntropy(buffer.data(), bytesRead);

        bool flagRegion = false;

        // Detection rules
        if (protectStr == "RWX") {
            flagRegion = true; // Always flag RWX
        }
        else if (protectStr == "RX" || protectStr == "RW") {
            if (entropy >= 7.0 && mbi.RegionSize > 64000)
                flagRegion = true; // Flag suspicious large high-entropy regions
        }

        if (flagRegion) {
            MemoryRegion region{ mbi.BaseAddress, mbi.RegionSize, protectStr, entropy };
            suspiciousRegions.push_back(region);

            std::ostringstream out;
            out << "[FLAGGED REGION] Memory: 0x" << std::hex << (uintptr_t)mbi.BaseAddress
                << " Size: " << std::dec << mbi.RegionSize
                << " Protect: " << protectStr
                << " Entropy: " << std::fixed << std::setprecision(2) << entropy;
            std::cout << out.str() << std::endl;
            logFile << out.str() << std::endl;
        }
    }

    if (suspiciousRegions.empty()) {
        std::string msg = "Process memory has not been manipulated.";
        std::cout << msg << std::endl;
        logFile << msg << std::endl;
    }

    std::cout << "\nScan complete. Press Enter to exit...";
    std::cin.ignore();
    std::cin.get();

    CloseHandle(hProcess);
    logFile.close();
    return 0;
}
