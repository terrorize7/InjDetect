#pragma once
#include <vector>
#include <string>
#include <windows.h>

struct MemoryRegion {
    void* baseAddress;
    SIZE_T size;
    std::string protect;
    double entropy;
    bool hasPE;
    bool moduleMismatch;
    bool flagged;
    bool critical;
    int severity;
};

bool IsAddressInModule(void* address, DWORD pid);
unsigned long long GetThreadStartAddress(DWORD threadId);
double CalculateEntropy(const std::vector<unsigned char>& buffer);
bool IsPEHeader(const std::vector<unsigned char>& buffer);
