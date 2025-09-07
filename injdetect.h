#pragma once
#include <fstream>
#include <string>
#include "Utils.h"

void Log(std::ofstream& logFile, const std::string& message);
std::string ProtectToStr(DWORD protect);
bool Is64BitProcess(HANDLE hProcess);
void ComputeSeverity(MemoryRegion& region);
