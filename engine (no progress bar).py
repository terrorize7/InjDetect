import os
import sys
import ctypes
import ctypes.wintypes as wintypes
import subprocess

# --- UAC Elevation Check ---
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    if not is_admin():
        # Relaunch with admin rights
        params = " ".join([f'"{x}"' for x in sys.argv])
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        sys.exit(0)

# --- Module Enumeration ---
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
MAX_PATH = 260

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", wintypes.LPVOID),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.CHAR * 256),
        ("szExePath", wintypes.CHAR * MAX_PATH),
    ]

def enumerate_modules(pid):
    h_snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid
    )
    if h_snapshot == -1:
        raise Exception("Failed to create snapshot")

    me32 = MODULEENTRY32()
    me32.dwSize = ctypes.sizeof(MODULEENTRY32)

    modules = []
    if ctypes.windll.kernel32.Module32First(h_snapshot, ctypes.byref(me32)):
        while True:
            path = me32.szExePath.decode(errors="ignore")
            modules.append(path)
            if not ctypes.windll.kernel32.Module32Next(h_snapshot, ctypes.byref(me32)):
                break

    ctypes.windll.kernel32.CloseHandle(h_snapshot)
    return modules

# --- File Attributes ---
FILE_ATTRIBUTE_HIDDEN      = 0x2
FILE_ATTRIBUTE_SYSTEM      = 0x4
FILE_ATTRIBUTE_DIRECTORY   = 0x10
FILE_ATTRIBUTE_ARCHIVE     = 0x20
FILE_ATTRIBUTE_NORMAL      = 0x80
FILE_ATTRIBUTE_TEMPORARY   = 0x100
FILE_ATTRIBUTE_OFFLINE     = 0x1000
FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000

def get_file_attributes(filepath):
    attrs = ctypes.windll.kernel32.GetFileAttributesW(filepath)
    if attrs == -1:
        return "Unavailable"

    flags = []
    if attrs & FILE_ATTRIBUTE_HIDDEN:
        flags.append("Hidden")
    if attrs & FILE_ATTRIBUTE_SYSTEM:
        flags.append("System")
    if attrs & FILE_ATTRIBUTE_DIRECTORY:
        flags.append("Directory")
    if attrs & FILE_ATTRIBUTE_ARCHIVE:
        flags.append("Archive")
    if attrs & FILE_ATTRIBUTE_NORMAL:
        flags.append("Normal")
    if attrs & FILE_ATTRIBUTE_TEMPORARY:
        flags.append("Temporary")
    if attrs & FILE_ATTRIBUTE_OFFLINE:
        flags.append("Offline")
    if attrs & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED:
        flags.append("NotIndexed")

    return ", ".join(flags) if flags else "None"

# --- Signature Check via PowerShell ---
def check_signatures_powershell(modules):
    existing = [m for m in modules if os.path.exists(m)]
    if not existing:
        return {}

    ps_command = (
        "Get-AuthenticodeSignature @("
        + ",".join([f"'{m}'" for m in existing])
        + ") | ForEach-Object { $_.Status }"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_command],
        capture_output=True,
        text=True
    )
    statuses = result.stdout.strip().splitlines()
    return dict(zip(existing, statuses))

# --- Logging ---
def log_results(modules, attributes, signatures, logfile="modules.log"):
    with open(logfile, "w", encoding="utf-8") as f:
        for m in modules:
            attr = attributes.get(m, "Unknown")
            sig  = signatures.get(m, "Unknown")
            if sig != "Valid":
                line = f"[FLAGGED MODULE] {m} | Attributes: {attr} | Signature: {sig}"
            else:
                line = f"{m} | Attributes: {attr} | Signature: {sig}"
            print(line)
            f.write(line + "\n")

# --- Main ---
if __name__ == "__main__":
    run_as_admin()

    try:
        pid = int(input("Enter the PID of the process to analyze: "))
    except ValueError:
        print("Invalid PID.")
        sys.exit(1)

    try:
        modules = enumerate_modules(pid)
    except Exception as e:
        print(f"Failed to enumerate modules: {e}")
        sys.exit(1)

    attributes = {m: get_file_attributes(m) for m in modules}
    signatures = check_signatures_powershell(modules)

    log_results(modules, attributes, signatures)

    input("\nAnalysis complete. Press Enter to exit...")
