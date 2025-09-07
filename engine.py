import os
import sys
import ctypes
import ctypes.wintypes as wintypes
import subprocess
import time
import threading
from datetime import datetime, timedelta

# --- UAC Elevation Check ---
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    if not is_admin():
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

# --- Enhanced Progress Bar Class ---
class SmoothProgressBar:
    def __init__(self):
        self.total_steps = 0
        self.current_step = 0
        self.current_stage = ""
        self.start_time = None
        self.stage_weights = {
            "Enumerating Modules": 0.1,    # 10% of total time
            "Gathering Attributes": 0.2,    # 20% of total time
            "Checking Signatures": 0.5,     # 50% of total time (slowest)
            "Logging Results": 0.2          # 20% of total time
        }
        self.stage_progress = {}
        self.accumulated_progress = 0
        self.lock = threading.Lock()
        self.last_update_time = 0
        self.update_interval = 0.05  # Update display every 50ms
        self.smooth_progress = 0
        self.target_progress = 0
        self.animation_thread = None
        self.running = False
        self.console_lines_used = 0
        
    def initialize(self, module_count):
        """Initialize the progress bar with total expected steps"""
        self.total_steps = module_count * 4  # enum + attr + sig + log per module
        self.start_time = datetime.now()
        self.running = True
        
        # Initialize stage progress tracking
        for stage in self.stage_weights:
            self.stage_progress[stage] = {"current": 0, "total": module_count}
        
        # Start the smooth animation thread
        self.animation_thread = threading.Thread(target=self._animate_progress, daemon=True)
        self.animation_thread.start()
    
    def _animate_progress(self):
        """Smoothly animate the progress bar"""
        while self.running:
            with self.lock:
                # Smooth transition to target progress
                diff = self.target_progress - self.smooth_progress
                if abs(diff) > 0.001:
                    self.smooth_progress += diff * 0.3  # Smooth easing
                else:
                    self.smooth_progress = self.target_progress
            
            # Update display at regular intervals
            current_time = time.time()
            if current_time - self.last_update_time >= self.update_interval:
                self._render()
                self.last_update_time = current_time
            
            time.sleep(0.01)  # 10ms animation loop
    
    def update_stage(self, stage_name, current_item=0, total_items=0):
        """Update the current stage and progress"""
        with self.lock:
            self.current_stage = stage_name
            
            if total_items > 0:
                self.stage_progress[stage_name] = {
                    "current": current_item,
                    "total": total_items
                }
            
            # Calculate accumulated progress based on stage weights
            accumulated = 0
            for stage, weight in self.stage_weights.items():
                if stage == self.current_stage:
                    # Add partial progress for current stage
                    if self.stage_progress[stage]["total"] > 0:
                        stage_completion = self.stage_progress[stage]["current"] / self.stage_progress[stage]["total"]
                        accumulated += weight * stage_completion
                    break
                elif stage in self.stage_progress and self.stage_progress[stage]["current"] >= self.stage_progress[stage]["total"]:
                    # Add full weight for completed stages
                    accumulated += weight
            
            self.target_progress = accumulated
    
    def _render(self):
        """Render the progress bar to console"""
        bar_length = 50
        percent = self.smooth_progress * 100
        filled = int(bar_length * self.smooth_progress)
        
        # Create the progress bar
        bar = "█" * filled + "░" * (bar_length - filled)
        
        # Calculate ETA
        eta_str = self._calculate_eta()
        
        # Build the status line
        status = f"\r[{bar}] {percent:5.1f}% | {self.current_stage.ljust(25)} | {eta_str}"
        
        # Clear the line and write the status
        sys.stdout.write("\r" + " " * 100)  # Clear line
        sys.stdout.write(status)
        sys.stdout.flush()
    
    def _calculate_eta(self):
        """Calculate estimated time remaining"""
        if not self.start_time or self.smooth_progress <= 0:
            return "ETA: Calculating..."
        
        elapsed = (datetime.now() - self.start_time).total_seconds()
        if self.smooth_progress >= 1.0:
            return "Complete!"
        
        estimated_total = elapsed / self.smooth_progress
        remaining = estimated_total - elapsed
        
        if remaining < 60:
            return f"ETA: {int(remaining)}s"
        elif remaining < 3600:
            return f"ETA: {int(remaining/60)}m {int(remaining%60)}s"
        else:
            return f"ETA: {int(remaining/3600)}h {int((remaining%3600)/60)}m"
    
    def complete_stage(self, stage_name):
        """Mark a stage as complete"""
        with self.lock:
            if stage_name in self.stage_progress:
                self.stage_progress[stage_name]["current"] = self.stage_progress[stage_name]["total"]
    
    def finish(self):
        """Complete the progress bar"""
        self.running = False
        if self.animation_thread:
            self.animation_thread.join(timeout=0.5)
        
        with self.lock:
            self.smooth_progress = 1.0
            self.target_progress = 1.0
        
        self._render()
        print()  # New line after progress bar

# --- Console Output Manager ---
class ConsoleOutputManager:
    def __init__(self):
        self.output_buffer = []
        self.lock = threading.Lock()
    
    def add_output(self, text):
        """Add text to output buffer"""
        with self.lock:
            self.output_buffer.append(text)
    
    def flush_output(self):
        """Flush all buffered output"""
        with self.lock:
            if self.output_buffer:
                # Clear progress bar line
                sys.stdout.write("\r" + " " * 100 + "\r")
                # Print buffered output
                for line in self.output_buffer:
                    print(line)
                self.output_buffer.clear()

# --- Main ---
if __name__ == "__main__":
    run_as_admin()

    try:
        pid = int(input("Enter the PID of the process to analyze: "))
    except ValueError:
        print("Invalid PID.")
        sys.exit(1)

    # Initialize progress bar and output manager
    progress = SmoothProgressBar()
    output = ConsoleOutputManager()
    
    print("\nStarting analysis...")
    
    # Stage 1: Enumerating modules
    modules = enumerate_modules(pid)
    module_count = len(modules)
    
    if module_count == 0:
        print("No modules found for the specified process.")
        sys.exit(1)
    
    progress.initialize(module_count)
    
    # Update progress for enumeration
    progress.update_stage("Enumerating Modules", module_count, module_count)
    time.sleep(0.2)  # Brief pause to show enumeration complete
    
    # Stage 2: Gathering attributes
    attributes = {}
    for i, m in enumerate(modules, 1):
        progress.update_stage("Gathering Attributes", i, module_count)
        attributes[m] = get_file_attributes(m)
        time.sleep(0.01)  # Small delay for smooth animation
    
    progress.complete_stage("Gathering Attributes")
    
    # Stage 3: Checking signatures (batch process for efficiency)
    progress.update_stage("Checking Signatures", 0, module_count)
    
    # Process signatures in batches for better performance
    batch_size = 10
    signatures = {}
    for i in range(0, module_count, batch_size):
        batch = modules[i:min(i+batch_size, module_count)]
        batch_sigs = check_signatures_powershell(batch)
        signatures.update(batch_sigs)
        
        # Update progress
        processed = min(i + batch_size, module_count)
        progress.update_stage("Checking Signatures", processed, module_count)
    
    progress.complete_stage("Checking Signatures")
    
    # Stage 4: Logging results
    flagged_modules = []
    with open("modules.log", "w", encoding="utf-8") as f:
        for i, m in enumerate(modules, 1):
            progress.update_stage("Logging Results", i, module_count)
            
            sig = signatures.get(m, "Unknown")
            attr = attributes.get(m, "Unknown")
            
            if sig != "Valid":
                line = f"[FLAGGED MODULE] {m} | Attributes: {attr} | Signature: {sig}"
                flagged_modules.append(line)
            else:
                line = f"{m} | Attributes: {attr} | Signature: {sig}"
            
            f.write(line + "\n")
            time.sleep(0.005)  # Small delay for smooth animation
    
    progress.complete_stage("Logging Results")
    progress.finish()
    
    # Display summary
    print("\n" + "="*80)
    print(f"Analysis Complete - Total Modules: {module_count}")
    print("="*80)
    
    if flagged_modules:
        print(f"\n⚠ Found {len(flagged_modules)} flagged module(s):")
        print("-"*80)
        for module in flagged_modules[:10]:  # Show first 10 flagged modules
            print(module)
        if len(flagged_modules) > 10:
            print(f"... and {len(flagged_modules) - 10} more. Check modules.log for full details.")
    else:
        print("\n✓ All modules have valid signatures.")
    
    print(f"\nResults saved to: {os.path.abspath('modules.log')}")
    input("\nPress Enter to exit...")