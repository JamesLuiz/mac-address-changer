"""
mac_gui_changer.py
Cross-platform GUI MAC Address Changer with Windows registry fallback.
NOTE: On Linux/macOS, you must run this script with 'sudo' for MAC fetching and changing.
e.g., sudo python3 mac_gui_changer.py
"""

import tkinter as tk
from tkinter import ttk, messagebox
import subprocess, platform, random, re
from pathlib import Path
import sys 

# ---------------- Utility ----------------

def run(cmd, capture=False, shell=False, check_permissions=False):
    """
    Runs a command, optionally capturing output.
    If check_permissions is True on Linux/macOS, it checks if it's run with sudo.
    """
    sysname = get_system()
    
    if check_permissions and (sysname == "linux" or sysname == "darwin"):
        # Check for root/sudo access before running privileged commands
        if Path("/usr/bin/id").exists():
            if not run(["/usr/bin/id", "-u"], capture=True).strip() == '0':
                return "Permission denied: Run the script with sudo."

    try:
        if capture:
            result = subprocess.run(cmd, shell=shell, check=True, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return result.stdout.strip()
        else:
            subprocess.run(cmd, shell=shell, check=True)
            return True
    except subprocess.CalledProcessError as e:
        # Print detailed error to console
        error_msg = f"Command failed: {' '.join(e.cmd)}\nStdout: {e.stdout.strip()}\nStderr: {e.stderr.strip()}"
        print(f"--- Command Error ---\n{error_msg}\n---------------------", file=sys.stderr)
        return e.stderr.strip() if e.stderr else str(e)
    except FileNotFoundError:
        return f"Error: Command not found or not in PATH: {cmd[0]}"
    except Exception as e:
        return str(e)

def get_system():
    return platform.system().lower()

def is_valid_mac(mac):
    # Allows for both hyphenated and colon-separated formats, case-insensitive
    return re.match(r"^(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})$", mac) is not None

def random_mac():
    # Ensures the MAC is locally administered and unicast
    first_byte = random.randint(0x00, 0xFF)
    first_byte = (first_byte & 0b11111110) | 0b00000010
    
    mac_parts = [first_byte] + [random.randint(0, 255) for _ in range(5)]
    return ":".join(f"{x:02x}" for x in mac_parts).upper()

def get_interfaces():
    sysname = get_system()
    try:
        if sysname == "linux":
            out = run(["ip", "a"], capture=True)
            return re.findall(r"^\d+: ([^:]+): .*?(?<!lo)", out, re.MULTILINE | re.DOTALL)
        elif sysname == "darwin":
            out = run(["ifconfig"], capture=True)
            return re.findall(r"^([a-z0-9]+):", out, re.MULTILINE)
        elif sysname == "windows":
            # List all adapters that are not 'Disconnected' (includes 'Up' and 'Disabled')
            ps = "Get-NetAdapter | Where-Object {$_.Status -ne 'Disconnected'} | Select-Object -ExpandProperty Name"
            out = run(["powershell", "-Command", ps], capture=True)
            return [x.strip() for x in out.splitlines() if x.strip()]
    except Exception as e:
        print(f"Error fetching interfaces: {e}", file=sys.stderr)
    return []

def get_current_mac(iface):
    sysname = get_system()
    try:
        if sysname == "linux":
            out = run(["ip", "link", "show", iface], capture=True, check_permissions=True)
            if "Permission denied" in out: return out
            m = re.search(r"link/ether\s+([0-9a-f:]{17})", out)
            return m.group(1).upper() if m else "Unknown"
        elif sysname == "darwin":
            out = run(["ifconfig", iface], capture=True, check_permissions=True)
            if "Permission denied" in out: return out
            m = re.search(r"ether\s+([0-9a-f:]{17})", out)
            return m.group(1).upper() if m else "Unknown"
        elif sysname == "windows":
            # 1. Try getting Hardware MAC (more reliable)
            ps_hardware = f"(Get-NetAdapter -Name '{iface}' | Get-NetAdapterHardwareInfo -ErrorAction SilentlyContinue).MacAddress"
            out_hardware = run(["powershell", "-Command", ps_hardware], capture=True)
            if out_hardware:
                return out_hardware.replace("-", ":").upper()

            # 2. Fallback to basic MAC address
            ps_basic = f"(Get-NetAdapter -Name '{iface}').MacAddress"
            out_basic = run(["powershell", "-Command", ps_basic], capture=True)
            if out_basic:
                 return out_basic.replace("-", ":").upper()
            
            return "Unknown"

    except Exception as e:
        print(f"Error fetching current MAC for {iface}: {e}", file=sys.stderr)
    return "Unknown"

def set_mac(iface, new_mac):
    sysname = get_system()
    
    # Check for permissions on Linux/macOS before execution
    if sysname != "windows": 
        perm_check = run([], check_permissions=True)
        if isinstance(perm_check, str) and "Permission denied" in perm_check:
            return perm_check

    try:
        new_mac = new_mac.lower() 
        
        if sysname == "linux":
            run(["ip", "link", "set", iface, "down"], check_permissions=True)
            run(["ip", "link", "set", iface, "address", new_mac], check_permissions=True)
            run(["ip", "link", "set", iface, "up"], check_permissions=True)
        elif sysname == "darwin":
            run(["ifconfig", iface, "down"], check_permissions=True)
            run(["ifconfig", iface, "ether", new_mac], check_permissions=True)
            run(["ifconfig", iface, "up"], check_permissions=True)
        elif sysname == "windows":
            mac_no_sep = new_mac.replace(":", "").replace("-", "")
            
            # 1. Preferred method: Set-NetAdapterAdvancedProperty (requires admin)
            ps_adv = (
                f"$a = Get-NetAdapter -Name '{iface}' -ErrorAction Stop; "
                f"try {{ "
                f"Set-NetAdapterAdvancedProperty -Name $a.Name -DisplayName 'Network Address' "
                f"-DisplayValue '{mac_no_sep}' -ErrorAction Stop; "
                "Restart-NetAdapter -Name $a.Name -Confirm:$false; "
                "Write-Host 'Success: AdvancedProperty' "
                f"}} catch [System.UnauthorizedAccessException] {{ Write-Host 'Windows Error: Access denied, run as Administrator.' }} "
                f"catch {{ Write-Host 'Fallback' }}" # Fallback triggered on ObjectNotFound, etc.
            )
            result = run(["powershell", "-Command", ps_adv], capture=True)

            if "Success: AdvancedProperty" in str(result):
                return True
            
            if "Windows Error: Access denied, run as Administrator" in str(result):
                 return "Windows Error: Run the script as Administrator."

            # 2. Fallback method: Registry modification (requires admin)
            # FIX: Removed the outer 'powershell -Command' from the string itself.
            reg_cmd_content = (
                f"$adapter = Get-NetAdapter -Name '{iface}' -ErrorAction Stop; "
                "$regPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}\\'; "
                "$keys = Get-ChildItem $regPath -ErrorAction SilentlyContinue | Where-Object {$_.PSPath -match '\\d{4}'}; "
                "if (-not $keys) { Write-Host 'Fallback: Registry key access failed or not found.' } "
                "foreach ($k in $keys) { "
                "try { "
                "$val = Get-ItemProperty -Path $k.PSPath -Name 'DriverDesc' -ErrorAction Stop; "
                "if ($val.DriverDesc -eq $adapter.InterfaceDescription) { "
                f"Set-ItemProperty -Path $k.PSPath -Name 'NetworkAddress' -Value '{mac_no_sep}' -Force -ErrorAction Stop; "
                "Write-Host 'Success: Registry'; "
                f"Restart-NetAdapter -Name '{iface}' -Confirm:$false; "
                "} "
                "} catch [System.Security.SecurityException] { Write-Host 'Windows Error: Registry Access Denied (Run as Administrator).' } "
                "catch {} " # Catch other generic errors during the loop
                "} "
            )
            
            reg_result = run(["powershell", "-Command", reg_cmd_content], capture=True)
            
            if "Success: Registry" in str(reg_result):
                return True
            elif "Windows Error: Registry Access Denied" in str(reg_result):
                return "Windows Error: Run the script as Administrator."
            else:
                # Compile the full error output from both failed attempts
                return f"MAC change failed via PowerShell (AdvancedProperty) and Registry. \nAdvancedProperty Result: {result}\nRegistry output: {reg_result}"
            
        return True
    except Exception as e:
        print(f"General error setting MAC for {iface}: {e}", file=sys.stderr) 
        return str(e)

def save_original_mac(iface, mac):
    d = Path.home() / ".mac_changer"
    d.mkdir(exist_ok=True)
    (d / f"{iface}.orig").write_text(mac.upper()) 

def load_original_mac(iface):
    f = Path.home() / ".mac_changer" / f"{iface}.orig"
    return f.read_text().strip().upper() if f.exists() else None

# ---------------- GUI ----------------

class MACChangerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("MAC Address Changer")
        self.root.geometry("640x430")
        self.root.configure(bg="#1e1e1e")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", font=("Segoe UI", 10), padding=6)
        style.configure("TLabel", background="#1e1e1e", foreground="white")

        self.iface_var = tk.StringVar()
        self.mac_var = tk.StringVar()
        self.current_mac = tk.StringVar(value="")

        ttk.Label(root, text="Select Network Interface:").pack(pady=(20, 5))
        self.iface_combo = ttk.Combobox(root, textvariable=self.iface_var, width=40, state="readonly")
        self.iface_combo.pack()
        self.iface_combo.bind("<<ComboboxSelected>>", self.update_current_mac)

        ttk.Label(root, text="New MAC Address (AA:BB:CC:DD:EE:FF):").pack(pady=(15, 5))
        ttk.Entry(root, textvariable=self.mac_var, width=40).pack()

        button_frame = ttk.Frame(root)
        button_frame.pack(pady=15)
        ttk.Button(button_frame, text="🔄 Random MAC", command=self.random_mac_action).grid(row=0, column=0, padx=6)
        ttk.Button(button_frame, text="💾 Save Original", command=self.save_original_action).grid(row=0, column=1, padx=6)
        ttk.Button(button_frame, text="🧩 Change MAC", command=self.change_mac_action).grid(row=0, column=2, padx=6)
        ttk.Button(button_frame, text="♻️ Restore", command=self.restore_mac_action).grid(row=0, column=3, padx=6)

        ttk.Label(root, text="Current MAC Address:").pack(pady=(25, 5))
        self.mac_display = tk.Label(root, textvariable=self.current_mac,
                                     font=("Consolas", 13, "bold"), fg="#00ff7f",
                                     bg="#1e1e1e", width=42, relief="sunken")
        self.mac_display.pack(pady=5)
        
        ttk.Label(root, text="💡 NOTE: Requires **sudo** (Linux/macOS) or **Administrator** (Windows) to run.", 
                  foreground="#ffa500", background="#1e1e1e").pack(pady=(10, 0))

        self.load_interfaces()

    def load_interfaces(self):
        interfaces = get_interfaces()
        if not interfaces:
            messagebox.showerror("Error", "No network interfaces detected or script lacks permission to list them. Check console for details.")
            return
        self.iface_combo["values"] = interfaces
        if interfaces:
             self.iface_combo.current(0)
             self.update_current_mac()

    def update_current_mac(self, event=None):
        iface = self.iface_var.get().strip()
        if iface:
            mac_address = get_current_mac(iface)
            self.current_mac.set(mac_address)
            if "Permission denied" in mac_address or "Windows Error" in mac_address:
                self.mac_display.config(fg="red")
            else:
                 self.mac_display.config(fg="#00ff7f")

    def random_mac_action(self):
        self.mac_var.set(random_mac())

    def save_original_action(self):
        iface = self.iface_var.get().strip()
        if not iface:
            messagebox.showerror("Error", "Select an interface.")
            return
        cur = get_current_mac(iface)
        if cur != "Unknown" and "Permission denied" not in cur:
            save_original_mac(iface, cur)
            messagebox.showinfo("Saved", f"Original MAC saved: {cur}")
        else:
             messagebox.showerror("Error", f"Could not fetch current MAC to save: {cur}")
             print(f"Error saving original MAC: Could not fetch current MAC: {cur}", file=sys.stderr) 

    def change_mac_action(self):
        iface = self.iface_var.get().strip()
        new_mac = self.mac_var.get().strip().upper() 
        
        if not iface or not new_mac:
            messagebox.showerror("Error", "Select an interface and enter a MAC address.")
            return
        if not is_valid_mac(new_mac):
            messagebox.showerror("Error", "Invalid MAC format (use AA:BB:CC:DD:EE:FF).")
            return
        
        result = set_mac(iface, new_mac)
        
        if result is True:
            new_current_mac = get_current_mac(iface)
            messagebox.showinfo("Success", f"MAC changed successfully to {new_mac}")
            self.current_mac.set(new_current_mac)
            self.mac_display.config(fg="#00ff7f")
        else:
            if "Permission denied" in str(result) or "Windows Error: Run the script as Administrator" in str(result):
                error_msg = "MAC change **failed** due to insufficient permissions. Please run the script with **sudo** (Linux/macOS) or as **Administrator** (Windows)."
            else:
                 # Clean up the error message for the GUI
                 error_msg = str(result).replace("\n", " ")[:200] + "..." 
            
            messagebox.showerror("Error", error_msg)
            print(f"MAC Change Error (GUI Displayed): {error_msg}", file=sys.stderr)
            print(f"Full set_mac result:\n{result}", file=sys.stderr) # Print the full, multi-line result

    def restore_mac_action(self):
        iface = self.iface_var.get().strip()
        orig = load_original_mac(iface)
        if not orig:
            messagebox.showerror("Error", "No saved original MAC found.")
            return
            
        result = set_mac(iface, orig)
        
        if result is True:
            messagebox.showinfo("Restored", f"MAC restored to {orig}")
            self.current_mac.set(orig)
            self.mac_display.config(fg="#00ff7f")
        else:
            if "Permission denied" in str(result) or "Windows Error: Run the script as Administrator" in str(result):
                error_msg = "MAC restore **failed** due to insufficient permissions. Please run the script with **sudo** (Linux/macOS) or as **Administrator** (Windows)."
            else:
                error_msg = str(result).replace("\n", " ")[:200] + "..."

            messagebox.showerror("Error", error_msg)
            print(f"MAC Restore Error (GUI Displayed): {error_msg}", file=sys.stderr)
            print(f"Full set_mac result:\n{result}", file=sys.stderr)


if __name__ == "__main__":
    print("MAC Changer GUI started. Check console for detailed command output and errors.")
    root = tk.Tk()
    app = MACChangerApp(root)
    root.mainloop()