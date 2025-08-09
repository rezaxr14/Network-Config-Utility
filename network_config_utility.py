import ctypes
import json
import os
import sys
import tkinter as tk
from tkinter import messagebox, ttk
import winreg
import wmi

# --- Configuration ---
DNS_CONFIG_FILE = "dns_servers.json"
PROXY_CONFIG_FILE = "proxies.json"

DEFAULT_DNS_SERVERS = {
    "Google": ["8.8.8.8", "8.8.4.4"],
    "Cloudflare": ["1.1.1.1", "1.0.0.1"],
    "Verisign": ["64.6.64.6", "64.6.65.6"],
    "Neustar": ["78.157.42.100", "78.157.42.101"],
    "Internal": ["10.202.10.10", "10.202.10.11"],
    "OpenDNS": ["208.67.222.222", "208.67.220.220"]
}

DEFAULT_PROXIES = {
    "No Proxy": {"server": "", "port": "", "user": "", "pass": "", "type": "Disabled"},
    "Proxy 1": {"server": "192.168.1.159", "port": "8080", "user": "", "pass": "", "type": "HTTP"},
    "Proxy 2": {"server": "192.168.178.134", "port": "8080", "user": "", "pass": "", "type": "HTTP"}
}


# --- Core Functions ---
def is_admin():
    """Checks for administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def run_as_admin():
    """Reruns the script with administrator privileges."""
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)

# --- Data Management ---
def load_json_file(filename, default_data):
    """Loads a JSON file or creates it with defaults."""
    if not os.path.exists(filename):
        with open(filename, 'w') as f:
            json.dump(default_data, f, indent=4)
        return default_data
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        messagebox.showerror("File Error", f"Could not read {filename}. Using default settings.")
        return default_data

def save_json_file(filename, data):
    """Saves a dictionary to a JSON file."""
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        return True
    except IOError:
        return False

# --- Network Functions (Using WMI) ---
def get_network_interfaces():
    """Gets a list of network interfaces and their WMI objects."""
    wmi_conn = wmi.WMI()
    interfaces = []
    for interface in wmi_conn.Win32_NetworkAdapterConfiguration(IPEnabled=True):
        if interface.Description:
            interfaces.append({"name": interface.Description, "wmi_object": interface})
    return interfaces

def set_dns(wmi_object, primary_dns, secondary_dns):
    """Sets the DNS servers for a given WMI network interface object."""
    try:
        dns_list = [primary_dns]
        if secondary_dns:
            dns_list.append(secondary_dns)
        
        result = wmi_object.SetDNSServerSearchOrder(DNSServerSearchOrder=dns_list)
        if result[0] == 0:  # Success code
            messagebox.showinfo("Success", f"DNS for '{wmi_object.Description}' changed successfully!")
            return True
        else:
            messagebox.showerror("Error", f"Failed to set DNS. Error Code: {result[0]}")
            return False
    except Exception as e:
        messagebox.showerror("Error", f"Failed to set DNS. Details: {e}")
        return False

def set_dynamic_dns(wmi_object):
    """Sets the DNS to be obtained automatically via DHCP using WMI."""
    try:
        result = wmi_object.SetDNSServerSearchOrder() # No arguments means DHCP
        if result[0] == 0:
            messagebox.showinfo("Success", f"DNS for '{wmi_object.Description}' set to automatic (DHCP)!")
            return True
        else:
            messagebox.showerror("Error", f"Failed to reset DNS. Error Code: {result[0]}")
            return False
    except Exception as e:
        messagebox.showerror("Error", f"Failed to reset DNS. Details: {e}")
        return False

# --- Proxy Functions ---
def set_proxy(proxy_server, port, proxy_type, user="", password=""):
    """Sets the system-wide proxy via registry."""
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                          r'Software\Microsoft\Windows\CurrentVersion\Internet Settings',
                                          0, winreg.KEY_WRITE)
        
        proxy_address = f"{proxy_server}:{port}"
        winreg.SetValueEx(registry_key, 'ProxyServer', 0, winreg.REG_SZ, proxy_address)
        winreg.SetValueEx(registry_key, 'ProxyEnable', 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(registry_key, 'ProxyOverride', 0, winreg.REG_SZ, '<local>')
        
        winreg.CloseKey(registry_key)
        
        # Refresh internet settings
        internet_set_option = ctypes.windll.wininet.InternetSetOptionW
        internet_set_option(0, 39, 0, 0) # INTERNET_OPTION_SETTINGS_CHANGED
        internet_set_option(0, 37, 0, 0) # INTERNET_OPTION_REFRESH
        
        messagebox.showinfo("Success", f"Proxy set to {proxy_address} successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to set proxy. Details: {e}")

def disable_proxy():
    """Disables the system-wide proxy via registry."""
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                          r'Software\Microsoft\Windows\CurrentVersion\Internet Settings',
                                          0, winreg.KEY_WRITE)
        winreg.SetValueEx(registry_key, 'ProxyEnable', 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(registry_key)
        
        # Refresh internet settings
        internet_set_option = ctypes.windll.wininet.InternetSetOptionW
        internet_set_option(0, 39, 0, 0)
        internet_set_option(0, 37, 0, 0)

        messagebox.showinfo("Success", "Proxy has been disabled.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to disable proxy. Details: {e}")

# --- GUI Application ---
class DnsChangerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DNS & Proxy Changer (Enhanced)")
        self.root.geometry("500x650")
        self.root.resizable(False, False)
        
        # Load data
        self.dns_servers = load_json_file(DNS_CONFIG_FILE, DEFAULT_DNS_SERVERS)
        self.proxies = load_json_file(PROXY_CONFIG_FILE, DEFAULT_PROXIES)

        self.style = ttk.Style(self.root)
        self.style.theme_use('vista')

        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.pack(fill="both", expand=True)

        # DNS Settings Group
        dns_frame = ttk.LabelFrame(main_frame, text="DNS Settings", padding="10")
        dns_frame.pack(fill="x", pady=(0, 10))

        ttk.Label(dns_frame, text="1. Select Network Interface:", font=("Segoe UI", 10, "bold")).pack(fill='x', pady=(0, 5))
        self.interface_var = tk.StringVar()
        self.interface_dropdown = ttk.Combobox(dns_frame, textvariable=self.interface_var, state="readonly")
        self.interfaces = get_network_interfaces()
        self.interface_dropdown['values'] = [i['name'] for i in self.interfaces]
        self.interface_dropdown.pack(fill="x", ipady=4)

        ttk.Label(dns_frame, text="2. Select DNS Server:", font=("Segoe UI", 10, "bold")).pack(fill='x', pady=(15, 5))
        self.dns_selection_var = tk.StringVar()
        self.dns_dropdown = ttk.Combobox(dns_frame, textvariable=self.dns_selection_var, state="readonly")
        self.dns_dropdown.bind("<<ComboboxSelected>>", self.update_dns_display)
        self.dns_dropdown.pack(fill="x", ipady=4)

        info_frame = ttk.Frame(dns_frame, padding="5")
        info_frame.pack(fill='x', pady=5)
        self.primary_dns_label = ttk.Label(info_frame, text="Primary: N/A")
        self.primary_dns_label.pack(anchor="w")
        self.secondary_dns_label = ttk.Label(info_frame, text="Secondary: N/A")
        self.secondary_dns_label.pack(anchor="w")

        dns_button_frame = ttk.Frame(dns_frame)
        dns_button_frame.pack(fill='x', pady=5)
        set_dns_button = ttk.Button(dns_button_frame, text="Apply DNS", command=self.apply_selected_dns)
        set_dns_button.pack(side="left", expand=True, fill="x", ipady=5, padx=(0, 5))
        set_dhcp_button = ttk.Button(dns_button_frame, text="Reset to Automatic (DHCP)", command=self.reset_dns_dhcp)
        set_dhcp_button.pack(side="left", expand=True, fill="x", ipady=5, padx=(5, 0))
        add_dns_button = ttk.Button(dns_frame, text="Add/Manage Custom DNS", command=self.open_manage_dns_window)
        add_dns_button.pack(fill='x', pady=5, ipady=5)

        # Proxy Settings Group
        proxy_frame = ttk.LabelFrame(main_frame, text="Proxy Settings", padding="10")
        proxy_frame.pack(fill="x", pady=10)

        ttk.Label(proxy_frame, text="Select Proxy Configuration:", font=("Segoe UI", 10, "bold")).pack(fill='x', pady=(0, 5))
        self.proxy_var = tk.StringVar()
        self.proxy_dropdown = ttk.Combobox(proxy_frame, textvariable=self.proxy_var, state="readonly")
        self.proxy_dropdown.bind("<<ComboboxSelected>>", self.update_proxy_details)
        self.proxy_dropdown.pack(fill="x", ipady=4)

        # Proxy Details Frame (new)
        proxy_details_frame = ttk.Frame(proxy_frame, padding="5")
        proxy_details_frame.pack(fill="x", pady=5)
        self.proxy_details_label = ttk.Label(proxy_details_frame, text="Details: N/A", wraplength=400)
        self.proxy_details_label.pack(anchor="w")
        
        apply_proxy_button = ttk.Button(proxy_frame, text="Apply Proxy", command=self.apply_proxy_settings)
        apply_proxy_button.pack(fill='x', pady=10, ipady=5)
        
        add_proxy_button = ttk.Button(proxy_frame, text="Add/Manage Custom Proxies", command=self.open_manage_proxy_window)
        add_proxy_button.pack(fill='x', ipady=5)

        # Initial population
        self.refresh_dns_dropdown()
        self.refresh_proxy_dropdown()
        
    def get_selected_wmi_object(self):
        """Helper to get the WMI object for the selected interface."""
        selected_name = self.interface_var.get()
        for interface in self.interfaces:
            if interface['name'] == selected_name:
                return interface['wmi_object']
        return None

    def refresh_dns_dropdown(self):
        """Reloads DNS servers and updates the dropdown menu."""
        self.dns_servers = load_json_file(DNS_CONFIG_FILE, DEFAULT_DNS_SERVERS)
        self.dns_dropdown['values'] = list(self.dns_servers.keys())
        self.dns_selection_var.set("")
        self.update_dns_display()

    def update_dns_display(self, event=None):
        """Updates the primary/secondary IP labels based on selection."""
        selected_name = self.dns_selection_var.get()
        ips = self.dns_servers.get(selected_name)
        if ips and len(ips) >= 2:
            self.primary_dns_label.config(text=f"Primary: {ips[0]}")
            self.secondary_dns_label.config(text=f"Secondary: {ips[1]}")
        else:
            self.primary_dns_label.config(text="Primary: N/A")
            self.secondary_dns_label.config(text="Secondary: N/A")

    def apply_selected_dns(self):
        """Applies the selected DNS to the selected interface."""
        wmi_obj = self.get_selected_wmi_object()
        dns_name = self.dns_selection_var.get()

        if not wmi_obj:
            messagebox.showwarning("Warning", "Please select a network interface.")
            return
        if not dns_name:
            messagebox.showwarning("Warning", "Please select a DNS server.")
            return
            
        primary, secondary = self.dns_servers[dns_name]
        set_dns(wmi_obj, primary, secondary)

    def reset_dns_dhcp(self):
        """Resets DNS to automatic for the selected interface."""
        wmi_obj = self.get_selected_wmi_object()
        if not wmi_obj:
            messagebox.showwarning("Warning", "Please select a network interface first.")
            return
        set_dynamic_dns(wmi_obj)

    def refresh_proxy_dropdown(self):
        """Reloads proxies and updates the dropdown menu."""
        self.proxies = load_json_file(PROXY_CONFIG_FILE, DEFAULT_PROXIES)
        self.proxy_dropdown['values'] = list(self.proxies.keys())
        self.proxy_var.set("")
        self.update_proxy_details()

    def update_proxy_details(self, event=None):
        """Updates the proxy details label based on the selected proxy."""
        selected_name = self.proxy_var.get()
        proxy_info = self.proxies.get(selected_name)
        if proxy_info and proxy_info.get('server'):
            details = (f"Server: {proxy_info['server']}:{proxy_info['port']}\n"
                           f"Type: {proxy_info['type']}\n"
                           f"User: {proxy_info.get('user') if proxy_info.get('user') else 'None'}")
            self.proxy_details_label.config(text=details)
        elif selected_name == "No Proxy":
            self.proxy_details_label.config(text="Details: Proxy is disabled.")
        else:
            self.proxy_details_label.config(text="Details: N/A")

    def apply_proxy_settings(self):
        """Applies the selected proxy setting."""
        selected_name = self.proxy_var.get()
        if not selected_name:
            messagebox.showwarning("Warning", "Please select a proxy option.")
            return
        
        proxy_info = self.proxies[selected_name]

        if proxy_info.get('server'):
            set_proxy(proxy_info['server'], proxy_info['port'], proxy_info['type'], proxy_info.get('user', ''), proxy_info.get('pass', ''))
        else:
            disable_proxy()

    # Management Windows
    def open_manage_dns_window(self):
        """Opens the Toplevel window to add/manage DNS servers."""
        manage_window = tk.Toplevel(self.root)
        manage_window.title("Manage DNS Servers")
        manage_window.geometry("400x350")
        manage_window.transient(self.root)
        manage_window.grab_set()

        frame = ttk.Frame(manage_window, padding="15")
        frame.pack(fill="both", expand=True)
        
        # --- Listbox for existing DNS ---
        list_frame = ttk.Frame(frame)
        list_frame.pack(fill="both", expand=True, pady=(0, 10))
        ttk.Label(list_frame, text="Existing DNS Servers:", font=("Segoe UI", 10, "bold")).pack(anchor='w')
        listbox = tk.Listbox(list_frame, height=5)
        for name in self.dns_servers:
            listbox.insert(tk.END, name)
        listbox.pack(fill="both", expand=True)

        # --- Form to add new DNS ---
        form_frame = ttk.LabelFrame(frame, text="Add/Edit DNS", padding="10")
        form_frame.pack(fill="x")
        ttk.Label(form_frame, text="Name:").grid(row=0, column=0, sticky='w', pady=2)
        name_entry = ttk.Entry(form_frame)
        name_entry.grid(row=0, column=1, sticky='ew', padx=5)
        ttk.Label(form_frame, text="Primary IP:").grid(row=1, column=0, sticky='w', pady=2)
        primary_entry = ttk.Entry(form_frame)
        primary_entry.grid(row=1, column=1, sticky='ew', padx=5)
        ttk.Label(form_frame, text="Secondary IP:").grid(row=2, column=0, sticky='w', pady=2)
        secondary_entry = ttk.Entry(form_frame)
        secondary_entry.grid(row=2, column=1, sticky='ew', padx=5)
        form_frame.columnconfigure(1, weight=1)

        def add_new():
            name = name_entry.get().strip()
            primary = primary_entry.get().strip()
            secondary = secondary_entry.get().strip()
            if not all([name, primary, secondary]):
                messagebox.showwarning("Input Error", "All fields are required.", parent=manage_window)
                return
            self.dns_servers[name] = [primary, secondary]
            if save_json_file(DNS_CONFIG_FILE, self.dns_servers):
                messagebox.showinfo("Success", f"DNS '{name}' saved.", parent=manage_window)
                self.refresh_dns_dropdown()
                manage_window.destroy()
            else:
                messagebox.showerror("Save Error", "Could not save the DNS file.", parent=manage_window)

        def delete_selected():
            try:
                selected_index = listbox.curselection()[0]
                name_to_delete = listbox.get(selected_index)
            except IndexError:
                messagebox.showwarning("Selection Error", "Please select a DNS server to delete.", parent=manage_window)
                return

            if name_to_delete in DEFAULT_DNS_SERVERS:
                messagebox.showwarning("Error", "You cannot delete default DNS servers.", parent=manage_window)
                return
            
            if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete '{name_to_delete}'?", parent=manage_window):
                del self.dns_servers[name_to_delete]
                if save_json_file(DNS_CONFIG_FILE, self.dns_servers):
                    self.refresh_dns_dropdown()
                    manage_window.destroy()
                else:
                    messagebox.showerror("Save Error", "Could not save the DNS file.", parent=manage_window)

        # --- Button Bar ---
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill='x', pady=(15, 0))
        
        ttk.Button(button_frame, text="Add/Update", command=add_new).pack(side="left", expand=True, fill="x", padx=(0, 5))
        ttk.Button(button_frame, text="Delete Selected", command=delete_selected).pack(side="left", expand=True, fill="x", padx=5)
        # *** MISSING BUTTON ADDED HERE ***
        ttk.Button(button_frame, text="Close", command=manage_window.destroy).pack(side="left", expand=True, fill="x", padx=(5, 0))

    def open_manage_proxy_window(self):
        """Opens the Toplevel window to add/manage proxies."""
        manage_window = tk.Toplevel(self.root)
        manage_window.title("Manage Proxies")
        manage_window.geometry("450x500")
        manage_window.transient(self.root)
        manage_window.grab_set()

        frame = ttk.Frame(manage_window, padding="15")
        frame.pack(fill="both", expand=True)

        list_frame = ttk.Frame(frame)
        list_frame.pack(fill="both", expand=True, pady=(0, 10))
        ttk.Label(list_frame, text="Existing Proxies:", font=("Segoe UI", 10, "bold")).pack(anchor='w')
        listbox = tk.Listbox(list_frame, height=6)
        for name in self.proxies:
            listbox.insert(tk.END, name)
        listbox.pack(fill="both", expand=True)

        form_frame = ttk.LabelFrame(frame, text="Add/Edit Proxy", padding="10")
        form_frame.pack(fill="x", pady=(10, 0))
        
        fields = ["Name:", "Server Address:", "Port:", "Username (Optional):", "Password (Optional):"]
        self.proxy_entries = {}
        for i, field in enumerate(fields):
            ttk.Label(form_frame, text=field).grid(row=i, column=0, sticky='w', pady=2)
            show_char = "*" if "Password" in field else ""
            entry = ttk.Entry(form_frame, show=show_char)
            entry.grid(row=i, column=1, sticky='ew', padx=5, pady=2)
            self.proxy_entries[field.split(' ')[0].lower()] = entry
        form_frame.columnconfigure(1, weight=1)

        def add_new():
            name = self.proxy_entries['name:'].get().strip()
            server = self.proxy_entries['server'].get().strip()
            port = self.proxy_entries['port:'].get().strip()
            user = self.proxy_entries['username'].get().strip()
            password = self.proxy_entries['password'].get().strip()
            
            if not all([name, server, port]):
                messagebox.showwarning("Input Error", "Name, Server, and Port are required.", parent=manage_window)
                return
            self.proxies[name] = {"server": server, "port": port, "user": user, "pass": password, "type": "HTTP"}
            if save_json_file(PROXY_CONFIG_FILE, self.proxies):
                self.refresh_proxy_dropdown()
                manage_window.destroy()
            else:
                messagebox.showerror("Save Error", "Could not save the proxy file.", parent=manage_window)

        def delete_selected():
            try:
                selected_index = listbox.curselection()[0]
                name_to_delete = listbox.get(selected_index)
            except IndexError:
                messagebox.showwarning("Selection Error", "Please select a proxy to delete.", parent=manage_window)
                return

            if name_to_delete in DEFAULT_PROXIES:
                messagebox.showwarning("Error", "You cannot delete default proxy settings.", parent=manage_window)
                return
            
            if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete '{name_to_delete}'?", parent=manage_window):
                del self.proxies[name_to_delete]
                if save_json_file(PROXY_CONFIG_FILE, self.proxies):
                    self.refresh_proxy_dropdown()
                    manage_window.destroy()
                else:
                     messagebox.showerror("Save Error", "Could not save the proxy file.", parent=manage_window)

        # --- Button Bar ---
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill='x', pady=(15, 0))
        
        ttk.Button(button_frame, text="Add/Update", command=add_new).pack(side="left", expand=True, fill="x", padx=(0, 5))
        ttk.Button(button_frame, text="Delete Selected", command=delete_selected).pack(side="left", expand=True, fill="x", padx=5)
        # *** MISSING BUTTON ADDED HERE ***
        ttk.Button(button_frame, text="Close", command=manage_window.destroy).pack(side="left", expand=True, fill="x", padx=(5, 0))

def main():
    """Main function to check admin rights and run the GUI."""
    if not is_admin():
        run_as_admin()
        sys.exit()
    
    # Check for WMI module and install if missing
    try:
        import wmi
    except ImportError:
        messagebox.showerror("Dependency Missing", "The 'wmi' module is not installed. Please install it by running 'pip install wmi' in an administrator command prompt.")
        sys.exit()

    root = tk.Tk()
    app = DnsChangerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()