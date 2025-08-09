# DNS & Proxy Changer

A powerful and user-friendly desktop utility for Windows that allows you to quickly change your network's DNS and proxy settings. Built with Python and Tkinter, this tool provides a seamless graphical interface, eliminating the need for complex command-line commands.

## ✨ Features

* **Silent and Fast Operation:** Utilizes Windows Management Instrumentation (WMI) to modify network settings without opening a command prompt, ensuring a clean and swift user experience.
* **DNS Management:**
    * Easily switch between predefined DNS servers like Google, Cloudflare, and OpenDNS.
    * Add, edit, or delete your own custom DNS server configurations.
    * Reset to automatic (DHCP) DNS settings with a single click.
* **Proxy Management:**
    * Configure system-wide proxy settings.
    * Save and switch between different proxy configurations.
    * Add custom proxies with support for authentication (username and password).
* **Intuitive GUI:** A clean and responsive graphical interface built with Tkinter makes it simple to manage your network configurations.
* **Administrator-Level Access:** The script automatically requests administrator privileges to ensure it can successfully modify system-level network settings.

---

## 📸 Screenshots

### Main Interface

![Main Interface](https://github.com/rezaxr14/Network-Config-Utility/blob/main/Screenshot_main.png)

The main window provides a clear and concise way to select your network interface, choose a DNS server configuration, and apply your desired proxy settings.

### Manage DNS Servers

![Manage DNS Servers](https://github.com/rezaxr14/Network-Config-Utility/blob/main/Screenshot_addDNS.png)

This dedicated window allows you to view existing DNS configurations and easily add new custom DNS servers.

### Manage Proxies

![Manage Proxies](https://github.com/rezaxr14/Network-Config-Utility/blob/main/Screenshot_addProxy.png)

This window lets you manage your stored proxy configurations, including adding new ones with optional authentication details.

---

## 🚀 Getting Started

### Prerequisites

* Python 3.x
* Windows Operating System

### Installation

1.  **Clone the repository:**
    ```sh
    git clone [https://github.com/](https://github.com/)<YourUsername>/DNS-Proxy-Changer.git
    cd DNS-Proxy-Changer
    ```

2.  **Install the required dependencies:**
    ```sh
    pip install -r requirements.txt
    ```

### Usage

Run the script with administrator privileges. The application will handle the rest.

```sh
python dns_proxy_changer.py