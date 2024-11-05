import os
import socket
import requests
import subprocess
import logging
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from ttkbootstrap import Style
import threading

# Logger configuration
logging.basicConfig(filename='host_to_ip.log', level=logging.INFO, format='%(asctime)s - %(message)s')

class IPGeolocation:
    API_URL = "http://ip-api.com/json/{}"

    @classmethod
    def get_geolocation(cls, ip):
        """Fetch geolocation data for a given IP address."""
        try:
            response = requests.get(cls.API_URL.format(ip))
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logging.error(f"Error retrieving geolocation for {ip}: {e}")
            return {}

class Scanner:
    def run_nmap(self, ip):
        """Run Nmap on the specified IP address."""
        return self.execute_command(f"nmap -A -T4 -Pn {ip}")

    def run_skipfish(self, ip):
        """Run Skipfish on the specified IP address."""
        return self.execute_command(f"skipfish -o output_dir {ip}")

    def run_nikto(self, ip):
        """Run Nikto on the specified IP address."""
        return self.execute_command(f"nikto -h {ip}")

    def run_wpscan(self, ip):
        """Run WPScan on the specified IP address."""
        return self.execute_command(f"wpscan --url http://{ip}/ --no-banner")

    def execute_command(self, command):
        """Execute the constructed command in the shell."""
        try:
            process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
            output = process.stdout.strip() or f"Error: {process.stderr.strip()}"
            logging.info(f"Executed: {command} - Output: {output}")
            return output
        except Exception as e:
            logging.error(f"Execution error for command '{command}': {e}")
            return f"Execution error: {str(e)}"

class R1MAHostToIPApp:
    def __init__(self, root):
        self.root = root
        self.style = Style(theme='darkly')
        self.root.title("R1MA Host to IP")
        self.root.geometry("900x700")
        self.setup_gui()

    def setup_gui(self):
        """Setup the main GUI components."""
        self.main_frame = ttk.Frame(self.root, padding="20")
        self.main_frame.pack(expand=True, fill="both")

        self.tab_control = ttk.Notebook(self.main_frame)
        self.tab_control.pack(expand=True, fill="both")

        self.setup_ip_lookup_tab()
        self.setup_vulnerability_scan_tab()
        self.setup_footer()

    def setup_ip_lookup_tab(self):
        """Set up the IP lookup tab."""
        ip_frame = ttk.Frame(self.tab_control)
        self.tab_control.add(ip_frame, text="IP & Geolocation")

        ttk.Label(ip_frame, text="Enter Hostname or IP Address:", font=("Comic Sans MS", 12)).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.target_entry = ttk.Entry(ip_frame, width=60)
        self.target_entry.grid(row=0, column=1, pady=5)

        self.lookup_button = ttk.Button(ip_frame, text="Get Geolocation", bootstyle="danger", command=self.lookup_ip)
        self.lookup_button.grid(row=1, column=0, columnspan=2, pady=10)

        self.geo_output_area = scrolledtext.ScrolledText(ip_frame, width=80, height=20, wrap=tk.WORD)
        self.geo_output_area.grid(row=2, column=0, columnspan=2, pady=10)

        ttk.Label(ip_frame, text="NOTE: This tool is strictly for educational purposes only.", font=("Arial", 10), foreground="red").grid(row=3, column=0, columnspan=2, pady=10)

    def setup_vulnerability_scan_tab(self):
        """Set up the vulnerability scan tab."""
        scan_frame = ttk.Frame(self.tab_control)
        self.tab_control.add(scan_frame, text="Vulnerability Scan")

        ttk.Label(scan_frame, text="Target Host:", font=("Comic Sans MS", 12)).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.scan_target_entry = ttk.Entry(scan_frame, width=60)
        self.scan_target_entry.grid(row=0, column=1, pady=5)

        self.start_scan_button = ttk.Button(scan_frame, text="Run All Scans", bootstyle="danger", command=self.start_scan_thread)
        self.start_scan_button.grid(row=1, column=0, columnspan=2, pady=10)

        self.scan_output_area = scrolledtext.ScrolledText(scan_frame, width=80, height=20, wrap=tk.WORD)
        self.scan_output_area.grid(row=2, column=0, columnspan=2, pady=10)

        ttk.Label(scan_frame, text="NOTE: This tool is strictly for educational purposes only.", font=("Arial", 10), foreground="red").grid(row=3, column=0, columnspan=2, pady=10)

    def setup_footer(self):
        """Set up the footer section of the GUI."""
        footer_label = ttk.Label(self.main_frame, text="R1MA Host to IP Tool", font=("Helvetica", 10), background="black", foreground="white")
        footer_label.pack(side=tk.BOTTOM, pady=5)

    def log_message(self, message, output_area):
        """Log messages to the specified output area and log file."""
        timestamped_message = f"{message}\n"

        # Schedule the output area update
        self.root.after(0, output_area.insert, tk.END, timestamped_message)
        self.root.after(0, output_area.see, tk.END)  # Scroll to the end

        logging.info(message)

    def lookup_ip(self):
        """Lookup the IP address and display its geolocation."""
        host = self.target_entry.get().strip()
        if not host:
            messagebox.showwarning("Warning", "Please enter a hostname or IP address.")
            return

        try:
            ip = socket.gethostbyname(host)
            self.log_message(f"Resolved IP: {ip}", self.geo_output_area)
            geo_data = IPGeolocation.get_geolocation(ip)

            if geo_data and geo_data.get("status") == "success":
                output = (
                    f"IP: {geo_data['query']}\n"
                    f"Country: {geo_data['country']}\n"
                    f"Region: {geo_data['regionName']}\n"
                    f"City: {geo_data['city']}\n"
                    f"ZIP: {geo_data['zip']}\n"
                    f"Latitude: {geo_data['lat']}\n"
                    f"Longitude: {geo_data['lon']}\n"
                    f"ISP: {geo_data['isp']}\n"
                )
                self.log_message(output, self.geo_output_area)
            else:
                self.log_message(f"Failed to retrieve geolocation for {ip}.", self.geo_output_area)
        except socket.gaierror:
            messagebox.showerror("Error", "Could not resolve host to IP address.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def start_scan_thread(self):
        """Start the scan in a new thread."""
        self.start_scan_button.config(state='disabled')  # Disable button during scan
        scan_thread = threading.Thread(target=self.run_all_scans)
        scan_thread.start()

    def run_all_scans(self):
        """Run all available vulnerability scans."""
        host = self.scan_target_entry.get().strip()
        if not host:
            self.log_message("Warning: Please enter a target host.", self.scan_output_area)
            self.root.after(lambda: self.start_scan_button.config(state='normal'))  # Re-enable button
            return

        self.log_message("Starting all scans...", self.scan_output_area)

        scanner = Scanner()
        
        # Run all scans and log results
        scan_methods = [
            (scanner.run_nmap, "Nmap Output"),
            (scanner.run_skipfish, "Skipfish Output"),
            (scanner.run_nikto, "Nikto Output"),
            (scanner.run_wpscan, "WPScan Output")
        ]

        for scan_method, name in scan_methods:
            output = scan_method(host)
            self.log_message(f"{name}:\n{output}\n", self.scan_output_area)

        self.root.after(lambda: self.start_scan_button.config(state='normal'))  # Re-enable button

def main():
    root = tk.Tk()
    app = R1MAHostToIPApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()