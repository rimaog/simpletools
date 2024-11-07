Simple Python Tools Collection

Hello guys! Here are a couple of simple yet powerful Python scripts for your security toolkit. Below you'll find a brief description of each tool, how to install dependencies, and instructions on how to use them.
Tools Overview
1. Universal Brute Force Tool

This is a universal brute force tool with a simple and easy-to-use GUI. Currently, it supports the following login types:

    Instagram
    Twitter
    Joomla
    WordPress

Feel free to add more login types if you want. The tool is very straightforward thanks to its simple GUI.
2. Vulnerability Tool

This tool combines multiple well-known security tools:

    Nikto
    Nmap
    WPScan
    Skipfish

It has a simple GUI with two tabs:

    Tab 1: IP & Geo Location
    This is a host-to-IP grabber. It also includes DNS history and can bypass Cloudflare with the appropriate API key.

    Tab 2: Vulnerability Scan
    Simply input the target host (e.g., google.com) and press Start Scan. It will automatically run all the tools (Nikto, WPScan, Nmap, and Skipfish) with their default parameters. You cannot choose individual tools—everything runs together.

Important Note

I do not take responsibility for any actions you perform with these tools.
These tools are for educational purposes only.
Use them responsibly and make sure you have permission before testing or scanning any website.
Requirements

Before running these tools, make sure you have the necessary dependencies installed:

    Nikto
    WPScan
    Nmap
    Skipfish

You can install them using your system’s package manager or follow the specific installation instructions for each tool.
How to Use
Universal Brute Force Tool

    Update your system (if necessary):

sudo apt-get update
sudo apt-get upgrade

Install Python 3 (if not already installed):

sudo apt-get install python3

Run the script:

Navigate to the directory where the bruteforce.py file is located and execute:

    python3 bruteforce.py

    The GUI will launch, and you can select your target login type and start the brute force attack.

Vulnerability Tool

    Install necessary dependencies:

pip3 install requests pandas ttkbootstrap Pillow

If pip3 doesn't work, follow these steps:

    Create a virtual environment:

python3 -m venv venv
source venv/bin/activate

Install dependencies again inside the virtual environment:

    pip3 install requests pandas ttkbootstrap Pillow

Run the script:

Navigate to the directory where the vulntool.py file is located and execute:

    python3 vulntool.py

    The GUI will launch, and you can begin using the IP & Geo Location tab or the Vulnerability Scan tab.

Disclaimer

Important:
Use these tools responsibly. Only run these tools on systems or websites you have explicit permission to test.
The author is not responsible for any misuse of these tools or any damages caused.
