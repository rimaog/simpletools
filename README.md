Simple Python Tools Collection

Hello guys! Here are a couple of simple yet powerful Python scripts for your security toolkit. Below you'll find a brief description of each tool, how to install dependencies, and instructions on how to use them.
Tools Overview
1. Universal Brute Force Tool

This is a universal brute force tool with a simple and easy-to-use GUI. Currently, it supports the following login types:

    Instagram
    Twitter
    Joomla
    WordPress

Feel free to add more login types if you want. The tool is very straightforward thanks to its simple GUI. You just need to select the login type, provide the target username, and input a list of passwords to attempt.
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

Installation
Step 1: Clone the Repository

First, clone the repository to your local machine using the following command:

git clone https://github.com/rimaog/simpletools.git

Step 2: Install Dependencies
Universal Brute Force Tool

The Universal Brute Force Tool requires the requests library. To install it, use:

pip install requests

Vulnerability Tool

For the Vulnerability Tool, you will need to install several external tools, including:

    Nmap
    Nikto
    Skipfish
    WPScan

You can install them using your system’s package manager. For example, on Ubuntu:

sudo apt update
sudo apt install nmap nikto skipfish wpscan

Additionally, for the Vulnerability Tool GUI, you need to install the following Python dependencies:

pip install requests pandas ttkbootstrap Pillow

If pip isn't working, follow these steps to install dependencies inside a virtual environment:

    Create a virtual environment:

python3 -m venv venv

Activate the virtual environment:

source venv/bin/activate  # Linux/macOS
venv\Scripts\activate  # Windows

Install the required dependencies:

    pip install requests pandas ttkbootstrap Pillow

Step 3: Running the Applications

After installation, you can launch each tool from your terminal.
Universal Brute Force Tool:

To run the Universal Brute Force Tool, use the following command:

sudo python3 bruteforce.py

This will launch the brute force tool's simple GUI, where you can select the target platform (Instagram, WordPress, Joomla, Twitter) and start the attack.
Vulnerability Tool:

To run the Vulnerability Tool, use the following command:

python3 vulntool.py

This will launch the application with the IP & Geo Location and Vulnerability Scan tabs. You can use the IP & Geo Location tab to resolve hostnames to IP addresses and get geolocation details. The Vulnerability Scan tab allows you to run scans using Nikto, WPScan, Nmap, and Skipfish on your target host.
Usage
Universal Brute Force Tool

    Launch the Brute Force Tool:
    Run the following command to start the brute force tool with a simple GUI:

    sudo python3 bruteforce.py

    Select the Target:
    In the GUI, choose the login type you want to attack:
        Instagram
        WordPress
        Joomla
        Twitter

    Provide Login Details:
    Enter the target's username and password list (a .txt file with usernames and passwords to use for brute-forcing).

    Start the Attack:
    Once you've selected the target and provided the necessary details, click the "Start Attack" button to begin the brute force attempt.

Vulnerability Tool
IP & Geo Location:

    Open the app and navigate to the "IP & Geo Location" tab.
    Enter a hostname (e.g., example.com) to resolve it to an IP address.
    The tool will display the IP address and geolocation details, including country, city, region, latitude, longitude, ISP, etc.

Vulnerability Scan:

    Navigate to the "Vulnerability Scan" tab.
    Enter a target host (e.g., google.com) and press Start Scan.
    The tool will run Nikto, WPScan, Nmap, and Skipfish with default parameters and display the results in the GUI.

Disclaimer

Important: Use these tools responsibly. Only run these tools on systems or websites you have explicit permission to test. The author is not responsible for any misuse of these tools or any damages caused. These tools are intended for educational purposes only.
