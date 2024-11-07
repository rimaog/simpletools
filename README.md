Simple Python Tools Collection

This collection contains a few simple Python scripts that can help you with testing and learning about security. Below you'll find a summary of each tool, how to install dependencies, and instructions on how to use them.
Tools Overview
1. Universal Brute Force Tool

This tool tries different username and password combinations to log in to websites. Currently, it supports:

    Instagram
    WordPress
    Joomla

2. Vulnerability Tool

This tool combines multiple security tools to check for common issues on websites:

    Nikto
    Nmap
    WPScan
    Skipfish

It has two features:

    IP & Geo Location — Find the IP address and location of a website.
    Vulnerability Scan — Run basic security tests on a website.

Installation
Step 1: Clone the Repository

Clone the repository to your computer using the command:

git clone https://github.com/rimaog/simpletools.git
cd simpletools

Step 2: Install Dependencies
For the Brute Force Tool:

Install the required Python libraries:

pip install requests aiohttp

If you are on Linux, also install the Tkinter library:

sudo apt-get install python3-tk

For the Vulnerability Tool:

    Install the required tools for scanning:

sudo apt update
sudo apt install nmap nikto skipfish wpscan

    Install the Python libraries for the GUI:

pip install requests pandas ttkbootstrap Pillow

If pip isn't working, you can use a virtual environment:

python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate  # Windows
pip install requests pandas ttkbootstrap Pillow

Running the Applications
Universal Brute Force Tool

To run the brute force tool:

sudo python3 bruteforce.py

This will open the GUI. You can select the website type (Instagram, WordPress, Joomla) and start the process.
Vulnerability Tool

To run the vulnerability tool:

python3 vulntool.py

This will open the tool with two sections: IP & Geo Location and Vulnerability Scan.
How to Use
Universal Brute Force Tool

    Open the tool by running:

    sudo python3 bruteforce.py

    Choose the website type (Instagram, WordPress, Joomla).

    Upload a list of usernames and passwords in .txt format.

    Click "Start Attack" to begin.

Vulnerability Tool

    IP & Geo Location: Enter a website address to find its IP and location.

    Vulnerability Scan: Enter a website address to check for basic security issues.

Disclaimer

Use these tools only on systems or websites you have permission to test. These tools are for educational purposes only. The author is not responsible for any misuse or damage caused.
