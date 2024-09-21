import os
import subprocess
import sys

# List of required libraries
required_libraries = [
    "requests",
    "beautifulsoup4",
    "pyOpenSSL",
    "lxml",
    "urllib3",
    "bs4",
    "python-shodan",  # For Shodan API
    "pysocks",        # For proxy support
    "dnspython",      # For DNS checks
    "cryptography",   # For encryption and certificates
    "html5lib"       # For parsing HTML5
]

def install_libraries():
    for library in required_libraries:
        subprocess.check_call([sys.executable, "-m", "pip", "install", library])

def main():
    print("Installing required libraries...")
    install_libraries()
    print("Installation complete.")

    # Automatically run the awvs.py file
    if os.path.exists("awvs.py"):
        print("Running awvs.py...")
        subprocess.run([sys.executable, "awvs.py"])
    else:
        print("awvs.py file not found.")

if __name__ == "__main__":
    main()