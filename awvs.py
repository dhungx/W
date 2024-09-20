import requests
from bs4 import BeautifulSoup
import re
import json
import time
import ssl
import socket
from OpenSSL import crypto
from urllib.parse import urlparse
from requests.exceptions import SSLError

class WebVulnerabilityScanner:
    def __init__(self, target_url, proxies=None, session_cookie=None):
        self.target_url = target_url
        self.found_vulnerabilities = []
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        if session_cookie:
            self.headers['Cookie'] = session_cookie
        self.proxies = proxies if proxies else {}

    def scan_https_ssl(self):
        parsed_url = urlparse(self.target_url)
        if parsed_url.scheme != "https":
            self.found_vulnerabilities.append("Website is not using HTTPS.")
        else:
            ssl_context = ssl.create_default_context()
            try:
                conn = ssl_context.wrap_socket(
                    socket.socket(socket.AF_INET),
                    server_hostname=parsed_url.netloc
                )
                conn.connect((parsed_url.netloc, 443))
                cert_bin = conn.getpeercert(True)
                cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
                expiration_date = cert.get_notAfter().decode("utf-8")
                if expiration_date < time.strftime("%Y%m%d%H%M%SZ"):
                    self.found_vulnerabilities.append("SSL certificate has expired.")
            except SSLError as e:
                self.found_vulnerabilities.append(f"SSL Error: {str(e)}")
            except Exception as e:
                self.found_vulnerabilities.append(f"Error checking SSL certificate: {str(e)}")

    def scan_software_version(self):
        response = requests.get(self.target_url, headers=self.headers, proxies=self.proxies)
        server_header = response.headers.get('Server')
        if server_header:
            self.found_vulnerabilities.append(f"Server header found: {server_header}")
            # Add logic to check known vulnerabilities for this server software version
            # For instance, lookup against a CVE database

    def scan_security_headers(self):
        response = requests.get(self.target_url, headers=self.headers, proxies=self.proxies)
        if 'Content-Security-Policy' not in response.headers:
            self.found_vulnerabilities.append("Missing Content-Security-Policy header.")
        if 'X-Frame-Options' not in response.headers:
            self.found_vulnerabilities.append("Missing X-Frame-Options header.")
        if 'Strict-Transport-Security' not in response.headers:
            self.found_vulnerabilities.append("Missing Strict-Transport-Security header.")
        if 'X-Content-Type-Options' not in response.headers:
            self.found_vulnerabilities.append("Missing X-Content-Type-Options header.")
    
    def scan_cors(self):
        response = requests.get(self.target_url, headers=self.headers, proxies=self.proxies)
        if 'Access-Control-Allow-Origin' in response.headers:
            if response.headers['Access-Control-Allow-Origin'] == '*':
                self.found_vulnerabilities.append("CORS vulnerability: Access-Control-Allow-Origin set to '*'.")
            else:
                self.found_vulnerabilities.append(f"CORS header detected with origin: {response.headers['Access-Control-Allow-Origin']}")

    def scan_api_endpoints(self):
        # Example: scan for common API endpoints vulnerabilities
        api_endpoints = ["/api/v1/users", "/api/v1/products", "/api/v1/orders"]
        for endpoint in api_endpoints:
            url = f"{self.target_url}{endpoint}"
            response = requests.get(url, headers=self.headers, proxies=self.proxies)
            if response.status_code == 200:
                self.found_vulnerabilities.append(f"Potentially exposed API endpoint: {url}")
    
    def scan_xss(self):
        xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
        for payload in xss_payloads:
            url = f"{self.target_url}?search={payload}"
            response = requests.get(url, headers=self.headers, proxies=self.proxies)
            if payload in response.text:
                self.found_vulnerabilities.append(f"XSS Vulnerability found with payload: {payload}")

    def report(self, output_format="text"):
        if output_format == "json":
            with open("vulnerability_report.json", "w") as report_file:
                json.dump(self.found_vulnerabilities, report_file, indent=4)
            print("Report saved as vulnerability_report.json")
        elif output_format == "html":
            with open("vulnerability_report.html", "w") as report_file:
                report_file.write("<html><body><h1>Vulnerability Report</h1><ul>")
                for vulnerability in self.found_vulnerabilities:
                    report_file.write(f"<li>{vulnerability}</li>")
                report_file.write("</ul></body></html>")
            print("Report saved as vulnerability_report.html")
        else:
            if self.found_vulnerabilities:
                print("Vulnerabilities found:")
                for vulnerability in self.found_vulnerabilities:
                    print(f"- {vulnerability}")
            else:
                print("No vulnerabilities found.")

if __name__ == "__main__":
    target = input("Enter the target URL: ")
    proxies_input = input("Enter proxy (optional, leave blank if none): ")
    session_cookie = input("Enter session cookie (optional): ")
    proxies = {"http": proxies_input, "https": proxies_input} if proxies_input else None
    
    scanner = WebVulnerabilityScanner(target, proxies=proxies, session_cookie=session_cookie)
    
    start_time = time.time()

    print("Scanning for vulnerabilities...")
    scanner.scan_https_ssl()
    scanner.scan_software_version()
    scanner.scan_security_headers()
    scanner.scan_cors()
    scanner.scan_api_endpoints()
    scanner.scan_xss()

    # Report
    output_format = input("Enter output format (text, json, html): ")
    scanner.report(output_format)

    elapsed_time = time.time() - start_time
    print(f"Scan completed in {elapsed_time:.2f} seconds")