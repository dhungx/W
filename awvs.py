import requests
from bs4 import BeautifulSoup
import json
import time
import ssl
import socket
from OpenSSL import crypto
from urllib.parse import urlparse
from requests.exceptions import SSLError
import logging

logging.basicConfig(filename='scanner.log', level=logging.INFO)

class WebVulnerabilityScanner:
    def __init__(self, target_url, proxies=None, session_cookie=None, shodan_api_key=None):
        self.target_url = target_url
        self.found_vulnerabilities = []
        self.shodan_api_key = shodan_api_key
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        if session_cookie:
            self.headers['Cookie'] = session_cookie
        self.proxies = proxies if proxies else {}

    def scan_https_ssl(self):
        parsed_url = urlparse(self.target_url)
        if parsed_url.scheme != "https":
            self.found_vulnerabilities.append({"message": "Website is not using HTTPS.", "details": "This can expose user data."})
            logging.warning("HTTPS not found.")
        else:
            ssl_context = ssl.create_default_context()
            try:
                conn = ssl_context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=parsed_url.netloc)
                conn.connect((parsed_url.netloc, 443))
                cert_bin = conn.getpeercert(True)
                cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
                expiration_date = cert.get_notAfter().decode("utf-8")
                if expiration_date < time.strftime("%Y%m%d%H%M%SZ"):
                    self.found_vulnerabilities.append({"message": "SSL certificate has expired.", "details": "Renew your SSL certificate."})
                    logging.warning("SSL certificate expired.")
            except SSLError as e:
                self.found_vulnerabilities.append({"message": f"SSL Error: {str(e)}", "details": "Check your SSL configuration."})
                logging.error(f"SSL Error: {str(e)}")
            except Exception as e:
                self.found_vulnerabilities.append({"message": f"Error checking SSL certificate: {str(e)}", "details": "An unexpected error occurred."})
                logging.error(f"Error checking SSL certificate: {str(e)}")

    def scan_software_version(self):
        try:
            response = requests.get(self.target_url, headers=self.headers, proxies=self.proxies)
            server_header = response.headers.get('Server')
            if server_header:
                self.found_vulnerabilities.append({"message": f"Server header found: {server_header}", "details": "Potentially vulnerable software version."})
                logging.info(f"Server header: {server_header}")
        except Exception as e:
            logging.error(f"Error scanning software version: {str(e)}")

    def scan_security_headers(self):
        try:
            response = requests.get(self.target_url, headers=self.headers, proxies=self.proxies)
            security_headers = {
                'Content-Security-Policy': "Missing Content-Security-Policy header.",
                'X-Frame-Options': "Missing X-Frame-Options header.",
                'Strict-Transport-Security': "Missing Strict-Transport-Security header.",
                'X-Content-Type-Options': "Missing X-Content-Type-Options header."
            }
            for header, message in security_headers.items():
                if header not in response.headers:
                    self.found_vulnerabilities.append({"message": message, "details": "Consider adding this header for better security."})
        except Exception as e:
            logging.error(f"Error scanning security headers: {str(e)}")

    def scan_cors(self):
        try:
            response = requests.get(self.target_url, headers=self.headers, proxies=self.proxies)
            if 'Access-Control-Allow-Origin' in response.headers:
                if response.headers['Access-Control-Allow-Origin'] == '*':
                    self.found_vulnerabilities.append({"message": "CORS vulnerability: Access-Control-Allow-Origin set to '*'.", "details": "Restrict origins."})
                else:
                    self.found_vulnerabilities.append({"message": f"CORS header detected with origin: {response.headers['Access-Control-Allow-Origin']}", "details": "Review CORS policy."})
        except Exception as e:
            logging.error(f"Error scanning CORS: {str(e)}")

    def scan_api_endpoints(self):
        api_endpoints = ["/api/v1/users", "/api/v1/products", "/api/v1/orders"]
        for endpoint in api_endpoints:
            try:
                url = f"{self.target_url}{endpoint}"
                response = requests.get(url, headers=self.headers, proxies=self.proxies)
                if response.status_code == 200:
                    self.found_vulnerabilities.append({"message": f"Potentially exposed API endpoint: {url}", "details": "Review the API for security."})
            except Exception as e:
                logging.error(f"Error scanning API endpoints: {str(e)}")

    def scan_xss(self):
        xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
        for payload in xss_payloads:
            try:
                url = f"{self.target_url}?search={payload}"
                response = requests.get(url, headers=self.headers, proxies=self.proxies)
                if payload in response.text:
                    self.found_vulnerabilities.append({"message": f"XSS Vulnerability found with payload: {payload}", "details": "Implement input sanitization."})
            except Exception as e:
                logging.error(f"Error scanning for XSS: {str(e)}")

    def scan_sql_injection(self):
        sql_payloads = ["' OR 1=1--", "' OR 'a'='a", "\" OR \"a\"=\"a", "'; DROP TABLE users--"]
        for payload in sql_payloads:
            try:
                url = f"{self.target_url}?id={payload}"
                response = requests.get(url, headers=self.headers, proxies=self.proxies)
                if "syntax error" in response.text.lower() or "mysql" in response.text.lower() or "you have an error in your sql syntax" in response.text.lower():
                    self.found_vulnerabilities.append({"message": "SQL Injection Vulnerability found.", "details": f"Payload: {payload}"})
            except Exception as e:
                logging.error(f"Error scanning for SQL Injection: {str(e)}")

    def scan_command_injection(self):
        command_payloads = ["; ls", "&& ls", "| ls", "`ls`"]
        for payload in command_payloads:
            try:
                url = f"{self.target_url}?cmd={payload}"
                response = requests.get(url, headers=self.headers, proxies=self.proxies)
                if "bin" in response.text or "root" in response.text:
                    self.found_vulnerabilities.append({"message": "Command Injection Vulnerability found.", "details": f"Payload: {payload}"})
            except Exception as e:
                logging.error(f"Error scanning for Command Injection: {str(e)}")

    def scan_directory_traversal(self):
        traversal_payloads = ["../../../../etc/passwd", "../../windows/win.ini", "../etc/hosts"]
        for payload in traversal_payloads:
            try:
                url = f"{self.target_url}?file={payload}"
                response = requests.get(url, headers=self.headers, proxies=self.proxies)
                if "root:x:" in response.text or "[extensions]" in response.text:
                    self.found_vulnerabilities.append({"message": "Directory Traversal Vulnerability found.", "details": f"Payload: {payload}"})
            except Exception as e:
                logging.error(f"Error scanning for Directory Traversal: {str(e)}")

    def scan_csrf(self):
        csrf_tokens = ["<input type='hidden' name='csrf_token' value='", "<meta name='csrf-token' content='"]
        try:
            response = requests.get(self.target_url, headers=self.headers, proxies=self.proxies)
            if any(token in response.text for token in csrf_tokens):
                self.found_vulnerabilities.append({"message": "CSRF protection may be present.", "details": "Verify the implementation of CSRF tokens."})
            else:
                self.found_vulnerabilities.append({"message": "No CSRF protection detected.", "details": "Consider implementing CSRF protection."})
        except Exception as e:
            logging.error(f"Error scanning for CSRF: {str(e)}")

    def check_http_methods(self):
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
        try:
            for method in methods:
                response = requests.request(method, self.target_url, headers=self.headers, proxies=self.proxies)
                if response.status_code == 405:
                    self.found_vulnerabilities.append({"message": f"HTTP method {method} is not allowed.", "details": "Review allowed HTTP methods."})
        except Exception as e:
            logging.error(f"Error checking HTTP methods: {str(e)}")

    def scan_directory_listing(self):
        try:
            response = requests.get(self.target_url, headers=self.headers, proxies=self.proxies)
            if "Index of" in response.text:
                self.found_vulnerabilities.append({"message": "Directory listing is enabled.", "details": "Consider disabling directory listing."})
        except Exception as e:
            logging.error(f"Error scanning for Directory Listing: {str(e)}")

    def detect_language(self):
        try:
            response = requests.get(self.target_url, headers=self.headers, proxies=self.proxies)
            if response.status_code == 200:
                if 'PHP' in response.text:
                    self.found_vulnerabilities.append({"message": "Detected language: PHP", "details": "Ensure PHP is up to date."})
                elif 'Node.js' in response.text:
                    self.found_vulnerabilities.append({"message": "Detected language: Node.js", "details": "Ensure Node.js is up to date."})
                elif 'Django' in response.text:
                    self.found_vulnerabilities.append({"message": "Detected language: Python (Django)", "details": "Ensure Django is up to date."})
                elif 'Ruby on Rails' in response.text:
                    self.found_vulnerabilities.append({"message": "Detected language: Ruby on Rails", "details": "Ensure Rails is up to date."})
                else:
                    self.found_vulnerabilities.append({"message": "Language could not be detected.", "details": "Check the website source code."})
        except Exception as e:
            logging.error(f"Error detecting language: {str(e)}")

    def shodan_lookup(self):
        if self.shodan_api_key:
            try:
                shodan_url = f"https://api.shodan.io/shodan/host/{urlparse(self.target_url).netloc}?key={self.shodan_api_key}"
                response = requests.get(shodan_url)
                if response.status_code == 200:
                    data = response.json()
                    if 'data' in data:
                        self.found_vulnerabilities.append({"message": "Shodan data found.", "details": json.dumps(data['data'], indent=2)})
            except Exception as e:
                self.found_vulnerabilities.append({"message": "Failed to retrieve Shodan data.", "details": str(e)})
                logging.error(f"Error in Shodan lookup: {str(e)}")

    def report(self, output_format="text"):
        if output_format == "json":
            with open("vulnerability_report.json", "w") as report_file:
                json.dump(self.found_vulnerabilities, report_file, indent=4)
            print("Report saved as vulnerability_report.json")
        elif output_format == "html":
            with open("vulnerability_report.html", "w") as report_file:
                report_file.write(self.generate_html_report())
            print("Report saved as vulnerability_report.html")
        else:
            if self.found_vulnerabilities:
                print("Vulnerabilities found:")
                for vulnerability in self.found_vulnerabilities:
                    print(f"- {vulnerability['message']}: {vulnerability['details']}")
            else:
                print("No vulnerabilities found.")

    def generate_html_report(self):
        html = """
        <html>
        <head>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #1a1a1a;
                    color: #ffffff;
                }
                h1 {
                    color: #f44336;
                    text-align: center;
                    animation: fadeIn 2s;
                }
                ul {
                    list-style-type: none;
                    padding: 0;
                }
                li {
                    background: #333;
                    margin: 10px 0;
                    padding: 20px;
                    border-radius: 5px;
                    animation: slideIn 0.5s;
                }
                .vulnerability:hover {
                    background: #2e2e2e;
                }
                details {
                    cursor: pointer;
                    margin-top: 10px;
                    background: #1c1c1c;
                    border-radius: 5px;
                    padding: 10px;
                    transition: background 0.3s;
                }
                summary {
                    color: #f44336;
                    font-weight: bold;
                }
                summary::-webkit-details-marker {
                    display: none;
                }
                @keyframes fadeIn {
                    from { opacity: 0; }
                    to { opacity: 1; }
                }
                @keyframes slideIn {
                    from { transform: translateY(-10px); opacity: 0; }
                    to { transform: translateY(0); opacity: 1; }
                }

                footer {
                    text-align: center;
                    padding: 20px;
                    background-color: #282c34;
                    color: white;
                    position: relative;
                    overflow: hidden;
                }

                footer p {
                    opacity: 0; /* Bắt đầu ở trạng thái mờ */
                    transform: translateY(20px); /* Dịch xuống một chút */
                    animation: fadeInUp 2s forwards; /* Thêm animation */
                }

                @keyframes fadeInUp {
                    to {
                        opacity: 1; /* Kết thúc ở trạng thái rõ ràng */
                        transform: translateY(0); /* Dịch về vị trí ban đầu */
                    }
                }
            </style>
        </head>
        <body>
            <h1>Vulnerability Report</h1>
            <ul>
        """
        for vulnerability in self.found_vulnerabilities:
            html += f"""
                <li class="vulnerability">
                    <details>
                        <summary>{vulnerability['message']}</summary>
                        <p>{vulnerability['details']}</p>
                    </details>
                </li>
            """
        html += """
            </ul>
            <footer><p>&copy; 2024 ViBoss Studio</p></footer>
        </body>
        </html>
        """
        return html

if __name__ == "__main__":
    target = input("Enter the target URL: ")
    proxies_input = input("Enter proxy (optional, leave blank if none): ")
    session_cookie = input("Enter session cookie (optional): ")
    shodan_api_key = input("Enter Shodan API key (optional): ")
    proxies = {"http": proxies_input, "https": proxies_input} if proxies_input else None

    scanner = WebVulnerabilityScanner(target, proxies=proxies, session_cookie=session_cookie, shodan_api_key=shodan_api_key)

    start_time = time.time()

    print("Scanning for vulnerabilities...")
    scanner.scan_https_ssl()
    scanner.scan_software_version()
    scanner.scan_security_headers()
    scanner.scan_cors()
    scanner.scan_api_endpoints()
    scanner.scan_xss()
    scanner.scan_sql_injection()
    scanner.scan_command_injection()
    scanner.scan_directory_traversal()
    scanner.scan_csrf()  # New function for CSRF
    scanner.check_http_methods()  # New function for checking HTTP methods
    scanner.scan_directory_listing()  # New function for directory listing
    scanner.detect_language()
    scanner.shodan_lookup()

    # Report
    output_format = input("Enter output format (text, json, html): ")
    scanner.report(output_format)

    elapsed_time = time.time() - start_time
    print(f"Scan completed in {elapsed_time:.2f} seconds")