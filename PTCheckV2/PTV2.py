import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from datetime import datetime

# Function to check for SQL Injection vulnerability
def check_sql_injection(url):
    payloads = ["' OR 1=1 --", "' UNION SELECT NULL --", "' OR 'a'='a"]
    for payload in payloads:
        test_url = f"{url}{payload}"
        try:
            response = requests.get(test_url)
            if "error" in response.text.lower() or "warning" in response.text.lower():
                return True, payload
        except requests.RequestException:
            continue
    return False, None

# Function to check for Cross-Site Scripting (XSS) vulnerability
def check_xss(url):
    payloads = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>"]
    for payload in payloads:
        test_url = f"{url}?search={payload}"  # Assume a query param
        try:
            response = requests.get(test_url)
            if payload in response.text:
                return True, payload
        except requests.RequestException:
            continue
    return False, None

# Function to check for Open Redirect vulnerability
def check_open_redirect(url):
    try:
        response = requests.get(url, allow_redirects=True)
        if response.history:  # If there was a redirect
            for resp in response.history:
                if 'Location' in resp.headers and 'http' in resp.headers['Location']:
                    return True
    except requests.RequestException:
        pass
    return False

# Function to check for Missing HTTP Security Headers
def check_security_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers
        required_headers = ["Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options"]
        missing_headers = [header for header in required_headers if header not in headers]
        return missing_headers
    except requests.RequestException:
        return []

# Function to crawl the website and get all page URLs
def crawl_website(base_url):
    visited_urls = set()
    urls_to_visit = [base_url]
    
    while urls_to_visit:
        url = urls_to_visit.pop(0)
        if url not in visited_urls:
            visited_urls.add(url)
            try:
                response = requests.get(url)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find all links on the page and add them to the list to visit
                for link in soup.find_all('a', href=True):
                    full_url = urljoin(url, link['href'])
                    if base_url in full_url and full_url not in visited_urls:
                        urls_to_visit.append(full_url)
            except requests.RequestException:
                continue
    
    return visited_urls

# Function to generate the report
def generate_report(vulnerabilities, filename):
    with open(filename, 'w') as f:
        if not vulnerabilities:
            f.write("No vulnerabilities found.\n")
        else:
            for vuln, page, code, fix, exploit in vulnerabilities:
                f.write(f"\n[Vulnerability Found] {vuln} on {page}\n")
                f.write(f"Payload: {code}\n")
                f.write(f"Suggested Fix: {fix}\n")
                f.write(f"Exploit: {exploit}\n")
                f.write("-" * 80 + "\n")
    print(f"Report saved to {filename}")

# Main function to run the script
def main():
    url = input("Enter the URL of the website to scan: ").strip()
    
    # Ensure the URL is properly formatted
    if not url.startswith("http"):
        url = "http://" + url
    
    # Crawl the website and get all URLs
    print(f"Crawling {url}...\n")
    all_urls = crawl_website(url)
    
    vulnerabilities = []
    
    # Check each URL for vulnerabilities
    for page_url in all_urls:
        print(f"Scanning {page_url}...")

        # Check for SQL Injection
        sql_vuln, sql_payload = check_sql_injection(page_url)
        if sql_vuln:
            vulnerabilities.append((
                "SQL Injection vulnerability",
                page_url,
                sql_payload,
                "Fix: Use parameterized queries to prevent injection attacks.",
                "An attacker could execute arbitrary SQL commands, potentially gaining access to the database or altering its contents."
            ))

        # Check for XSS
        xss_vuln, xss_payload = check_xss(page_url)
        if xss_vuln:
            vulnerabilities.append((
                "XSS vulnerability",
                page_url,
                xss_payload,
                "Fix: Sanitize user input and escape output to prevent script execution.",
                "An attacker could inject malicious scripts to steal user data, session cookies, or perform other malicious actions."
            ))

        # Check for Open Redirect
        if check_open_redirect(page_url):
            vulnerabilities.append((
                "Open Redirect vulnerability",
                page_url,
                "N/A",
                "Fix: Validate redirect URLs to ensure they do not point to malicious sites.",
                "An attacker could trick users into visiting malicious websites, leading to phishing or malware attacks."
            ))

        # Check for Missing Security Headers
        missing_headers = check_security_headers(page_url)
        if missing_headers:
            for header in missing_headers:
                vulnerabilities.append((
                    f"Missing {header} security header",
                    page_url,
                    "N/A",
                    f"Fix: Add {header} header to improve security.",
                    "Missing security headers make the website vulnerable to various attacks like clickjacking, MIME sniffing, etc."
                ))

    # Generate the report file
    if vulnerabilities:
        # Create a filename with timestamp to avoid overwriting files
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"vulnerabilities_report_{timestamp}.txt"
        generate_report(vulnerabilities, filename)
    else:
        print("No vulnerabilities found.")

# Run the script
if __name__ == "__main__":
    main()
