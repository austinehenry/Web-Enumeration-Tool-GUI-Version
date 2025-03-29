import socket
import ssl
import dns.resolver
import json
from datetime import datetime
import asyncio
import aiohttp
from urllib.parse import urlparse

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP"
}

class WebScanner:
    def __init__(self):
        self.results = {}

    def scan_ports(self, host, ports):
        open_ports = []
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                if sock.connect_ex((host, port)) == 0:
                    open_ports.append(f"{port} ({COMMON_PORTS.get(port, 'Unknown')})")
        return open_ports

    def get_ssl_info(self, hostname):
        try:
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(2)
                s.connect((hostname, 443))
                cert = s.getpeercert()
                return {
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'expiry': cert.get('notAfter', 'Unknown'),
                    'subject': dict(x[0] for x in cert.get('subject', []))
                }
        except Exception:
            return {}

    async def analyze_headers(self, url):
        headers_result = {}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=3) as response:
                    headers = response.headers
                    headers_result = {
                        'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Missing'),
                        'Content-Security-Policy': headers.get('Content-Security-Policy', 'Missing'),
                        'X-Frame-Options': headers.get('X-Frame-Options', 'Missing'),
                        'X-XSS-Protection': headers.get('X-XSS-Protection', 'Missing')
                    }
        except Exception:
            headers_result = {
                'Strict-Transport-Security': 'Failed to fetch',
                'Content-Security-Policy': 'Failed to fetch',
                'X-Frame-Options': 'Failed to fetch',
                'X-XSS-Protection': 'Failed to fetch'
            }
        return headers_result

    def enumerate_subdomains(self, domain):
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            return [str(rdata) for rdata in answers]
        except Exception:
            return []

    def check_risks(self, security_headers):
        risks = []
        if security_headers.get('Strict-Transport-Security') == 'Missing':
            risks.append("No HSTS: Website is vulnerable to MITM attacks.")
        if security_headers.get('Content-Security-Policy') == 'Missing':
            risks.append("No CSP: Website might be vulnerable to XSS attacks.")
        return risks if risks else ['Safe to visit']

    async def scan_target(self, url):
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        security_headers = await self.analyze_headers(url)

        self.results = {
            'timestamp': datetime.now().isoformat(),
            'target': url,
            'subdomains': self.enumerate_subdomains(hostname),
            'open_ports': self.scan_ports(hostname, COMMON_PORTS.keys()),
            'ssl_info': self.get_ssl_info(hostname) if parsed_url.scheme == 'https' else {},
            'security_headers': security_headers,
        }
        self.results['risks'] = self.check_risks(self.results['security_headers'])
        return self.results
