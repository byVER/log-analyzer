#!/usr/bin/env python3
"""
Nginx Access Log Security Analyzer
Parses nginx access logs and identifies potential security threats
"""

import re
import sys
import argparse
from datetime import datetime
from typing import List, Dict, Tuple
from collections import defaultdict


class SecurityTags:
    """Security threat tags for categorization"""
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    BRUTE_FORCE = "BRUTE_FORCE"
    SUSPICIOUS_USER_AGENT = "SUSPICIOUS_USER_AGENT"
    LARGE_PAYLOAD = "LARGE_PAYLOAD"
    ERROR_4XX = "ERROR_4XX"
    ERROR_5XX = "ERROR_5XX"
    SCANNER = "SCANNER"
    SHELL_INJECTION = "SHELL_INJECTION"


class NginxLogParser:
    """Parser for nginx access logs"""
    
    # Common nginx log format pattern
    LOG_PATTERN = re.compile(
        r'(?P<remote_addr>[\d\.]+) - (?P<remote_user>.*?) \[(?P<time_local>.*?)\] '
        r'"(?P<request>.*?)" (?P<status>\d{3}) (?P<body_bytes_sent>\d+) '
        r'"(?P<http_referer>.*?)" "(?P<http_user_agent>.*?)"'
    )
    
    def parse_line(self, line: str) -> Dict:
        """Parse a single nginx access log line"""
        match = self.LOG_PATTERN.match(line)
        if not match:
            return None
        
        log_dict = match.groupdict()
        
        # Parse request into method, path, protocol
        request_parts = log_dict['request'].split(' ', 2)
        if len(request_parts) == 3:
            log_dict['method'] = request_parts[0]
            log_dict['path'] = request_parts[1]
            log_dict['protocol'] = request_parts[2]
        else:
            log_dict['method'] = ''
            log_dict['path'] = log_dict['request']
            log_dict['protocol'] = ''
        
        return log_dict


class SecurityAnalyzer:
    """Analyzes log entries for security threats"""
    
    # SQL injection patterns
    SQL_PATTERNS = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # SQL meta-characters
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",  # SQL syntax
        r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",  # SQL OR
        r"((\%27)|(\'))union",  # UNION
        r"exec(\s|\+)+(s|x)p\w+",  # Stored procedures
        r"select.*from",  # SELECT FROM
        r"insert.*into",  # INSERT INTO
        r"delete.*from",  # DELETE FROM
        r"drop.*table",  # DROP TABLE
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
        r"<iframe",
        r"<object",
        r"<embed",
        r"eval\s*\(",
        r"expression\s*\(",
    ]
    
    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.",
        r"%2e%2e",
        r"\.\.\\",
        r"%252e",
    ]
    
    # Shell injection patterns
    SHELL_PATTERNS = [
        r";\s*(ls|cat|wget|curl|nc|bash|sh|chmod|chown)",
        r"\|\s*(ls|cat|wget|curl|nc|bash|sh)",
        r"`.*`",
        r"\$\(.*\)",
        r"&&\s*(ls|cat|wget|curl|nc|bash|sh)",
    ]
    
    # Scanner/bot user agents
    SCANNER_AGENTS = [
        r"nikto",
        r"sqlmap",
        r"nmap",
        r"masscan",
        r"acunetix",
        r"burp",
        r"metasploit",
        r"nessus",
        r"openvas",
        r"qualys",
        r"w3af",
        r"havij",
        r"grabber",
    ]
    
    def __init__(self):
        self.sql_regex = [re.compile(p, re.IGNORECASE) for p in self.SQL_PATTERNS]
        self.xss_regex = [re.compile(p, re.IGNORECASE) for p in self.XSS_PATTERNS]
        self.path_regex = [re.compile(p, re.IGNORECASE) for p in self.PATH_TRAVERSAL_PATTERNS]
        self.shell_regex = [re.compile(p, re.IGNORECASE) for p in self.SHELL_PATTERNS]
        self.scanner_regex = [re.compile(p, re.IGNORECASE) for p in self.SCANNER_AGENTS]
        
        # Track IPs for brute force detection
        self.ip_requests = defaultdict(int)
        self.ip_failures = defaultdict(int)
    
    def analyze(self, log_entry: Dict) -> List[str]:
        """Analyze a log entry and return list of security tags"""
        tags = []
        
        if not log_entry:
            return tags
        
        path = log_entry.get('path', '')
        user_agent = log_entry.get('http_user_agent', '')
        status = int(log_entry.get('status', 0))
        body_bytes = int(log_entry.get('body_bytes_sent', 0))
        remote_addr = log_entry.get('remote_addr', '')
        
        # Check for SQL injection
        if any(regex.search(path) for regex in self.sql_regex):
            tags.append(SecurityTags.SQL_INJECTION)
        
        # Check for XSS
        if any(regex.search(path) for regex in self.xss_regex):
            tags.append(SecurityTags.XSS)
        
        # Check for path traversal
        if any(regex.search(path) for regex in self.path_regex):
            tags.append(SecurityTags.PATH_TRAVERSAL)
        
        # Check for shell injection
        if any(regex.search(path) for regex in self.shell_regex):
            tags.append(SecurityTags.SHELL_INJECTION)
        
        # Check for scanner/bot
        if any(regex.search(user_agent) for regex in self.scanner_regex):
            tags.append(SecurityTags.SCANNER)
        
        # Check for suspicious user agents
        if user_agent == '-' or len(user_agent) < 10:
            tags.append(SecurityTags.SUSPICIOUS_USER_AGENT)
        
        # Check for large payloads
        if body_bytes > 1000000:  # > 1MB
            tags.append(SecurityTags.LARGE_PAYLOAD)
        
        # Check HTTP status codes
        if 400 <= status < 500:
            tags.append(SecurityTags.ERROR_4XX)
            self.ip_failures[remote_addr] += 1
        
        if 500 <= status < 600:
            tags.append(SecurityTags.ERROR_5XX)
        
        # Track requests per IP for brute force detection
        self.ip_requests[remote_addr] += 1
        
        # Check for brute force (many failures from same IP)
        if self.ip_failures[remote_addr] > 10:
            tags.append(SecurityTags.BRUTE_FORCE)
        
        return tags


class LogAnalyzer:
    """Main log analyzer class"""
    
    def __init__(self):
        self.parser = NginxLogParser()
        self.analyzer = SecurityAnalyzer()
        self.results = []
    
    def analyze_file(self, filepath: str) -> List[Tuple[Dict, List[str]]]:
        """Analyze a log file and return entries with security tags"""
        results = []
        
        try:
            with open(filepath, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    log_entry = self.parser.parse_line(line)
                    if log_entry:
                        tags = self.analyzer.analyze(log_entry)
                        if tags:
                            results.append((log_entry, tags))
        except FileNotFoundError:
            print(f"Error: File '{filepath}' not found", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error processing file: {e}", file=sys.stderr)
            sys.exit(1)
        
        return results
    
    def print_report(self, results: List[Tuple[Dict, List[str]]]):
        """Print analysis report"""
        if not results:
            print("No security threats detected.")
            return
        
        print(f"\n{'='*80}")
        print(f"SECURITY LOG ANALYSIS REPORT")
        print(f"{'='*80}\n")
        print(f"Total security events detected: {len(results)}\n")
        
        # Count tags
        tag_counts = defaultdict(int)
        for _, tags in results:
            for tag in tags:
                tag_counts[tag] += 1
        
        print("Threat Summary:")
        print("-" * 80)
        for tag, count in sorted(tag_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {tag:30s}: {count:5d}")
        
        print(f"\n{'='*80}")
        print("Detailed Events:")
        print(f"{'='*80}\n")
        
        for log_entry, tags in results:
            print(f"Time: {log_entry.get('time_local', 'N/A')}")
            print(f"IP: {log_entry.get('remote_addr', 'N/A')}")
            print(f"Request: {log_entry.get('method', '')} {log_entry.get('path', '')}")
            print(f"Status: {log_entry.get('status', 'N/A')}")
            print(f"User-Agent: {log_entry.get('http_user_agent', 'N/A')[:80]}")
            print(f"Tags: {', '.join(tags)}")
            print("-" * 80)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Nginx Access Log Security Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s access.log
  %(prog)s /var/log/nginx/access.log
        """
    )
    
    parser.add_argument(
        'logfile',
        help='Path to nginx access log file'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    
    args = parser.parse_args()
    
    analyzer = LogAnalyzer()
    results = analyzer.analyze_file(args.logfile)
    analyzer.print_report(results)


if __name__ == '__main__':
    main()
