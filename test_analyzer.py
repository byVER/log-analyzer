#!/usr/bin/env python3
"""
Simple tests for the log analyzer
"""

import unittest
from log_analyzer import NginxLogParser, SecurityAnalyzer, SecurityTags


class TestNginxLogParser(unittest.TestCase):
    """Test nginx log parsing"""
    
    def setUp(self):
        self.parser = NginxLogParser()
    
    def test_parse_valid_log(self):
        """Test parsing a valid log line"""
        log_line = '192.168.1.1 - - [30/Oct/2025:10:15:23 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
        result = self.parser.parse_line(log_line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['remote_addr'], '192.168.1.1')
        self.assertEqual(result['method'], 'GET')
        self.assertEqual(result['path'], '/index.html')
        self.assertEqual(result['status'], '200')
        self.assertEqual(result['body_bytes_sent'], '1234')
    
    def test_parse_invalid_log(self):
        """Test parsing an invalid log line"""
        log_line = 'invalid log line'
        result = self.parser.parse_line(log_line)
        
        self.assertIsNone(result)


class TestSecurityAnalyzer(unittest.TestCase):
    """Test security analysis"""
    
    def setUp(self):
        self.analyzer = SecurityAnalyzer()
    
    def test_sql_injection_detection(self):
        """Test SQL injection detection"""
        log_entry = {
            'path': "/admin.php?id=1' OR '1'='1",
            'http_user_agent': 'Mozilla/5.0',
            'status': '403',
            'body_bytes_sent': '532',
            'remote_addr': '192.168.1.1'
        }
        tags = self.analyzer.analyze(log_entry)
        
        self.assertIn(SecurityTags.SQL_INJECTION, tags)
        self.assertIn(SecurityTags.ERROR_4XX, tags)
    
    def test_xss_detection(self):
        """Test XSS detection"""
        log_entry = {
            'path': "/search?q=<script>alert('XSS')</script>",
            'http_user_agent': 'Mozilla/5.0',
            'status': '200',
            'body_bytes_sent': '2341',
            'remote_addr': '192.168.1.2'
        }
        tags = self.analyzer.analyze(log_entry)
        
        self.assertIn(SecurityTags.XSS, tags)
    
    def test_path_traversal_detection(self):
        """Test path traversal detection"""
        log_entry = {
            'path': '/../../etc/passwd',
            'http_user_agent': 'curl/7.68.0',
            'status': '404',
            'body_bytes_sent': '178',
            'remote_addr': '192.168.1.3'
        }
        tags = self.analyzer.analyze(log_entry)
        
        self.assertIn(SecurityTags.PATH_TRAVERSAL, tags)
        self.assertIn(SecurityTags.ERROR_4XX, tags)
    
    def test_shell_injection_detection(self):
        """Test shell injection detection"""
        log_entry = {
            'path': '/exec?cmd=ls;cat /etc/passwd',
            'http_user_agent': 'Mozilla/5.0',
            'status': '403',
            'body_bytes_sent': '178',
            'remote_addr': '192.168.1.4'
        }
        tags = self.analyzer.analyze(log_entry)
        
        self.assertIn(SecurityTags.SHELL_INJECTION, tags)
    
    def test_scanner_detection(self):
        """Test scanner detection"""
        log_entry = {
            'path': '/api/users',
            'http_user_agent': 'sqlmap/1.5.2',
            'status': '200',
            'body_bytes_sent': '45678',
            'remote_addr': '192.168.1.5'
        }
        tags = self.analyzer.analyze(log_entry)
        
        self.assertIn(SecurityTags.SCANNER, tags)
    
    def test_suspicious_user_agent(self):
        """Test suspicious user agent detection"""
        log_entry = {
            'path': '/login.php',
            'http_user_agent': '-',
            'status': '401',
            'body_bytes_sent': '234',
            'remote_addr': '192.168.1.6'
        }
        tags = self.analyzer.analyze(log_entry)
        
        self.assertIn(SecurityTags.SUSPICIOUS_USER_AGENT, tags)
        self.assertIn(SecurityTags.ERROR_4XX, tags)
    
    def test_normal_request(self):
        """Test that normal requests don't trigger tags"""
        log_entry = {
            'path': '/normal-page.html',
            'http_user_agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
            'status': '200',
            'body_bytes_sent': '3456',
            'remote_addr': '192.168.1.7'
        }
        tags = self.analyzer.analyze(log_entry)
        
        # Normal request should have no tags
        self.assertEqual(len(tags), 0)


if __name__ == '__main__':
    unittest.main()
