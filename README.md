# Nginx Access Log Security Analyzer

A Python-based security log analyzer that parses nginx access logs and identifies potential security threats by tagging suspicious patterns and behaviors.

## Features

- **SQL Injection Detection**: Identifies SQL injection attempts in URLs
- **XSS Detection**: Detects Cross-Site Scripting patterns
- **Path Traversal Detection**: Finds directory traversal attempts
- **Shell Injection Detection**: Identifies command injection patterns
- **Brute Force Detection**: Detects multiple failed login attempts from the same IP
- **Scanner Detection**: Identifies security scanning tools and bots
- **Suspicious User Agents**: Flags requests with missing or suspicious user agents
- **HTTP Error Tracking**: Tags 4xx and 5xx errors
- **Large Payload Detection**: Identifies unusually large responses

## Security Tags

The analyzer categorizes threats with the following tags:

- `SQL_INJECTION`: SQL injection attempts detected in URL parameters
- `XSS`: Cross-Site Scripting patterns found
- `PATH_TRAVERSAL`: Directory traversal attempts (../, etc.)
- `SHELL_INJECTION`: Command injection patterns
- `BRUTE_FORCE`: Multiple failed authentication attempts from same IP
- `SCANNER`: Known security scanner or bot detected
- `SUSPICIOUS_USER_AGENT`: Missing or suspicious user agent string
- `ERROR_4XX`: Client errors (400-499)
- `ERROR_5XX`: Server errors (500-599)
- `LARGE_PAYLOAD`: Response size exceeds 1MB

## Installation

No external dependencies required. Uses Python 3.6+ standard library only.

```bash
git clone https://github.com/byVER/log-analyzer.git
cd log-analyzer
```

## Usage

Basic usage:

```bash
python3 log_analyzer.py /path/to/nginx/access.log
```

With verbose output:

```bash
python3 log_analyzer.py -v /var/log/nginx/access.log
```

Using the example log file:

```bash
python3 log_analyzer.py example_access.log
```

## Example Output

```
================================================================================
SECURITY LOG ANALYSIS REPORT
================================================================================

Total security events detected: 15

Threat Summary:
--------------------------------------------------------------------------------
  ERROR_4XX                     :    14
  SUSPICIOUS_USER_AGENT         :    12
  SQL_INJECTION                 :     1
  XSS                           :     1
  PATH_TRAVERSAL                :     2
  SHELL_INJECTION               :     1
  BRUTE_FORCE                   :     3
  SCANNER                       :     2
  ERROR_5XX                     :     1

================================================================================
Detailed Events:
================================================================================

Time: 30/Oct/2025:10:15:24 +0000
IP: 192.168.1.101
Request: GET /admin.php?id=1' OR '1'='1
Status: 403
User-Agent: Mozilla/5.0 (X11; Linux x86_64)
Tags: SQL_INJECTION, ERROR_4XX
--------------------------------------------------------------------------------
[Additional events...]
```

## Log Format Support

The analyzer supports the standard nginx combined log format:

```
$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
```

Example:
```
192.168.1.1 - - [30/Oct/2025:10:15:23 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

See LICENSE file for details.