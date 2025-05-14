# GoXSScanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Report Card](https://goreportcard.com/badge/github.com/yourusername/goxssscanner)](https://goreportcard.com/report/github.com/yourusername/goxssscanner)

GoXSScanner is a high-performance tool for detecting reflected cross-site scripting (XSS) vulnerabilities in web applications. Written in Go, this scanner offers a combination of speed, accuracy, and flexibility for security professionals and penetration testers.

![GoXSScanner](https://github.com/vijay922/XSS-Scanner/blob/main/Logo.png?raw=true)

<img src="https://github.com/vijay922/XSS-Scanner/blob/main/Logo.png?raw=true" alt="GoXSScanner" width="600"/>


## Features

### Detection & Innovation
- **Zero False Positives**: Advanced detection algorithms minimize false positives
- **Multiple Detection Modes**: GET, POST, and header-based XSS detection
- **DOM-Based XSS Detection**: Identifies DOM-based vulnerabilities
- **Path-Based Analysis**: Checks URL paths for potential injection points
- **JSON Web App Support**: Handles modern JSON-based applications
- **Reflection Checker**: Precisely identifies payload reflections

### Scanning & Efficiency
- **High Performance**: Scans thousands of payloads in seconds
- **Multi-threading**: Configurable concurrent threads for faster scanning
- **Stealth Mode**: Three levels (low, medium, high) to evade WAFs and security filters
- **Customizable Delay**: Control request timing to avoid detection
- **Form Detection**: Automatically finds and tests HTML forms

### Configuration & Customization
- **Customizable Payloads**: Use the built-in library or your own payload list
- **Easy Configuration**: Simple command-line interface
- **Result Filtering**: One-result option to stop after first finding
- **Configurable Output**: Save results to file in markdown format

### Security & Reliability
- **WAF Bypass**: Stealth mode helps bypass Web Application Firewalls
- **Cookie Support**: Maintain session state during scanning
- **Custom User-Agent**: Specify any user agent string
- **Timeout Control**: Set request timeouts to handle slow servers

## Installation

### Prerequisites
- Go 1.18 or higher

### Install from source
```bash
# Clone the repository
git clone https://github.com/vijay922/XSS-Scanner.git
cd goxssscanner

# Build the binary
go build -o goxssscanner xss_scanner.go

# Make it executable (Linux/macOS)
chmod +x goxssscanner
```

## Usage

### Basic Usage
```bash
./goxssscanner -url https://example.com/page?param=value
```

### Advanced Options
```bash
./goxssscanner -url https://example.com/page?param=value \
  -threads 20 \
  -stealth high \
  -payloads custom_payloads.txt \
  -output results.txt \
  -check-headers \
  -verbose
```

### All Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-url` | Target URL to scan (required) | - |
| `-threads` | Number of concurrent threads | 10 |
| `-delay` | Delay between requests in milliseconds | 0 |
| `-timeout` | HTTP request timeout in seconds | 10 |
| `-user-agent` | Custom User-Agent string | Mozilla/5.0... |
| `-cookies` | Cookies to include with requests | - |
| `-payloads` | File containing custom XSS payloads | - |
| `-output` | Output file to save results | - |
| `-stealth` | Stealth mode level (low, medium, high) | medium |
| `-verbose` | Enable verbose output | false |
| `-form-only` | Only scan forms | false |
| `-check-headers` | Check headers for XSS | true |
| `-one-result` | Stop after finding first vulnerability | false |

## Examples

### Scan a Simple Query Parameter
```bash
./goxssscanner -url "http://testfire.net/search.jsp?query=test"
```

### Scan with Custom Payloads and Save Results
```bash
./goxssscanner -url "https://vulnerable-site.com/page?id=1" \
  -payloads my_payloads.txt \
  -output scan_results.md
```

### Stealth Mode for WAF Evasion
```bash
./goxssscanner -url "https://secured-site.com/search?q=test" \
  -stealth high \
  -delay 500
```

### Using Cookies for Authenticated Scanning
```bash
./goxssscanner -url "https://app.example.com/dashboard" \
  -cookies "session=abc123; auth=xyz789"
```

## Sample Output

```
[+] XSS Scanner starting with 25 payloads
[+] Target: http://testfire.net/search.jsp?query=test
[+] Threads: 10
[+] Stealth Mode: medium
[*] Testing parameter: query
[!] Potential XSS found in parameter 'query' with payload: <script>alert('XSS')</script>
[!] Potential XSS found in parameter 'query' with payload: <img src=x onerror=alert('XSS')>

[+] Found 2 potential XSS vulnerabilities:
[1] http://testfire.net/search.jsp?query=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E
    Parameter: query
    Payload: <script>alert('XSS')</script>
    Type: GET

[2] http://testfire.net/search.jsp?query=%3Cimg+src%3Dx+onerror%3Dalert%28%27XSS%27%29%3E
    Parameter: query
    Payload: <img src=x onerror=alert('XSS')>
    Type: GET
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Security Considerations

This tool is designed for legitimate security testing with proper authorization. Always ensure you have permission to test the target systems. Unauthorized testing of systems may be illegal and unethical.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

- This tool was inspired by various open-source XSS scanners and security testing frameworks
- Special thanks to the Go community for providing excellent networking libraries

## Disclaimer

This tool is provided for educational and professional security testing purposes only. The authors are not responsible for any misuse or damage caused by this program. Use responsibly.
