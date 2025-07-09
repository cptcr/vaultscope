# VaultScope

**Enterprise-grade Localhost API Security Assessment Tool**

VaultScope is a comprehensive JavaFX-based desktop application designed to perform active security testing on REST APIs hosted strictly on localhost environments. The tool executes real security probes, generates detailed vulnerability reports, and provides security scoring to help developers identify and remediate potential security issues.

## Features

### Core Security Testing
- **SQL Injection Detection** - Tests for various SQL injection vectors
- **NoSQL Injection Detection** - MongoDB and other NoSQL database injection tests
- **Path Traversal Testing** - Directory traversal and file access vulnerabilities
- **Cross-Site Scripting (XSS)** - Reflected XSS vulnerability detection
- **XML External Entity (XXE)** - XML parser security testing
- **HTTP Method Override** - Dangerous HTTP method exposure testing
- **Header Injection** - HTTP header manipulation vulnerability testing
- **Authentication Bypass** - Tests for authentication and authorization flaws
- **Rate Limiting Assessment** - Brute force protection evaluation

### Security Reporting
- **Real-time Vulnerability Dashboard** - Live display of discovered vulnerabilities
- **Security Score Calculation** - Numerical scoring with letter grades (A-F)
- **Detailed Vulnerability Analysis** - Comprehensive details with remediation guidance
- **JSON Export** - Machine-readable reports for integration
- **HTML Export** - Professional styled reports for documentation

### User Experience
- **Modern JavaFX Interface** - Clean, intuitive desktop application
- **Light/Dark Theme Support** - Customizable appearance
- **Real-time Traffic Monitoring** - Live HTTP request/response logging
- **Progress Tracking** - Visual scan progress indicators
- **Localhost-only Security** - Strict validation to prevent external scanning

## Requirements

- **Java 17 or newer**
- **Maven 3.6+** (for building)
- **Windows or Linux** (macOS not supported)
- **Target APIs must be hosted on localhost or 127.0.0.1**

## Installation

### Pre-built Binaries
Download the appropriate installer from the releases section:
- Windows: `VaultScope-1.0.0.exe` or `VaultScope-1.0.0.msi`
- Linux: `VaultScope-1.0.0.deb`

### Building from Source

#### Windows
```cmd
git clone https://github.com/cptcr/vaultscope.git
cd vaultscope
build.bat
```

#### Linux
```bash
git clone https://github.com/cptcr/vaultscope.git
cd vaultscope
chmod +x build.sh
./build.sh
```

## Usage

1. **Launch VaultScope** - Start the application using the installed executable
2. **Enter Target URL** - Input localhost URL (e.g., `localhost:8080`, `127.0.0.1:3000`)
3. **Start Security Scan** - Click "Start Security Scan" to begin assessment
4. **Review Results** - Analyze vulnerabilities in the dashboard
5. **Export Reports** - Generate JSON or HTML reports for documentation

### Supported URL Formats
- `localhost`
- `localhost:8080`
- `127.0.0.1`
- `127.0.0.1:3000`
- `http://localhost:8080/api`
- `https://127.0.0.1:443`

## Security Testing Details

VaultScope performs **active security testing** by sending real HTTP requests with security payloads to the target API. The tool analyzes responses for:

- Error messages indicating vulnerabilities
- Response timing anomalies
- Status code patterns
- Content analysis for sensitive information disclosure
- Authentication and authorization bypass indicators

## Report Format

### JSON Reports
Structured data format containing:
- Scan metadata (timestamp, target URL)
- Vulnerability list with severity ratings
- Security score calculation
- Detailed findings with remediation advice

### HTML Reports
Professional styled reports featuring:
- Executive summary with vulnerability counts
- Security score visualization
- Detailed vulnerability descriptions
- Remediation recommendations
- Professional formatting for stakeholder communication

## Limitations

- **Localhost Only** - Application strictly validates URLs to prevent external scanning
- **No Simulation** - Performs real active testing, not simulated assessments
- **Windows/Linux Only** - macOS packaging not supported
- **Manual Testing** - Requires manual configuration of target endpoints

## License

Licensed under the Apache License 2.0. See LICENSE file for details.

## Author

**CPTCR**
- Website: [https://cptcr.dev](https://cptcr.dev)
- GitHub: [https://github.com/cptcr](https://github.com/cptcr)

## Contributing

Contributions are welcome! Please read the contributing guidelines and submit pull requests for any improvements.

## Disclaimer

VaultScope is designed for legitimate security testing of your own applications hosted on localhost. Users are responsible for ensuring they have proper authorization before testing any systems. The authors are not responsible for any misuse of this tool.