# VaultScope

**Enterprise-grade Localhost API Security Assessment Tool**

VaultScope is a comprehensive JavaFX-based desktop application designed to perform active security testing on REST APIs hosted strictly on localhost environments. The tool executes real security probes, generates detailed vulnerability reports, and provides security scoring to help developers identify and remediate potential security issues.

## 🛡️ Features

### Core Security Testing
- **SQL Injection Detection** - Tests for various SQL injection vectors including time-based and error-based
- **NoSQL Injection Detection** - MongoDB and other NoSQL database injection tests
- **Path Traversal Testing** - Directory traversal and file access vulnerabilities
- **Cross-Site Scripting (XSS)** - Reflected XSS vulnerability detection
- **XML External Entity (XXE)** - XML parser security testing
- **HTTP Method Override** - Dangerous HTTP method exposure testing
- **Header Injection** - HTTP header manipulation vulnerability testing
- **Authentication Bypass** - Tests for authentication and authorization flaws
- **Rate Limiting Assessment** - Brute force protection evaluation

### Security Reporting
- **Real-time Vulnerability Dashboard** - Live display of discovered vulnerabilities with severity ratings
- **Security Score Calculation** - Numerical scoring (0-100) with letter grades (A-F)
- **Detailed Vulnerability Analysis** - Comprehensive details with remediation guidance
- **JSON Export** - Machine-readable reports for integration with other tools
- **HTML Export** - Professional styled reports for documentation and stakeholder communication

### User Experience
- **Modern JavaFX Interface** - Clean, intuitive desktop application inspired by modern documentation sites
- **Light/Dark Theme Support** - Customizable appearance for user preference
- **Real-time Traffic Monitoring** - Live HTTP request/response logging during scans
- **Progress Tracking** - Visual scan progress indicators with status updates
- **Localhost-only Security** - Strict validation to prevent external scanning for ethical use

## 📋 Requirements

- **Java 17 or newer** (OpenJDK or Oracle JDK)
- **Maven 3.6+** (for building from source)
- **Windows or Linux** (macOS not supported)
- **Target APIs must be hosted on localhost or 127.0.0.1**

## 🚀 Installation

### Pre-built Binaries
Download the appropriate installer from the releases section:
- **Windows**: `VaultScope-1.0.0.exe` or `VaultScope-1.0.0.msi`
- **Linux**: `VaultScope-1.0.0.deb`

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

The build process will create:
- Executable JAR files in `target/`
- Platform-specific installers in `target/dist/`
- Runtime images for standalone execution

## 📖 Usage

### Quick Start
1. **Launch VaultScope** - Start the application using the installed executable or JAR file
2. **Enter Target URL** - Input localhost URL in the sidebar (e.g., `localhost:8080`, `127.0.0.1:3000`)
3. **Start Security Scan** - Click "🔍 Start Security Scan" to begin comprehensive assessment
4. **Review Results** - Analyze vulnerabilities in the dashboard with detailed explanations
5. **Export Reports** - Generate JSON or HTML reports for documentation and tracking

### Supported URL Formats
VaultScope strictly validates URLs to ensure only localhost testing:
- `localhost`
- `localhost:8080`
- `127.0.0.1`
- `127.0.0.1:3000`
- `http://localhost:8080/api`
- `https://127.0.0.1:443`

Any non-localhost URLs will be rejected to prevent accidental external scanning.

### Running from JAR
```bash
java -jar target/vaultscope-1.0.0.jar
```

### Running with Runtime Image
```bash
# Windows
target\java-runtime\bin\vaultscope.exe

# Linux
target/java-runtime/bin/vaultscope
```

## 🔍 Security Testing Details

VaultScope performs **active security testing** by sending real HTTP requests with security payloads to the target API. The tool analyzes responses for:

- **Error messages** indicating vulnerabilities or information disclosure
- **Response timing anomalies** suggesting time-based injection attacks
- **Status code patterns** revealing unauthorized access or errors
- **Content analysis** for sensitive information disclosure
- **Authentication and authorization bypass** indicators

### Test Categories
1. **Information Disclosure** - Server headers, error details, technology stack exposure
2. **Injection Attacks** - SQL, NoSQL, XML, and command injection vulnerabilities
3. **Access Control** - Authentication bypass, privilege escalation, method override
4. **Input Validation** - XSS, path traversal, header injection
5. **Security Headers** - Missing protective headers and configurations
6. **Rate Limiting** - Brute force protection and DoS prevention

## 📊 Report Formats

### JSON Reports
Structured data format containing:
- Scan metadata (timestamp, target URL, duration)
- Vulnerability list with complete details and severity ratings
- Security score calculation with breakdown
- Technical details including payloads and response information

### HTML Reports
Professional styled reports featuring:
- Executive summary with vulnerability counts and security score
- Detailed vulnerability descriptions with technical information
- Remediation recommendations for each finding
- Professional formatting suitable for stakeholder communication
- Responsive design for viewing on various devices

## ⚠️ Limitations & Ethical Use

- **Localhost Only** - Application strictly validates URLs to prevent external scanning
- **No Simulation** - Performs real active testing, not simulated assessments
- **Windows/Linux Only** - macOS packaging not supported in current version
- **Manual Configuration** - Requires manual configuration of target endpoints
- **Ethical Use Required** - Only use on systems you own or have explicit permission to test

## 🔧 Technical Architecture

### Technology Stack
- **Frontend**: JavaFX 21 with FXML and CSS styling
- **HTTP Client**: Apache HttpComponents Client 5.x
- **JSON Processing**: Jackson 2.15.x with Java Time module
- **Build System**: Maven with shade and jpackage plugins
- **Packaging**: jlink runtime images and platform-specific installers

### Project Structure
```
vaultscope/
├── src/main/java/dev/cptcr/vaultscope/
│   ├── VaultScopeApplication.java          # Main application entry point
│   ├── controller/MainController.java      # JavaFX controller
│   ├── model/                              # Data models
│   │   ├── SecurityResult.java
│   │   └── Vulnerability.java
│   └── service/                            # Business logic
│       ├── SecurityScanner.java            # Core scanning engine
│       ├── ReportService.java              # Report generation
│       └── UrlValidator.java               # URL validation
├── src/main/resources/
│   ├── fxml/main-view.fxml                 # UI layout
│   └── css/                                # Styling
│       ├── styles.css                      # Light theme
│       └── dark-theme.css                  # Dark theme
├── build.bat                               # Windows build script
├── build.sh                                # Linux build script
└── pom.xml                                 # Maven configuration
```

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests for any improvements.

### Development Setup
1. Clone the repository
2. Ensure Java 17+ and Maven 3.6+ are installed
3. Run `mvn compile` to verify setup
4. Use your preferred IDE with JavaFX support

### Code Style
- Follow existing code formatting and naming conventions
- Write clear, self-documenting code without excessive comments
- Ensure all new features include appropriate error handling
- Test thoroughly on both Windows and Linux platforms

## 📄 License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE) file for details.

## 👤 Author

**CPTCR**
- Website: [https://cptcr.dev](https://cptcr.dev)
- GitHub: [https://github.com/cptcr](https://github.com/cptcr)

## 🚨 Disclaimer

VaultScope is designed for legitimate security testing of your own applications hosted on localhost. Users are responsible for ensuring they have proper authorization before testing any systems. The authors are not responsible for any misuse of this tool.

**Use Responsibly:**
- Only test systems you own or have explicit written permission to test
- Follow responsible disclosure practices for any vulnerabilities found
- Comply with all applicable laws and regulations
- Do not use for malicious purposes or unauthorized testing

## 📚 Documentation

For detailed documentation, tutorials, and best practices, visit:
- [Official Documentation](https://cptcr.dev/vaultscope)
- [Security Testing Guide](https://cptcr.dev/vaultscope/guide)
- [API Reference](https://cptcr.dev/vaultscope/api)

## 🐛 Support & Issues

If you encounter any issues or have feature requests:
1. Check existing [GitHub Issues](https://github.com/cptcr/vaultscope/issues)
2. Create a new issue with detailed information
3. Include system information, error messages, and steps to reproduce

## 🔄 Changelog

### Version 1.0.0
- Initial release with comprehensive security testing capabilities
- JavaFX-based user interface with light/dark themes
- Support for SQL injection, XSS, path traversal, and other common vulnerabilities
- JSON and HTML report generation
- Windows and Linux installer packages
- Localhost-only URL validation for ethical use

---

*Built with ❤️ for the cybersecurity community*