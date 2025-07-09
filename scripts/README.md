# VaultScope Enterprise - Cross-Platform Testing Suite

## 🛡️ Overview

This directory contains comprehensive testing scripts and configuration for VaultScope Enterprise cross-platform validation. The testing suite ensures compatibility, security, and quality across all supported platforms.

## 📁 Files

### Core Testing Scripts

- **`validate-build.sh`** - Linux/Unix build validation script
- **`validate-build.bat`** - Windows build validation script  
- **`cross-platform-test.py`** - Python-based comprehensive test orchestrator
- **`test-config.json`** - Comprehensive testing configuration

### Usage

#### Linux/Unix Validation
```bash
# Make script executable
chmod +x validate-build.sh

# Run validation
./validate-build.sh

# Output: validation-report-YYYYMMDD-HHMMSS.txt
```

#### Windows Validation
```cmd
# Run validation
validate-build.bat

# Output: validation-report-YYYYMMDD-HHMMSS.txt
```

#### Python Test Suite
```bash
# Install Python dependencies (if needed)
pip install -r requirements.txt

# Run comprehensive tests
python cross-platform-test.py

# Output: test_report_YYYYMMDD_HHMMSS.json
```

## 🧪 Test Categories

### 1. Environment Setup Tests
- **Java Version Check** - Validates Java 17+ installation
- **Maven Installation** - Confirms Maven 3.6+ availability
- **Git Availability** - Checks Git installation
- **Platform Tools** - Validates platform-specific packaging tools

### 2. Build Process Tests
- **Maven Compile** - Tests compilation process
- **Maven Package** - Validates JAR packaging
- **Dependency Resolution** - Checks dependency management
- **Resource Processing** - Validates resource handling

### 3. Unit Test Suite
- **Core Functionality** - Tests primary application logic
- **Security Validation** - Validates security components
- **UI Components** - Tests JavaFX components
- **Utility Classes** - Validates utility functions

### 4. Integration Test Suite
- **End-to-End Scanning** - Full security scan workflow
- **Report Generation** - Tests report creation
- **Database Operations** - Validates SQLite integration
- **File System Operations** - Tests file handling

### 5. Security Analysis
- **Dependency Vulnerabilities** - OWASP dependency checking
- **Static Code Analysis** - SpotBugs security analysis
- **Security Patterns** - Validates security implementations
- **Input Validation** - Tests input sanitization

### 6. Artifact Validation
- **JAR Validation** - Validates executable JAR
- **Runtime Image** - Tests jlink runtime creation
- **Native Installers** - Validates platform installers
- **Checksums** - Verifies artifact integrity

### 7. Runtime Execution Tests
- **Application Startup** - Tests application launch
- **Basic Functionality** - Validates core features
- **Error Handling** - Tests error scenarios
- **Graceful Shutdown** - Validates cleanup

## 🎯 Quality Gates

### Code Coverage
- **Minimum**: 80%
- **Target**: 90%

### Security Vulnerabilities
- **Critical**: 0 allowed
- **High**: 0 allowed
- **Medium**: 5 maximum
- **Low**: 20 maximum

### Performance Thresholds
- **Startup Time**: < 10 seconds
- **Memory Usage**: < 256MB initial
- **Scan Duration**: < 300 seconds

## 🔧 Configuration

### Environment Variables

#### Test Environment
```bash
export JAVA_OPTS="-Xmx512m -Djava.awt.headless=true"
export MAVEN_OPTS="-Xmx256m"
export VAULTSCOPE_TEST_MODE="true"
export VAULTSCOPE_LOG_LEVEL="DEBUG"
```

#### Production Environment
```bash
export JAVA_OPTS="-Xmx1g"
export MAVEN_OPTS="-Xmx512m"
export VAULTSCOPE_LOG_LEVEL="INFO"
```

### Test Data
- **Sample APIs**: Test endpoints for validation
- **Expected Vulnerabilities**: Known security issues for testing
- **Test Payloads**: Security testing payloads

## 📊 Reporting

### Report Formats
- **JSON**: Machine-readable test results
- **HTML**: Human-readable test reports
- **JUnit**: CI/CD integration format

### Report Contents
- **Test Results**: Pass/fail status for each test
- **Performance Metrics**: Duration and resource usage
- **Security Findings**: Vulnerability analysis
- **Platform Information**: Environment details
- **Artifact Analysis**: Build output validation

## 🚀 CI/CD Integration

### GitHub Actions
The testing suite integrates with GitHub Actions for automated testing:

```yaml
- name: Run Cross-Platform Tests
  run: |
    chmod +x scripts/validate-build.sh
    ./scripts/validate-build.sh
    python scripts/cross-platform-test.py
```

### Jenkins Integration
```groovy
stage('Cross-Platform Testing') {
    parallel {
        stage('Linux') {
            steps {
                sh 'scripts/validate-build.sh'
            }
        }
        stage('Windows') {
            steps {
                bat 'scripts/validate-build.bat'
            }
        }
        stage('Python Suite') {
            steps {
                sh 'python scripts/cross-platform-test.py'
            }
        }
    }
}
```

## 🔍 Troubleshooting

### Common Issues

#### Java Version Issues
```bash
# Check Java version
java -version

# Install Java 17+
sudo apt install openjdk-17-jdk  # Ubuntu/Debian
sudo yum install java-17-openjdk  # RHEL/CentOS
```

#### Maven Issues
```bash
# Check Maven version
mvn -version

# Install Maven
sudo apt install maven  # Ubuntu/Debian
sudo yum install maven  # RHEL/CentOS
```

#### Platform-Specific Tools
```bash
# Linux - Install packaging tools
sudo apt install dpkg-dev  # DEB packages
sudo pacman -S base-devel  # Arch packages

# Windows - Install WiX Toolset
# Download from: https://wixtoolset.org/
```

### Log Analysis
- **Test Logs**: Available in `test-reports/` directory
- **Application Logs**: Located in `~/.vaultscope/logs/`
- **Build Logs**: Maven output in `target/` directory

## 🔐 Security Considerations

### Test Security
- All tests run in isolated environments
- No external network access required
- Localhost-only testing enforced
- Test data sanitization

### Sensitive Data
- No real credentials in test data
- Mock authentication for testing
- Encrypted test configurations
- Secure artifact handling

## 🤝 Contributing

### Adding New Tests
1. Create test in appropriate category
2. Update `test-config.json` configuration
3. Add documentation to this README
4. Ensure cross-platform compatibility

### Test Guidelines
- **Isolation**: Tests should not depend on each other
- **Repeatability**: Tests should produce consistent results
- **Coverage**: Aim for comprehensive test coverage
- **Performance**: Keep test execution time reasonable

## 📞 Support

For testing issues or questions:
- **GitHub Issues**: Report test failures and improvements
- **Documentation**: Comprehensive testing documentation
- **Community**: Discord server for real-time support

---

*VaultScope Enterprise Testing Suite - Built for reliability and security*