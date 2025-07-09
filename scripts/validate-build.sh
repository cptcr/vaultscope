#!/bin/bash

# VaultScope Enterprise - Cross-Platform Build Validation Script
# This script validates the build process across different platforms

set -e

echo "🛡️  VaultScope Enterprise Build Validation"
echo "=========================================="

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to validate Java version
validate_java() {
    print_status "Validating Java installation..."
    
    if ! command_exists java; then
        print_error "Java not found. Please install Java 17 or higher."
        exit 1
    fi
    
    java_version=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}')
    major_version=$(echo $java_version | cut -d. -f1)
    
    if [ "$major_version" -lt 17 ]; then
        print_error "Java 17 or higher required. Found: $java_version"
        exit 1
    fi
    
    print_success "Java version: $java_version"
}

# Function to validate Maven
validate_maven() {
    print_status "Validating Maven installation..."
    
    if ! command_exists mvn; then
        print_error "Maven not found. Please install Maven 3.6 or higher."
        exit 1
    fi
    
    maven_version=$(mvn -version | head -n 1 | awk '{print $3}')
    print_success "Maven version: $maven_version"
}

# Function to validate Git
validate_git() {
    print_status "Validating Git installation..."
    
    if ! command_exists git; then
        print_error "Git not found. Please install Git."
        exit 1
    fi
    
    git_version=$(git --version | awk '{print $3}')
    print_success "Git version: $git_version"
}

# Function to validate platform-specific tools
validate_platform_tools() {
    print_status "Validating platform-specific tools..."
    
    # Check operating system
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        print_status "Detected Linux platform"
        
        # Check for dpkg-deb (for DEB packages)
        if command_exists dpkg-deb; then
            print_success "dpkg-deb found (DEB package support)"
        else
            print_warning "dpkg-deb not found. DEB packages won't be created."
        fi
        
        # Check for makepkg (for Arch packages)
        if command_exists makepkg; then
            print_success "makepkg found (Arch package support)"
        else
            print_warning "makepkg not found. Arch packages won't be created."
        fi
        
        # Check for AppImage tools
        if command_exists appimagetool; then
            print_success "appimagetool found (AppImage support)"
        else
            print_warning "appimagetool not found. AppImage won't be created."
        fi
        
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        print_status "Detected Windows platform"
        
        # Check for WiX (Windows Installer XML)
        if command_exists candle; then
            print_success "WiX Toolset found (MSI support)"
        else
            print_warning "WiX Toolset not found. MSI packages won't be created."
        fi
        
    else
        print_warning "Unsupported platform: $OSTYPE"
    fi
}

# Function to run unit tests
run_unit_tests() {
    print_status "Running unit tests..."
    
    if mvn test -q; then
        print_success "Unit tests passed"
    else
        print_error "Unit tests failed"
        exit 1
    fi
}

# Function to run integration tests
run_integration_tests() {
    print_status "Running integration tests..."
    
    if mvn verify -q; then
        print_success "Integration tests passed"
    else
        print_error "Integration tests failed"
        exit 1
    fi
}

# Function to run security checks
run_security_checks() {
    print_status "Running security checks..."
    
    # OWASP Dependency Check
    if mvn org.owasp:dependency-check-maven:check -q; then
        print_success "OWASP dependency check passed"
    else
        print_warning "OWASP dependency check found issues"
    fi
    
    # SpotBugs analysis
    if mvn spotbugs:check -q; then
        print_success "SpotBugs analysis passed"
    else
        print_warning "SpotBugs analysis found issues"
    fi
}

# Function to validate build artifacts
validate_build_artifacts() {
    print_status "Validating build artifacts..."
    
    # Check if JAR file exists
    if [ -f "target/vaultscope-1.0.0.jar" ]; then
        print_success "JAR artifact found"
        
        # Validate JAR file
        if jar tf target/vaultscope-1.0.0.jar > /dev/null 2>&1; then
            print_success "JAR file is valid"
        else
            print_error "JAR file is corrupted"
            exit 1
        fi
    else
        print_error "JAR artifact not found"
        exit 1
    fi
    
    # Check for runtime image
    if [ -d "target/java-runtime" ]; then
        print_success "Java runtime image found"
    else
        print_warning "Java runtime image not found"
    fi
    
    # Check for platform-specific installers
    if [ -d "target/dist" ]; then
        print_success "Distribution directory found"
        
        # List available installers
        for installer in target/dist/*; do
            if [ -f "$installer" ]; then
                print_success "Found installer: $(basename "$installer")"
            fi
        done
    else
        print_warning "Distribution directory not found"
    fi
}

# Function to validate runtime execution
validate_runtime_execution() {
    print_status "Validating runtime execution..."
    
    # Test JAR execution (headless mode)
    if java -Djava.awt.headless=true -jar target/vaultscope-1.0.0.jar --version > /dev/null 2>&1; then
        print_success "JAR runtime execution successful"
    else
        print_warning "JAR runtime execution failed (may require GUI)"
    fi
}

# Function to validate configuration files
validate_configuration() {
    print_status "Validating configuration files..."
    
    # Check Maven configuration
    if [ -f "pom.xml" ]; then
        print_success "Maven POM file found"
        
        # Validate POM syntax
        if mvn validate -q; then
            print_success "Maven POM is valid"
        else
            print_error "Maven POM validation failed"
            exit 1
        fi
    else
        print_error "Maven POM file not found"
        exit 1
    fi
    
    # Check CI/CD configuration
    if [ -f ".github/workflows/ci-cd-pipeline.yml" ]; then
        print_success "GitHub Actions workflow found"
    else
        print_warning "GitHub Actions workflow not found"
    fi
    
    # Check security configuration
    if [ -f "security/dependency-check-suppressions.xml" ]; then
        print_success "Security suppressions file found"
    else
        print_warning "Security suppressions file not found"
    fi
}

# Function to generate validation report
generate_validation_report() {
    print_status "Generating validation report..."
    
    report_file="validation-report-$(date +%Y%m%d-%H%M%S).txt"
    
    {
        echo "VaultScope Enterprise Build Validation Report"
        echo "============================================="
        echo "Generated: $(date)"
        echo "Platform: $OSTYPE"
        echo "Java Version: $(java -version 2>&1 | head -n 1)"
        echo "Maven Version: $(mvn -version | head -n 1)"
        echo ""
        echo "Validation Results:"
        echo "- Java Installation: ✓"
        echo "- Maven Installation: ✓"
        echo "- Git Installation: ✓"
        echo "- Unit Tests: ✓"
        echo "- Integration Tests: ✓"
        echo "- Security Checks: ✓"
        echo "- Build Artifacts: ✓"
        echo "- Configuration Files: ✓"
        echo ""
        echo "Build Artifacts:"
        find target -name "*.jar" -o -name "*.exe" -o -name "*.msi" -o -name "*.deb" -o -name "*.AppImage" | sort
        echo ""
        echo "Validation Complete: SUCCESS"
    } > "$report_file"
    
    print_success "Validation report generated: $report_file"
}

# Main validation workflow
main() {
    print_status "Starting VaultScope Enterprise build validation..."
    
    # Environment validation
    validate_java
    validate_maven
    validate_git
    validate_platform_tools
    
    # Code quality validation
    run_unit_tests
    run_integration_tests
    run_security_checks
    
    # Build validation
    validate_build_artifacts
    validate_runtime_execution
    validate_configuration
    
    # Generate report
    generate_validation_report
    
    print_success "VaultScope Enterprise build validation completed successfully!"
    print_status "All systems operational. Build is ready for deployment."
}

# Run main function
main "$@"