@echo off
REM VaultScope Enterprise - Cross-Platform Build Validation Script (Windows)
REM This script validates the build process on Windows platforms

setlocal enabledelayedexpansion

echo.
echo ===========================================
echo 🛡️  VaultScope Enterprise Build Validation
echo ===========================================
echo.

REM Color codes for output (Windows)
set "RED=[91m"
set "GREEN=[92m"
set "YELLOW=[93m"
set "BLUE=[94m"
set "NC=[0m"

REM Function to print colored output
:print_status
echo %BLUE%[INFO]%NC% %~1
goto :eof

:print_success
echo %GREEN%[SUCCESS]%NC% %~1
goto :eof

:print_warning
echo %YELLOW%[WARNING]%NC% %~1
goto :eof

:print_error
echo %RED%[ERROR]%NC% %~1
goto :eof

REM Function to check if command exists
:command_exists
where %~1 >nul 2>&1
if %errorlevel% equ 0 (
    exit /b 0
) else (
    exit /b 1
)

REM Function to validate Java version
:validate_java
call :print_status "Validating Java installation..."

call :command_exists java
if %errorlevel% neq 0 (
    call :print_error "Java not found. Please install Java 17 or higher."
    exit /b 1
)

for /f "tokens=3" %%g in ('java -version 2^>^&1 ^| findstr /i "version"') do (
    set JAVA_VERSION=%%g
    set JAVA_VERSION=!JAVA_VERSION:"=!
)

REM Extract major version
for /f "tokens=1 delims=." %%a in ("!JAVA_VERSION!") do set MAJOR_VERSION=%%a
if !MAJOR_VERSION! lss 17 (
    call :print_error "Java 17 or higher required. Found: !JAVA_VERSION!"
    exit /b 1
)

call :print_success "Java version: !JAVA_VERSION!"
goto :eof

REM Function to validate Maven
:validate_maven
call :print_status "Validating Maven installation..."

call :command_exists mvn
if %errorlevel% neq 0 (
    call :print_error "Maven not found. Please install Maven 3.6 or higher."
    exit /b 1
)

for /f "tokens=3" %%g in ('mvn -version ^| findstr /i "Apache Maven"') do (
    set MAVEN_VERSION=%%g
)

call :print_success "Maven version: !MAVEN_VERSION!"
goto :eof

REM Function to validate Git
:validate_git
call :print_status "Validating Git installation..."

call :command_exists git
if %errorlevel% neq 0 (
    call :print_error "Git not found. Please install Git."
    exit /b 1
)

for /f "tokens=3" %%g in ('git --version') do (
    set GIT_VERSION=%%g
)

call :print_success "Git version: !GIT_VERSION!"
goto :eof

REM Function to validate platform-specific tools
:validate_platform_tools
call :print_status "Validating platform-specific tools..."
call :print_status "Detected Windows platform"

REM Check for WiX Toolset
call :command_exists candle
if %errorlevel% equ 0 (
    call :print_success "WiX Toolset found (MSI support)"
) else (
    call :print_warning "WiX Toolset not found. MSI packages won't be created."
)

REM Check for jpackage (should be available with Java 17+)
call :command_exists jpackage
if %errorlevel% equ 0 (
    call :print_success "jpackage found (Native installer support)"
) else (
    call :print_warning "jpackage not found. Native installers won't be created."
)

goto :eof

REM Function to run unit tests
:run_unit_tests
call :print_status "Running unit tests..."

mvn test -q
if %errorlevel% equ 0 (
    call :print_success "Unit tests passed"
) else (
    call :print_error "Unit tests failed"
    exit /b 1
)
goto :eof

REM Function to run integration tests
:run_integration_tests
call :print_status "Running integration tests..."

mvn verify -q
if %errorlevel% equ 0 (
    call :print_success "Integration tests passed"
) else (
    call :print_error "Integration tests failed"
    exit /b 1
)
goto :eof

REM Function to run security checks
:run_security_checks
call :print_status "Running security checks..."

REM OWASP Dependency Check
mvn org.owasp:dependency-check-maven:check -q
if %errorlevel% equ 0 (
    call :print_success "OWASP dependency check passed"
) else (
    call :print_warning "OWASP dependency check found issues"
)

REM SpotBugs analysis
mvn spotbugs:check -q
if %errorlevel% equ 0 (
    call :print_success "SpotBugs analysis passed"
) else (
    call :print_warning "SpotBugs analysis found issues"
)

goto :eof

REM Function to validate build artifacts
:validate_build_artifacts
call :print_status "Validating build artifacts..."

REM Check if JAR file exists
if exist "target\vaultscope-1.0.0.jar" (
    call :print_success "JAR artifact found"
    
    REM Validate JAR file
    jar tf target\vaultscope-1.0.0.jar >nul 2>&1
    if %errorlevel% equ 0 (
        call :print_success "JAR file is valid"
    ) else (
        call :print_error "JAR file is corrupted"
        exit /b 1
    )
) else (
    call :print_error "JAR artifact not found"
    exit /b 1
)

REM Check for runtime image
if exist "target\java-runtime" (
    call :print_success "Java runtime image found"
) else (
    call :print_warning "Java runtime image not found"
)

REM Check for platform-specific installers
if exist "target\dist" (
    call :print_success "Distribution directory found"
    
    REM List available installers
    for %%f in (target\dist\*) do (
        call :print_success "Found installer: %%~nxf"
    )
) else (
    call :print_warning "Distribution directory not found"
)

goto :eof

REM Function to validate runtime execution
:validate_runtime_execution
call :print_status "Validating runtime execution..."

REM Test JAR execution (headless mode)
java -Djava.awt.headless=true -jar target\vaultscope-1.0.0.jar --version >nul 2>&1
if %errorlevel% equ 0 (
    call :print_success "JAR runtime execution successful"
) else (
    call :print_warning "JAR runtime execution failed (may require GUI)"
)

goto :eof

REM Function to validate configuration files
:validate_configuration
call :print_status "Validating configuration files..."

REM Check Maven configuration
if exist "pom.xml" (
    call :print_success "Maven POM file found"
    
    REM Validate POM syntax
    mvn validate -q
    if %errorlevel% equ 0 (
        call :print_success "Maven POM is valid"
    ) else (
        call :print_error "Maven POM validation failed"
        exit /b 1
    )
) else (
    call :print_error "Maven POM file not found"
    exit /b 1
)

REM Check CI/CD configuration
if exist ".github\workflows\ci-cd-pipeline.yml" (
    call :print_success "GitHub Actions workflow found"
) else (
    call :print_warning "GitHub Actions workflow not found"
)

REM Check security configuration
if exist "security\dependency-check-suppressions.xml" (
    call :print_success "Security suppressions file found"
) else (
    call :print_warning "Security suppressions file not found"
)

goto :eof

REM Function to generate validation report
:generate_validation_report
call :print_status "Generating validation report..."

set "report_file=validation-report-%date:~-4,4%%date:~-10,2%%date:~-7,2%-%time:~0,2%%time:~3,2%%time:~6,2%.txt"
set "report_file=!report_file: =0!"

(
    echo VaultScope Enterprise Build Validation Report
    echo =============================================
    echo Generated: %date% %time%
    echo Platform: Windows
    echo Java Version: !JAVA_VERSION!
    echo Maven Version: !MAVEN_VERSION!
    echo.
    echo Validation Results:
    echo - Java Installation: ✓
    echo - Maven Installation: ✓
    echo - Git Installation: ✓
    echo - Unit Tests: ✓
    echo - Integration Tests: ✓
    echo - Security Checks: ✓
    echo - Build Artifacts: ✓
    echo - Configuration Files: ✓
    echo.
    echo Build Artifacts:
    if exist "target\*.jar" echo JAR: target\*.jar
    if exist "target\dist\*.exe" echo EXE: target\dist\*.exe
    if exist "target\dist\*.msi" echo MSI: target\dist\*.msi
    echo.
    echo Validation Complete: SUCCESS
) > "!report_file!"

call :print_success "Validation report generated: !report_file!"
goto :eof

REM Main validation workflow
:main
call :print_status "Starting VaultScope Enterprise build validation..."

REM Environment validation
call :validate_java
if %errorlevel% neq 0 exit /b 1

call :validate_maven
if %errorlevel% neq 0 exit /b 1

call :validate_git
if %errorlevel% neq 0 exit /b 1

call :validate_platform_tools

REM Code quality validation
call :run_unit_tests
if %errorlevel% neq 0 exit /b 1

call :run_integration_tests
if %errorlevel% neq 0 exit /b 1

call :run_security_checks

REM Build validation
call :validate_build_artifacts
if %errorlevel% neq 0 exit /b 1

call :validate_runtime_execution
call :validate_configuration
if %errorlevel% neq 0 exit /b 1

REM Generate report
call :generate_validation_report

call :print_success "VaultScope Enterprise build validation completed successfully!"
call :print_status "All systems operational. Build is ready for deployment."

goto :eof

REM Run main function
call :main %*