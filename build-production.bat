@echo off
REM VaultScope Production Build Script for Windows
REM This script builds production-ready installers for VaultScope

echo 🚀 Starting VaultScope Production Build
echo ======================================

REM Check if Maven is installed
where mvn >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Maven is not installed. Please install Maven first.
    exit /b 1
)

REM Check if Java 17+ is available
for /f "tokens=3" %%i in ('java -version 2^>^&1 ^| findstr /i "version"') do set java_version=%%i
set java_version=%java_version:"=%
for /f "tokens=1 delims=." %%i in ("%java_version%") do set java_major=%%i
if %java_major% lss 17 (
    echo ❌ Java 17 or later is required. Current version: %java_version%
    exit /b 1
)

echo ✅ Java %java_version% detected
for /f "tokens=3" %%i in ('mvn -version ^| findstr /i "Apache Maven"') do echo ✅ Maven %%i detected

REM Clean previous builds
echo 🧹 Cleaning previous builds...
mvn clean

REM Build the application
echo 🔨 Building application...
mvn package -DskipTests

REM Check if JAR was built successfully
if not exist "target\vaultscope-1.0.0.jar" (
    echo ❌ JAR build failed
    exit /b 1
)

echo ✅ JAR built successfully

REM Build Windows installers
echo 🪟 Building Windows EXE installer...
mvn package -Pjpackage -Djpackage.type=exe -DskipTests
if exist "target\dist\VaultScope-1.0.0.exe" (
    echo ✅ Windows EXE installer created: target\dist\VaultScope-1.0.0.exe
) else (
    echo ⚠️  EXE installer creation failed
)

echo 🪟 Building Windows MSI installer...
mvn package -Pjpackage -Djpackage.type=msi -DskipTests
if exist "target\dist\VaultScope-1.0.0.msi" (
    echo ✅ Windows MSI installer created: target\dist\VaultScope-1.0.0.msi
) else (
    echo ⚠️  MSI installer creation failed
)

echo.
echo 🎉 Build completed successfully!
echo ================================
echo 📦 Available artifacts:
echo    - JAR: target\vaultscope-1.0.0.jar
if exist "target\dist" (
    echo    - Installers: target\dist\
    dir target\dist\
)

echo.
echo 🚀 To run the application:
echo    java -jar target\vaultscope-1.0.0.jar
echo.
echo 📖 For more information, see SETUP.md