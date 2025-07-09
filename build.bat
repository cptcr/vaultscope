@echo off
echo ====================================================
echo Building VaultScope - Enterprise API Security Tool
echo Author: CPTCR ^| https://cptcr.dev 
echo GitHub: https://github.com/cptcr
echo License: Apache License 2.0
echo ====================================================
echo.

where mvn >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Maven is not installed or not in PATH
    echo Please install Maven 3.6+ and try again
    pause
    exit /b 1
)

where java >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Java is not installed or not in PATH
    echo Please install Java 17+ and try again
    pause
    exit /b 1
)

for /f "tokens=3" %%g in ('java -version 2^>^&1 ^| findstr /i "version"') do (
    set JAVA_VERSION=%%g
)
set JAVA_VERSION=%JAVA_VERSION:"=%
for /f "delims=. tokens=1-3" %%a in ("%JAVA_VERSION%") do (
    set MAJOR=%%a
    set MINOR=%%b
    set PATCH=%%c
)

if %MAJOR% lss 17 (
    echo [ERROR] Java 17 or newer is required. Current version: %JAVA_VERSION%
    pause
    exit /b 1
)

echo [INFO] Java version: %JAVA_VERSION%
echo [INFO] Maven detected
echo.

echo [STEP 1/5] Cleaning previous builds...
call mvn clean
if %errorlevel% neq 0 (
    echo [ERROR] Clean failed
    pause
    exit /b 1
)

echo.
echo [STEP 2/5] Compiling and packaging application...
call mvn compile package -DskipTests
if %errorlevel% neq 0 (
    echo [ERROR] Build failed during compilation/packaging
    pause
    exit /b 1
)

echo.
echo [STEP 3/5] Creating module path and runtime image...
if not exist "target\modules" mkdir target\modules
copy "target\vaultscope-1.0.0.jar" "target\modules\"

jlink --module-path "target\modules;%JAVA_HOME%\jmods" ^
      --add-modules vaultscope ^
      --launcher vaultscope=vaultscope/dev.cptcr.vaultscope.VaultScopeApplication ^
      --output target\java-runtime ^
      --compress=2 ^
      --no-header-files ^
      --no-man-pages

if %errorlevel% neq 0 (
    echo [WARNING] jlink failed, continuing with standard JAR
)

echo.
echo [STEP 4/5] Creating Windows installers...
if exist "target\java-runtime" (
    jpackage --input target\modules ^
             --name VaultScope ^
             --main-jar vaultscope-1.0.0.jar ^
             --main-class dev.cptcr.vaultscope.VaultScopeApplication ^
             --runtime-image target\java-runtime ^
             --dest target\dist ^
             --type exe ^
             --vendor "CPTCR" ^
             --app-version "1.0.0" ^
             --description "Enterprise API Security Assessment Tool" ^
             --win-dir-chooser ^
             --win-menu ^
             --win-shortcut
             
    jpackage --input target\modules ^
             --name VaultScope ^
             --main-jar vaultscope-1.0.0.jar ^
             --main-class dev.cptcr.vaultscope.VaultScopeApplication ^
             --runtime-image target\java-runtime ^
             --dest target\dist ^
             --type msi ^
             --vendor "CPTCR" ^
             --app-version "1.0.0" ^
             --description "Enterprise API Security Assessment Tool" ^
             --win-dir-chooser ^
             --win-menu ^
             --win-shortcut
) else (
    echo [WARNING] Runtime image not available, skipping installer creation
)

echo.
echo [STEP 5/5] Creating distribution directory...
if not exist "target\dist" mkdir target\dist
copy "target\vaultscope-1.0.0.jar" "target\dist\"

echo.
echo ====================================================
echo BUILD COMPLETED SUCCESSFULLY!
echo ====================================================
echo.
echo Artifacts created:
echo - JAR: target\vaultscope-1.0.0.jar
echo - Shaded JAR: target\dist\vaultscope-1.0.0.jar
if exist "target\dist\VaultScope-1.0.0.exe" echo - Windows EXE: target\dist\VaultScope-1.0.0.exe
if exist "target\dist\VaultScope-1.0.0.msi" echo - Windows MSI: target\dist\VaultScope-1.0.0.msi
if exist "target\java-runtime" echo - Runtime: target\java-runtime\
echo.
echo To run the application:
echo   java -jar target\vaultscope-1.0.0.jar
echo.
if exist "target\java-runtime" (
    echo Or use the runtime image:
    echo   target\java-runtime\bin\vaultscope.exe
    echo.
)
echo Repository: https://github.com/cptcr/vaultscope
echo Documentation: https://cptcr.dev
echo.
pause