@echo off
echo Building VaultScope - Enterprise API Security Assessment Tool
echo Author: CPTCR ^| https://cptcr.dev ^| https://github.com/cptcr
echo License: Apache License 2.0
echo.

where mvn >nul 2>&1
if %errorlevel% neq 0 (
    echo Maven is not installed. Please install Maven first.
    exit /b 1
)

where java >nul 2>&1
if %errorlevel% neq 0 (
    echo Java is not installed. Please install Java 17 or newer.
    exit /b 1
)

echo Step 1: Cleaning previous builds...
call mvn clean

echo Step 2: Compiling and packaging application...
call mvn compile package

if %errorlevel% neq 0 (
    echo Build failed during compilation/packaging phase
    exit /b 1
)

echo Step 3: Creating runtime image...
jlink --module-path "target/dependency;target/classes" ^
      --add-modules vaultscope ^
      --launcher vaultscope=vaultscope/dev.cptcr.vaultscope.VaultScopeApplication ^
      --output target/java-runtime ^
      --compress=2 ^
      --no-header-files ^
      --no-man-pages

if %errorlevel% neq 0 (
    echo Runtime image creation failed
    exit /b 1
)

echo Step 4: Creating installers...
call mvn jpackage:jpackage@win
call mvn jpackage:jpackage@win-msi

echo.
echo Build completed successfully!
echo Executables created in target\dist\
echo.
echo To run the application directly:
echo   java --module-path target\classes --module vaultscope/dev.cptcr.vaultscope.VaultScopeApplication
echo.
echo Or use the runtime image:
echo   target\java-runtime\bin\vaultscope.exe

pause