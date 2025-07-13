@echo off
echo Starting VaultScope Enterprise (Debug)...
cd "%~dp0VaultScope.Enterprise"

echo Building debug version...
dotnet build src\VaultScope.UI\VaultScope.UI.csproj

if %ERRORLEVEL% NEQ 0 (
    echo Build failed!
    pause
    exit /b 1
)

echo Running debug executable directly...
src\VaultScope.UI\bin\Debug\net8.0\VaultScope.UI.exe

if %ERRORLEVEL% NEQ 0 (
    echo Application failed to start!
    pause
    exit /b 1
)

echo Application closed successfully.
pause