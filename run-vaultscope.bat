@echo off
echo Starting VaultScope Enterprise...
cd "%~dp0VaultScope.Enterprise"

echo Building for Windows...
dotnet build src\VaultScope.UI\VaultScope.UI.csproj --runtime win-x64

if %ERRORLEVEL% NEQ 0 (
    echo Build failed!
    pause
    exit /b 1
)

echo Starting application...
dotnet run --project src\VaultScope.UI\VaultScope.UI.csproj --runtime win-x64

if %ERRORLEVEL% NEQ 0 (
    echo Application failed to start!
    pause
    exit /b 1
)

echo Application closed successfully.
pause
