@echo off
echo Starting VaultScope Enterprise...
cd "%~dp0VaultScope.Enterprise"

echo Publishing Windows executable...
dotnet publish src\VaultScope.UI\VaultScope.UI.csproj -c Release -r win-x64 --self-contained true -o publish\win-x64

if %ERRORLEVEL% NEQ 0 (
    echo Publish failed!
    pause
    exit /b 1
)

echo Starting VaultScope Enterprise...
publish\win-x64\VaultScope.UI.exe

if %ERRORLEVEL% NEQ 0 (
    echo Application failed to start!
    pause
    exit /b 1
)

echo Application closed successfully.
pause
