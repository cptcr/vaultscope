@echo off
echo Starting VaultScope Enterprise Debug Session...
cd "%~dp0VaultScope.Enterprise"

echo Building application...
dotnet build src\VaultScope.UI\VaultScope.UI.csproj

if %ERRORLEVEL% NEQ 0 (
    echo Build failed!
    pause
    exit /b %ERRORLEVEL%
)

echo Starting application with detailed logging...
set AVALONIA_LOGGER=Trace
set DOTNET_ENVIRONMENT=Development

dotnet run --project src\VaultScope.UI\VaultScope.UI.csproj --verbosity normal

echo Application exited. Press any key to close.
pause