@echo off
echo Starting VaultScope Enterprise (Debug with Output)...
cd "%~dp0VaultScope.Enterprise"

echo Building debug version...
dotnet build src\VaultScope.UI\VaultScope.UI.csproj

if %ERRORLEVEL% NEQ 0 (
    echo Build failed!
    pause
    exit /b 1
)

echo Running with dotnet command to capture output...
echo.
echo =============== APPLICATION OUTPUT ===============
dotnet src\VaultScope.UI\bin\Debug\net8.0\win-x64\VaultScope.UI.dll
echo =============== END OUTPUT ===============
echo.

echo Exit code: %ERRORLEVEL%
pause