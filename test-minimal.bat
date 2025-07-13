@echo off
echo Testing minimal VaultScope Enterprise...
cd "%~dp0VaultScope.Enterprise\src\VaultScope.UI"

echo Compiling minimal test...
dotnet build --verbosity quiet

echo Running minimal test...
dotnet run --no-build --property:StartupObject=VaultScope.UI.MinimalProgram

echo Test completed. Press any key to close.
pause