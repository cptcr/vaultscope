@echo off
cd "%~dp0VaultScope.Enterprise"
echo Starting VaultScope Enterprise Security Platform...
dotnet run --project src\VaultScope.UI\VaultScope.UI.csproj
pause