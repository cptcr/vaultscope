# VaultScope Enterprise

<div align="center">
  <img src="docs/images/logo.png" alt="VaultScope Logo" width="200"/>
  
  **Professional API Security Assessment Tool**
  
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?logo=.net)](https://dotnet.microsoft.com/)
  [![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)](https://github.com/VaultScope/VaultScope-Enterprise)
  [![Build Status](https://img.shields.io/github/workflow/status/VaultScope/VaultScope-Enterprise/CI)](https://github.com/VaultScope/VaultScope-Enterprise/actions)
</div>

## 🛡️ Overview

VaultScope Enterprise is a professional-grade security assessment tool designed specifically for testing localhost applications. Built with .NET 8.0 and Avalonia UI, it provides comprehensive vulnerability scanning capabilities with a modern, cross-platform interface.

### ✨ Key Features

- **🔍 Comprehensive Vulnerability Detection**
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Command Injection
  - XML External Entity (XXE)
  - Server-Side Request Forgery (SSRF)
  - Path Traversal
  - Authentication Bypass
  - Security Headers Analysis

- **🎨 Modern User Interface**
  - Beautiful purple/black dark theme
  - Smooth animations and transitions
  - Real-time scan progress
  - Interactive dashboard

- **📊 Advanced Reporting**
  - HTML, JSON, and PDF export formats
  - Detailed vulnerability descriptions
  - OWASP categorization
  - Security scoring system

- **💾 Data Persistence**
  - SQLite database with Entity Framework Core
  - Historical scan tracking
  - Trend analysis

- **🌍 Cross-Platform Support**
  - Windows (.msi, .exe)
  - macOS (.dmg, .pkg)
  - Linux (.deb, .rpm, .AppImage)

## 🚀 Getting Started

### Prerequisites

- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- Visual Studio 2022, VS Code, or JetBrains Rider

### Installation

#### Option 1: Download Pre-built Binaries

Download the latest release for your platform from the [Releases](https://github.com/VaultScope/VaultScope-Enterprise/releases) page.

#### Option 2: Build from Source

```bash
# Clone the repository
git clone https://github.com/VaultScope/VaultScope-Enterprise.git
cd VaultScope-Enterprise

# Restore dependencies
dotnet restore

# Build the application
dotnet build --configuration Release

# Run the application
dotnet run --project src/VaultScope.UI/VaultScope.UI.csproj
```

## 🎯 Usage

1. **Launch VaultScope Enterprise**
2. **Enter your localhost URL** (e.g., `http://localhost:3000`)
3. **Configure scan options**:
   - Select vulnerability detectors
   - Set authentication if needed
   - Choose scan depth
4. **Start the scan** and monitor progress
5. **Review results** in the detailed report
6. **Export findings** in your preferred format

### Example Scan

```bash
# Using the CLI (future feature)
vaultscope scan http://localhost:8080 --all-detectors --output report.html
```

## 🏗️ Architecture

```
VaultScope.Enterprise/
├── src/
│   ├── VaultScope.Core/           # Core models and interfaces
│   ├── VaultScope.Security/       # Vulnerability detectors
│   ├── VaultScope.Infrastructure/ # Data access and utilities
│   ├── VaultScope.UI/            # Avalonia UI application
│   └── VaultScope.Tests/         # Unit and integration tests
├── docs/                         # Documentation
├── scripts/                      # Build and deployment scripts
└── .github/                      # GitHub workflows
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Install development dependencies
dotnet tool restore

# Run tests
dotnet test

# Run with hot reload
dotnet watch run --project src/VaultScope.UI/VaultScope.UI.csproj
```

## 📋 Security Policy

Please review our [Security Policy](SECURITY.md) for reporting vulnerabilities.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Avalonia UI](https://avaloniaui.net/) - Cross-platform UI framework
- [Entity Framework Core](https://docs.microsoft.com/ef/core/) - Data access
- [ReactiveUI](https://reactiveui.net/) - MVVM framework
- [OWASP](https://owasp.org/) - Security guidelines

## 📞 Support

- **Documentation**: [docs.vaultscope.io](https://docs.vaultscope.io)
- **Issues**: [GitHub Issues](https://github.com/VaultScope/VaultScope-Enterprise/issues)
- **Discussions**: [GitHub Discussions](https://github.com/VaultScope/VaultScope-Enterprise/discussions)

---

<div align="center">
  Made with ❤️ by the VaultScope Team
</div>