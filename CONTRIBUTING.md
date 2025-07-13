# Contributing to VaultScope Enterprise

Thank you for considering contributing to VaultScope Enterprise! Your involvement helps make VaultScope Enterprise a better tool for everyone.

## Code of Conduct

This project and all participants are governed by the [VaultScope Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code. Please report unacceptable behavior to [security@vaultscope.dev](mailto:security@vaultscope.dev).

## How Can I Contribute?

### Reporting Bugs

Before creating a bug report, please check existing issues to avoid duplicates. When reporting a bug, include as many details as possible.

**How to Submit a Good Bug Report**

Bugs are tracked as [GitHub issues](https://github.com/cptcr/vaultscope/issues). Create an issue and provide:

* **Clear, descriptive title** for the issue.
* **Exact steps to reproduce the problem** in detail.
* **Specific examples** (links, code snippets, etc.).
* **Describe the observed behavior** and explain the problem.
* **Describe the expected behavior** and why.
* **Include screenshots or GIFs** to demonstrate the issue.
* **If related to performance or memory**, include a CPU profile.
* **Details about your environment**:
  * VaultScope Enterprise version
  * OS name and version
  * If running in a VM, specify the VM software

### Suggesting Enhancements

Enhancement suggestions are tracked as [GitHub issues](https://github.com/cptcr/vaultscope/issues). Create an issue and provide:

* **Clear, descriptive title** for the suggestion.
* **Step-by-step description** of the enhancement.
* **Specific examples** (code snippets, etc.).
* **Describe current behavior** and **expected behavior**.
* **Screenshots or GIFs** to illustrate your suggestion.
* **Explain why the enhancement is useful** to VaultScope Enterprise users.

### Your First Code Contribution

Not sure where to start? Look for these labels:

* [Beginner issues](https://github.com/cptcr/vaultscope/labels/beginner) – simple issues, good for first contributions.
* [Help wanted issues](https://github.com/cptcr/vaultscope/labels/help%20wanted) – issues needing extra attention.

### Pull Requests

To have your contribution considered:

1. Fork the repo and create your branch from `main`.
2. Add tests for new code.
3. Update documentation for API changes.
4. Ensure all tests pass.
5. Make sure your code lints.
6. Submit a pull request!

## Development Process

### Prerequisites

* [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
* [Git](https://git-scm.com/)
* An IDE such as [Visual Studio 2022](https://visualstudio.microsoft.com/), [VS Code](https://code.visualstudio.com/), or [JetBrains Rider](https://www.jetbrains.com/rider/)

### Setting Up Your Development Environment

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/vaultscope.git
cd vaultscope

# Add upstream remote
git remote add upstream https://github.com/cptcr/vaultscope.git

# Install dependencies
dotnet restore

# Build the project
dotnet build

# Run tests
dotnet test
```

### Coding Standards

* **C# Coding Conventions**: Follow [Microsoft C# Coding Conventions](https://learn.microsoft.com/dotnet/csharp/fundamentals/coding-style/coding-conventions)
* **File Organization**: One type per file; file name matches type name; use folders for related types
* **Naming Conventions**: PascalCase for classes/methods/properties; camelCase for variables/parameters; UPPER_CASE for constants; prefix interfaces with 'I'
* **Code Style**: 4 spaces for indentation; opening braces on new line; always use braces; keep lines under 120 characters

### Testing

* Write unit tests for new functionality
* Ensure all tests pass before submitting a PR
* Aim for high code coverage (>80%)
* Use meaningful test names

```csharp
[Fact]
public void SqlInjectionDetector_ShouldDetectBasicSqlInjection()
{
    // Arrange
    var detector = new SqlInjectionDetector();
    
    // Act
    var result = detector.Detect("SELECT * FROM users WHERE id = '1' OR '1'='1'");
    
    // Assert
    Assert.True(result.IsVulnerable);
}
```

### Commit Messages

* Use present tense ("Add feature")
* Use imperative mood ("Move cursor to...")
* Limit first line to 72 characters
* Reference issues and PRs after the first line
* Consider starting with an emoji:
  * 🎨 `:art:` format/structure improvements
  * 🐛 `:bug:` bug fixes
  * 🔥 `:fire:` code/file removal
  * 📝 `:memo:` documentation
  * 🚀 `:rocket:` performance improvements
  * ✅ `:white_check_mark:` tests
  * 🔒 `:lock:` security
  * ⬆️ `:arrow_up:` dependency upgrades
  * ⬇️ `:arrow_down:` dependency downgrades

### Documentation

* Update README.md for interface changes
* Update XML documentation for public APIs
* Add/update docs in `/docs`
* Include JSDoc for client-side JavaScript

## Community

### Communication Channels

* [GitHub Discussions](https://github.com/cptcr/vaultscope/discussions) – general discussions
* [GitHub Issues](https://github.com/cptcr/vaultscope/issues) – bugs and feature requests
* [Security Email](mailto:security@vaultscope.dev) – security concerns

### Code Reviews

All submissions require review via GitHub pull requests. See [GitHub Help](https://help.github.com/articles/about-pull-requests/) for details.

### Recognition

Significant contributors are recognized in [CONTRIBUTORS.md](CONTRIBUTORS.md).

## Additional Notes

### Issue and Pull Request Labels

Labels we use:

* `bug` – bug reports
* `enhancement` – feature requests
* `documentation` – docs-related
* `good first issue` – good for newcomers
* `help wanted` – needs extra attention
* `question` – information requested
* `wontfix` – will not be worked on
* `duplicate` – already exists
* `invalid` – not valid

## Questions?

Open an issue with the `question` label and we'll help.

Thank you for contributing to VaultScope Enterprise! 🎉
