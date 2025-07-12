# Contributing to VaultScope Enterprise

First off, thank you for considering contributing to VaultScope Enterprise! It's people like you that make VaultScope Enterprise such a great tool.

## Code of Conduct

This project and everyone participating in it is governed by the [VaultScope Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to [security@vaultscope.io](mailto:security@vaultscope.io).

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible.

**How Do I Submit A Good Bug Report?**

Bugs are tracked as [GitHub issues](https://github.com/VaultScope/VaultScope-Enterprise/issues). Create an issue and provide the following information:

* **Use a clear and descriptive title** for the issue to identify the problem.
* **Describe the exact steps which reproduce the problem** in as many details as possible.
* **Provide specific examples to demonstrate the steps**. Include links to files or GitHub projects, or copy/pasteable snippets.
* **Describe the behavior you observed after following the steps** and point out what exactly is the problem with that behavior.
* **Explain which behavior you expected to see instead and why.**
* **Include screenshots and animated GIFs** which show you following the described steps and clearly demonstrate the problem.
* **If the problem is related to performance or memory**, include a CPU profile capture with your report.
* **Include details about your configuration and environment**:
  * Which version of VaultScope Enterprise are you using?
  * What's the name and version of the OS you're using?
  * Are you running VaultScope Enterprise in a virtual machine? If so, which VM software are you using?

### Suggesting Enhancements

Enhancement suggestions are tracked as [GitHub issues](https://github.com/VaultScope/VaultScope-Enterprise/issues). Create an issue and provide the following information:

* **Use a clear and descriptive title** for the issue to identify the suggestion.
* **Provide a step-by-step description of the suggested enhancement** in as many details as possible.
* **Provide specific examples to demonstrate the steps**. Include copy/pasteable snippets which you use in those examples.
* **Describe the current behavior** and **explain which behavior you expected to see instead** and why.
* **Include screenshots and animated GIFs** which help you demonstrate the steps or point out the part of VaultScope Enterprise which the suggestion is related to.
* **Explain why this enhancement would be useful** to most VaultScope Enterprise users.

### Your First Code Contribution

Unsure where to begin contributing to VaultScope Enterprise? You can start by looking through these `beginner` and `help-wanted` issues:

* [Beginner issues](https://github.com/VaultScope/VaultScope-Enterprise/labels/beginner) - issues which should only require a few lines of code, and a test or two.
* [Help wanted issues](https://github.com/VaultScope/VaultScope-Enterprise/labels/help%20wanted) - issues which should be a bit more involved than `beginner` issues.

### Pull Requests

The process described here has several goals:

- Maintain VaultScope Enterprise's quality
- Fix problems that are important to users
- Engage the community in working toward the best possible VaultScope Enterprise
- Enable a sustainable system for VaultScope Enterprise's maintainers to review contributions

Please follow these steps to have your contribution considered by the maintainers:

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation.
4. Ensure the test suite passes.
5. Make sure your code lints.
6. Issue that pull request!

## Development Process

### Prerequisites

* [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
* [Git](https://git-scm.com/)
* An IDE such as [Visual Studio 2022](https://visualstudio.microsoft.com/), [VS Code](https://code.visualstudio.com/), or [JetBrains Rider](https://www.jetbrains.com/rider/)

### Setting Up Your Development Environment

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/VaultScope-Enterprise.git
cd VaultScope-Enterprise

# Add upstream remote
git remote add upstream https://github.com/VaultScope/VaultScope-Enterprise.git

# Install dependencies
dotnet restore

# Build the project
dotnet build

# Run tests
dotnet test
```

### Coding Standards

* **C# Coding Conventions**: Follow the [Microsoft C# Coding Conventions](https://docs.microsoft.com/en-us/dotnet/csharp/fundamentals/coding-style/coding-conventions)
* **File Organization**: 
  * One type per file
  * File name should match the type name
  * Use folders to organize related types
* **Naming Conventions**:
  * Use PascalCase for class names, method names, and property names
  * Use camelCase for local variables and parameters
  * Use UPPER_CASE for constants
  * Prefix interfaces with 'I'
* **Code Style**:
  * Use 4 spaces for indentation (no tabs)
  * Place opening braces on a new line
  * Always use braces for if/for/while/etc., even for single statements
  * Keep lines under 120 characters when possible

### Testing

* Write unit tests for all new functionality
* Ensure all tests pass before submitting a PR
* Aim for high code coverage (>80%)
* Use meaningful test names that describe what is being tested

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

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests liberally after the first line
* Consider starting the commit message with an applicable emoji:
  * 🎨 `:art:` when improving the format/structure of the code
  * 🐛 `:bug:` when fixing a bug
  * 🔥 `:fire:` when removing code or files
  * 📝 `:memo:` when writing docs
  * 🚀 `:rocket:` when improving performance
  * ✅ `:white_check_mark:` when adding tests
  * 🔒 `:lock:` when dealing with security
  * ⬆️ `:arrow_up:` when upgrading dependencies
  * ⬇️ `:arrow_down:` when downgrading dependencies

### Documentation

* Update the README.md with details of changes to the interface
* Update the XML documentation comments for public APIs
* Add or update relevant documentation in the `/docs` folder
* Include JSDoc comments for any client-side JavaScript

## Community

### Communication Channels

* [GitHub Discussions](https://github.com/VaultScope/VaultScope-Enterprise/discussions) - For general discussions
* [GitHub Issues](https://github.com/VaultScope/VaultScope-Enterprise/issues) - For bugs and feature requests
* [Security Email](mailto:security@vaultscope.io) - For security-related concerns

### Code Reviews

All submissions, including submissions by project members, require review. We use GitHub pull requests for this purpose. Consult [GitHub Help](https://help.github.com/articles/about-pull-requests/) for more information on using pull requests.

### Recognition

Contributors who have made significant contributions will be recognized in our [CONTRIBUTORS.md](CONTRIBUTORS.md) file.

## Additional Notes

### Issue and Pull Request Labels

This section lists the labels we use to help us track and manage issues and pull requests.

* `bug` - Issues that are bugs
* `enhancement` - Issues that are feature requests
* `documentation` - Issues or PRs related to documentation
* `good first issue` - Good for newcomers
* `help wanted` - Extra attention is needed
* `question` - Further information is requested
* `wontfix` - This will not be worked on
* `duplicate` - This issue or pull request already exists
* `invalid` - This doesn't seem right

## Questions?

Don't hesitate to ask questions! Open an issue with the `question` label, and we'll be happy to help.

Thank you for contributing to VaultScope Enterprise! 🎉