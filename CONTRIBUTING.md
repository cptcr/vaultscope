# Contributing to VaultScope

Thank you for your interest in contributing to VaultScope! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contribution Guidelines](#contribution-guidelines)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)
- [Security Policy](#security-policy)

## Code of Conduct

This project and everyone participating in it is governed by our commitment to creating a welcoming and inclusive environment. By participating, you are expected to uphold professional standards and treat all contributors with respect.

### Our Standards

- Use welcoming and inclusive language
- Be respectful of differing viewpoints and experiences
- Gracefully accept constructive criticism
- Focus on what is best for the community
- Show empathy towards other community members

## Getting Started

### Prerequisites

- Java 17 or newer (OpenJDK or Oracle JDK)
- Maven 3.6 or newer
- Git
- IDE with JavaFX support (IntelliJ IDEA, Eclipse, or VS Code)

### Development Setup

1. **Fork the Repository**
   ```bash
   git clone https://github.com/your-username/vaultscope.git
   cd vaultscope
   ```

2. **Set Up Development Environment**
   ```bash
   # Verify Java version
   java -version
   
   # Verify Maven installation
   mvn -version
   
   # Install dependencies
   mvn clean install
   ```

3. **Run the Application**
   ```bash
   # Using Maven
   mvn javafx:run
   
   # Or build and run JAR
   mvn clean package
   java -jar target/vaultscope-1.0.0.jar
   ```

4. **Run Tests**
   ```bash
   mvn test
   ```

## Contribution Guidelines

### Code Style

- Follow existing code formatting and naming conventions
- Use descriptive variable and method names
- Write clean, self-documenting code
- Avoid excessive comments - code should be readable
- Ensure proper error handling for all new features

### Coding Standards

- **Java**: Follow Oracle Java coding conventions
- **JavaFX**: Use FXML for UI layouts when possible
- **CSS**: Maintain consistent styling with existing themes
- **Documentation**: Update relevant documentation for new features

### Branch Naming

Use descriptive branch names that indicate the type of work:

- `feature/add-oauth2-support`
- `bugfix/fix-jwt-validation`
- `enhancement/improve-error-handling`
- `docs/update-readme`

### Commit Messages

Write clear, concise commit messages:

```
type(scope): brief description

Detailed explanation if necessary.

- List specific changes
- Reference related issues (#123)
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code formatting
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance tasks

## Pull Request Process

### Before Submitting

1. **Create an Issue First**
   - For significant changes, create an issue to discuss the proposal
   - Reference the issue number in your pull request

2. **Test Your Changes**
   - Ensure all existing tests pass
   - Add tests for new functionality
   - Test on both Windows and Linux if possible
   - Verify the application builds and runs correctly

3. **Update Documentation**
   - Update README.md if needed
   - Add or update code documentation
   - Update CHANGELOG.md for significant changes

### Submitting the Pull Request

1. **Create Pull Request**
   - Use a descriptive title
   - Fill out the pull request template
   - Reference related issues

2. **Pull Request Description**
   ```markdown
   ## Description
   Brief description of changes made.
   
   ## Type of Change
   - [ ] Bug fix
   - [ ] New feature
   - [ ] Breaking change
   - [ ] Documentation update
   
   ## Testing
   - [ ] Unit tests pass
   - [ ] Manual testing completed
   - [ ] Cross-platform testing (if applicable)
   
   ## Checklist
   - [ ] Code follows project style guidelines
   - [ ] Self-review completed
   - [ ] Documentation updated
   - [ ] No new warnings or errors
   ```

### Review Process

1. **Automated Checks**
   - CI/CD pipeline must pass
   - Code quality checks must pass
   - Security scans must pass

2. **Code Review**
   - At least one maintainer review required
   - Address all review comments
   - Keep discussions constructive

3. **Merge Requirements**
   - All checks passing
   - Approved by maintainer
   - No merge conflicts
   - Documentation updated

## Issue Reporting

### Bug Reports

Use the bug report template and include:

- **Environment**: OS, Java version, VaultScope version
- **Steps to Reproduce**: Clear, numbered steps
- **Expected Behavior**: What should happen
- **Actual Behavior**: What actually happens
- **Screenshots**: If applicable
- **Additional Context**: Any other relevant information

### Feature Requests

Use the feature request template and include:

- **Problem Description**: What problem does this solve?
- **Proposed Solution**: Detailed description of the feature
- **Alternatives Considered**: Other approaches you've considered
- **Additional Context**: Any other relevant information

### Security Issues

**Do not report security vulnerabilities in public issues.**

For security-related issues:
1. Email details to [security@cptcr.dev]
2. Include detailed description and reproduction steps
3. Allow reasonable time for response before public disclosure

## Development Guidelines

### Adding New Security Tests

When adding new security test functionality:

1. **Test Categories**
   - Authentication vulnerabilities
   - Authorization bypasses
   - Input validation issues
   - Information disclosure
   - Session management flaws

2. **Implementation Guidelines**
   - Add tests to appropriate service class
   - Follow existing pattern for vulnerability detection
   - Include proper error handling
   - Add logging for test progress
   - Update UI to display new vulnerability types

3. **Testing Requirements**
   - Test against known vulnerable applications
   - Verify no false positives
   - Ensure graceful failure handling
   - Test performance impact

### Authentication Support

When adding new authentication methods:

1. **Update AuthenticationConfig**
   - Add new auth type enum
   - Add required configuration fields
   - Update UI form generation

2. **Implement in AuthenticationTester**
   - Add specific vulnerability tests
   - Follow existing vulnerability detection patterns
   - Add comprehensive error handling

3. **Update Documentation**
   - Add to README.md
   - Update user guide
   - Add configuration examples

### UI/UX Changes

For interface modifications:

1. **Design Consistency**
   - Follow existing design patterns
   - Maintain accessibility standards
   - Test with both light and dark themes

2. **User Experience**
   - Ensure intuitive navigation
   - Provide clear feedback
   - Maintain responsive design

## Release Process

### Version Numbering

We use Semantic Versioning (SemVer):
- **Major** (1.0.0): Breaking changes
- **Minor** (1.1.0): New features, backward compatible
- **Patch** (1.0.1): Bug fixes, backward compatible

### Release Checklist

1. **Pre-release**
   - Update version numbers
   - Update CHANGELOG.md
   - Run full test suite
   - Update documentation

2. **Release**
   - Create release tag
   - Build release artifacts
   - Update GitHub release
   - Announce release

## Getting Help

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and community discussion
- **Email**: Direct contact for sensitive issues

### Documentation

- **README.md**: Basic setup and usage
- **Wiki**: Detailed documentation and guides
- **Code Comments**: Inline documentation
- **JavaDoc**: API documentation

### Community

- Be respectful and professional
- Help others when possible
- Share knowledge and experiences
- Contribute to discussions

## Recognition

Contributors will be recognized in:
- GitHub contributors list
- CHANGELOG.md for significant contributions
- README.md acknowledgments section

## License

By contributing to VaultScope, you agree that your contributions will be licensed under the Apache License 2.0.

---

**Questions?** Feel free to open an issue or start a discussion. We're here to help!

**Thank you for contributing to VaultScope!** 🛡️