# Contributing to Sentra

Thanks for your interest in contributing to Sentra.

## Getting Started

Fork the repository and clone your fork:

```bash
git clone https://github.com/SentralLabs/Sentra.git
cd Sentra
```

Install dependencies:

```bash
npm install
```

Run the test suite:

```bash
npm test
```

Run tests once instead of watch mode:

```bash
npm test -- --run
```

Build the package:

```bash
npm run build
```

## Development Guidelines

Before submitting a change:

* Keep changes focused and minimal.
* Add or update tests for behavioral changes.
* Make sure all tests pass.
* Make sure the package builds successfully.
* Avoid exposing sensitive information in errors, logs, or tests.
* Preserve the existing public API unless the change intentionally introduces a breaking change.

## Pull Requests

For significant changes:

1. Create a feature branch.
2. Make your changes.
3. Add or update tests.
4. Run the test suite.
5. Run the build.
6. Open a pull request with a clear description of the change.

Example:

```bash
git checkout -b feature/my-change
```

Then:

```bash
npm test -- --run
npm run build
```

## Commit Messages

Use clear commit messages that describe the change.

Examples:

```text
feat: add session lookup
fix: prevent refresh token reuse
docs: improve authentication example
test: add refresh token rotation tests
chore: update dependencies
```

## Reporting Bugs

For non-security bugs, open a GitHub issue and include:

* Sentra version
* Node.js version
* Operating system
* Steps to reproduce
* Expected behavior
* Actual behavior
* Relevant error messages

Do not include passwords, tokens, secrets, or other sensitive information.

## Security Issues

Do not report security vulnerabilities through public GitHub issues.

See [SECURITY.md](SECURITY.md) for the security reporting process.
