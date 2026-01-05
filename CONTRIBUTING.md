# Contributing to BUCIN

Thank you for your interest in contributing to BUCIN! 🎉

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Code Style](#code-style)
- [Pull Request Process](#pull-request-process)

---

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment.

---

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Bucin.git
   cd Bucin
   ```
3. **Create a branch** for your feature:
   ```bash
   git checkout -b feature/your-feature-name
   ```

---

## How to Contribute

### 🐛 Bug Reports
- Use the GitHub issue tracker
- Include Python version and OS
- Provide steps to reproduce
- Include error messages/tracebacks

### 💡 Feature Requests
- Open an issue describing the feature
- Explain the use case
- Discuss implementation approach

### 🔧 Code Contributions
- Fix bugs
- Add new reconnaissance modules
- Improve existing functionality
- Add tests
- Improve documentation

---

## Development Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .

# Run the tool
bucin --help
```

---

## Code Style

### Python Guidelines

- Follow **PEP 8** style guide
- Use **type hints** for function signatures
- Write **docstrings** for functions and classes
- Keep functions focused and under 50 lines
- Use meaningful variable names

### Example

```python
def fetch_records(domain: str, timeout: int = 10) -> List[Dict[str, str]]:
    """
    Fetch DNS records for a domain.
    
    Args:
        domain: Target domain name
        timeout: Request timeout in seconds
        
    Returns:
        List of DNS record dictionaries
    """
    results = []
    # ... implementation
    return results
```

### Formatting

```bash
# Format with black (optional)
pip install black
black bucin.py
```

---

## Pull Request Process

1. **Update** your branch with main:
   ```bash
   git fetch origin
   git rebase origin/main
   ```

2. **Test** your changes thoroughly

3. **Commit** with clear messages:
   ```bash
   git commit -m "feat: add wayback machine integration"
   ```
   
   Commit prefixes:
   - `feat:` New feature
   - `fix:` Bug fix
   - `docs:` Documentation
   - `refactor:` Code refactoring
   - `test:` Adding tests

4. **Push** and create a Pull Request:
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Fill out** the PR template with:
   - Description of changes
   - Related issue numbers
   - Screenshots (if applicable)

---

## 🎯 Good First Issues

Look for issues labeled `good first issue` for beginner-friendly tasks.

---

## ❓ Questions?

Open an issue or reach out to [@Masriyan](https://github.com/Masriyan).

---

**Thank you for contributing!** 🚀
