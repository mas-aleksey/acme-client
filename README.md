# Async ACME Library

[![publish](https://github.com/mas-aleksey/acme-client/workflows/Build/badge.svg)](https://github.com/mas-aleksey/acme-client/actions?query=workflow%3A%22build%22)
[![coverage](https://coveralls.io/repos/mas-aleksey/acme-client/badge.svg)](https://coveralls.io/r/mas-aleksey/acme-client?branch=python-3)
[![codeql](https://github.com/mas-aleksey/acme-client/workflows/CodeQL/badge.svg)](https://github.com/mas-aleksey/acme-client/actions/workflows/codeql-analysis.yml)
[![pypi](https://img.shields.io/pypi/v/acme-client-lib.svg)](https://pypi.python.org/pypi/acme-client-lib)
[![license](https://img.shields.io/github/license/mas-aleksey/acme-client)](https://github.com/mas-aleksey/acme-client/blob/main/LICENSE)

## 🚀 Project Overview

The Async ACME Client Library is a comprehensive asynchronous Python implementation for managing SSL/TLS 
certificates using the ACME(Automated Certificate Management Environment) protocol. 
Designed for simplicity and flexibility, this library enables programmatic certificate issuance, renewal, 
and management with modern Python async capabilities. It is most convenient to use for cloud providers.

## Key Features

- 🔒 Asynchronous ACME protocol implementation
- 🌐 Support for Let's Encrypt and other ACME-compatible certificate authorities
- 🔑 RSA key management and cryptographic operations
- 🧩 Modular and extensible design
- 🚀 Modern Python async/await syntax support

## Installation

```bash
pip install acme-client-lib
```

## Quick Start Example

For example use file:
[example.py](https://github.com/mas-aleksey/acme-client/blob/main/example.py)

## Core Components

### 1. RSA Key Management (`_rsa_utils.py`)
- Generate and manage RSA keys
- Create Certificate Signing Requests (CSRs)
- Handle cryptographic operations

### 2. ACME Client (`_client.py`)
- Create ACME accounts
- Manage certificate orders
- Handle challenge verification
- Download certificate chains
- Revoke certificate

### 3. Data Schemas (`_schemas.py`)
- Pydantic models for ACME protocol entities
- Structured representation of challenges, orders, and errors

## Supported Workflows

1. Account Registration
2. Certificate Order Initialization
3. Challenge Verification
4. Certificate Finalization
5. Certificate Chain Download
6. Certificate Revocation

## Configuration Options

- ACME Server URL
- Account Email
- Domain Names
- Key Size
- Challenge Handling Strategy

## System Requirements

- Python 3.9+
- `cryptography` library
- `josepy` library
- Async runtime support

## Development Tools

- Poetry for dependency management
- Black for code formatting
- Ruff for linting
- MyPy for type checking
- Pytest for testing
- Pre-commit hooks

## Security Considerations

- Uses industry-standard cryptographic primitives
- Supports configurable key sizes
- Implements ACME protocol best practices
- Secure async HTTP interactions

## Limitations

- Requires manual DNS challenge resolution
- Designed for async environments

## Testing

Comprehensive test suite covering:
- Directory retrieval
- Nonce generation
- Account creation
- Order management
- Challenge verification
- Certificate retrieval

## License

MIT License - Open-source, commercial use allowed

## Contributing

Contributions are welcome! Please review our contribution guidelines and follow our code quality standards.

## Future Roadmap

- Enhanced HTTP-01 challenge automation
- More flexible certificate management
- Expanded CA support

## Recommended Use Cases

- Automated certificate management
- DevOps certificate workflows
- Web service SSL automation
- Continuous integration certificate provisioning

## Helpful Resources

- Let's Encrypt Documentation
- ACME Protocol Specification
- Project Example Scripts

## Contact

For issues, support, or contributions, please open a GitHub issue or contact the maintainers.

---

**Note**: Always ensure you have the latest version and review the documentation for the most up-to-date information.