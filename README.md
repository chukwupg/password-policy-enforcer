# Password Policy Enforcer

## Overview
This is a configurable password policy enforcement tool built in Python.

This project validates passwords against customizable security policies,
including length, complexity, repetition, sequential patterns, and entropy
estimation. It is designed as a foundational security utility and a learning
project focused on secure authentication practices.

## Features (Current – v1.0)
- Configurable password policy via JSON
- Minimum length and character class enforcement
- Detection of common and banned password patterns
- Repeated and sequential character checks
- Heuristic entropy estimation
- CLI usage and importable Python module
- Unit tests with pytest

## Project Structure
- `password_enforcer.py` – core validation logic and CLI
- `policy.json` – configurable password policy
- `test_password_enforcer.py` – unit tests

## Usage

Validate a single password:
```
python password_enforcer.py --password "MySecureP@ssw0rd!"

```

Validate multiple passwords:

```
python password_enforcer.py --password-file passwords.txt

```

## Why This Project Matters
Weak passwords remain one of the most common causes of account compromise.
This project demonstrates practical understanding of password policy design,
security trade-offs, and defensive controls used in real-world systems.

## Roadmap
Planned improvements will be tracked via GitHub Issues and Pull Requests:

- Integrate zxcvbn for advanced password strength estimation
- Add breached-password detection using k-Anonymity
- Build an HTML-based client/server demo

## Author

👩‍💻 **Chukwu PraiseGod**  
Follow my journey: [X](https://x.com/chukwupg) | [LinkedIn](https://linkedin.com/in/chukwupg)  

