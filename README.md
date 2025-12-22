# Password Policy Enforcer

## Overview
This is a configurable password policy enforcement tool built in Python.

This project validates passwords against customizable security policies,
including length, complexity, repetition, and sequential patterns. It implements zxcvbn and HIBP which enforces modern security controls
used in real enterprise environments. 
It is designed as a foundational security utility and a learning project focused on secure authentication practices.

## Why This Project Exists

Weak and reused passwords remain one of the most common initial access vectors.
This project demonstrates how password security controls can be enforced,
tested, and enhanced using industry-recognized techniques.

## Features (v1.0)
- Configurable password policy via JSON
- Minimum length and character class enforcement
- Detection of common and banned password patterns
- Repeated and sequential character checks
- Heuristic entropy estimation
- CLI usage and importable Python module
- Unit tests with pytest

## Features (Current – v2.0)
- Policy-based password validation using a configurable JSON file
- Character class enforcement
- Repetition and sequence detection
- Advanced password strength analysis using zxcvbn
- Detection of compromised passwords via Have I Been Pwned (k-Anonymity)
- Actionable feedback for weak passwords
- Unit-tested enforcement logic using pytest

## Why zxcvbn?

Traditional entropy checks are unreliable.
zxcvbn evaluates real-world password weaknesses such as:

- Common words
- Predictable patterns
- User behavior

Passwords must score **≥ 3/4** to pass validation.

## Why HIBP?

Strong-looking passwords may already be compromised.
This tool checks passwords against known breaches using
HIBP’s k-Anonymity API without exposing plaintext passwords.

If HIBP is unavailable, the tool fails open and issues a warning.

## Project Structure (v1.0)
- `password_enforcer.py` – core validation logic and CLI
- `policy.json` – configurable password policy
- `test_password_enforcer.py` – unit tests

## Project Structure (Current - v2.0)
password-policy-enforcer/
├── password_enforcer.py      # Core validation logic
├── policy.json               # Configurable password rules
├── test_password_enforcer.py # Unit tests for validation logic
├── requirements.txt          # Project dependencies
├── README.md
└── .gitignore

## Setup & Installation

This project uses a Python virtual environment for dependency isolation.

> Note: Kali Linux enforces PEP 668 (externally managed Python environments), so dependencies must be installed inside a virtual environment rather than system-wide.

### Prerequisites
- Python 3.9+
- python3-venv
- pip

### Environment Setup

```bash
# Setup

1. Clone repo
2. Create and activate virtual environment:
   python3 -m venv venv
   source venv/bin/activate
3. Install dependencies:
   pip install -r requirements.txt
4. Run password enforcer:
   python password_enforcer.py --password "MyPassword123!"
5. Run tests:
   pytest -q
```

This is a **V1 → V2 defining change**.

## Password Strength Evaluation

Password strength is evaluated using the zxcvbn library, which models real-world
attack strategies rather than relying solely on character variety or length.

Passwords must meet a minimum strength score to be accepted, and users receive
actionable feedback when validation fails.

## Breached Password Detection

This project integrates the Have I Been Pwned (HIBP) API using a k-Anonymity model.

- Passwords are hashed locally using SHA-1
- Only the first 5 characters of the hash are transmitted
- Full passwords and hashes are never exposed

If a password is found in known breach datasets, validation fails regardless of
its apparent strength.

## Usage

Validate a single password:
```
python password_enforcer.py --password "MySecureP@ssw0rd!"

```

Validate multiple passwords:

```
python password_enforcer.py --password-file passwords.txt

```

## Testing

Unit tests are implemented using pytest to verify:

- Policy enforcement logic
- Password strength evaluation behavior
- Detection of breached passwords
- Safe handling of edge cases and failures

Run tests using:
```bash
pytest -q
```

This ties testing to **security assurance**, not just correctness.

## Why This Project Matters

Weak and reused passwords remain one of the most common initial access vectors.
This project demonstrates how password security controls can be enforced,
tested, and enhanced using industry-recognized techniques.

## Security Design Notes

This project prioritizes:
- Defense-in-depth (policy checks + strength analysis + breach detection)
- Privacy-preserving external checks
- Test-backed security controls
- Clear separation of configuration, logic, and verification

## Skills Practiced
- Password policy design
- Secure API consumption
- Threat-informed security controls
- Python security tooling
- Unit testing (pytest)
- Defensive error handling

## Roadmap 
Planned improvements will be tracked via GitHub Issues and Pull Requests:

- Integrate zxcvbn for advanced password strength estimation (Issue #1 - Resolved)
- Add breached-password detection using k-Anonymity (Issue #2 - Resolved)
- Build an HTML-based client/server demo (I will come back to this when I have adequate knowledge)

## Author

👩‍💻 **Chukwu PraiseGod**  
Follow my journey: [X](https://x.com/chukwupg) | [LinkedIn](https://linkedin.com/in/chukwupg)  

