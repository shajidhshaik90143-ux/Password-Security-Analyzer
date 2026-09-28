# 🔐 Password Security Analyzer

A strong, portfolio-ready cybersecurity project built with **Python + Streamlit**.

## Features

- Password strength score from 0–100
- Strength classification
- Shannon-style search-space entropy estimate
- Character composition analysis
- Common-password detection
- Repetition detection
- Sequential-pattern detection
- Keyboard-pattern detection
- Year/date-like pattern detection
- Dictionary/password-fragment detection
- Security recommendations
- Attack-resistance indicators
- Cryptographically secure password generator using `secrets`
- Configurable passphrase generator
- Optional Have I Been Pwned (HIBP) k-anonymity check
- No local password storage
- Technical-details panel
- Automated tests

## Project structure

```text
Password_Security_Analyzer/
├── app.py
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
├── src/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── generator.py
│   └── breach.py
├── tests/
│   └── test_analyzer.py
└── data/
    └── README.md
```

## Requirements

- Python 3.10–3.13 recommended
- Windows, Linux, or macOS
- Internet is optional; only the HIBP feature needs network access.

## Windows installation

Open PowerShell in the project directory:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

If PowerShell blocks activation, use:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.venv\Scripts\Activate.ps1
```

Alternative without activation:

```powershell
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m streamlit run app.py
```

## Run tests

```powershell
pytest -q
```

## Security notes

The analyzer is a heuristic tool, not a proof that a password is secure.

The local analyzer does not save passwords to disk.

The optional HIBP check uses the Pwned Passwords range API's k-anonymity model. The full SHA-1 hash is calculated locally, and only the first five hexadecimal characters are sent to the service.

Do not use a real production password for demonstrations. For a college demo, use a test password.

## Suggested viva questions

1. What is password entropy?
2. Why is length important for password security?
3. What is a dictionary attack?
4. What is password spraying?
5. Why are keyboard patterns weak?
6. Why should passwords not be reused?
7. What is a password manager?
8. What is HIBP?
9. How does k-anonymity protect the full password hash?
10. Why is `secrets` preferable to `random` for security-sensitive generation?
11. Why should passwords not be logged?
12. Why can a high entropy estimate still fail to prove a password is safe?

## Disclaimer

This educational project is intended for defensive security awareness and password hygiene.
