# SmartSecurityBot

A security-focused Telegram bot built with Python and `python-telegram-bot`.
It provides secure password generation, password-strength analysis, breached-password checks, scam-message analysis, suspicious-link analysis, account-recovery guidance, security checklists, and practical security tips.

## Features

- Secure password generation with Python's `secrets` module
- Custom password length from 8 to 128 characters
- Uppercase, lowercase, number, and special-character options
- Optional exclusion of ambiguous characters such as `0`, `O`, `1`, `I`, and `l`
- Generation of up to 10 passwords per request
- Password-strength and estimated-entropy analysis
- Breached-password lookup using the Pwned Passwords k-anonymity model
- Scam-message heuristic analysis
- Suspicious-link heuristic analysis without opening the URL
- Account-compromise emergency guidance
- Account-security checklist and score
- Security tips
- Per-user rate limiting
- Network error handling
- Telegram inline-button interface

## Commands

| Command | Description |
|---|---|
| `/start` | Open the main menu |
| `/password` | Generate secure passwords |
| `/strength` | Analyze a test password |
| `/breach` | Check a test password against known breach hashes |
| `/scam` | Analyze a suspicious message |
| `/link` | Analyze a suspicious URL |
| `/emergency` | Open the account-recovery guide |
| `/checklist` | Calculate an account-security score |
| `/tips` | Show a practical security tip |
| `/help` | Show help |
| `/cancel` | Cancel the current operation |

## Technology

- Python 3.11+
- `python-telegram-bot` 22.8
- HTTPX 0.28.1
- Telegram Bot API
- Pwned Passwords range API

## Local installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/SmartSecurityBot.git
cd SmartSecurityBot
```

### 2. Create a virtual environment

Windows PowerShell:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
py -m pip install -r requirements.txt
```

### 4. Set the bot token

Windows PowerShell:

```powershell
$env:BOT_TOKEN="YOUR_NEW_BOTFATHER_TOKEN"
```

Do not place the real token in `app.py`, `.env.example`, screenshots, issues, or commits.

### 5. Run

```powershell
py app.py
```

## Deployment

The project runs as a Python polling application.

Start command:

```bash
python app.py
```

Required environment variable:

```text
BOT_TOKEN=your_new_bot_token
```

Do not run the same bot token locally and on the hosting provider at the same time. Two polling instances cause Telegram `409 Conflict` errors.

## Security and privacy

- Bot tokens are read from environment variables.
- HTTPX request logging is reduced to avoid printing the Telegram token in request URLs.
- Generated passwords are not intentionally persisted.
- Submitted passwords and messages are not intentionally persisted.
- Users should not submit a password currently used on a real account.
- Breach checks send only the first five characters of a local SHA-1 hash to the Pwned Passwords range API.
- Scam and link checks are heuristic assessments, not safety guarantees.

## Limitations

- In-memory rate-limit data is reset when the application restarts.
- The bot has no persistent database or admin dashboard yet.
- Suspicious-link analysis does not open or scan remote websites.
- Password entropy is an estimate based on detected character groups.

## Author

Mohamed Oussema Marzougui

## License

This project is licensed under the MIT License. See `LICENSE`.
