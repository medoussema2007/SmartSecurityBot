"""SmartSecurityBot

A single-file Telegram security assistant built with python-telegram-bot 22.x.

Features:
- Secure password generator with user-selected options
- Password strength analysis
- Pwned Passwords check using HIBP k-anonymity
- Scam-message heuristic analysis
- Suspicious-link heuristic analysis
- Account-compromise emergency guide
- Account security checklist and score
- Security tips
- Simple per-user rate limiting
- Error logging

Setup:
1. Set the BOT_TOKEN environment variable.
2. Install: py -m pip install -r requirements.txt
3. Run locally: py app.py

Security:
- Never publish your token.
- The bot does not persist passwords or submitted messages.
- Do not use /breach or /strength with a real password currently in use.
"""

from __future__ import annotations

import hashlib
import os
import ipaddress
import logging
import math
import re
import secrets
import string
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlparse

import httpx
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.error import NetworkError, TimedOut
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    filters,
)


# -----------------------------------------------------------------------------
# CONFIGURATION
# Add BOT_TOKEN in the hosting platform Environment Variables section.
# For local PowerShell testing:
#   $env:BOT_TOKEN="YOUR_NEW_TOKEN"
#   py app.py
# -----------------------------------------------------------------------------
BOT_TOKEN: Final[str | None] = os.getenv("BOT_TOKEN")


# -----------------------------------------------------------------------------
# CONSTANTS
# -----------------------------------------------------------------------------
MIN_PASSWORD_LENGTH: Final[int] = 8
MAX_PASSWORD_LENGTH: Final[int] = 128
MAX_PASSWORD_COUNT: Final[int] = 10
SPECIAL_CHARACTERS: Final[str] = "!@#$%^&*()-_=+[]{};:,.?/"
AMBIGUOUS_CHARACTERS: Final[str] = "0O1Il"
HIBP_RANGE_URL: Final[str] = "https://api.pwnedpasswords.com/range/{}"

# Conversation states
(
    GEN_LENGTH,
    GEN_UPPER,
    GEN_LOWER,
    GEN_NUMBERS,
    GEN_SPECIAL,
    GEN_AMBIGUOUS,
    GEN_COUNT,
    STRENGTH_INPUT,
    BREACH_CONFIRM,
    BREACH_INPUT,
    SCAM_INPUT,
    LINK_INPUT,
    EMERGENCY_ACCOUNT,
    EMERGENCY_ACCESS,
    EMERGENCY_OTP,
    EMERGENCY_LINK,
    CHECKLIST_UNIQUE,
    CHECKLIST_MFA,
    CHECKLIST_RECOVERY,
    CHECKLIST_SESSIONS,
    CHECKLIST_UPDATES,
) = range(21)


# -----------------------------------------------------------------------------
# LOGGING
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("smart_security_bot")

# Avoid exposing the Telegram bot token inside HTTP request logs.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


# -----------------------------------------------------------------------------
# RATE LIMITING
# -----------------------------------------------------------------------------
@dataclass(frozen=True)
class RateRule:
    requests: int
    seconds: int


RATE_RULES: Final[dict[str, RateRule]] = {
    "general": RateRule(12, 60),
    "breach": RateRule(5, 60),
    "generate": RateRule(8, 60),
}
RATE_BUCKETS: defaultdict[tuple[int, str], deque[float]] = defaultdict(deque)


def is_rate_limited(user_id: int, category: str = "general") -> tuple[bool, int]:
    rule = RATE_RULES[category]
    now = time.monotonic()
    bucket = RATE_BUCKETS[(user_id, category)]

    while bucket and now - bucket[0] >= rule.seconds:
        bucket.popleft()

    if len(bucket) >= rule.requests:
        wait = max(1, math.ceil(rule.seconds - (now - bucket[0])))
        return True, wait

    bucket.append(now)
    return False, 0


async def enforce_rate_limit(
    update: Update,
    category: str = "general",
) -> bool:
    user = update.effective_user
    if user is None:
        return False

    limited, wait = is_rate_limited(user.id, category)
    if limited:
        target = update.callback_query.message if update.callback_query else update.message
        if target:
            await target.reply_text(
                f"⚠️ Too many requests. Please wait {wait} seconds and try again."
            )
        return False
    return True


# -----------------------------------------------------------------------------
# KEYBOARDS
# -----------------------------------------------------------------------------
def main_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("🔐 Generate Password", callback_data="menu_generate")],
            [
                InlineKeyboardButton("🛡 Strength Check", callback_data="menu_strength"),
                InlineKeyboardButton("🕵️ Breach Check", callback_data="menu_breach"),
            ],
            [
                InlineKeyboardButton("📩 Analyze Scam", callback_data="menu_scam"),
                InlineKeyboardButton("🔗 Check Link", callback_data="menu_link"),
            ],
            [InlineKeyboardButton("🚨 My Account May Be Hacked", callback_data="menu_emergency")],
            [InlineKeyboardButton("✅ Security Checklist", callback_data="menu_checklist")],
            [
                InlineKeyboardButton("💡 Security Tip", callback_data="menu_tip"),
                InlineKeyboardButton("ℹ️ Help", callback_data="menu_help"),
            ],
        ]
    )


def yes_no_keyboard(prefix: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [[
            InlineKeyboardButton("✅ Yes", callback_data=f"{prefix}_yes"),
            InlineKeyboardButton("❌ No", callback_data=f"{prefix}_no"),
        ]]
    )


def account_keyboard() -> InlineKeyboardMarkup:
    services = ["Google", "Microsoft", "Instagram", "Facebook", "Telegram", "GitHub", "Other"]
    rows = []
    for index in range(0, len(services), 2):
        row = [InlineKeyboardButton(s, callback_data=f"em_account_{s.lower()}") for s in services[index:index+2]]
        rows.append(row)
    return InlineKeyboardMarkup(rows)


# -----------------------------------------------------------------------------
# GENERIC HELPERS
# -----------------------------------------------------------------------------
async def send_or_edit(update: Update, text: str, reply_markup=None) -> None:
    if update.callback_query:
        await update.callback_query.answer()
        await update.callback_query.edit_message_text(text, reply_markup=reply_markup)
    elif update.message:
        await update.message.reply_text(text, reply_markup=reply_markup)


def bool_from_callback(data: str) -> bool:
    return data.endswith("_yes")


def remove_ambiguous(chars: str) -> str:
    return "".join(c for c in chars if c not in AMBIGUOUS_CHARACTERS)


# -----------------------------------------------------------------------------
# START, HELP, TIPS
# -----------------------------------------------------------------------------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await enforce_rate_limit(update):
        return
    context.user_data.clear()
    await send_or_edit(
        update,
        "🔐 Welcome to SmartSecurityBot!\n\n"
        "Generate strong passwords, analyze suspicious content, and follow practical account-security guidance.\n\n"
        "Choose a feature:",
        main_menu(),
    )


HELP_TEXT = (
    "ℹ️ SmartSecurityBot Help\n\n"
    "/start - Open the main menu\n"
    "/password - Generate secure passwords\n"
    "/strength - Analyze a test password\n"
    "/breach - Check a test password against known breach hashes\n"
    "/scam - Analyze a suspicious message\n"
    "/link - Analyze a suspicious URL\n"
    "/emergency - Account-compromise response guide\n"
    "/checklist - Account security checklist\n"
    "/tips - Show a security tip\n"
    "/cancel - Cancel the current operation\n\n"
    "Privacy:\n"
    "• The bot does not intentionally store passwords or messages.\n"
    "• Do not submit a real password currently used on an account.\n"
    "• Link and scam analysis are risk assessments, not guarantees."
)


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await enforce_rate_limit(update):
        return
    await send_or_edit(update, HELP_TEXT, main_menu())


SECURITY_TIPS: Final[list[str]] = [
    "Use a different password for every account. Password reuse turns one breach into many compromised accounts.",
    "Use at least 14 to 16 characters for important accounts. Length usually helps more than complicated substitutions.",
    "Enable multi-factor authentication. Prefer passkeys or security keys when the service supports them.",
    "Never share an OTP, recovery code, password, or QR login code, even with someone claiming to be support.",
    "Review active sessions on email, social-media, and messaging accounts, then close sessions you do not recognize.",
    "Keep recovery email addresses and phone numbers current, and store recovery codes offline in a safe place.",
    "Do not approve an unexpected MFA notification. Someone may already know your password.",
    "Before opening a link, inspect the real domain name, not only the logo or the words inside the URL.",
    "Use a reputable password manager instead of saving passwords in plain text notes or chat messages.",
    "Update your operating system, browser, and apps. Security updates fix known weaknesses.",
]


async def tips(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await enforce_rate_limit(update):
        return
    tip = secrets.choice(SECURITY_TIPS)
    await send_or_edit(update, f"💡 Security Tip\n\n{tip}", main_menu())


# -----------------------------------------------------------------------------
# PASSWORD GENERATION
# -----------------------------------------------------------------------------
async def generate_begin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not await enforce_rate_limit(update, "generate"):
        return ConversationHandler.END
    context.user_data.clear()
    await send_or_edit(
        update,
        f"🔢 Enter the password length.\n\nMinimum: {MIN_PASSWORD_LENGTH}\n"
        f"Maximum: {MAX_PASSWORD_LENGTH}\nRecommended: 14 or more\n\nExample: 16",
    )
    return GEN_LENGTH


async def generate_length(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    try:
        length = int(update.message.text.strip())
    except ValueError:
        await update.message.reply_text("❌ Enter a whole number, for example: 16")
        return GEN_LENGTH

    if not MIN_PASSWORD_LENGTH <= length <= MAX_PASSWORD_LENGTH:
        await update.message.reply_text(
            f"❌ Length must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH}."
        )
        return GEN_LENGTH

    context.user_data["length"] = length
    await update.message.reply_text("Include uppercase letters?", reply_markup=yes_no_keyboard("upper"))
    return GEN_UPPER


async def generate_upper(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    context.user_data["uppercase"] = bool_from_callback(query.data)
    await query.edit_message_text("Include lowercase letters?", reply_markup=yes_no_keyboard("lower"))
    return GEN_LOWER


async def generate_lower(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    context.user_data["lowercase"] = bool_from_callback(query.data)
    await query.edit_message_text("Include numbers?", reply_markup=yes_no_keyboard("numbers"))
    return GEN_NUMBERS


async def generate_numbers(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    context.user_data["numbers"] = bool_from_callback(query.data)
    await query.edit_message_text("Include special characters?", reply_markup=yes_no_keyboard("special"))
    return GEN_SPECIAL


async def generate_special(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    context.user_data["special"] = bool_from_callback(query.data)

    selected = any(
        context.user_data.get(key, False)
        for key in ("uppercase", "lowercase", "numbers", "special")
    )
    if not selected:
        await query.edit_message_text(
            "❌ Select at least one character group. Start again with /password.",
            reply_markup=main_menu(),
        )
        context.user_data.clear()
        return ConversationHandler.END

    await query.edit_message_text(
        "Exclude ambiguous characters such as 0, O, 1, I and l?",
        reply_markup=yes_no_keyboard("ambiguous"),
    )
    return GEN_AMBIGUOUS


async def generate_ambiguous(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    context.user_data["exclude_ambiguous"] = bool_from_callback(query.data)
    await query.edit_message_text(
        f"How many passwords? Enter a number from 1 to {MAX_PASSWORD_COUNT}."
    )
    return GEN_COUNT


def build_password(settings: dict) -> str:
    groups: list[str] = []
    if settings.get("uppercase"):
        groups.append(string.ascii_uppercase)
    if settings.get("lowercase"):
        groups.append(string.ascii_lowercase)
    if settings.get("numbers"):
        groups.append(string.digits)
    if settings.get("special"):
        groups.append(SPECIAL_CHARACTERS)

    if settings.get("exclude_ambiguous"):
        groups = [remove_ambiguous(group) for group in groups]

    length = int(settings["length"])
    if length < len(groups):
        raise ValueError("Password length is smaller than the number of required groups.")

    chars = [secrets.choice(group) for group in groups]
    pool = "".join(groups)
    chars.extend(secrets.choice(pool) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def password_analysis(password: str) -> dict:
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_number = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    pool = 0
    if has_upper:
        pool += 26
    if has_lower:
        pool += 26
    if has_number:
        pool += 10
    if has_special:
        pool += len(SPECIAL_CHARACTERS)

    entropy = round(len(password) * math.log2(pool), 1) if pool else 0.0
    score = 0
    score += len(password) >= 8
    score += len(password) >= 12
    score += len(password) >= 16
    score += has_upper
    score += has_lower
    score += has_number
    score += has_special
    score += len(set(password)) / max(1, len(password)) >= 0.65

    if score <= 3:
        rating = "Weak 🔴"
    elif score <= 5:
        rating = "Medium 🟠"
    elif score <= 7:
        rating = "Strong 🟢"
    else:
        rating = "Very Strong 🛡️"

    return {
        "upper": has_upper,
        "lower": has_lower,
        "number": has_number,
        "special": has_special,
        "entropy": entropy,
        "rating": rating,
    }


async def generate_count(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    try:
        count = int(update.message.text.strip())
    except ValueError:
        await update.message.reply_text(f"❌ Enter a number from 1 to {MAX_PASSWORD_COUNT}.")
        return GEN_COUNT

    if not 1 <= count <= MAX_PASSWORD_COUNT:
        await update.message.reply_text(f"❌ Enter a number from 1 to {MAX_PASSWORD_COUNT}.")
        return GEN_COUNT

    passwords = [build_password(context.user_data) for _ in range(count)]
    lines = ["🔐 Generated Passwords\n"]
    for index, password in enumerate(passwords, start=1):
        analysis = password_analysis(password)
        lines.append(
            f"{index}. {password}\n"
            f"   {analysis['rating']} | estimated entropy: {analysis['entropy']} bits"
        )
    lines.append("\n⚠️ Store passwords in a password manager. Do not reuse them.")
    await update.message.reply_text("\n\n".join(lines), reply_markup=main_menu())
    context.user_data.clear()
    return ConversationHandler.END


# -----------------------------------------------------------------------------
# PASSWORD STRENGTH
# -----------------------------------------------------------------------------
async def strength_begin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not await enforce_rate_limit(update):
        return ConversationHandler.END
    await send_or_edit(
        update,
        "🛡 Send a TEST password to analyze.\n\n"
        "Do not send a password currently used on a real account.",
    )
    return STRENGTH_INPUT


async def strength_result(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    password = update.message.text
    result = password_analysis(password)
    recommendations = []
    if len(password) < 14:
        recommendations.append("Use at least 14 characters.")
    if not result["upper"]:
        recommendations.append("Add uppercase letters.")
    if not result["lower"]:
        recommendations.append("Add lowercase letters.")
    if not result["number"]:
        recommendations.append("Add numbers.")
    if not result["special"]:
        recommendations.append("Add special characters.")

    text = (
        "🛡 Password Analysis\n\n"
        f"Length: {len(password)}\n"
        f"Uppercase: {'✅' if result['upper'] else '❌'}\n"
        f"Lowercase: {'✅' if result['lower'] else '❌'}\n"
        f"Numbers: {'✅' if result['number'] else '❌'}\n"
        f"Special characters: {'✅' if result['special'] else '❌'}\n"
        f"Estimated entropy: {result['entropy']} bits\n"
        f"Rating: {result['rating']}\n"
    )
    if recommendations:
        text += "\nRecommendations:\n• " + "\n• ".join(recommendations)
    text += "\n\nDelete the submitted test message if you do not need it anymore."

    await update.message.reply_text(text, reply_markup=main_menu())
    return ConversationHandler.END


# -----------------------------------------------------------------------------
# HIBP BREACH CHECK
# -----------------------------------------------------------------------------
async def breach_begin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not await enforce_rate_limit(update, "breach"):
        return ConversationHandler.END
    await send_or_edit(
        update,
        "🕵️ Breached Password Check\n\n"
        "The bot hashes the submitted text locally and sends only the first 5 SHA-1 hash characters to the Pwned Passwords API.\n\n"
        "Do not submit a password currently used on a real account. Continue?",
        yes_no_keyboard("breachconfirm"),
    )
    return BREACH_CONFIRM


async def breach_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    if not bool_from_callback(query.data):
        await query.edit_message_text("Breach check cancelled.", reply_markup=main_menu())
        return ConversationHandler.END
    await query.edit_message_text("Send a TEST password to check against known breach hashes.")
    return BREACH_INPUT


async def query_pwned_passwords(password: str) -> int:
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    headers = {"User-Agent": "SmartSecurityBot/1.0", "Add-Padding": "true"}
    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.get(HIBP_RANGE_URL.format(prefix), headers=headers)
        response.raise_for_status()

    for line in response.text.splitlines():
        returned_suffix, count = line.split(":", 1)
        if returned_suffix == suffix:
            return int(count)
    return 0


async def breach_result(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    password = update.message.text
    try:
        count = await query_pwned_passwords(password)
    except (httpx.HTTPError, ValueError):
        logger.exception("Pwned Passwords lookup failed")
        await update.message.reply_text(
            "⚠️ The breach service is temporarily unavailable. Try again later.",
            reply_markup=main_menu(),
        )
        return ConversationHandler.END

    if count:
        text = (
            f"🚨 This password hash appeared {count:,} times in known breach data.\n\n"
            "Do not use it. If you already use it, change it everywhere, use unique passwords, and enable MFA."
        )
    else:
        text = (
            "✅ This password hash was not found in the queried breach dataset.\n\n"
            "This does not prove the password is strong or private. Use a unique, long password and enable MFA."
        )
    await update.message.reply_text(text, reply_markup=main_menu())
    return ConversationHandler.END


# -----------------------------------------------------------------------------
# SCAM MESSAGE ANALYZER
# -----------------------------------------------------------------------------
SCAM_PATTERNS: Final[list[tuple[str, str, int]]] = [
    (r"\b(otp|one[- ]time password|verification code|security code)\b", "Requests or mentions an OTP/security code", 3),
    (r"\b(password|pin|cvv|bank account|card number)\b", "Requests or mentions sensitive credentials", 3),
    (r"\b(urgent|immediately|right now|within \d+ (minutes|hours))\b", "Creates urgency or time pressure", 2),
    (r"\b(winner|won|prize|lottery|giveaway|reward)\b", "Promises an unexpected prize or reward", 2),
    (r"\b(account.{0,20}(blocked|suspended|closed)|verify.{0,20}account)\b", "Threatens account restriction or demands verification", 2),
    (r"\b(send money|transfer|crypto|bitcoin|gift card|western union)\b", "Requests difficult-to-reverse payment", 3),
    (r"\b(click|open|visit).{0,30}(link|website|url)\b", "Pushes the recipient to open a link", 1),
    (r"\b(secret|do not tell|confidential)\b", "Asks for secrecy", 2),
    (r"https?://|www\.", "Contains a web link", 1),
]


async def scam_begin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not await enforce_rate_limit(update):
        return ConversationHandler.END
    await send_or_edit(
        update,
        "📩 Paste the suspicious message.\n\n"
        "Remove names, phone numbers, account numbers, and other personal information first.",
    )
    return SCAM_INPUT


async def scam_result(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    text = update.message.text.lower()
    findings = []
    score = 0
    for pattern, description, points in SCAM_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL):
            findings.append(description)
            score += points

    if score >= 7:
        risk = "High 🔴"
    elif score >= 3:
        risk = "Medium 🟠"
    else:
        risk = "Low or unclear 🟡"

    result = f"📩 Scam Risk Assessment\n\nRisk: {risk}\n"
    if findings:
        result += "\nWarning signs:\n• " + "\n• ".join(findings)
    else:
        result += "\nNo common scam phrases were detected by the basic rules."
    result += (
        "\n\nRecommended action:\n"
        "• Do not share passwords, OTPs, recovery codes, or payment details.\n"
        "• Verify the request through the organization's official app or website.\n"
        "• Do not call a number or open a link supplied by the suspicious sender.\n\n"
        "This is a heuristic assessment, not a guarantee."
    )
    await update.message.reply_text(result, reply_markup=main_menu())
    return ConversationHandler.END


# -----------------------------------------------------------------------------
# SUSPICIOUS LINK ANALYZER
# -----------------------------------------------------------------------------
SHORTENERS: Final[set[str]] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy"
}
SUSPICIOUS_TLDS: Final[set[str]] = {"zip", "mov", "top", "click", "work", "gq", "tk", "xyz"}
BRANDS: Final[set[str]] = {"paypal", "microsoft", "google", "apple", "telegram", "instagram", "facebook", "amazon", "netflix"}


def analyze_url(raw_url: str) -> tuple[int, list[str], str]:
    value = raw_url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "http://" + value

    parsed = urlparse(value)
    host = (parsed.hostname or "").lower().rstrip(".")
    findings: list[str] = []
    score = 0

    if not host:
        return 10, ["The URL has no valid hostname"], value

    if parsed.scheme != "https":
        findings.append("Does not use HTTPS")
        score += 1

    try:
        ipaddress.ip_address(host)
        findings.append("Uses an IP address instead of a normal domain")
        score += 3
    except ValueError:
        pass

    if host in SHORTENERS:
        findings.append("Uses a URL-shortening service that hides the destination")
        score += 2

    if "@" in parsed.netloc:
        findings.append("Contains @ in the authority section, which can hide the real destination")
        score += 3

    if "xn--" in host:
        findings.append("Uses an internationalized/punycode domain")
        score += 2

    if host.count(".") >= 4:
        findings.append("Contains an unusually large number of subdomains")
        score += 1

    if len(host) > 45:
        findings.append("Uses an unusually long hostname")
        score += 1

    labels = host.split(".")
    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        findings.append(f"Uses a higher-risk or frequently abused .{tld} domain extension")
        score += 1

    if any(keyword in value.lower() for keyword in ("login", "verify", "secure", "account", "update", "wallet")):
        findings.append("Contains login, verification, account, or wallet language")
        score += 1

    for brand in BRANDS:
        if brand in host and not host.endswith(f"{brand}.com"):
            findings.append(f"Mentions the brand name '{brand}' inside a different domain")
            score += 2
            break

    return score, findings, value


async def link_begin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not await enforce_rate_limit(update):
        return ConversationHandler.END
    await send_or_edit(
        update,
        "🔗 Send the full suspicious URL.\n\n"
        "The bot performs a local heuristic analysis. It does not open the page.",
    )
    return LINK_INPUT


async def link_result(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    score, findings, normalized = analyze_url(update.message.text)
    if score >= 6:
        risk = "High 🔴"
    elif score >= 3:
        risk = "Medium 🟠"
    else:
        risk = "Low or unclear 🟡"

    text = f"🔗 Link Risk Assessment\n\nRisk: {risk}\nNormalized URL: {normalized}\n"
    if findings:
        text += "\nWarning signs:\n• " + "\n• ".join(findings)
    else:
        text += "\nNo obvious warning signs were detected by the basic rules."
    text += (
        "\n\nDo not treat a low score as proof of safety. Verify the domain through an official app, bookmark, or trusted search result."
    )
    await update.message.reply_text(text, reply_markup=main_menu())
    return ConversationHandler.END


# -----------------------------------------------------------------------------
# EMERGENCY GUIDE
# -----------------------------------------------------------------------------
async def emergency_begin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not await enforce_rate_limit(update):
        return ConversationHandler.END
    context.user_data.clear()
    await send_or_edit(update, "🚨 Which account may be compromised?", account_keyboard())
    return EMERGENCY_ACCOUNT


async def emergency_account(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    context.user_data["account"] = query.data.removeprefix("em_account_").title()
    await query.edit_message_text("Can you still log in to the account?", reply_markup=yes_no_keyboard("emaccess"))
    return EMERGENCY_ACCESS


async def emergency_access(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    context.user_data["access"] = bool_from_callback(query.data)
    await query.edit_message_text("Did you share an OTP, recovery code, or password?", reply_markup=yes_no_keyboard("emotp"))
    return EMERGENCY_OTP


async def emergency_otp(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    context.user_data["shared_secret"] = bool_from_callback(query.data)
    await query.edit_message_text("Did you open a suspicious link or install a file/app?", reply_markup=yes_no_keyboard("emlink"))
    return EMERGENCY_LINK


async def emergency_result(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    opened_link = bool_from_callback(query.data)
    account = context.user_data.get("account", "Account")
    access = context.user_data.get("access", False)
    shared = context.user_data.get("shared_secret", False)

    steps = []
    if access:
        steps.append("From a trusted device, change the password to a new unique password.")
        steps.append("Sign out of every other active session or device.")
    else:
        steps.append("Use the service's official account-recovery page or app. Do not use links sent by strangers.")
        steps.append("Secure the recovery email account first, because it may control account recovery.")

    if shared:
        steps.append("Treat the shared password, OTP, or recovery code as compromised. Replace credentials immediately.")
    if opened_link:
        steps.append("Disconnect and scan the device, remove unknown apps/extensions, and update the operating system and browser.")

    steps.extend([
        "Enable MFA, preferably a passkey or security key when available.",
        "Verify recovery email addresses, phone numbers, forwarding rules, and connected applications.",
        "Review recent logins, messages, purchases, and security notifications.",
        "Warn contacts if the account sent suspicious messages.",
        "Contact the service through its official support channel if recovery fails.",
    ])

    text = f"🚨 {account} Recovery Plan\n\n"
    text += "\n".join(f"{i}. {step}" for i, step in enumerate(steps, 1))
    text += "\n\nIf money was stolen, contact the bank/payment provider immediately and preserve screenshots and transaction details."
    await query.edit_message_text(text, reply_markup=main_menu())
    context.user_data.clear()
    return ConversationHandler.END


# -----------------------------------------------------------------------------
# SECURITY CHECKLIST
# -----------------------------------------------------------------------------
CHECKLIST_QUESTIONS: Final[list[tuple[int, str, str]]] = [
    (CHECKLIST_UNIQUE, "unique", "Do you use a unique password for this account?"),
    (CHECKLIST_MFA, "mfa", "Is multi-factor authentication enabled?"),
    (CHECKLIST_RECOVERY, "recovery", "Are recovery methods current and recovery codes stored safely?"),
    (CHECKLIST_SESSIONS, "sessions", "Have you reviewed active sessions/devices recently?"),
    (CHECKLIST_UPDATES, "updates", "Is the device and browser fully updated?"),
]


async def checklist_begin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not await enforce_rate_limit(update):
        return ConversationHandler.END
    context.user_data.clear()
    await send_or_edit(update, CHECKLIST_QUESTIONS[0][2], yes_no_keyboard("cl_unique"))
    return CHECKLIST_UNIQUE


async def checklist_step(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    current_state = None
    for state, key, _ in CHECKLIST_QUESTIONS:
        if query.data.startswith(f"cl_{key}_"):
            current_state = state
            context.user_data[f"check_{key}"] = bool_from_callback(query.data)
            break

    if current_state is None:
        return ConversationHandler.END

    index = next(i for i, item in enumerate(CHECKLIST_QUESTIONS) if item[0] == current_state)
    if index + 1 < len(CHECKLIST_QUESTIONS):
        next_state, next_key, question = CHECKLIST_QUESTIONS[index + 1]
        await query.edit_message_text(question, reply_markup=yes_no_keyboard(f"cl_{next_key}"))
        return next_state

    weights = {"unique": 25, "mfa": 25, "recovery": 20, "sessions": 15, "updates": 15}
    score = sum(weight for key, weight in weights.items() if context.user_data.get(f"check_{key}"))
    missing = [key for key in weights if not context.user_data.get(f"check_{key}")]
    labels = {
        "unique": "Use a unique password",
        "mfa": "Enable MFA",
        "recovery": "Secure recovery methods and codes",
        "sessions": "Review active sessions",
        "updates": "Install device and browser updates",
    }

    if score >= 85:
        rating = "Excellent 🟢"
    elif score >= 60:
        rating = "Good, but improve the missing controls 🟠"
    else:
        rating = "Needs attention 🔴"

    text = f"✅ Security Score: {score}/100\nRating: {rating}\n"
    if missing:
        text += "\nNext actions:\n• " + "\n• ".join(labels[key] for key in missing)
    await query.edit_message_text(text, reply_markup=main_menu())
    context.user_data.clear()
    return ConversationHandler.END


# -----------------------------------------------------------------------------
# CANCEL AND ERROR HANDLING
# -----------------------------------------------------------------------------
async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data.clear()
    await send_or_edit(update, "❌ Operation cancelled.", main_menu())
    return ConversationHandler.END


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    error = context.error
    if isinstance(error, (NetworkError, TimedOut)):
        logger.warning("Temporary Telegram network problem: %s", error)
        return
    logger.error("Unhandled exception", exc_info=(type(error), error, error.__traceback__))


# -----------------------------------------------------------------------------
# APPLICATION SETUP
# -----------------------------------------------------------------------------
def build_application() -> Application:
    if not BOT_TOKEN:
        raise RuntimeError(
            "BOT_TOKEN is missing. Add it as an environment variable before running the bot."
        )

    app = (
        Application.builder()
        .token(BOT_TOKEN)
        .connect_timeout(30)
        .read_timeout(30)
        .write_timeout(30)
        .build()
    )

    password_conversation = ConversationHandler(
        entry_points=[
            CommandHandler("password", generate_begin),
            CallbackQueryHandler(generate_begin, pattern=r"^menu_generate$"),
        ],
        states={
            GEN_LENGTH: [MessageHandler(filters.TEXT & ~filters.COMMAND, generate_length)],
            GEN_UPPER: [CallbackQueryHandler(generate_upper, pattern=r"^upper_(yes|no)$")],
            GEN_LOWER: [CallbackQueryHandler(generate_lower, pattern=r"^lower_(yes|no)$")],
            GEN_NUMBERS: [CallbackQueryHandler(generate_numbers, pattern=r"^numbers_(yes|no)$")],
            GEN_SPECIAL: [CallbackQueryHandler(generate_special, pattern=r"^special_(yes|no)$")],
            GEN_AMBIGUOUS: [CallbackQueryHandler(generate_ambiguous, pattern=r"^ambiguous_(yes|no)$")],
            GEN_COUNT: [MessageHandler(filters.TEXT & ~filters.COMMAND, generate_count)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )

    strength_conversation = ConversationHandler(
        entry_points=[
            CommandHandler("strength", strength_begin),
            CallbackQueryHandler(strength_begin, pattern=r"^menu_strength$"),
        ],
        states={STRENGTH_INPUT: [MessageHandler(filters.TEXT & ~filters.COMMAND, strength_result)]},
        fallbacks=[CommandHandler("cancel", cancel)],
    )

    breach_conversation = ConversationHandler(
        entry_points=[
            CommandHandler("breach", breach_begin),
            CallbackQueryHandler(breach_begin, pattern=r"^menu_breach$"),
        ],
        states={
            BREACH_CONFIRM: [CallbackQueryHandler(breach_confirm, pattern=r"^breachconfirm_(yes|no)$")],
            BREACH_INPUT: [MessageHandler(filters.TEXT & ~filters.COMMAND, breach_result)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )

    scam_conversation = ConversationHandler(
        entry_points=[
            CommandHandler("scam", scam_begin),
            CallbackQueryHandler(scam_begin, pattern=r"^menu_scam$"),
        ],
        states={SCAM_INPUT: [MessageHandler(filters.TEXT & ~filters.COMMAND, scam_result)]},
        fallbacks=[CommandHandler("cancel", cancel)],
    )

    link_conversation = ConversationHandler(
        entry_points=[
            CommandHandler("link", link_begin),
            CallbackQueryHandler(link_begin, pattern=r"^menu_link$"),
        ],
        states={LINK_INPUT: [MessageHandler(filters.TEXT & ~filters.COMMAND, link_result)]},
        fallbacks=[CommandHandler("cancel", cancel)],
    )

    emergency_conversation = ConversationHandler(
        entry_points=[
            CommandHandler("emergency", emergency_begin),
            CallbackQueryHandler(emergency_begin, pattern=r"^menu_emergency$"),
        ],
        states={
            EMERGENCY_ACCOUNT: [CallbackQueryHandler(emergency_account, pattern=r"^em_account_")],
            EMERGENCY_ACCESS: [CallbackQueryHandler(emergency_access, pattern=r"^emaccess_(yes|no)$")],
            EMERGENCY_OTP: [CallbackQueryHandler(emergency_otp, pattern=r"^emotp_(yes|no)$")],
            EMERGENCY_LINK: [CallbackQueryHandler(emergency_result, pattern=r"^emlink_(yes|no)$")],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )

    checklist_conversation = ConversationHandler(
        entry_points=[
            CommandHandler("checklist", checklist_begin),
            CallbackQueryHandler(checklist_begin, pattern=r"^menu_checklist$"),
        ],
        states={
            CHECKLIST_UNIQUE: [CallbackQueryHandler(checklist_step, pattern=r"^cl_unique_(yes|no)$")],
            CHECKLIST_MFA: [CallbackQueryHandler(checklist_step, pattern=r"^cl_mfa_(yes|no)$")],
            CHECKLIST_RECOVERY: [CallbackQueryHandler(checklist_step, pattern=r"^cl_recovery_(yes|no)$")],
            CHECKLIST_SESSIONS: [CallbackQueryHandler(checklist_step, pattern=r"^cl_sessions_(yes|no)$")],
            CHECKLIST_UPDATES: [CallbackQueryHandler(checklist_step, pattern=r"^cl_updates_(yes|no)$")],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("tips", tips))
    app.add_handler(CommandHandler("cancel", cancel))

    app.add_handler(CallbackQueryHandler(start, pattern=r"^menu_start$"))
    app.add_handler(CallbackQueryHandler(help_command, pattern=r"^menu_help$"))
    app.add_handler(CallbackQueryHandler(tips, pattern=r"^menu_tip$"))

    app.add_handler(password_conversation)
    app.add_handler(strength_conversation)
    app.add_handler(breach_conversation)
    app.add_handler(scam_conversation)
    app.add_handler(link_conversation)
    app.add_handler(emergency_conversation)
    app.add_handler(checklist_conversation)

    app.add_error_handler(error_handler)
    return app


def main() -> None:
    app = build_application()
    print("✅ SmartSecurityBot is running. Press Ctrl+C to stop it.")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
