# Deployment checklist

1. Revoke any token that has appeared in screenshots, browser history, chat messages, or logs.
2. Create a new token with BotFather.
3. Add the token to the hosting provider as `BOT_TOKEN` or `TELEGRAM_BOT_TOKEN`.
4. Install dependencies with `pip install -r requirements.txt`.
5. Use `python app.py` as the start command.
6. Stop every local instance before starting the hosted instance.
7. Confirm that logs contain `Application started` and no `409 Conflict`.
8. Test `/start`, `/password`, `/strength`, `/breach`, `/scam`, `/link`, `/emergency`, `/checklist`, `/tips`, and `/cancel`.
