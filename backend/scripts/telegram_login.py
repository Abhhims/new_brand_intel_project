"""One-time Telegram login for the social module (D-10).

Needs TELEGRAM_API_ID and TELEGRAM_API_HASH (from https://my.telegram.org) in the environment / .env.
Asks for the monitoring account's phone number and the login code Telegram sends, then prints a
session string to put in TELEGRAM_SESSION. Run interactively:

    python -m scripts.telegram_login
    docker compose -f deploy/docker-compose.yml exec -it api python -m scripts.telegram_login
"""

from telethon.sessions import StringSession
from telethon.sync import TelegramClient

from app.config import get_settings


def main() -> None:
    s = get_settings()
    if not (s.telegram_api_id and s.telegram_api_hash):
        raise SystemExit("Set TELEGRAM_API_ID and TELEGRAM_API_HASH first (https://my.telegram.org → API development tools)")
    with TelegramClient(StringSession(), s.telegram_api_id, s.telegram_api_hash) as client:
        me = client.get_me()
        print(f"\nLogged in as {me.first_name} (@{me.username}).")
        print("Add this line to deploy/.env and restart the workers — keep it secret, it is a login:\n")
        print(f"TELEGRAM_SESSION={client.session.save()}\n")


if __name__ == "__main__":
    main()
