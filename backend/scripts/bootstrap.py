"""Create the first admin account if no users exist (run on API start-up)."""

from sqlalchemy import func, select

from app.config import get_settings
from app.core.security import hash_password
from app.db.models import Role, User
from app.db.session import session_scope


def main() -> None:
    s = get_settings()
    with session_scope() as db:
        if (db.scalar(select(func.count()).select_from(User)) or 0) > 0:
            print("bootstrap: users already exist, nothing to do")
            return
        db.add(User(email=s.bootstrap_admin_email.lower(), name="Administrator",
                    password_hash=hash_password(s.bootstrap_admin_password), role=Role.admin))
        print(f"bootstrap: created admin {s.bootstrap_admin_email} — change the password after first login")


if __name__ == "__main__":
    main()
