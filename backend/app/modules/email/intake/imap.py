"""Fetch new messages from an IMAP reporting mailbox (phishing@... or dmarc@...)."""

from __future__ import annotations

import imaplib

import structlog

log = structlog.get_logger(__name__)


class ImapSource:
    def __init__(self, host: str, user: str, password: str, port: int = 993, mailbox: str = "INBOX",
                 processed_mailbox: str = "Processed") -> None:
        self.host, self.port, self.user, self.password = host, port, user, password
        self.mailbox, self.processed_mailbox = mailbox, processed_mailbox

    def fetch_new(self, mark_seen: bool = False, limit: int = 200) -> list[tuple[str, bytes]]:
        """Return (uid, raw-bytes) for UNSEEN messages. With mark_seen, flag them \\Seen after reading."""
        out: list[tuple[str, bytes]] = []
        client = imaplib.IMAP4_SSL(self.host, self.port)
        try:
            client.login(self.user, self.password)
            client.select(self.mailbox)
            status, data = client.search(None, "UNSEEN")
            if status != "OK" or not data or not data[0]:
                return out
            uids = data[0].split()[:limit]
            for uid in uids:
                status, msg = client.fetch(uid, "(RFC822)")
                if status != "OK" or not msg:
                    continue
                raw = next((part[1] for part in msg if isinstance(part, tuple) and part[1]), None)
                if raw:
                    out.append((uid.decode() if isinstance(uid, bytes) else str(uid), raw))
                    if mark_seen:
                        client.store(uid, "+FLAGS", "\\Seen")
        except Exception as exc:  # noqa: BLE001 - connection / auth failures are reported, not raised into beat
            log.warning("imap_fetch_failed", host=self.host, error=str(exc)[:200])
            raise
        finally:
            try:
                client.logout()
            except Exception:  # noqa: BLE001
                pass
        return out
