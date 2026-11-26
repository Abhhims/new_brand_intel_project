"""Google Workspace intake (optional). Reads a label via the Gmail API with a service account.

Implements the same fetch_new() interface as ImapSource. Requires a service account with domain-wide delegation and
the gmail.readonly scope; credentials come from config (gmail_*). Enable by setting GMAIL_* in .env.
"""

from __future__ import annotations

import base64

import structlog

from app.config import get_settings

log = structlog.get_logger(__name__)


class GmailSource:
    def __init__(self, service_account_json: str, delegated_user: str, label: str = "INBOX") -> None:
        self.service_account_json, self.delegated_user, self.label = service_account_json, delegated_user, label

    def _service(self):
        try:
            from google.oauth2 import service_account
            from googleapiclient.discovery import build

            creds = service_account.Credentials.from_service_account_file(
                self.service_account_json, scopes=["https://www.googleapis.com/auth/gmail.readonly"]
            ).with_subject(self.delegated_user)
            return build("gmail", "v1", credentials=creds, cache_discovery=False)
        except Exception as exc:  # noqa: BLE001 - google libraries optional / not installed
            log.warning("gmail_service_failed", error=str(exc)[:150])
            return None

    def fetch_new(self, mark_seen: bool = False, limit: int = 50) -> list[tuple[str, bytes]]:
        service = self._service()
        if service is None:
            return []
        try:
            listing = service.users().messages().list(
                userId="me", q="is:unread", labelIds=[self.label], maxResults=limit).execute()
            out = []
            for item in listing.get("messages", []):
                msg = service.users().messages().get(userId="me", id=item["id"], format="raw").execute()
                raw = base64.urlsafe_b64decode(msg["raw"])
                out.append((item["id"], raw))
                if mark_seen:
                    service.users().messages().modify(
                        userId="me", id=item["id"], body={"removeLabelIds": ["UNREAD"]}).execute()
            return out
        except Exception as exc:  # noqa: BLE001
            log.warning("gmail_fetch_failed", error=str(exc)[:150])
            return []


def source_from_config() -> GmailSource | None:
    s = get_settings()
    if s.gmail_service_account_json and s.gmail_delegated_user:
        return GmailSource(s.gmail_service_account_json, s.gmail_delegated_user, s.gmail_label)
    return None
