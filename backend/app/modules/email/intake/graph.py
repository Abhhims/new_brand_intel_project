"""Microsoft 365 intake (optional). Reads a reported-phishing folder via Microsoft Graph.

Implements the same fetch_new() interface as ImapSource. Requires an app registration with Mail.Read application
permission and admin consent; credentials come from config (ms_graph_*). Left as a thin adapter: the mailbox poller
uses whichever source is configured. Enable by setting MS_GRAPH_* in .env.
"""

from __future__ import annotations

import structlog

from app.config import get_settings
from app.core.fetch import fetch

log = structlog.get_logger(__name__)


class GraphSource:
    def __init__(self, tenant: str, client_id: str, client_secret: str, user: str, folder: str = "Inbox") -> None:
        self.tenant, self.client_id, self.client_secret = tenant, client_id, client_secret
        self.user, self.folder = user, folder

    def _token(self) -> str | None:
        import httpx

        url = f"https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/token"
        try:
            with httpx.Client(timeout=15.0) as client:
                resp = client.post(url, data={"client_id": self.client_id, "client_secret": self.client_secret,
                                              "scope": "https://graph.microsoft.com/.default",
                                              "grant_type": "client_credentials"})
            return resp.json().get("access_token") if resp.status_code == 200 else None
        except Exception as exc:  # noqa: BLE001
            log.warning("graph_token_failed", error=str(exc)[:150])
            return None

    def fetch_new(self, mark_seen: bool = False, limit: int = 50) -> list[tuple[str, bytes]]:
        token = self._token()
        if not token:
            return []
        base = f"https://graph.microsoft.com/v1.0/users/{self.user}/mailFolders/{self.folder}/messages"
        try:
            listing = fetch(f"{base}?$filter=isRead eq false&$top={limit}&$select=id",
                            headers={"Authorization": f"Bearer {token}"})
            import json

            ids = [m["id"] for m in json.loads(listing.content or b"{}").get("value", [])]
        except Exception as exc:  # noqa: BLE001
            log.warning("graph_list_failed", error=str(exc)[:150])
            return []
        out = []
        for mid in ids:
            raw = fetch(f"{base}/{mid}/$value", headers={"Authorization": f"Bearer {token}"})
            if raw.status == 200 and raw.content:
                out.append((mid, raw.content))
                if mark_seen:
                    _mark_read(base, mid, token)
        return out


def _mark_read(base: str, mid: str, token: str) -> None:
    import httpx

    try:
        with httpx.Client(timeout=10.0) as client:
            client.patch(f"{base}/{mid}", json={"isRead": True},
                         headers={"Authorization": f"Bearer {token}"})
    except Exception:  # noqa: BLE001
        pass


def source_from_config() -> GraphSource | None:
    s = get_settings()
    if all([s.ms_graph_tenant, s.ms_graph_client_id, s.ms_graph_client_secret, s.ms_graph_user]):
        return GraphSource(s.ms_graph_tenant, s.ms_graph_client_id, s.ms_graph_client_secret, s.ms_graph_user,
                           s.ms_graph_folder)
    return None
