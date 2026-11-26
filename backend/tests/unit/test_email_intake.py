import pytest

from app.modules.email.intake.imap import ImapSource

pytestmark = pytest.mark.req("EML-19")


class _FakeIMAP:
    """Minimal imaplib.IMAP4_SSL stand-in holding two UNSEEN messages."""

    MESSAGES = {b"1": b"From: a@x.test\r\nSubject: one\r\n\r\nbody one\r\n",
                b"2": b"From: b@y.test\r\nSubject: two\r\n\r\nbody two\r\n"}

    def __init__(self, host, port=993):
        self.seen: set[bytes] = set()
        self.selected = None

    def login(self, user, password):
        return "OK", []

    def select(self, mailbox):
        self.selected = mailbox
        return "OK", [str(len(self.MESSAGES)).encode()]

    def search(self, charset, *criteria):
        unseen = [uid for uid in self.MESSAGES if uid not in self.seen]
        return "OK", [b" ".join(unseen)]

    def fetch(self, uid, parts):
        return "OK", [(f"{uid.decode()} (RFC822)".encode(), self.MESSAGES[uid]), b")"]

    def store(self, uid, flags, value):  # mark \Seen
        self.seen.add(uid)
        return "OK", []

    def list(self):
        return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

    def logout(self):
        return "OK", []


def test_fetch_new_returns_unseen(monkeypatch):
    fake = _FakeIMAP("h")
    monkeypatch.setattr("imaplib.IMAP4_SSL", lambda host, port=993: fake)
    src = ImapSource(host="h", port=993, user="u", password="p", mailbox="INBOX")
    messages = src.fetch_new()
    assert len(messages) == 2
    assert b"body one" in messages[0][1]


def test_second_poll_skips_seen(monkeypatch):
    fake = _FakeIMAP("h")
    monkeypatch.setattr("imaplib.IMAP4_SSL", lambda host, port=993: fake)
    src = ImapSource(host="h", port=993, user="u", password="p", mailbox="INBOX")
    first = src.fetch_new(mark_seen=True)
    assert len(first) == 2
    second = ImapSource(host="h", port=993, user="u", password="p", mailbox="INBOX")
    # same fake instance keeps the seen set
    monkeypatch.setattr("imaplib.IMAP4_SSL", lambda host, port=993: fake)
    assert src.fetch_new() == [] or second.fetch_new() == []
