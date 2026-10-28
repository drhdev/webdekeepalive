import os
import socket
import sys

import pytest
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Tests must never reach a real server: every HTTP, IMAP or SMTP connection that is not faked fails loudly."""
    def blocked(*args, **kwargs):
        raise RuntimeError("Network access is disabled in tests")
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr("webdekeepalive.time.sleep", lambda seconds: None)
