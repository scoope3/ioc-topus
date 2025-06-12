"""Unit-tests for VirusTotalClient (no real HTTP)."""

import json
import queue
import os

import pytest
import responses

from ioc_topus.api.virustotal import VirusTotalClient

# ----------------------------------------------------------------------
# Fixture: patch env var so the client doesn't raise “missing key”
# ----------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _dummy_key(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "DUMMY")
    yield
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)


# ----------------------------------------------------------------------
# Helper / constants
# ----------------------------------------------------------------------
VT = VirusTotalClient()       # picks up dummy key
BASE = "https://www.virustotal.com/api/v3"


# ----------------------------------------------------------------------
# Happy-path test for an IP address
# ----------------------------------------------------------------------
@responses.activate
def test_query_ip_returns_reputation():
    ip = "23.106.253.194"
    url = f"{BASE}/ip_addresses/{ip}"

    fake_body = {
        "data": {
            "id": ip,
            "type": "ip_address",
            "attributes": {"reputation": 99},
        }
    }

    responses.add(responses.GET, url, json=fake_body, status=200)

    q = queue.Queue()
    VT.query_ioc(ip, "ip_address", q)

    ioc, typ, full, srcs, err = q.get_nowait()

    assert err is None
    assert srcs == ["VirusTotal API"]
    assert full["attributes"]["reputation"] == 99
