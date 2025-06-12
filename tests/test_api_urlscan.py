"""Unit-tests for UrlscanClient (SecurityTrails)."""

import json
import queue
import os

import pytest
import responses

from ioc_topus.api.urlscan import UrlscanClient

@pytest.fixture(autouse=True)
def _dummy_key(monkeypatch):
    monkeypatch.setenv("SECURITYTRAILS_API_KEY", "DUMMY")
    yield
    monkeypatch.delenv("SECURITYTRAILS_API_KEY", raising=False)


US = UrlscanClient()                    # dummy key
SEARCH = "https://urlscan.io/api/v1/search/"
RESULT = "https://urlscan.io/api/v1/result/"


@responses.activate
def test_domain_search_and_result():
    domain = "innerteams.us"
    search_q = f"domain:{domain}"

    # 1) /search (one hit with ID abc123)
    responses.add(
        responses.GET,
        SEARCH,
        match=[responses.matchers.query_param_matcher({"q": search_q, "size": "100"})],
        json={
            "results": [
                {
                    "_id": "abc123",
                    "task": {"time": "2024-01-01T00:00:00Z"},
                    "page": {"ip": "23.106.253.194"},   # ← add this line
                }
            ]
        },
        status=200,
    )

    # 2) /result/abc123
    responses.add(
        responses.GET,
        f"{RESULT}abc123/",
        json={
            "page": {"ip": "23.106.253.194"},
            "lists": {
                "urls": [],          # ← new (requested_urls comes from here)
                "ips": [],
                "asns": [],
                "domains": [],
                "servers": [],
                "certificates": [],
                "hashes": [],
            },
            "task": {"time": "2024-01-01T00:00:00Z"},
        },
        status=200,
    )

    q = queue.Queue()
    US.query_ioc(domain, "domain", q)
    ioc, typ, data, srcs, err = q.get_nowait()

    assert err is None
    assert data["securitytrails_sections"]["urlscan Webpage Analysis"]["analysis"][0]["webpage_ip"] == "23.106.253.194"
