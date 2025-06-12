import queue
from ioc_topus.api import validin

def _fake_domain_call(domain, q):
    q.put((domain, "domain", {"validin": "ok"}, ["Validin API"], None))

def _fake_ip_call(ip, q):
    q.put((ip, "ip_address", {"validin": "ok"}, ["Validin API"], None))

def test_validin_stubs(monkeypatch):
    monkeypatch.setattr(validin, "query_validin_domain", _fake_domain_call)
    monkeypatch.setattr(validin, "query_validin_ip", _fake_ip_call)

    q = queue.Queue()
    validin.query_validin_domain("example.com", q)
    _, _, data, srcs, err = q.get_nowait()
    assert data["validin"] == "ok"
