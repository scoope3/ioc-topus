from ioc_topus.core.ioc import validate_ioc, IOC
from ioc_topus.core.merge import merge_api_results


def test_validate_ioc():
    assert validate_ioc("23.106.253.194") == "ip_address"
    assert validate_ioc("https://u1.establishhertz.shop/fzqgh4orzn.aac") == "url"
    assert validate_ioc("45b41525494546333fdc8e0065e432c583229997c3fe6685fee05004d8de81e8") == "file_hash"


def test_ioc_dataclass():
    obj = IOC("innerteams.us")
    assert obj.type == "domain"
    assert str(obj) == "innerteams.us"


def test_merge_keeps_truthy():
    a = ("ioc", "domain", {"field": "value"}, ["A"], None)
    b = ("ioc", "domain", {"field": ""}, ["B"], None)
    merged = merge_api_results(a, b)
    assert merged[2]["field"] == "value"
    assert set(merged[3]) == {"A", "B"}
