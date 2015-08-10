import json
from jwkest.jwt import JWT

__author__ = 'roland'


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_pack_jwt():
    _jwt = JWT(**{"alg": "none", "cty": "jwt"})
    jwt = _jwt.pack(parts=[{"iss": "joe", "exp": 1300819380,
                            "http://example.com/is_root": True}, ""])

    p = jwt.split('.')
    assert len(p) == 3


def test_pack_unpack():
    _jwt = JWT(**{"alg": "none"})
    payload = {"iss": "joe", "exp": 1300819380,
               "http://example.com/is_root": True}
    jwt = _jwt.pack(parts=[payload, ""])

    _jwt2 = JWT().unpack(jwt)

    assert _jwt2
    out_payload = _jwt2.payload()
    assert _eq(out_payload.keys(), ["iss", "exp", "http://example.com/is_root"])
    assert out_payload["iss"] == payload["iss"]
    assert out_payload["exp"] == payload["exp"]
    assert out_payload["http://example.com/is_root"] == payload[
        "http://example.com/is_root"]


def test_unpack_str():
    _jwt = JWT(**{"alg": "none"})
    payload = {"iss": "joe", "exp": 1300819380,
               "http://example.com/is_root": True}
    jwt = _jwt.pack(parts=[payload, ""])

    jwt = jwt.decode('utf-8')

    _jwt2 = JWT().unpack(jwt)
    assert _jwt2
    out_payload = _jwt2.payload()


if __name__ == "__main__":
    test_unpack_str()
