from binascii import hexlify
import json
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import _RSAobj
from jwkest.jwk import dump_jwk
from jwkest.jwk import pem_cert2rsa
from jwkest.jwk import RSAKey
from jwkest.jwk import base64_to_long
from jwkest.jwk import load_jwks
from jwkest.jwk import dump_jwks

__author__ = 'rohe0002'

CERT = "certs/cert.pem"
KEY = "certs/server.key"

JWK = {"keys": [
    {'kty': 'RSA', 'use': 'foo', 'e': 'AQAB', 'kid': "abc",
     'n': 'wf-wiusGhA-gleZYQAOPQlNUIucPiqXdPVyieDqQbXXOPBe3nuggtVzeq7pVFH1dZz4dY2Q2LA5DaegvP8kRvoSB_87ds3dy3Rfym_GUSc5B0l1TgEobcyaep8jguRoHto6GWHfCfKqoUYZq4N8vh4LLMQwLR6zi6Jtu82nB5k8'}
]}


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_pem_cert2rsa():
    _ckey = pem_cert2rsa(CERT)
    assert isinstance(_ckey, _RSAobj)


def test_extract_rsa_from_cert_2():
    _ckey = pem_cert2rsa(CERT)
    _jwk = RSAKey(key=_ckey)
    _jwk.decomp()

    print _jwk

    _n = base64_to_long(str(_jwk.n))

    assert _ckey.n == _n


def test_kspec():
    _ckey = pem_cert2rsa(CERT)
    _jwk = RSAKey(key=_ckey)
    _jwk.decomp()

    print _jwk
    assert _jwk.kty == "RSA"
    assert _jwk.e == JWK["keys"][0]["e"]
    assert _jwk.n == JWK["keys"][0]["n"]


def test_loads_0():
    keys = load_jwks(json.dumps(JWK))
    assert len(keys) == 1
    key = keys[0]
    assert key.kid == "abc"
    assert key.kty == "RSA"

    _ckey = pem_cert2rsa(CERT)

    print key
    _n = base64_to_long(str(key.n))
    assert _n == _ckey.n
    _e = base64_to_long(str(key.e))
    assert _e == _ckey.e


def test_loads_1():
    jwk = {
        "keys": [
            {
                'kty': 'RSA',
                'use': 'foo',
                'e': 'AQAB',
                "n": 'wf-wiusGhA-gleZYQAOPQlNUIucPiqXdPVyieDqQbXXOPBe3nuggtVzeq7pVFH1dZz4dY2Q2LA5DaegvP8kRvoSB_87ds3dy3Rfym_GUSc5B0l1TgEobcyaep8jguRoHto6GWHfCfKqoUYZq4N8vh4LLMQwLR6zi6Jtu82nB5k8',
                'kid': "1"
            }, {
                'kty': 'RSA',
                'use': 'bar',
                'e': 'AQAB',
                "n": 'wf-wiusGhA-gleZYQAOPQlNUIucPiqXdPVyieDqQbXXOPBe3nuggtVzeq7pVFH1dZz4dY2Q2LA5DaegvP8kRvoSB_87ds3dy3Rfym_GUSc5B0l1TgEobcyaep8jguRoHto6GWHfCfKqoUYZq4N8vh4LLMQwLR6zi6Jtu82nB5k8',
                'kid': "2"
            }
        ]
    }

    keys = load_jwks(json.dumps(jwk))
    print keys
    assert len(keys) == 2
    kids = [k.kid for k in keys]
    assert _eq(kids, ["1", "2"])


def test_dumps():
    _ckey = pem_cert2rsa(CERT)
    jwk = dump_jwk(_ckey)
    assert _eq(jwk.keys(), ["kty", "e", "n"])


def test_dump_jwk():
    _ckey = pem_cert2rsa(CERT)
    jwk = dump_jwks([{"key": _ckey}])
    print jwk
    _wk = json.loads(jwk)
    assert _wk.keys() == ["keys"]
    assert len(_wk["keys"]) == 1
    assert _eq(_wk["keys"][0].keys(), ["kty", "e", "n"])


def test_load_jwk():
    _ckey = pem_cert2rsa(CERT)
    jwk = dump_jwks([{"key": _ckey}])
    wk = load_jwks(jwk)
    print wk
    assert len(wk) == 1
    key = wk[0]
    assert key.kty == "RSA"
    assert isinstance(key.key, _RSAobj)


def test_import_rsa_key():
    _ckey = RSA.importKey(open(KEY, 'r').read())
    assert isinstance(_ckey, _RSAobj)
    jwk = dump_jwk(_ckey)
    print jwk
    assert _eq(jwk.keys(), ["kty", "e", "n"])
    assert jwk["n"] == '5zbNbHIYIkGGJ3RGdRKkYmF4gOorv5eDuUKTVtuu3VvxrpOWvwnFV-NY0LgqkQSMMyVzodJE3SUuwQTUHPXXY5784vnkFqzPRx6bHgPxKz7XfwQjEBTafQTMmOeYI8wFIOIHY5i0RWR-gxDbh_D5TXuUqScOOqR47vSpIbUH-nc'
    assert jwk['e'] == 'AQAB'


if __name__ == "__main__":
    test_pem_cert2rsa()