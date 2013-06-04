from binascii import hexlify
import json
import M2Crypto
from jwkest import jwe
from jwkest.jwk import dump_jwk
from jwkest.jwk import RSA_key
from jwkest.jwk import long_to_mpi
from jwkest.jwk import base64_to_long
from jwkest.jwk import load_jwks
from jwkest.jwk import x509_rsa_loads
from jwkest.jwk import rsa_load
from jwkest.jwk import rsa_loads
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


def test_x509_rsa_loads():
    _ckey = x509_rsa_loads(open(CERT).read())
    assert isinstance(_ckey, M2Crypto.RSA.RSA_pub)


def test_x509_rsa_loads_2():
    _ckey = x509_rsa_loads(open(CERT).read())
    _jwk = RSA_key(key=_ckey)
    _jwk.decomp()

    print _jwk

    _n = long_to_mpi(base64_to_long(str(_jwk.n)))

    cn = jwe.hd2ia(hexlify(_ckey.n))
    jn = jwe.hd2ia(hexlify(_n))

    assert cn == jn


def test_kspec():
    _ckey = x509_rsa_loads(open(CERT).read())
    _jwk = RSA_key(key=_ckey)
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

    _ckey = x509_rsa_loads(open(CERT).read())

    print key
    _n = long_to_mpi(base64_to_long(str(key.n)))
    assert _n == _ckey.n
    _e = long_to_mpi(base64_to_long(str(key.e)))
    assert _e == _ckey.e


def test_loads_1():
    JWK = {
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

    keys = load_jwks(json.dumps(JWK))
    print keys
    assert len(keys) == 2
    kids = [k.kid for k in keys]
    assert _eq(kids, ["1", "2"])


def test_dumps():
    _ckey = x509_rsa_loads(open(CERT).read())
    jwk = dump_jwk(_ckey)
    assert _eq(jwk.keys(), ["kty", "e", "n"])


def test_dump_jwk():
    _ckey = x509_rsa_loads(open(CERT).read())
    jwk = dump_jwks([{"key": _ckey}])
    print jwk
    _wk = json.loads(jwk)
    assert _wk.keys() == ["keys"]
    assert len(_wk["keys"]) == 1
    assert _eq(_wk["keys"][0].keys(), ["kty", "e", "n"])


def test_load_jwk():
    _ckey = x509_rsa_loads(open(CERT).read())
    jwk = dump_jwks([{"key": _ckey}])
    wk = load_jwks(jwk)
    print wk
    assert len(wk) == 1
    key = wk[0]
    assert key.kty == "RSA"
    assert isinstance(key.key, M2Crypto.RSA.RSA)


def test_rsa_load():
    _ckey = rsa_load(KEY)
    assert isinstance(_ckey, M2Crypto.RSA.RSA)
    jwk = dump_jwk(_ckey)
    print jwk
    assert _eq(jwk.keys(), ["kty", "e", "n"])
    assert jwk["n"] == '5zbNbHIYIkGGJ3RGdRKkYmF4gOorv5eDuUKTVtuu3VvxrpOWvwnFV-NY0LgqkQSMMyVzodJE3SUuwQTUHPXXY5784vnkFqzPRx6bHgPxKz7XfwQjEBTafQTMmOeYI8wFIOIHY5i0RWR-gxDbh_D5TXuUqScOOqR47vSpIbUH-nc'
    assert jwk['e'] == 'AQAB'


def test_rsa_loads():
    _ckey = rsa_loads(open(KEY).read())
    assert isinstance(_ckey, M2Crypto.RSA.RSA)
    jwk = dump_jwk(_ckey)
    print jwk
    assert _eq(jwk.keys(), ["kty", "e", "n"])
    assert jwk["n"] == '5zbNbHIYIkGGJ3RGdRKkYmF4gOorv5eDuUKTVtuu3VvxrpOWvwnFV-NY0LgqkQSMMyVzodJE3SUuwQTUHPXXY5784vnkFqzPRx6bHgPxKz7XfwQjEBTafQTMmOeYI8wFIOIHY5i0RWR-gxDbh_D5TXuUqScOOqR47vSpIbUH-nc'
    assert jwk['e'] == 'AQAB'

if __name__ == "__main__":
    test_dumps()