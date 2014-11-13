import base64
import json
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import _RSAobj
import struct
from cryptlib.ecc import P256
from jwkest.jwk import dump_jwk
from jwkest.jwk import ECKey
from jwkest.jwk import byte_arr
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


def test_urlsafe_base64decode():
    l = base64_to_long(JWK["keys"][0]["n"])
    # convert it to base64
    bys = byte_arr(l)
    data = struct.pack('%sB' % len(bys), *bys)
    if not len(data):
        data = '\x00'
    s0 = base64.b64encode(data)
    # try to convert it back to long, should throw an exception
    try:
        l = base64_to_long(s0)
    except ValueError:
        pass
    else:
        assert False


def test_pem_cert2rsa():
    _ckey = pem_cert2rsa(CERT)
    assert isinstance(_ckey, _RSAobj)


def test_extract_rsa_from_cert_2():
    _ckey = pem_cert2rsa(CERT)
    _key = RSAKey()
    _key.load_key(_ckey)

    print _key

    assert _ckey.n == _key.get_key().n


def test_kspec():
    _ckey = pem_cert2rsa(CERT)
    _key = RSAKey()
    _key.load_key(_ckey)

    print _key
    jwk = _key.serialize()
    assert jwk["kty"] == "RSA"
    assert jwk["e"] == JWK["keys"][0]["e"]
    assert jwk["n"] == JWK["keys"][0]["n"]


def test_loads_0():
    keys = load_jwks(json.dumps(JWK))
    assert len(keys) == 1
    key = keys[0]
    assert key.kid == "abc"
    assert key.kty == "RSA"

    _ckey = pem_cert2rsa(CERT)

    print key
    assert key.n == _ckey.n
    assert key.e == _ckey.e


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


ECKEY = {
    "crv": "P-521",
    "x": "AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk",
    "y": "ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2",
    "d": "AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C"
}


def test_import_export_eckey():
    _key = ECKey(**ECKEY)
    exp_key = _key.serialize()
    assert _eq(exp_key.keys(), ["y", "x", "crv", "kty"])


def test_create_eckey():
    priv, pub = P256.key_pair()
    ec = ECKey(x=pub[0], y=pub[1], d=priv, crv="P-256")
    exp_key = ec.serialize()
    assert _eq(exp_key.keys(), ["y", "x", "crv", "kty"])


def test_verify_2():
    _key = RSAKey()
    _key.load_key(pem_cert2rsa(CERT))
    assert _key.verify()


if __name__ == "__main__":
    test_verify_2()