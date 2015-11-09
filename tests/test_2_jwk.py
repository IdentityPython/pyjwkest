from __future__ import print_function
import base64
from collections import Counter
import json
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import _RSAobj
import struct
import six
from jwkest.ecc import P256
from jwkest import long2intarr
from jwkest.jwk import jwk_wrap
from jwkest.jwk import import_rsa_key_from_file
from jwkest.jwk import rsa_eq
from jwkest.jwk import keyrep
from jwkest.jwk import KEYS
from jwkest.jwk import base64url_to_long
from jwkest.jwk import ECKey
from jwkest.jwk import pem_cert2rsa
from jwkest.jwk import RSAKey
from jwkest.jwk import base64_to_long
import os.path
import pytest

__author__ = 'rohe0002'
BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


CERT = full_path("cert.pem")
KEY = full_path("server.key")

N = 'wf-wiusGhA-gleZYQAOPQlNUIucPiqXdPVyieDqQbXXOPBe3nuggtVzeq7pVFH1dZz4dY2Q2LA5DaegvP8kRvoSB_87ds3dy3Rfym_GUSc5B0l1TgEobcyaep8jguRoHto6GWHfCfKqoUYZq4N8vh4LLMQwLR6zi6Jtu82nB5k8'
E = 'AQAB'

JWK = {"keys": [
    {'kty': 'RSA', 'use': 'foo', 'e': E, 'kid': "abc",
     'n': N}
]}


def _eq(l1, l2):
    return Counter(l1) == Counter(l2)


def test_urlsafe_base64decode():
    l = base64_to_long(N)
    # convert it to base64
    bys = long2intarr(l)
    data = struct.pack('%sB' % len(bys), *bys)
    if not len(data):
        data = '\x00'
    s0 = base64.b64encode(data)
    # try to convert it back to long, should throw an exception if the strict
    # function is used
    with pytest.raises(ValueError):
        base64url_to_long(s0)

    # Not else, should not raise exception
    l = base64_to_long(s0)
    assert l


def test_pem_cert2rsa():
    _ckey = pem_cert2rsa(CERT)
    assert isinstance(_ckey, _RSAobj)


def test_extract_rsa_from_cert_2():
    _ckey = pem_cert2rsa(CERT)
    _key = RSAKey()
    _key.load_key(_ckey)

    print(_key)

    assert _ckey.n == _key.get_key().n


def test_kspec():
    _ckey = pem_cert2rsa(CERT)
    _key = RSAKey()
    _key.load_key(_ckey)

    print(_key)
    jwk = _key.serialize()
    assert jwk["kty"] == "RSA"
    assert jwk["e"] == JWK["keys"][0]["e"]
    assert jwk["n"] == JWK["keys"][0]["n"]


def test_loads_0():
    keys = KEYS()
    keys.load_dict(JWK)
    assert len(keys) == 1
    key = keys["rsa"][0]
    assert key.kid == 'abc'
    assert key.kty == 'RSA'

    _ckey = pem_cert2rsa(CERT)

    print(key)
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

    keys = KEYS()
    keys.load_dict(jwk)
    print(keys)
    assert len(keys) == 2
    assert _eq(keys.kids(), ['1', '2'])


def test_dumps():
    _ckey = pem_cert2rsa(CERT)
    jwk = jwk_wrap(_ckey).serialize()
    assert _eq(list(jwk.keys()), ["kty", "e", "n", "kid"])


def test_dump_jwk():
    keylist0 = KEYS()
    keylist0.wrap_add(pem_cert2rsa(CERT))
    jwk = keylist0.dump_jwks()

    print(jwk)
    _wk = json.loads(jwk)
    assert list(_wk.keys()) == ["keys"]
    assert len(_wk["keys"]) == 1
    assert _eq(list(_wk["keys"][0].keys()), ["kty", "e", "n", "kid"])


def test_load_jwk():
    keylist0 = KEYS()
    keylist0.wrap_add(pem_cert2rsa(CERT))
    jwk = keylist0.dump_jwks()

    keylist1 = KEYS()
    keylist1.load_jwks(jwk)
    print(keylist1)
    assert len(keylist1) == 1
    key = keylist1["rsa"][0]
    assert key.kty == 'RSA'
    assert isinstance(key.key, _RSAobj)


def test_import_rsa_key():
    _ckey = RSA.importKey(open(full_path(KEY), 'r').read())
    assert isinstance(_ckey, _RSAobj)
    djwk = jwk_wrap(_ckey).to_dict()
    print(djwk)
    assert _eq(djwk.keys(), ["kty", "e", "n", "p", "q", "d", "kid"])
    assert djwk["n"] == '5zbNbHIYIkGGJ3RGdRKkYmF4gOorv5eDuUKTVtuu3VvxrpOWvwnFV-NY0LgqkQSMMyVzodJE3SUuwQTUHPXXY5784vnkFqzPRx6bHgPxKz7XfwQjEBTafQTMmOeYI8wFIOIHY5i0RWR-gxDbh_D5TXuUqScOOqR47vSpIbUH-nc'
    assert djwk['e'] == 'AQAB'
    assert djwk['kid'] == 'ceb1941d5dec739c127b206c27511d2fcef06481'


def test_serialize_rsa_pub_key():
    rsakey = RSAKey(key=import_rsa_key_from_file(full_path("rsa.pub")))
    assert rsakey.d == ''

    d_rsakey = rsakey.serialize(private=True)
    restored_key = RSAKey(**d_rsakey)

    assert rsa_eq(restored_key, rsakey)


def test_serialize_rsa_priv_key():
    rsakey = RSAKey(key=import_rsa_key_from_file(full_path("rsa.key")))
    assert rsakey.d

    d_rsakey = rsakey.serialize(private=True)
    restored_key = RSAKey(**d_rsakey)

    assert rsa_eq(restored_key, rsakey)


ECKEY = {
    "crv": "P-521",
    "x": u'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk',
    "y": u'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2',
    "d": u'AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C'
}


def test_import_export_eckey():
    _key = ECKey(**ECKEY)
    _key.deserialize()
    assert _eq(list(_key.keys()), ["y", "x", "d", "crv", "kty"])


def test_create_eckey():
    priv, pub = P256.key_pair()
    ec = ECKey(x=pub[0], y=pub[1], d=priv, crv="P-256")
    exp_key = ec.serialize()
    assert _eq(list(exp_key.keys()), ["y", "x", "crv", "kty"])


def test_verify_2():
    _key = RSAKey()
    _key.load_key(pem_cert2rsa(CERT))
    assert _key.verify()


def test_cmp_rsa():
    _key1 = RSAKey()
    _key1.load_key(pem_cert2rsa(CERT))

    _key2 = RSAKey()
    _key2.load_key(pem_cert2rsa(CERT))

    assert _key1 == _key2


def test_cmp_rsa_ec():
    _key1 = RSAKey()
    _key1.load_key(pem_cert2rsa(CERT))

    _key2 = ECKey(**ECKEY)

    assert _key1 != _key2


def test_cmp_neq_ec():
    priv, pub = P256.key_pair()
    _key1 = ECKey(x=pub[0], y=pub[1], d=priv, crv="P-256")
    _key2 = ECKey(**ECKEY)

    assert _key1 != _key2


JWKS = {"keys": [
    {
        "n": u"zkpUgEgXICI54blf6iWiD2RbMDCOO1jV0VSff1MFFnujM4othfMsad7H1kRo50YM5S_X9TdvrpdOfpz5aBaKFhT6Ziv0nhtcekq1eRl8mjBlvGKCE5XGk-0LFSDwvqgkJoFYInq7bu0a4JEzKs5AyJY75YlGh879k1Uu2Sv3ZZOunfV1O1Orta-NvS-aG_jN5cstVbCGWE20H0vFVrJKNx0Zf-u-aA-syM4uX7wdWgQ-owoEMHge0GmGgzso2lwOYf_4znanLwEuO3p5aabEaFoKNR4K6GjQcjBcYmDEE4CtfRU9AEmhcD1kleiTB9TjPWkgDmT9MXsGxBHf3AKT5w",
        "e": u"AQAB",
        "kty": "RSA",
        "kid": "5-VBFv40P8D4I-7SFz7hMugTbPs",
        "use": "enc"
    },
    {
        "k": u"YTEyZjBlMDgxMGI4YWU4Y2JjZDFiYTFlZTBjYzljNDU3YWM0ZWNiNzhmNmFlYTNkNTY0NzMzYjE",
        "kty": "oct",
        "use": "enc"
    },
    {
        "kty": "EC",
        "kid": "7snis",
        "use": "sig",
        "x": u'q0WbWhflRbxyQZKFuQvh2nZvg98ak-twRoO5uo2L7Po',
        "y": u'GOd2jL_6wa0cfnyA0SmEhok9fkYEnAHFKLLM79BZ8_E',
        "crv": "P-256"
    }
]}


def test_keys():
    keyl = KEYS()
    keyl.load_dict(JWKS)

    assert len(keyl) == 3
    print(keyl.keys())
    print(keyl.dump_jwks())
    assert _eq(keyl.keys(), ['RSA', 'oct', 'EC'])
    assert len(keyl['rsa']) == 1
    assert len(keyl['oct']) == 1
    assert len(keyl['ec']) == 1
    assert _eq(keyl.kids(), ['5-VBFv40P8D4I-7SFz7hMugTbPs', '7snis'])


def test_private_key_from_jwk():
    keys = []

    kspec = json.loads(open(full_path("jwk_private_key.json")).read())
    keys.append(keyrep(kspec))

    key = keys[0]

    assert isinstance(key.n, six.integer_types)
    assert isinstance(key.e, six.integer_types)
    assert isinstance(key.d, six.integer_types)
    assert isinstance(key.p, six.integer_types)
    assert isinstance(key.q, six.integer_types)
    assert isinstance(key.dp, six.integer_types)
    assert isinstance(key.dq, six.integer_types)
    assert isinstance(key.qi, six.integer_types)

    _d = key.to_dict()
    print(_d)
    print(_d.keys())
    assert _eq(list(_d.keys()),
               ['n', 'alg', 'dq', 'e', 'q', 'p', 'dp', 'd', 'ext', 'key_ops',
                'kty', 'qi', 'kid'])
    assert _eq(list(_d.keys()), kspec.keys())
    # Test that kid in file is preserved and not replaced
    assert key.kid == 'test'


if __name__ == "__main__":
    test_private_key_from_jwk()
