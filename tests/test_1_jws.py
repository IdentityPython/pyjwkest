import json
#from oic.utils.keystore import rsa_load

__author__ = 'rohe0002'

import jwkest
from jwkest import jws
from jwkest.jwk import loads, x509_rsa_loads

CERT = "certs/cert.pem"
KEY  = "certs/server.key"

def rsa_load(filename):
    """Read a PEM-encoded RSA key pair from a file.
        - same code as : https://github.com/rohe/pyoidc/blob/master/src/oic/utils/keyio.py
    """
    import M2Crypto
    return M2Crypto.RSA.load_key(filename, M2Crypto.util.no_passphrase_callback)

JWK = {"keys":[{'alg': 'RSA',
                'use': 'foo',
                'xpo': 'AQAB',
                'mod': 'wf-wiusGhA-gleZYQAOPQlNUIucPiqXdPVyieDqQbXXOPBe3nuggtVzeq7pVFH1dZz4dY2Q2LA5DaegvP8kRvoSB_87ds3dy3Rfym_GUSc5B0l1TgEobcyaep8jguRoHto6GWHfCfKqoUYZq4N8vh4LLMQwLR6zi6Jtu82nB5k8'}]}

def test_1():
    claimset = {"iss":"joe",
                "exp":1300819380,
                "http://example.com/is_root": True}

    _jwt = jwkest.pack(claimset)

    part = jwkest.unpack(_jwt)
    print part
    assert part[0] == {u'alg': u'none'}
    assert part[1] == \
           '{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}'

def test_hmac_256():
    payload = "Please take a moment to register today"
    keycol = {"hmac": "My hollow echo"}

    _jwt = jws.sign(payload, keycol, "HS256")

    info = jws.verify(_jwt, keycol)

    assert info == payload

def test_hmac_384():
    payload = "Please take a moment to register today"
    keycol = {"hmac": "My hollow echo"}

    _jwt = jws.sign(payload, keycol, "HS384")

    info = jws.verify(_jwt, keycol)

    assert info == payload

def test_hmac_512():
    payload = "Please take a moment to register today"
    keycol = {"hmac": "My hollow echo"}

    _jwt = jws.sign(payload, keycol, "HS512")

    info = jws.verify(_jwt, keycol)

    assert info == payload

def test_left_hash_hs256():
    hsh = jws.left_hash("Please take a moment to register today")
    assert hsh == "rCFHVJuxTqRxOsn2IUzgvA"

def test_left_hash_hs512():
    hsh = jws.left_hash("Please take a moment to register today", "HS512")
    assert hsh == "_h6feWLt8zbYcOFnaBmekTzMJYEHdVTaXlDgJSWsEeY"

def test_rs256():
    rsapub = rsa_load(KEY )

    payload = "Please take a moment to register today"
    keycol = {"rsa": [rsapub]}

    _jwt = jws.sign(payload, keycol, "RS256")

    info = jws.verify(_jwt, keycol)

    assert info == payload

def test_rs384():
    rsapub = rsa_load(KEY)

    payload = "Please take a moment to register today"
    keycol = {"rsa": [rsapub]}

    _jwt = jws.sign(payload, keycol, "RS384")

    info = jws.verify(_jwt, keycol)

    assert info == payload

def test_rs512():
    rsapub = rsa_load(KEY)

    payload = "Please take a moment to register today"
    keycol = {"rsa": [rsapub]}

    _jwt = jws.sign(payload, keycol, "RS512")

    info = jws.verify(_jwt, keycol)

    assert info == payload
