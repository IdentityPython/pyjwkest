from jwkest.jws import SIGNER_ALGS, verify

__author__ = 'rohe0002'

import jwkest
from jwkest import jws
from jwkest import b64e

#CERT = "certs/cert.pem"
KEY = "certs/server.key"


def rsa_load(filename):
    """Read a PEM-encoded RSA key pair from a file.
        - same code as :
            https://github.com/rohe/pyoidc/blob/master/src/oic/utils/keyio.py
    """
    import M2Crypto
    return M2Crypto.RSA.load_key(filename, M2Crypto.util.no_passphrase_callback)

JWK = {"keys": [{'alg': 'RSA',
                 'use': 'foo',
                 'xpo': 'AQAB',
                 'mod': 'wf-wiusGhA-gleZYQAOPQlNUIucPiqXdPVyieDqQbXXOPBe3nuggtVzeq7pVFH1dZz4dY2Q2LA5DaegvP8kRvoSB_87ds3dy3Rfym_GUSc5B0l1TgEobcyaep8jguRoHto6GWHfCfKqoUYZq4N8vh4LLMQwLR6zi6Jtu82nB5k8'}]}


def test_1():
    claimset = {"iss": "joe",
                "exp": 1300819380,
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
    rsapub = rsa_load(KEY)

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


def test_a_1_1a():
    header = '{"typ":"JWT",\r\n "alg":"HS256"}'
    val = b64e(header)
    assert val == "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"


def test_a_1_1b():
    payload = '{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}'
    val = b64e(payload)
    assert val == "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"

HMAC_KEY = [3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166,
            143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80,
            46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195,
            119, 98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245,
            103, 208, 128, 163]


def test_a_1_1c():

    hmac = jwkest.intarr2bin(HMAC_KEY)
    signer = SIGNER_ALGS["HS256"]
    header = '{"typ":"JWT",\r\n "alg":"HS256"}'
    payload = '{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}'
    sign_input = b64e(header) + '.' + b64e(payload)
    sig = signer.sign(sign_input, hmac)
    assert b64e(sig) == "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"


def test_a_1_3a():
    _jwt = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

    #keycol = {"hmac": jwkest.intarr2bin(HMAC_KEY)}
    header, claim, crypto, header_b64, claim_b64 = jwkest.unpack(_jwt)

    hmac = jwkest.intarr2bin(HMAC_KEY)
    signer = SIGNER_ALGS["HS256"]
    info = signer.verify(header_b64 + '.' + claim_b64, crypto, hmac)


def test_a_1_3b():
    _jwt = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    keycol = {"hmac": [jwkest.intarr2bin(HMAC_KEY)]}
    verify(_jwt, keycol)
