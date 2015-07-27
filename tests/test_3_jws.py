from __future__ import print_function
from jwkest.ecc import P256
from jwkest.ecc import P384
from jwkest.ecc import P521

import jwkest
from jwkest import jws
from jwkest import b64d, b64e

from jwkest.jwk import SYMKey, KEYS
from jwkest.jwk import ECKey
from jwkest.jwk import import_rsa_key_from_file
from jwkest.jwk import RSAKey
from jwkest.jws import SIGNER_ALGS, factory
from jwkest.jws import JWSig
from jwkest.jws import JWS

import codecs
import json
import io
import os.path

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)

KEY = full_path("server.key")

JWK = {"keys": [{'alg': 'RSA',
                 'use': 'foo',
                 'e': 'AQAB',
                 'n': (
                     'wf-wiusGhA-gleZYQAOPQlNUIucPiqXdPVyieDqQbXXOPBe3nuggtV'
                     'zeq7pVFH1dZz4dY2Q2LA5DaegvP8kRvoSB_87ds3dy3Rfym_GUSc5B'
                     '0l1TgEobcyaep8jguRoHto6GWHfCfKqoUYZq4N8vh4LLMQwLR6zi6J'
                     'tu82nB5k8')}]}

# 64*8 = 256 bits
HMAC_KEY = [3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166,
            143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80,
            46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195,
            119, 98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245,
            103, 208, 128, 163]


JWKS = {"keys": [
    {
        "n": b"zkpUgEgXICI54blf6iWiD2RbMDCOO1jV0VSff1MFFnujM4othfMsad7H1kRo50YM5S_X9TdvrpdOfpz5aBaKFhT6Ziv0nhtcekq1eRl8mjBlvGKCE5XGk-0LFSDwvqgkJoFYInq7bu0a4JEzKs5AyJY75YlGh879k1Uu2Sv3ZZOunfV1O1Orta-NvS-aG_jN5cstVbCGWE20H0vFVrJKNx0Zf-u-aA-syM4uX7wdWgQ-owoEMHge0GmGgzso2lwOYf_4znanLwEuO3p5aabEaFoKNR4K6GjQcjBcYmDEE4CtfRU9AEmhcD1kleiTB9TjPWkgDmT9MXsGxBHf3AKT5w",
        "e": b"AQAB",
        "kty": "RSA",
        "kid": "5-VBFv40P8D4I-7SFz7hMugTbPs",
        "use": "sig"
    },
    {
        "k": b"YTEyZjBlMDgxMGI4YWU4Y2JjZDFiYTFlZTBjYzljNDU3YWM0ZWNiNzhmNmFlYTNkNTY0NzMzYjE",
        "kty": "oct",
        "use": "sig"
    },
    {
        "kty": "EC",
        "kid": "7snis",
        "use": "sig",
        "x": "q0WbWhflRbxyQZKFuQvh2nZvg98ak-twRoO5uo2L7Po",
        "y": "GOd2jL_6wa0cfnyA0SmEhok9fkYEnAHFKLLM79BZ8_E",
        "crv": "P-256"
    }
]}


SIGKEYS = KEYS()
SIGKEYS.load_dict(JWKS)

def test_1():
    claimset = {"iss": "joe",
                "exp": 1300819380,
                "http://example.com/is_root": True}

    _jws = JWS(claimset, cty="JWT")
    _jwt = _jws.sign_compact()

    _jr = JWS()
    _msg = _jr.verify_compact(_jwt, allow_none=True)
    print(_jr)
    assert _jr.jwt.headers["alg"] == 'none'
    assert _msg == claimset


def test_hmac_256():
    payload = b'Please take a moment to register today'
    keys = [SYMKey(key=jwkest.intarr2bin(HMAC_KEY))]
    _jws = JWS(payload, alg="HS256")
    _jwt = _jws.sign_compact(keys)

    info = JWS().verify_compact(_jwt, keys)

    assert info == payload.decode("utf-8")


def test_hmac_384():
    payload = "Please take a moment to register today"
    keys = [SYMKey(key=b'My hollow echo', alg="HS384")]
    _jws = JWS(payload, alg="HS384")
    _jwt = _jws.sign_compact(keys)

    _rj = JWS()
    info = _rj.verify_compact(_jwt, keys)

    assert info == payload


def test_hmac_512():
    payload = "Please take a moment to register today"
    keys = [SYMKey(key=b'My hollow echo', alg="HS512")]
    _jws = JWS(payload, alg="HS512")
    _jwt = _jws.sign_compact(keys)

    _rj = JWS()
    info = _rj.verify_compact(_jwt, keys)
    assert info == payload


def test_hmac_from_keyrep():
    payload = "Please take a moment to register today"
    symkeys = [k for k in SIGKEYS if k.kty == "oct"]
    _jws = JWS(payload, alg="HS512")
    _jwt = _jws.sign_compact(symkeys)

    _rj = JWS()
    info = _rj.verify_compact(_jwt, symkeys)
    assert info == payload


def test_left_hash_hs256():
    hsh = jws.left_hash(b'Please take a moment to register today')
    assert hsh == b'rCFHVJuxTqRxOsn2IUzgvA'


def test_left_hash_hs512():
    hsh = jws.left_hash(b'Please take a moment to register today', "HS512")
    assert hsh == b'_h6feWLt8zbYcOFnaBmekTzMJYEHdVTaXlDgJSWsEeY'


def test_rs256():
    payload = "Please take a moment to register today"
    keys = [RSAKey(key=import_rsa_key_from_file(KEY))]
    #keys[0]._keytype = "private"
    _jws = JWS(payload, alg="RS256")
    _jwt = _jws.sign_compact(keys)

    _rj = JWS()
    info = _rj.verify_compact(_jwt, keys)

    assert info == payload


def test_rs384():
    payload = "Please take a moment to register today"
    keys = [RSAKey(key=import_rsa_key_from_file(KEY))]
    #keys[0]._keytype = "private"
    _jws = JWS(payload, alg="RS384")
    _jwt = _jws.sign_compact(keys)

    _rj = JWS()
    info = _rj.verify_compact(_jwt, keys)
    assert info == payload


def test_rs512():
    payload = "Please take a moment to register today"
    keys = [RSAKey(key=import_rsa_key_from_file(KEY))]
    #keys[0]._keytype = "private"
    _jws = JWS(payload, alg="RS512")
    _jwt = _jws.sign_compact(keys)

    _rj = JWS()
    info = _rj.verify_compact(_jwt, keys)
    assert info == payload


def test_a_1_1a():
    header = b'{"typ":"JWT",\r\n "alg":"HS256"}'
    val = b64e(header)
    assert val == b"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"


def test_a_1_1b():
    payload = b'{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}'
    val = b64e(payload)
    assert val == (b'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9'
                   b'leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ')


def test_a_1_1c():
    hmac = jwkest.intarr2bin(HMAC_KEY)
    signer = SIGNER_ALGS["HS256"]
    header = b'{"typ":"JWT",\r\n "alg":"HS256"}'
    payload = b'{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}'
    sign_input = b64e(header) + b'.' + b64e(payload)
    sig = signer.sign(sign_input, hmac)
    assert b64e(sig) == b'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'


def test_a_1_3a():
    _jwt = ("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJle"
            "HAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnV"
            "lfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")

    # keycol = {"hmac": jwkest.intarr2bin(HMAC_KEY)}
    jwt = JWSig().unpack(_jwt)

    hmac = jwkest.intarr2bin(HMAC_KEY)
    signer = SIGNER_ALGS["HS256"]
    signer.verify(jwt.sign_input(), jwt.signature(), hmac)


def test_a_1_3b():
    _jwt = ("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJl"
            "eHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0c"
            "nVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
    keys = [SYMKey(key=jwkest.intarr2bin(HMAC_KEY))]
    _jws2 = JWS()
    _jws2.verify_compact(_jwt, keys)


def test_jws_1():
    msg = {"iss": "joe", "exp": 1300819380, "http://example.com/is_root": True}
    key = SYMKey(key=jwkest.intarr2bin(HMAC_KEY))
    _jws = JWS(msg, cty="JWT", alg="HS256", jwk=key.to_dict())
    res = _jws.sign_compact()

    _jws2 = JWS(alg="HS256")
    _jws2.verify_compact(res, keys=[key])
    assert _jws2.msg == msg


def test_signer_es256():
    payload = "Please take a moment to register today"
    _key = ECKey().load_key(P256)
    keys = [_key]
    _jws = JWS(payload, alg="ES256")
    _jwt = _jws.sign_compact(keys)

    _rj = JWS()
    info = _rj.verify_compact(_jwt, keys)
    assert info == payload


def test_signer_es384():
    payload = "Please take a moment to register today"
    _key = ECKey().load_key(P384)
    keys = [_key]
    _jws = JWS(payload, alg="ES384")
    _jwt = _jws.sign_compact(keys)

    _rj = JWS()
    info = _rj.verify_compact(_jwt, keys)
    assert info == payload


def test_signer_es512():
    payload = "Please take a moment to register today"
    _key = ECKey().load_key(P521)
    keys = [_key]
    #keys[0]._keytype = "private"
    _jws = JWS(payload, alg="ES512")
    _jwt = _jws.sign_compact(keys)

    _rj = JWS()
    info = _rj.verify_compact(_jwt, keys)
    assert info == payload


def test_signer_ps256():
    payload = "Please take a moment to register today"
    keys = [RSAKey(key=import_rsa_key_from_file(KEY))]
    #keys[0]._keytype = "private"
    _jws = JWS(payload, alg="PS256")
    _jwt = _jws.sign_compact(keys)

    _rj = JWS()
    info = _rj.verify_compact(_jwt, keys)
    assert info == payload


def test_signer_ps256_fail():
    payload = "Please take a moment to register today"
    keys = [RSAKey(key=import_rsa_key_from_file(KEY))]
    #keys[0]._keytype = "private"
    _jws = JWS(payload, alg="PS256")
    _jwt = _jws.sign_compact(keys)[:-5] + b'abcde'

    _rj = JWS()
    try:
        _rj.verify_compact(_jwt, keys)
    except jwkest.BadSignature:
        pass
    else:
        assert False


def test_signer_ps384():
    payload = "Please take a moment to register today"
    keys = [RSAKey(key=import_rsa_key_from_file(KEY))]
    #keys[0]._keytype = "private"
    _jws = JWS(payload, alg="PS384")
    _jwt = _jws.sign_compact(keys)

    _rj = JWS()
    info = _rj.verify_compact(_jwt, keys)
    assert info == payload


def test_signer_ps512():
    payload = "Please take a moment to register today"
    # Key has to be big enough  > 512+512+2
    keys = [RSAKey(key=import_rsa_key_from_file(full_path("./size2048.key")))]
    #keys[0]._keytype = "private"
    _jws = JWS(payload, alg="PS521")
    _jwt = _jws.sign_compact(keys)

    _rj = factory(_jwt)
    info = _rj.verify_compact(_jwt, keys)
    assert info == payload


def test_no_alg_and_alg_none_same():
    payload = "Please take a moment to register today"
    _jws = JWS(payload, alg="none")

    # Create a JWS (signed JWT)
    _jwt0 = _jws.sign_compact([])

    # The class instance that sets up the signing operation
    _jws = JWS(payload)

    # Create a JWS (signed JWT)
    _jwt1 = _jws.sign_compact([])

    assert _jwt0 == _jwt1


def test_sign_2():
    keyset = {"keys": [
        {"alg": "RS512",
         "kty": "RSA",
         "d": "ckLyXxkbjC4szg8q8G0ERBZV-9CszeOxpRtx1KM9BLl0Do3li_Km2vvFvfXJ7MxQpiZ18pBoCcyYQEU262ym8wI22JWMPrZe24HCNxLxqzr_JEuBhpKFxQF6EFTSvJEJD1FkoTuCTvN0zD7YHGaJQG6JzVEuFUY3ewxjH0FYNa_ppTnPP3LC-T9u_GX9Yqyuw1KOYoHSzhWSWQOeAgs4dH9-iAxN1wdZ6eH1jFWAs43svk_rhwdgyJMlihFtV9MAInBlfi_Zu8wRVhVl5urkJrLf0tGFnMbnzb6dYSlUXxEYClpY12W7kXW9aePDqkCwI4oZyxmOmgq4hunKGR1dAQ",
         "e": "AQAB",
         "use": "sig",
         "kid": "af22448d-4c7b-464d-b63a-f5bd90f6d7d1",
         "n": "o9g8DpUwBW6B1qmcm-TfEh4rNX7n1t38jdo4Gkl_cI3q--7n0Blg0kN88LHZvyZjUB2NhBdFYNxMP8ucy0dOXvWGWzaPmGnq3DM__lN8P4WjD1cCTAVEYKawNBAmGKqrFj1SgpPNsSqiqK-ALM1w6mZ-QGimjOgwCyJy3l9lzZh5D8tKnS2t1pZgE0X5P7lZQWHYpHPqp4jKhETzrCpPGfv0Rl6nmmjp7NlRYBkWKf_HEKE333J6M039m2FbKgxrBg3zmYYpmHuMzVgxxb8LSiv5aqyeyJjxM-YDUAgNQBfKNhONqXyu9DqtSprNkw6sqmuxK0QUVrNYl3b03PgS5Q"
        }]}

    keys = KEYS()
    keys.load_dict(keyset)
    jws = JWS("payload", alg="RS512")
    jws.sign_compact(keys=keys)

def test_signer_protected_headers():
    payload = "Please take a moment to register today"
    _key = ECKey().load_key(P256)
    keys = [_key]
    _jws = JWS(payload, alg="ES256")
    protected = dict(header1=u"header1 is protected",
        header2="header2 is protected too", a=1)
    _jwt = _jws.sign_compact(keys, protected=protected)

    exp_protected = protected.copy()
    exp_protected['alg'] = 'ES256'
    enc_header, enc_payload, sig = _jwt.split(b'.')
    assert json.loads(b64d(enc_header).decode("utf-8")) == exp_protected
    assert b64d(enc_payload).decode("utf-8") == payload

    _rj = JWS()
    info = _rj.verify_compact(_jwt, keys)
    assert info == payload

def test_verify_protected_headers():
    payload = "Please take a moment to register today"
    _key = ECKey().load_key(P256)
    keys = [_key]
    _jws = JWS(payload, alg="ES256")
    protected = dict(header1=u"header1 is protected",
        header2="header2 is protected too", a=1)
    _jwt = _jws.sign_compact(keys, protected=protected)
    protectedHeader, enc_payload, sig = _jwt.split(b".")
    data = dict(payload=enc_payload, signatures=[
        dict(
            header=dict(alg=u"ES256", jwk=_key.serialize()),
            protected=protectedHeader,
            signature=sig,
            )
        ])
    fobj = io.BytesIO(JSONEncoder().encode(data).encode("utf-8"))
    _jws = JWS()
    reader = codecs.getreader("utf-8")
    assert _jws.verify_json(reader(fobj)) == payload

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, bytes):
            return o.decode('utf-8')
        return json.JSONEncoder.default(self, o)

if __name__ == "__main__":
    test_sign_2()
