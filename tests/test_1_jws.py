from __future__ import print_function
import json
from cryptlib.ecc import P256, P384, P521

import jwkest
from jwkest import jws
from jwkest import b64e

from jwkest.jwk import SYMKey, ECKey
from jwkest.jwk import import_rsa_key_from_file
from jwkest.jwk import RSAKey
from jwkest.jws import SIGNER_ALGS
from jwkest.jws import JWS

from path_util import full_path


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


def test_1():
    claimset = {"iss": "joe",
                "exp": 1300819380,
                "http://example.com/is_root": True}

    _jws = JWS(claimset, cty="JWT")
    _jwt = _jws.sign_compact()

    _jr = JWS()
    _jr.verify_compact(_jwt, allow_none=True)
    print(_jr)
    assert _jr.alg == u'none'
    assert _jr.msg == {"iss": "joe",
                       "exp": 1300819380,
                       "http://example.com/is_root": True}


def test_hmac_256():
    payload = "Please take a moment to register today"
    keys = [SYMKey(key=jwkest.intarr2bin(HMAC_KEY))]
    _jws = JWS(payload, alg="HS256")
    _jwt = _jws.sign_compact(keys)
    info = JWS().verify_compact(_jwt, keys)

    assert info == payload


def test_hmac_384():
    payload = "Please take a moment to register today"
    keys = [SYMKey(key="My hollow echo", alg="HS384")]
    _jws = JWS(payload, alg="HS384")
    _jwt = _jws.sign_compact(keys)

    _rj = JWS()
    info = _rj.verify_compact(_jwt, keys)

    assert info == payload


def test_hmac_512():
    payload = "Please take a moment to register today"
    keys = [SYMKey(key="My hollow echo", alg="HS512")]
    _jws = JWS(payload, alg="HS512")
    _jwt = _jws.sign_compact(keys)

    _rj = JWS()
    info = _rj.verify_compact(_jwt, keys)
    assert info == payload


def test_left_hash_hs256():
    hsh = jws.left_hash("Please take a moment to register today")
    assert hsh == "rCFHVJuxTqRxOsn2IUzgvA"


def test_left_hash_hs512():
    hsh = jws.left_hash("Please take a moment to register today", "HS512")
    assert hsh == "_h6feWLt8zbYcOFnaBmekTzMJYEHdVTaXlDgJSWsEeY"


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
    header = '{"typ":"JWT",\r\n "alg":"HS256"}'
    val = b64e(header)
    assert val == "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"


def test_a_1_1b():
    payload = '{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}'
    val = b64e(payload)
    assert val == ("eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9"
                   "leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ")


def test_a_1_1c():
    hmac = jwkest.intarr2bin(HMAC_KEY)
    signer = SIGNER_ALGS["HS256"]
    header = '{"typ":"JWT",\r\n "alg":"HS256"}'
    payload = '{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}'
    sign_input = b64e(header) + '.' + b64e(payload)
    sig = signer.sign(sign_input, hmac)
    assert b64e(sig) == "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"


def test_a_1_3a():
    _jwt = ("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJle"
            "HAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnV"
            "lfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")

    #keycol = {"hmac": jwkest.intarr2bin(HMAC_KEY)}
    header, claim, crypto, header_b64, claim_b64 = jwkest.unpack(_jwt)

    hmac = jwkest.intarr2bin(HMAC_KEY)
    signer = SIGNER_ALGS["HS256"]
    signer.verify(header_b64 + '.' + claim_b64, crypto, hmac)


def test_a_1_3b():
    _jwt = ("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJl"
            "eHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0c"
            "nVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
    keys = [SYMKey(key=jwkest.intarr2bin(HMAC_KEY))]
    _jws2 = JWS()
    _jws2.verify_compact(_jwt, keys)


def test_jws_1():
    msg = {"iss": "joe", "exp": 1300819380, "http://example.com/is_root": True}
    jwk = SYMKey(key=jwkest.intarr2bin(HMAC_KEY))
    _jws = JWS(msg, cty="JWT", alg="HS256", jwk=json.dumps(jwk.to_dict()))
    res = _jws.sign_compact()

    _jws2 = JWS(alg="HS256")
    _jws2.verify_compact(res)
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
    _jwt = _jws.sign_compact(keys)[:-5] + "abcde"

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

    _rj = JWS()
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

# This test is only to ensure that keys is properly passed in to sign_compact
def test_sign_json_hs256():
    payload = "Please take a moment to register today"
    keys = [SYMKey(key=jwkest.intarr2bin(HMAC_KEY))]
    _jws = JWS(payload, alg="HS256")
    _sig = {
        'alg': 'HS256'
    }
    _jwt = _jws.sign_json(per_signature_head=[_sig], keys=keys, alg='HS256')
    _jwt_sig = "%s.%s.%s" % ( _jwt['signatures'][0]['header'],
                              b64e(_jwt['payload']),
                              _jwt['signatures'][0]['signature'] )

    info = _jws.verify_compact(_jwt_sig, keys)

    assert info == payload

if __name__ == "__main__":
    test_signer_ps256_fail()
