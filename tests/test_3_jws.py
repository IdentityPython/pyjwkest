from __future__ import print_function

from Cryptodome.PublicKey import RSA
from jwkest.ecc import P256
from jwkest.ecc import P384
from jwkest.ecc import P521

import jwkest
from jwkest import jws, b64d_enc_dec
from jwkest import b64d, b64e

from jwkest.jwk import SYMKey, KEYS
from jwkest.jwk import ECKey
from jwkest.jwk import import_rsa_key_from_file
from jwkest.jwk import RSAKey
from jwkest.jws import SIGNER_ALGS, factory
from jwkest.jws import JWSig
from jwkest.jws import JWS

import json
import io
import os.path
from hashlib import md5

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

JWKS0 = {"keys": [
    {'e': 'AQAB', 'kty': 'RSA', 'alg': 'RSA256',
     'n': 'qYJqXTXsDroPYyQBBmSolK3bJtrSerEm'
          '-nrmbSpfn8Rz3y3oXLydvUqj8869PkcEzoJIY5Xf7xDN1Co_qyT9qge'
          '-3C6DEwGVHXOwRoXRGQ_h50Vsh60MB5MIuDN188EeZnQ30dtCTBB9KDTSEA2DunplhwLCq4xphnMNUaeHdEk',
     'kid': 'rsa1'},
    {
        "k":
            b"YTEyZjBlMDgxMGI4YWU4Y2JjZDFiYTFlZTBjYzljNDU3YWM0ZWNiNzhmNmFlYTNkNTY0NzMzYjE",
        "kty": "oct",
    }]}

JWKS = {"keys": [
    {
        "n":
            b"zkpUgEgXICI54blf6iWiD2RbMDCOO1jV0VSff1MFFnujM4othfMsad7H1kRo50YM5S_X9TdvrpdOfpz5aBaKFhT6Ziv0nhtcekq1eRl8mjBlvGKCE5XGk-0LFSDwvqgkJoFYInq7bu0a4JEzKs5AyJY75YlGh879k1Uu2Sv3ZZOunfV1O1Orta-NvS-aG_jN5cstVbCGWE20H0vFVrJKNx0Zf-u-aA-syM4uX7wdWgQ-owoEMHge0GmGgzso2lwOYf_4znanLwEuO3p5aabEaFoKNR4K6GjQcjBcYmDEE4CtfRU9AEmhcD1kleiTB9TjPWkgDmT9MXsGxBHf3AKT5w",
        "e": b"AQAB",
        "kty": "RSA",
        "kid": "rsa1",
        "use": "sig"
    },
    {
        "k":
            b"YTEyZjBlMDgxMGI4YWU4Y2JjZDFiYTFlZTBjYzljNDU3YWM0ZWNiNzhmNmFlYTNkNTY0NzMzYjE",
        "kty": "oct",
        "use": "sig"
    },
    {
        "kty": "EC",
        "kid": "ec1",
        "use": "sig",
        "x": "q0WbWhflRbxyQZKFuQvh2nZvg98ak-twRoO5uo2L7Po",
        "y": "GOd2jL_6wa0cfnyA0SmEhok9fkYEnAHFKLLM79BZ8_E",
        "crv": "P-256"
    }
]}

JWK2 = {
    "keys": [
        {
            "e": "AQAB",
            "issuer": "https://login.microsoftonline.com/{tenantid}/v2.0/",
            "kid": "kriMPdmBvx68skT8-mPAB3BseeA",
            "kty": "RSA",
            "n":
                "kSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS_AHsBeQPqYygfYVJL6_EgzVuwRk5txr9e3n1uml94fLyq_AXbwo9yAduf4dCHTP8CWR1dnDR-Qnz_4PYlWVEuuHHONOw_blbfdMjhY-C_BYM2E3pRxbohBb3x__CfueV7ddz2LYiH3wjz0QS_7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd_GTgWN8A-6SN1r4hzpjFKFLbZnBt77ACSiYx-IHK4Mp-NaVEi5wQtSsjQtI--XsokxRDqYLwus1I1SihgbV_STTg5enufuw",
            "use": "sig",
            "x5c": [
                "MIIDPjCCAiqgAwIBAgIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTQwMTAxMDcwMDAwWhcNMTYwMTAxMDcwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuwIDAQABo2IwYDBeBgNVHQEEVzBVgBDLebM6bK3BjWGqIBrBNFeNoS8wLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAA4IBAQCJ4JApryF77EKC4zF5bUaBLQHQ1PNtA1uMDbdNVGKCmSf8M65b8h0NwlIjGGGy/unK8P6jWFdm5IlZ0YPTOgzcRZguXDPj7ajyvlVEQ2K2ICvTYiRQqrOhEhZMSSZsTKXFVwNfW6ADDkN3bvVOVbtpty+nBY5UqnI7xbcoHLZ4wYD251uj5+lo13YLnsVrmQ16NCBYq2nQFNPuNJw6t3XUbwBHXpF46aLT1/eGf/7Xx6iy8yPJX4DyrpFTutDz882RWofGEO5t4Cw+zZg70dJ/hH/ODYRMorfXEW+8uKmXMKmX2wyxMKvfiPbTy5LmAU8Jvjs2tLg4rOBcXWLAIarZ"
            ],
            "x5t": "kriMPdmBvx68skT8-mPAB3BseeA"
        },
        {
            "e": "AQAB",
            "issuer": "https://login.microsoftonline.com/{tenantid}/v2.0/",
            "kid": "MnC_VZcATfM5pOYiJHMba9goEKY",
            "kty": "RSA",
            "n":
                "vIqz-4-ER_vNWLON9yv8hIYV737JQ6rCl6XfzOC628seYUPf0TaGk91CFxefhzh23V9Tkq-RtwN1Vs_z57hO82kkzL-cQHZX3bMJD-GEGOKXCEXURN7VMyZWMAuzQoW9vFb1k3cR1RW_EW_P-C8bb2dCGXhBYqPfHyimvz2WarXhntPSbM5XyS5v5yCw5T_Vuwqqsio3V8wooWGMpp61y12NhN8bNVDQAkDPNu2DT9DXB1g0CeFINp_KAS_qQ2Kq6TSvRHJqxRR68RezYtje9KAqwqx4jxlmVAQy0T3-T-IAbsk1wRtWDndhO6s1Os-dck5TzyZ_dNOhfXgelixLUQ",
            "use": "sig",
            "x5c": [
                "MIIC4jCCAcqgAwIBAgIQQNXrmzhLN4VGlUXDYCRT3zANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE0MTAyODAwMDAwMFoXDTE2MTAyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALyKs/uPhEf7zVizjfcr/ISGFe9+yUOqwpel38zgutvLHmFD39E2hpPdQhcXn4c4dt1fU5KvkbcDdVbP8+e4TvNpJMy/nEB2V92zCQ/hhBjilwhF1ETe1TMmVjALs0KFvbxW9ZN3EdUVvxFvz/gvG29nQhl4QWKj3x8opr89lmq14Z7T0mzOV8kub+cgsOU/1bsKqrIqN1fMKKFhjKaetctdjYTfGzVQ0AJAzzbtg0/Q1wdYNAnhSDafygEv6kNiquk0r0RyasUUevEXs2LY3vSgKsKseI8ZZlQEMtE9/k/iAG7JNcEbVg53YTurNTrPnXJOU88mf3TToX14HpYsS1ECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAfolx45w0i8CdAUjjeAaYdhG9+NDHxop0UvNOqlGqYJexqPLuvX8iyUaYxNGzZxFgGI3GpKfmQP2JQWQ1E5JtY/n8iNLOKRMwqkuxSCKJxZJq4Sl/m/Yv7TS1P5LNgAj8QLCypxsWrTAmq2HSpkeSk4JBtsYxX6uhbGM/K1sEktKybVTHu22/7TmRqWTmOUy9wQvMjJb2IXdMGLG3hVntN/WWcs5w8vbt1i8Kk6o19W2MjZ95JaECKjBDYRlhG1KmSBtrsKsCBQoBzwH/rXfksTO9JoUYLXiW0IppB7DhNH4PJ5hZI91R8rR0H3/bKkLSuDaKLWSqMhozdhXsIIKvJQ=="
            ],
            "x5t": "MnC_VZcATfM5pOYiJHMba9goEKY"
        },
        {
            "e": "AQAB",
            "issuer": "https://login.microsoftonline.com/9188040d-6c67-4c5b"
                      "-b112-36a304b66dad/v2.0/",
            "kid": "GvnPApfWMdLRi8PDmisFn7bprKg",
            "kty": "RSA",
            "n":
                "5ymq_xwmst1nstPr8YFOTyD1J5N4idYmrph7AyAv95RbWXfDRqy8CMRG7sJq"
                "-UWOKVOA4MVrd_NdV-ejj1DE5MPSiG"
                "-mZK_5iqRCDFvPYqOyRj539xaTlARNY4jeXZ0N6irZYKqSfYACjkkKxbLKcijSu1pJ48thXOTED0oNa6U",
            "use": "sig",
            "x5c": [
                "MIICWzCCAcSgAwIBAgIJAKVzMH2FfC12MA0GCSqGSIb3DQEBBQUAMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGljIEtleTAeFw0xMzExMTExODMzMDhaFw0xNjExMTAxODMzMDhaMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGljIEtleTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA5ymq/xwmst1nstPr8YFOTyD1J5N4idYmrph7AyAv95RbWXfDRqy8CMRG7sJq+UWOKVOA4MVrd/NdV+ejj1DE5MPSiG+mZK/5iqRCDFvPYqOyRj539xaTlARNY4jeXZ0N6irZYKqSfYACjkkKxbLKcijSu1pJ48thXOTED0oNa6UCAwEAAaOBijCBhzAdBgNVHQ4EFgQURCN+4cb0pvkykJCUmpjyfUfnRMowWQYDVR0jBFIwUIAURCN+4cb0pvkykJCUmpjyfUfnRMqhLaQrMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGljIEtleYIJAKVzMH2FfC12MAsGA1UdDwQEAwIBxjANBgkqhkiG9w0BAQUFAAOBgQB8v8G5/vUl8k7xVuTmMTDA878AcBKBrJ/Hp6RShmdqEGVI7SFR7IlBN1//NwD0n+IqzmnRV2PPZ7iRgMF/Fyvqi96Gd8X53ds/FaiQpZjUUtcO3fk0hDRQPtCYMII5jq+YAYjSybvF84saB7HGtucVRn2nMZc5cAC42QNYIlPMqA=="
            ],
            "x5t": "GvnPApfWMdLRi8PDmisFn7bprKg"
        },
        {
            "e": "AQAB",
            "issuer": "https://login.microsoftonline.com/9188040d-6c67-4c5b"
                      "-b112-36a304b66dad/v2.0/",
            "kid": "dEtpjbEvbhfgwUI-bdK5xAU_9UQ",
            "kty": "RSA",
            "n":
                "x7HNcD9ZxTFRaAgZ7-gdYLkgQua3zvQseqBJIt8Uq3MimInMZoE9QGQeSML7qZPlowb5BUakdLI70ayM4vN36--0ht8-oCHhl8YjGFQkU-Iv2yahWHEP-1EK6eOEYu6INQP9Lk0HMk3QViLwshwb-KXVD02jdmX2HNdYJdPyc0c",
            "use": "sig",
            "x5c": [
                "MIICWzCCAcSgAwIBAgIJAL3MzqqEFMYjMA0GCSqGSIb3DQEBBQUAMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGljIEtleTAeFw0xMzExMTExOTA1MDJaFw0xOTExMTAxOTA1MDJaMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGljIEtleTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAx7HNcD9ZxTFRaAgZ7+gdYLkgQua3zvQseqBJIt8Uq3MimInMZoE9QGQeSML7qZPlowb5BUakdLI70ayM4vN36++0ht8+oCHhl8YjGFQkU+Iv2yahWHEP+1EK6eOEYu6INQP9Lk0HMk3QViLwshwb+KXVD02jdmX2HNdYJdPyc0cCAwEAAaOBijCBhzAdBgNVHQ4EFgQULR0aj9AtiNMgqIY8ZyXZGsHcJ5gwWQYDVR0jBFIwUIAULR0aj9AtiNMgqIY8ZyXZGsHcJ5ihLaQrMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGljIEtleYIJAL3MzqqEFMYjMAsGA1UdDwQEAwIBxjANBgkqhkiG9w0BAQUFAAOBgQBshrsF9yls4ArxOKqXdQPDgHrbynZL8m1iinLI4TeSfmTCDevXVBJrQ6SgDkihl3aCj74IEte2MWN78sHvLLTWTAkiQSlGf1Zb0durw+OvlunQ2AKbK79Qv0Q+wwGuK+oymWc3GSdP1wZqk9dhrQxb3FtdU2tMke01QTut6wr7ig=="
            ],
            "x5t": "dEtpjbEvbhfgwUI-bdK5xAU_9UQ"
        }
    ]
}

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
    payload = 'Please take a moment to register today'
    keys = [SYMKey(key=jwkest.intarr2bin(HMAC_KEY))]
    _jws = JWS(payload, alg="HS256")
    _jwt = _jws.sign_compact(keys)

    info = JWS().verify_compact(_jwt, keys)

    assert info == payload


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
    hsh = jws.left_hash('Please take a moment to register today')
    assert hsh == 'rCFHVJuxTqRxOsn2IUzgvA'


def test_left_hash_hs512():
    hsh = jws.left_hash('Please take a moment to register today', "HS512")
    assert hsh == '_h6feWLt8zbYcOFnaBmekTzMJYEHdVTaXlDgJSWsEeY'


def test_rs256():
    payload = "Please take a moment to register today"
    keys = [RSAKey(key=import_rsa_key_from_file(KEY))]
    # keys[0]._keytype = "private"
    _jws = JWS(payload, alg="RS256")
    _jwt = _jws.sign_compact(keys)

    _rj = JWS()
    info = _rj.verify_compact(_jwt, keys)

    assert info == payload


def test_rs384():
    payload = "Please take a moment to register today"
    keys = [RSAKey(key=import_rsa_key_from_file(KEY))]
    # keys[0]._keytype = "private"
    _jws = JWS(payload, alg="RS384")
    _jwt = _jws.sign_compact(keys)

    _rj = JWS()
    info = _rj.verify_compact(_jwt, keys)
    assert info == payload


def test_rs512():
    payload = "Please take a moment to register today"
    keys = [RSAKey(key=import_rsa_key_from_file(KEY))]
    # keys[0]._keytype = "private"
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
    payload = b'{"iss":"joe",\r\n "exp":1300819380,' \
              b'\r\n "http://example.com/is_root":true}'
    val = b64e(payload)
    assert val == (
        b'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9'
        b'leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ')


def test_a_1_1c():
    hmac = jwkest.intarr2bin(HMAC_KEY)
    signer = SIGNER_ALGS["HS256"]
    header = b'{"typ":"JWT",\r\n "alg":"HS256"}'
    payload = b'{"iss":"joe",\r\n "exp":1300819380,' \
              b'\r\n "http://example.com/is_root":true}'
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
    _jws = JWS(msg, cty="JWT", alg="HS256", jwk=key.serialize())
    res = _jws.sign_compact()

    _jws2 = JWS(alg="HS256")
    _jws2.verify_compact(res, keys=[key])
    assert _jws2.msg == msg


def test_jws_2():
    msg = {"iss": "joe", "exp": 1300819380, "http://example.com/is_root": True}
    key = SYMKey(key=jwkest.intarr2bin(HMAC_KEY))
    _jws = JWS(msg, cty="JWT", alg="HS256", jwk=key.serialize())
    res = _jws.sign_compact()

    _jws2 = JWS(alg="HS256")
    _jws2.verify_compact_verbose(res, keys=[key])
    assert _jws2.msg == msg
    assert _jws2.key == key


def test_signer_es256():
    payload = "Please take a moment to register today"
    _key = ECKey().load_key(P256)
    keys = [_key]
    _jws = JWS(payload, alg="ES256")
    _jwt = _jws.sign_compact(keys)

    _rj = JWS()
    info = _rj.verify_compact(_jwt, keys)
    assert info == payload


def test_signer_es256_verbose():
    payload = "Please take a moment to register today"
    _key = ECKey().load_key(P256)
    keys = [_key]
    _jws = JWS(payload, alg="ES256")
    _jwt = _jws.sign_compact(keys)

    _rj = JWS()
    info = _rj.verify_compact_verbose(_jwt, keys)
    assert info['msg'] == payload
    assert info['key'] == _key


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
    # keys[0]._keytype = "private"
    _jws = JWS(payload, alg="ES512")
    _jwt = _jws.sign_compact(keys)

    _rj = JWS()
    info = _rj.verify_compact(_jwt, keys)
    assert info == payload


def test_signer_ps256():
    payload = "Please take a moment to register today"
    keys = [RSAKey(key=import_rsa_key_from_file(KEY))]
    # keys[0]._keytype = "private"
    _jws = JWS(payload, alg="PS256")
    _jwt = _jws.sign_compact(keys)

    _rj = JWS()
    info = _rj.verify_compact(_jwt, keys)
    assert info == payload


def test_signer_ps256_fail():
    payload = "Please take a moment to register today"
    keys = [RSAKey(key=import_rsa_key_from_file(KEY))]
    # keys[0]._keytype = "private"
    _jws = JWS(payload, alg="PS256")
    _jwt = _jws.sign_compact(keys)[:-5] + 'abcde'

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
    # keys[0]._keytype = "private"
    _jws = JWS(payload, alg="PS384")
    _jwt = _jws.sign_compact(keys)

    _rj = JWS()
    info = _rj.verify_compact(_jwt, keys)
    assert info == payload


def test_signer_ps512():
    payload = "Please take a moment to register today"
    # Key has to be big enough  > 512+512+2
    keys = [RSAKey(key=import_rsa_key_from_file(full_path("./size2048.key")))]
    # keys[0]._keytype = "private"
    _jws = JWS(payload, alg="PS512")
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
         "d": "ckLyXxkbjC4szg8q8G0ERBZV"
              "-9CszeOxpRtx1KM9BLl0Do3li_Km2vvFvfXJ7MxQpiZ18pBoCcyYQEU262ym8wI22JWMPrZe24HCNxLxqzr_JEuBhpKFxQF6EFTSvJEJD1FkoTuCTvN0zD7YHGaJQG6JzVEuFUY3ewxjH0FYNa_ppTnPP3LC-T9u_GX9Yqyuw1KOYoHSzhWSWQOeAgs4dH9-iAxN1wdZ6eH1jFWAs43svk_rhwdgyJMlihFtV9MAInBlfi_Zu8wRVhVl5urkJrLf0tGFnMbnzb6dYSlUXxEYClpY12W7kXW9aePDqkCwI4oZyxmOmgq4hunKGR1dAQ",
         "e": "AQAB",
         "use": "sig",
         "kid": "af22448d-4c7b-464d-b63a-f5bd90f6d7d1",
         "n": "o9g8DpUwBW6B1qmcm-TfEh4rNX7n1t38jdo4Gkl_cI3q"
              "--7n0Blg0kN88LHZvyZjUB2NhBdFYNxMP8ucy0dOXvWGWzaPmGnq3DM__lN8P4WjD1cCTAVEYKawNBAmGKqrFj1SgpPNsSqiqK-ALM1w6mZ-QGimjOgwCyJy3l9lzZh5D8tKnS2t1pZgE0X5P7lZQWHYpHPqp4jKhETzrCpPGfv0Rl6nmmjp7NlRYBkWKf_HEKE333J6M039m2FbKgxrBg3zmYYpmHuMzVgxxb8LSiv5aqyeyJjxM-YDUAgNQBfKNhONqXyu9DqtSprNkw6sqmuxK0QUVrNYl3b03PgS5Q"
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
    enc_header, enc_payload, sig = _jwt.split('.')
    assert json.loads(
            b64d(enc_header.encode("utf-8")).decode("utf-8")) == exp_protected
    assert b64d(enc_payload.encode("utf-8")).decode("utf-8") == payload

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
    protectedHeader, enc_payload, sig = _jwt.split(".")
    data = dict(payload=enc_payload, signatures=[
        dict(
                header=dict(alg=u"ES256", jwk=_key.serialize()),
                protected=protectedHeader,
                signature=sig,
        )
    ])
    _jws = JWS()
    assert _jws.verify_json(json.dumps(data)) == payload


def test_sign_json():
    key = ECKey().load_key(P256)
    payload = "hello world"
    unprotected_headers = {"abc": "xyz"}
    protected_headers = {"foo": "bar"}
    _jwt = JWS(msg=payload, alg="ES256").sign_json(
            headers=[(protected_headers, unprotected_headers)],
            keys=[key])
    jwt = json.loads(_jwt)
    assert b64d_enc_dec(jwt["payload"]) == payload
    assert len(jwt["signatures"]) == 1
    assert jwt["signatures"][0]["header"] == unprotected_headers
    assert json.loads(b64d_enc_dec(jwt["signatures"][0]["protected"])) == protected_headers


def test_verify_json():
    key = ECKey().load_key(P256)
    payload = "hello world"
    unprotected_headers = {"abc": "xyz"}
    protected_headers = {"foo": "bar"}
    _jwt = JWS(msg=payload, alg="ES256").sign_json(
            headers=[(protected_headers, unprotected_headers)],
            keys=[key])

    assert JWS().verify_json(_jwt, keys=[key])


def test_sign_json_dont_include_empty_unprotected_headers():
    key = ECKey().load_key(P256)
    protected_headers = {"foo": "bar"}
    _jwt = JWS(msg="hello world", alg="ES256").sign_json(headers=[(protected_headers, None)],
                                                         keys=[key])
    json_jws = json.loads(_jwt)
    assert "header" not in json_jws["signatures"][0]
    jws_protected_headers = json.loads(b64d_enc_dec(json_jws["signatures"][0]["protected"]))
    assert set(protected_headers.items()).issubset(set(jws_protected_headers.items()))


def test_sign_json_dont_include_empty_protected_headers():
    key = ECKey().load_key(P256)
    unprotected_headers = {"foo": "bar"}
    _jwt = JWS(msg="hello world", alg="ES256").sign_json(headers=[(None, unprotected_headers)],
                                                         keys=[key])
    json_jws = json.loads(_jwt)
    jws_protected_headers = json.loads(b64d_enc_dec(json_jws["signatures"][0]["protected"]))
    assert jws_protected_headers == {"alg": "ES256"}
    jws_unprotected_headers = json_jws["signatures"][0]["header"]
    assert unprotected_headers == jws_unprotected_headers


def test_sign_json_flattened_syntax():
    key = ECKey().load_key(P256)
    protected_headers = {"foo": "bar"}
    unprotected_headers = {"abc": "xyz"}
    payload = "hello world"
    _jwt = JWS(msg=payload, alg="ES256").sign_json(
            headers=[(protected_headers, unprotected_headers)],
            keys=[key], flatten=True)
    json_jws = json.loads(_jwt)
    assert "signatures" not in json_jws

    assert b64d_enc_dec(json_jws["payload"]) == payload
    assert json_jws["header"] == unprotected_headers
    assert json.loads(b64d_enc_dec(json_jws["protected"])) == protected_headers


def test_verify_json_flattened_syntax():
    key = ECKey().load_key(P256)
    protected_headers = {"foo": "bar"}
    unprotected_headers = {"abc": "xyz"}
    payload = "hello world"
    _jwt = JWS(msg=payload, alg="ES256").sign_json(
            headers=[(protected_headers, unprotected_headers)],
            keys=[key], flatten=True)

    assert JWS().verify_json(_jwt, keys=[key])


def test_sign_json_dont_flatten_if_multiple_signatures():
    key = ECKey().load_key(P256)
    unprotected_headers = {"foo": "bar"}
    _jwt = JWS(msg="hello world", alg="ES256").sign_json(headers=[(None, unprotected_headers),
                                                                  (None, {"abc": "xyz"})],
                                                         keys=[key], flatten=True)
    assert "signatures" in json.loads(_jwt)


def test_is_jws_recognize_compact_jws():
    key = ECKey().load_key(P256)
    jws = JWS(msg="hello world", alg="ES256").sign_compact([key])
    assert JWS().is_jws(jws)


def test_is_jws_recognize_json_serialized_jws():
    key = ECKey().load_key(P256)
    jws = JWS(msg="hello world", alg="ES256").sign_json([key])
    assert JWS().is_jws(jws)


def test_is_jws_recognize_flattened_json_serialized_jws():
    key = ECKey().load_key(P256)
    jws = JWS(msg="hello world", alg="ES256").sign_json([key], flatten=True)
    assert JWS().is_jws(jws)


def test_pick_use():
    keys = KEYS()
    keys.load_dict(JWK2)
    _jws = JWS("foobar", alg="RS256", kid="MnC_VZcATfM5pOYiJHMba9goEKY")
    _keys = _jws.pick_keys(keys, use="sig")
    assert len(_keys) == 1


def test_pick_wrong_alg():
    keys = KEYS()
    keys.load_dict(JWKS0)
    _jws = JWS("foobar", alg="RS256", kid="rsa1")  # should be RSA256
    _keys = _jws.pick_keys(keys, use="sig")
    assert len(_keys) == 0


def test_dj_usage():
    key_string = open(full_path("./size2048.key"), 'r').read()
    key = RSA.importKey(key_string)
    payload = "Please take a moment to register today"
    keys = [RSAKey(key=key, kid=md5(key_string.encode('utf-8')).hexdigest())]
    _jws = JWS(payload, alg='RS256')
    sjwt = _jws.sign_compact(keys)
    _jwt = factory(sjwt)
    assert _jwt.jwt.headers['alg'] == 'RS256'


def test_rs256_rm_signature():
    payload = "Please take a moment to register today"
    keys = [RSAKey(key=import_rsa_key_from_file(KEY))]
    # keys[0]._keytype = "private"
    _jws = JWS(payload, alg="RS256")
    _jwt = _jws.sign_compact(keys)

    p = _jwt.split('.')
    _jwt = '.'.join(p[:-1])

    _rj = JWS()
    try:
        _ = _rj.verify_compact(_jwt, keys)
    except jwkest.WrongNumberOfParts:
        pass
    else:
        assert False


def test_pick_alg_assume_alg_from_single_key():
    expected_alg = "HS256"
    keys = [SYMKey(k="foobar", alg=expected_alg)]

    alg = JWS()._pick_alg(keys)
    assert alg == expected_alg


def test_pick_alg_dont_get_alg_from_single_key_if_already_specified():
    expected_alg = "RS512"
    keys = [RSAKey(key=import_rsa_key_from_file(KEY), alg="RS256")]

    alg = JWS(alg=expected_alg)._pick_alg(keys)
    assert alg == expected_alg


if __name__ == "__main__":
    test_is_jws_recognize_json_serialized_jws()
