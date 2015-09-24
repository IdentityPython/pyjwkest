import base64
import os
import struct
from jwkest import long2intarr, b64d, b64e
from jwkest import intarr2long
from jwkest import base64_to_long
from jwkest import long_to_base64
from jwkest.jwk import pem_cert2rsa

__author__ = 'roland'

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


CERT = full_path("cert.pem")
KEY = full_path("server.key")

_CKEY = pem_cert2rsa(CERT)


def test_long_intarr_long():
    ia = long2intarr(_CKEY.n)
    _n = intarr2long(ia)
    assert _CKEY.n == _n


def test_long_bytes_long():
    ia = long2intarr(_CKEY.n)
    data = struct.pack('%sB' % len(ia), *ia)
    ia2 = struct.unpack('%sB' % len(data), data)
    _n = intarr2long(ia2)
    assert _CKEY.n == _n


def test_long_base64_long():
    _n = long_to_base64(_CKEY.n)
    l = base64_to_long(_n)
    assert _CKEY.n == l


def test_b64d_with_padded_data():
    data = "abcd".encode("utf-8")
    encoded = base64.urlsafe_b64encode(data)
    assert b64d(encoded) == data


def test_b64_encode_decode():
    data = "abcd".encode("utf-8")
    assert b64d(b64e(data)) == data


if __name__ == "__main__":
    test_long_base64_long()
