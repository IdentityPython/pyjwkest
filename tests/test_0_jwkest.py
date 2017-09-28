import base64
import os
import struct
from jwkest import long2intarr
from jwkest import b64d
from jwkest import b64e
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


def test_base64_long_base64():
    x64 = 'omXjOQmHl77TtpwMXL9WPcd-Xcg1bh8CoLGOyX1Ug_CLtZJx_SvSo0bj5bEiVb8eCa5mXuc6sDg9_RRpCvKHHxZG6f9qh5r3ZNY-yr5hKQqeMafWa4b6UqouLSSwKsNe5FWD327BoyaEsMyCRheQg4wX86G_8zqynuvbT6KzQbQtp4iqQvMWGswovmflsk7zoZUESAFu6L5xlJUEFXMlDLPH13SsPKwvL4MgHa-Cx938B0FReUFtq7qEQHIPhGSTOeTS-v8Acp6VqkmcLB4kCIsk_Icr46VTEPv3WWDHcbSzp-RPR0lTa8WTdOd_E98U70jfAZJAKMDWr4sQkvfk7w'
    _l = base64_to_long(x64)
    r64 = long_to_base64(_l)
    assert x64 == r64


if __name__ == "__main__":
    test_long_base64_long()
