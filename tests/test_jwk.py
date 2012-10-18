from binascii import hexlify
import M2Crypto
from jwkest import jwe
from jwkest.jwk import kspec
from jwkest.jwk import base64_to_long
from jwkest.jwk import long_to_mpi
from jwkest.jwk import x509_rsa_loads

__author__ = 'rohe0002'

def test_1():
    cert = "certs/cert.pem"

    _ckey = x509_rsa_loads(open(cert).read())
    _jwk = kspec(_ckey, "foo")

    e = base64_to_long(_jwk["exp"])
    n = base64_to_long(_jwk["mod"])

    _jkey = M2Crypto.RSA.new_pub_key((long_to_mpi(e), long_to_mpi(n)))

    cn = jwe.hd2ia(hexlify(_ckey.n))
    jn = jwe.hd2ia(hexlify(_jkey.n))

    assert cn == jn