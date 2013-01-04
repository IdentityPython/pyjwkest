from jwkest.jwk import x509_rsa_loads
from jwkest.jwk import kspec
from jwkest.jwk import base64_to_long

__author__ = 'rolandh'

cert = "certs/cert.pem"

_ckey = x509_rsa_loads(open(cert).read())
_jwk = kspec(_ckey, "foo")

print _jwk
e = base64_to_long(_jwk["xpo"])
n = base64_to_long(_jwk["mod"])

print e
print n
