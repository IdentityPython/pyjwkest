__author__ = 'rolandh'

from jwkest import jws
from jwkest.jwk import rsa_load

KEY = "certs/server.key"

_ckey = rsa_load(KEY)

payload = "Please take a moment to register today"

keycol = {"rsa": [_ckey]}

_jwt = jws.sign(payload, keycol, "RS256")

info = jws.verify(_jwt, keycol)

assert info == payload
