#!/usr/bin/env python
import json
import os
import argparse
from jwkest.jwk import RSAKey, rsa_load, dump_jwks

__author__ = 'rolandh'

parser = argparse.ArgumentParser()
parser.add_argument('-n', dest="name", default="pyoidc",
                    help="file names")
parser.add_argument('-p', dest="path", default=".",
                    help="Path to the directory for the files")
parser.add_argument('-k', dest="key", help="Key file")

args = parser.parse_args()

key = rsa_load(args.key)
rsa_key = RSAKey(key=key)
rsa_key.serialize()

# This will create JWK from the public RSA key
jwk_spec = json.dumps(rsa_key.to_dict(), "enc")

keyfile = os.path.join(args.path, args.name)

_out = dump_jwks([{"key":key, "use":"enc"}])

f = open(keyfile + ".jwk", "w")
f.write(_out)
f.close()
