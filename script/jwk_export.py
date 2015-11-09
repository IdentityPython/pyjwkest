#!/usr/bin/env python
import argparse
import json
import os

from jwkest.jwk import RSAKey
from jwkest.jwk import rsa_load

__author__ = 'rolandh'

parser = argparse.ArgumentParser()
parser.add_argument('-n', dest="name", default="pyoidc",
                    help="file names")
parser.add_argument('-p', dest="path", default=".",
                    help="Path to the directory for the files")
parser.add_argument('-k', dest="key", help="Key file")

args = parser.parse_args()

rsa_key = RSAKey(key=rsa_load(args.key))

keyfile = os.path.join(args.path, args.name)

f = open(keyfile + ".jwk", "w")
f.write(json.dumps(rsa_key.serialize()))
f.close()
