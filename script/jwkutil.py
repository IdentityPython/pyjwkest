#!/usr/bin/env python
import json
import sys

__author__ = 'rohe0002'

import argparse
import requests
from jwkest.jwk import RSAKey, keyrep, load_jwks
from jwkest.jwk import import_rsa_key_from_file
from jwkest.jwk import SYMKey
from jwkest.jws import JWS

def assign(lst):
    keys = {}
    for typ, key in lst:
        try:
            keys[typ].append(key)
        except KeyError:
            keys[typ] = [key]
    return keys


def lrequest(url, method="GET", **kwargs):
    return requests.request(method, url, **kwargs)


def sign(msg, key, alg):
    _jws = JWS(msg, alg=alg)
    return _jws.sign_compact(key)


def verify(msg, keys):
    _jws = JWS()
    return _jws.verify_compact(msg, keys)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', dest="sign", action='store_true')
    parser.add_argument('-v', dest="verify", action='store_true')
    parser.add_argument('-f', dest="msg_file",
                        help="File containing a message")
    parser.add_argument('-r', dest="rsa_file",
                        help="File containing a RSA key")
    parser.add_argument('-k', dest="hmac_key",
                        help="If using a HMAC algorithm this is the key")
    parser.add_argument('-a', dest="alg",
                        help="The signing algorithm")
    parser.add_argument('-j', dest="jwk", help="JSON Web Key")
    parser.add_argument('-J', dest="jwks", help="JSON Web Keys")
    parser.add_argument("message", nargs="?", help="The message")


    args = parser.parse_args()

    keys = []
    if args.rsa_file:
        keys = [RSAKey(key=import_rsa_key_from_file(args.rsa_file))]
    elif args.hmac_key:
        keys = [SYMKey(key=args.hmac_key)]

    if args.jwk:
        kspec = json.loads(open(args.jwk).read())
        keys.append(keyrep(kspec))

    if args.jwks:
        txt = open(args.jwks).read()
        keys.extend(load_jwks(txt))

    if not keys:
        exit(-1)

    if args.msg_file:
        message = open(args.msg_file).read().strip("\n")
    elif args.message == "-":
        message = sys.stdin.read()
    else:
        message = args.message

    if args.sign:
        print sign(message, keys, args.alg)
    elif args.verify:
        print verify(message, keys)


# Given that idptest contains a RSA private key PEM encoded
# ./jwkutil.py -s -r idptest -a RS256 -f ../setup.py > sig
# ./jwkutil.py -v -r idptest -f sig