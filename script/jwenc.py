#!/usr/bin/env python
import sys

__author__ = 'rohe0002'

import argparse
import requests
from jwkest.jwk import load_jwks_from_url, RSAKey, keyitems2keyreps
from jwkest.jwk import rsa_load
from jwkest.jwk import load_x509_cert
from jwkest.jwk import load_jwks
from jwkest.jwe import SUPPORTED, JWE
from jwkest.jwk import import_rsa_key_from_file
#from jwkest.jwe import JWE_RSA


def assign(lst):
    _keys = {}
    for typ, key in lst:
        try:
            _keys[typ].append(key)
        except KeyError:
            _keys[typ] = [key]
    return _keys


def lrequest(url, method="GET", **kwargs):
    return requests.request(method, url, **kwargs)


# arg can be RSA-OAEP
# enc for instance A128CBC+HS256

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', dest='debug', action='store_true',
                        help="Print debug information")
    parser.add_argument('-v', dest='verbose', action='store_true',
                        help="Print runtime information")
    parser.add_argument('-x', dest="x509_file",
                        help="File containing a X509 certificate")
    parser.add_argument('-X', dest="x509_url",
                        help="URL pointing to a file containing a X509 "
                             "certificate")
    parser.add_argument('-j', dest="jwk_file",
                        help="File containing a JWK")
    parser.add_argument('-J', dest="jwk_url",
                        help="URL pointing to a file containing a JWK")
    parser.add_argument('-r', dest="rsa_file",
                        help="A file containing a RSA key")
    parser.add_argument('-a', dest="alg",
                        help="The encryption algorithm")
    parser.add_argument("-e", dest="enc", help="The encryption method")
    parser.add_argument("-m", dest="mode", default="public",
                        help="Whether a public or private key should be used")
    parser.add_argument("-f", dest="file",
                        help="File to be encrypted")
    parser.add_argument("message", nargs="?", help="The message to encrypt")

    args = parser.parse_args()

    keys = {}
    if args.jwk_url:
        keys = assign(load_jwks_from_url(args.jwk_url, {}))
    elif args.jwk_file:
        keys = assign(load_jwks(open(args.jwk_file).read()))
    elif args.x509_url:
        keys = assign(load_x509_cert(lrequest, args.x509_url))
    elif args.x509_file:
        keys = {"RSA": [import_rsa_key_from_file(args.x509_file)]}
    elif args.rsa_file:
        keys = {"RSA": [rsa_load(args.rsa_file)]}
        mode = ""
    else:
        print >> sys.stderr, "Needs encryption key"
        exit()

    if not args.enc or not args.alg:
        print >> sys.stderr, "There are no default encryption methods"
        exit()

    if args.enc not in SUPPORTED["enc"]:
        print >> sys.stderr, "Encryption method %s not supported" % args.enc
        print >> sys.stderr, "Methods supported: %s" % SUPPORTED["enc"]
        exit()

    if args.alg not in SUPPORTED["alg"]:
        print >> sys.stderr, "Encryption algorithm %s not supported" % args.alg
        print >> sys.stderr, "Algorithms supported: %s" % SUPPORTED["alg"]
        exit()

    if args.file:
        message = open(args.file).read()
    elif args.message == "-":
        message = sys.stdin.read()
    else:
        message = args.message

    krs = keyitems2keyreps(keys)

    jwe = JWE(message, alg=args.alg, enc=args.enc)
    print jwe.encrypt(krs)
