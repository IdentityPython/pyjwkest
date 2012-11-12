#!/usr/bin/env python
import sys

__author__ = 'rohe0002'

import argparse
import requests
from jwkest.jwk import load_jwk, rsa_load
from jwkest.jwk import load_x509_cert
from jwkest.jwk import x509_rsa_loads
from jwkest.jwk import loads
from jwkest.jwe import SUPPORTED
from jwkest.jwe import encrypt

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

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', dest='debug', action='store_true',
                              help="Print debug information")
    parser.add_argument('-v', dest='verbose', action='store_true',
                              help="Print runtime information")
    parser.add_argument('-x', dest="x509_file",
                              help="File containing a X509 certificate")
    parser.add_argument('-X', dest="x509_url",
                        help="URL pointing to a file containing a X509 certificate")
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
    parser.add_argument("message", nargs="?", help="The message to encrypt")


    args = parser.parse_args()

    keys = {}
    mode = "public"
    if args.jwk_url:
        keys = assign(load_jwk(lrequest, args.jwk_url))
    elif args.jwk_file:
        keys = assign(loads(open(args.jwk_file).read()))
    elif args.x509_url:
        keys = assign(load_x509_cert(lrequest, args.x509_url))
    elif args.x509_file:
        keys = {"rsa": [x509_rsa_loads(open(args.x509_file).read())]}
    elif args.rsa_file:
        keys = {"rsa": [rsa_load(args.rsa_file)]}
        mode = ""
    else:
        print >> sys.stderr, "Needs encryption key"
        exit()

    if mode == "public" and args.mode == "private":
        print >> sys.stderr, "Can't encrypt with a private key I don't have"
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

    if args.int not in SUPPORTED["int"]:
        print >> sys.stderr, "Integrity method %s not supported" % args.int
        print >> sys.stderr, "Integrity methods supported: %s" % SUPPORTED["int"]
        exit()

    if args.message == "-":
        message = sys.stdin.read()
    else:
        message = args.message

    print encrypt(message, keys, args.alg, args.enc, "public")