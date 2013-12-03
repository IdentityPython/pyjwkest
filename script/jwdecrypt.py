#!/usr/bin/env python
import sys

__author__ = 'rohe0002'

import argparse
import requests
from jwkest.jwk import load_jwks_from_url
from jwkest.jwk import keyitems2keyreps
from jwkest.jwk import rsa_load
from jwkest.jwk import load_x509_cert
from jwkest.jwk import load_jwks
from jwkest.jwk import import_rsa_key_from_file
from jwkest.jwe import JWE


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


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', dest='debug', action='store_true',
                        help="Print debug information")
    #    parser.add_argument('-v', dest='verbose', action='store_true',
    #                        help="Print runtime information")
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
    parser.add_argument("-i", dest="int", help="Integrity method")
    parser.add_argument("-m", dest="mode", default="private",
                        help="Whether a public or private key should be used")
    parser.add_argument("-f", dest="file", help="File with the message")
    parser.add_argument("message", nargs="?", help="The message to encrypt")

    args = parser.parse_args()

    keys = {}
    if args.jwk_url:
        keys = assign(load_jwks_from_url(lrequest, args.jwk_url))
        if args.mode == "private":
            print >> sys.stderr, "Missing private key to decrypt with"
            exit()
    elif args.jwk_file:
        keys = assign(load_jwks(open(args.jwk_file).read()))
        if args.mode == "private":
            print >> sys.stderr, "Missing private key to decrypt with"
            exit()
    elif args.x509_url:
        keys = assign(load_x509_cert(lrequest, args.x509_url))
        if args.mode == "private":
            print >> sys.stderr, "Missing private key to decrypt with"
            exit()
    elif args.x509_file:
        keys = {"rsa": [import_rsa_key_from_file(args.x509_file)]}
        if args.mode == "private":
            print >> sys.stderr, "Missing private key to decrypt with"
            exit()
    elif args.rsa_file:
        keys = {"rsa": [rsa_load(args.rsa_file)]}
    else:
        print >> sys.stderr, "Needs encryption key"
        exit()

    if args.file:
        msg = open(args.file).read()
        msg = msg.strip("\n\r")
    else:
        msg = args.message

    krs = keyitems2keyreps(keys)

    jwe = JWE()
    print jwe.decrypt(msg, krs)
