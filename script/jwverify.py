#!/usr/bin/env python
import sys

__author__ = 'rohe0002'

import argparse
import requests

from jwkest import unpack
from jwkest.jws import verify
from jwkest.jwk import rsa_load
from jwkest.jwk import x509_rsa_loads
from jwkest.jwk import rsa_pub_load

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
    parser.add_argument('-r', dest="rsa_file",
                        help="File containing a RSA key")
    parser.add_argument('-p', dest="rsa_pub_file",
                        help="File containing a public RSA key")
    parser.add_argument('-k', dest="hmac_key",
                        help="If using a HMAC algorithm this is the key")
    parser.add_argument('-x', dest="x509_file",
                        help="File containing a X509 certificate")
    parser.add_argument("message", nargs="?",
                        help="The message to verify signature on")


    args = parser.parse_args()

    keys = {}
    if args.rsa_file:
        keys = {"rsa": [rsa_load(args.rsa_file)]}
    elif args.hmac_key:
        keys = {"hmac": [args.hmac_key]}
    elif args.x509_file:
        keys = {"rsa": [x509_rsa_loads(open(args.x509_file).read())]}
    elif args.rsa_pub_file:
        keys = {"rsa": [rsa_pub_load(args.rsa_pub_file)]}

    if args.message == "-":
        message = sys.stdin.read()
    else:
        message = args.message

    if keys:
        print verify(message, keys)
    else:
        print unpack(message)[1]
