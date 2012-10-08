#!/usr/bin/env python
__author__ = 'rohe0002'

import argparse
import requests
import sys

from jwkest import unpack
from jwkest.jws import verify
from jwkest.jwk import rsa_load

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
    parser.add_argument('-k', dest="hmac_key",
                        help="If using a HMAC algorithm this is the key")
    parser.add_argument("message", nargs="?",
                        help="The message to verify signature on")


    args = parser.parse_args()

    keys = {}
    if args.rsa_file:
        keys = {"rsa": [rsa_load(args.rsa_file)]}
    elif args.hmac_key:
        keys = {"hmac": [args.hmac_key]}
        #else:
    #    print >> sys.stderr, "Needs verification key"
    #    exit()

    if keys:
        print verify(args.message, keys)
    else:
        print unpack(args.message)[1]
