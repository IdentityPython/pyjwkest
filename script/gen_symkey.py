#! /usr/bin/env
import json
import random
import string

import argparse

from jwkest.jwk import SYMKey


__author__ = 'regu0004'

def rndstr(length):
    _basech = string.ascii_letters + string.digits
    return "".join([random.choice(_basech) for _ in range(length)])

def main():
    parser = argparse.ArgumentParser(description="Generate a new symmetric key and print it to stdout.")
    parser.add_argument("-s", dest="wrap_keyset", action="store_true",
                        help="Wrap the generated key in a key set (JWKS).")
    parser.add_argument("-n", dest="key_length", default=48, type=int, help="Length of the random string used as key.")
    parser.add_argument("--kid", dest="kid", help="Key id.")
    args = parser.parse_args()

    key = SYMKey(key=rndstr(args.key_length), kid=args.kid).serialize()
    if args.wrap_keyset:
        key_set = {"keys": [key]}
        print(json.dumps(key_set))
    else:
        print(json.dumps(key))


if __name__ == "__main__":
    main()