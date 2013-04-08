#!/usr/bin/env python
import json
import argparse
import os
import M2Crypto
from M2Crypto.util import no_passphrase_callback

__author__ = 'rolandh'

def create_and_store_rsa_key_pair(name="pyoidc", path=".", size=1024):
    #Seed the random number generator with 1024 random bytes (8192 bits)
    M2Crypto.Rand.rand_seed(os.urandom(size))

    key = M2Crypto.RSA.gen_key(size, 65537, lambda : None)

    keyfile = os.path.join(path,name)

    key.save_key(keyfile, None, callback=no_passphrase_callback)
    key.save_pub_key(keyfile + ".pub")

    jwk_spec = json.dumps(key, "enc")
    f = open(keyfile + ".jwk", "w")
    f.write( str(jwk_spec) )
    f.close()

    return key

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('-n', dest="name", default="pyoidc",
                        help="file names")
    parser.add_argument('-p', dest="path", default=".",
                        help="Path to the directory for the files")
    parser.add_argument('-s', dest="size", default=1024,
                        help="Key size", type=int)

    args = parser.parse_args()

    create_and_store_rsa_key_pair(args.name, args.path, args.size)
