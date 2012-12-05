# JSON Web Encryption
# Implemented
# draft-ietf-jose-json-web-encryption-05

import json
import os
import M2Crypto
import cStringIO
import hashlib
import logging
import zlib

from binascii import hexlify
import sys

from jwkest import b64d
from jwkest import b64e
from jwkest import intarr2bin
from jwkest import hd2ia
from jwkest.gcm import gcm_encrypt
from jwkest.gcm import gcm_decrypt
from jwkest.jws import SIGNER_ALGS

logger = logging.getLogger(__name__)

__author__ = 'rohe0002'

ENC = 1
DEC = 0

class CannotDecode(Exception):
    pass

class NotSupportedAlgorithm(Exception):
    pass

class MethodNotSupported(Exception):
    pass

# ---------------------------------------------------------------------------
# Base class
class Encrypter(object):
    """Abstract base class for encryption algorithms."""

    def __init__(self):
        pass

    def public_encrypt(self, msg, key):
        """Encrypt ``msg`` with ``key`` and return the encrypted message."""
        raise NotImplementedError

    def public_decrypt(self, msg, key):
        """Return decrypted message."""
        raise NotImplementedError

    def private_encrypt(self, msg, key):
        """Encrypt ``msg`` with ``key`` and return the encrypted message."""
        raise NotImplementedError

    def private_decrypt(self, msg, key):
        """Return decrypted message."""
        raise NotImplementedError

class RSAEncrypter(Encrypter):

    def public_encrypt(self, msg, key, padding="pkcs1_padding"):
        p = getattr(M2Crypto.RSA, padding)
        return key.public_encrypt(msg, p)

    def private_encrypt(self, msg, key, padding="pkcs1_padding"):
        p = getattr(M2Crypto.RSA, padding)
        return key.private_encrypt(msg, p)

    def public_decrypt(self, msg, key, padding="pkcs1_padding"):
        p = getattr(M2Crypto.RSA, padding)
        try:
            return key.public_decrypt(msg, p)
        except M2Crypto.RSA.RSAError, e:
            raise CannotDecode(e)

    def private_decrypt(self, msg, key, padding="pkcs1_padding"):
        p = getattr(M2Crypto.RSA, padding)
        try:
            return key.private_decrypt(msg, p)
        except M2Crypto.RSA.RSAError, e:
            raise CannotDecode(e)

# ---------------------------------------------------------------------------

def key_derivation(cmk, label, round=1, length=128, hashsize=256):
    """

    :param cmk: Content Master Key
    :param label: The label
    :param round: which round. An int (1-)
    :param length: length of the return digest
    :param hashsize:
    :return: a hash
    """
    be1 = [0,0,0,round]
    r = be1
    r.extend(cmk)
    r.extend(label)
    if hashsize == 256:
        hv = hashlib.sha256(intarr2bin(r))
    elif hashsize == 384:
        hv = hashlib.sha384(intarr2bin(r))
    elif hashsize == 512:
        hv = hashlib.sha512(intarr2bin(r))
    else:
        raise Exception("Unsupported hash length")

    #hd = hv.hexdigest()
    hd = hv.digest()

    #return hd[:(length/4)]
    return hd[:(length/8)]

def get_cek(cmk, round=1, length=128, hashsize=256):
    return key_derivation(cmk,
                          [69, 110, 99, 114, 121, 112, 116, 105, 111, 110],
                          round=round,
                          length=length,
                          hashsize=hashsize)

def get_cik(cmk, round=1, length=256, hashsize=256):
    return key_derivation(cmk,
                          [73, 110, 116, 101, 103, 114, 105, 116, 121],
                          round=round,
                          length=length,
                          hashsize=hashsize)

# ---------------------------------------------------------------------------

def cipher_filter(cipher, inf, outf):
    while 1:
        buf=inf.read()
        if not buf:
            break
        outf.write(cipher.update(buf))
    outf.write(cipher.final())
    return outf.getvalue()

def aes_enc(key, str):
    pbuf=cStringIO.StringIO(str)
    cbuf=cStringIO.StringIO()
    ciphertext = cipher_filter(key, pbuf, cbuf)
    pbuf.close()
    cbuf.close()
    return ciphertext

def aes_dec(key, ciptxt):
    pbuf=cStringIO.StringIO()
    cbuf=cStringIO.StringIO(ciptxt)
    plaintext=cipher_filter(key, cbuf, pbuf)
    pbuf.close()
    cbuf.close()
    return plaintext

def keysize(spec):
    if spec.startswith("HS"):
        return int(spec[2:])
    elif spec.startswith("CS"):
        return int(spec[2:])
    elif spec.startswith("A"):
        return int(spec[1:4])
    return 0

ENC2ALG = {"A128CBC": "aes_128_cbc", "A256CBC": "aes_256_cbc"}

SUPPORTED = {
    "alg": ["RSA1_5", "RSA-OAEP"],
    "enc": ["A128CBC+HS256", "A256CBC+HS512", "A256GCM"],
}

# ---------------------------------------------------------------------------

def rsa_encrypt(msg, key, alg="RSA-OAEP", enc="A256GCM",
                context="public", kdf="CS256", iv="", cmk="",
                compress=False, debug=False):

    # content master key 256 bit
    if not cmk:
        cmk = os.urandom(32)

    if context == "private":
        _encrypt = RSAEncrypter().private_encrypt
    else:
        _encrypt = RSAEncrypter().public_encrypt

    if alg == "RSA-OAEP":
        jwe_enc_key = _encrypt(cmk, key, 'pkcs1_oaep_padding')
    elif alg == "RSA1_5":
        jwe_enc_key = _encrypt(cmk, key)
    else:
        raise NotSupportedAlgorithm(alg)

    if debug:
        print >> sys.stderr, "enc_key:", hd2ia(hexlify(jwe_enc_key))

    if enc == "A256GCM":
        if not iv:
            iv = os.urandom(12) # 96 bits
        header = json.dumps({"alg":alg, "enc":enc})
        auth_data = b64e(header) + b'.' + b64e(jwe_enc_key) + b'.' + b64e(iv)
        ctxt, tag = gcm_encrypt(cmk, iv, msg, auth_data)
        res = auth_data + b'.' + b64e(ctxt)
    elif enc.startswith("A128CBC+") or enc.startswith("A256CBC+"):
        assert enc in SUPPORTED["enc"]
        ealg, int = enc.split("+")
        if not iv:
            if ealg == "A128CBC":
                iv = os.urandom(16) # 128 bits
            else: # ealg == "A256CBC"
                iv = os.urandom(32) # 256 bits
        _dc = hd2ia(hexlify(cmk))
        if debug:
            print >> sys.stderr, "_dc:", _dc

        cek = get_cek(_dc, length=keysize(ealg), hashsize=keysize(kdf))
        cik = get_cik(_dc, length=keysize(int), hashsize=keysize(kdf))
        c = M2Crypto.EVP.Cipher(alg=ENC2ALG[ealg], key=cek, iv=iv, op=ENC)

        _header = {"alg":alg, "enc":enc, "typ": "JWE"}

        if compress:
            msg = zlib.compress(msg)
            _header["zip"] = "DEF"

        ctxt = aes_enc(c, msg)
        #t = None
        header = json.dumps(_header)
        res = b'.'.join([b64e(header),b64e(jwe_enc_key),b64e(iv),b64e(ctxt)])
        signer = SIGNER_ALGS[int]
        tag = signer.sign(res, cik)
        if debug:
            print >> sys.stderr, "tag: %s" % hexlify(tag)
    else:
        raise NotSupportedAlgorithm(enc)

    if debug:
        print >> sys.stderr, "b64e.tag:", b64e(tag)

    res += b'.' + b64e(tag)
    return res

def rsa_decrypt(token, key, context, debug=False):
    """
    Does decryption according to the JWE proposal
    draft-ietf-jose-json-web-encryption-06

    :param token: The
    :param key:
    :return:
    """
    header, ejek, eiv, ctxt, tag = token.split(b".")
    dic = json.loads(b64d(header))
    iv = b64d(eiv)

    if context == "private":
        _decrypt = RSAEncrypter().private_decrypt
    else:
        _decrypt = RSAEncrypter().public_decrypt

    jek = b64d(ejek)

    if debug:
        print >> sys.stderr, "enc_key", hd2ia(hexlify(jek))

    if dic["alg"] == "RSA-OAEP":
        cmk = _decrypt(jek, key, 'pkcs1_oaep_padding')
    elif dic["alg"] == "RSA1_5":
        cmk = _decrypt(jek, key)
    else:
        raise NotSupportedAlgorithm(dic["alg"])

    enc = dic["enc"]
    assert enc in SUPPORTED["enc"]

    if enc == "A256GCM":
        auth_data = header + b'.' + ejek + b'.' + eiv
        msg = gcm_decrypt(cmk, iv, b64d(ctxt), auth_data, b64d(tag))
    elif enc.startswith("A128CBC+") or enc.startswith("A256CBC+"):
        enc, int = enc.split("+")

        _dc = hd2ia(hexlify(cmk))
        if debug:
            print >> sys.stderr, "_dc:", _dc

        cek = get_cek(_dc, length=keysize(enc), hashsize=keysize(int))
        cik = get_cik(_dc, length=keysize(int), hashsize=keysize(int))

        c = M2Crypto.EVP.Cipher(alg=ENC2ALG[enc], key=cek, iv=iv, op=DEC)

        msg = aes_dec(c, b64d(ctxt))
        if debug:
            print >> sys.stderr, "tag: '%s'" % tag

        verifier = SIGNER_ALGS[int]
        verifier.verify(b'.'.join([header,ejek,eiv,ctxt]), b64d(tag), cik)
    else:
        raise MethodNotSupported(enc)

    if "zip" in dic and dic["zip"] == "DEF":
        msg = zlib.decompress(msg)

    return msg

# =============================================================================

def encrypt(payload, keys, alg, enc, context, **kwargs):
    if alg.startswith("RSA") and alg in ["RSA-OAEP", "RSA1_5"]:
        encrypter = rsa_encrypt
        key = keys["rsa"][0]
    else:
        raise NotSupportedAlgorithm

    token = encrypter(payload, key, alg, enc, context, **kwargs)

    return token

def decrypt(token, dkeys, context, debug=False):

    header, ek, eiv, ctxt, tag = token.split(b".")
    dic = json.loads(b64d(str(header)))

    if dic["alg"].startswith("RSA") and dic["alg"] in ["RSA-OAEP", "RSA1_5"]:
        decrypter = rsa_decrypt
        keys = dkeys["rsa"]
    else:
        raise NotSupportedAlgorithm


    for key in keys:
        try:
            msg = decrypter(str(token), key, context, debug)
            return msg
        except KeyError:
            pass

    raise