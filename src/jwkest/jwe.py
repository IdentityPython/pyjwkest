# JSON Web Encryption
# Implemented
# draft-ietf-jose-json-web-encryption-05

import json
import os
import struct
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

def int2bigendian(n):
    return [ord(c) for c in struct.pack('>I', n)]

def party_value(pv):
    if pv:
        s = b64e(pv)
        r = int2bigendian(len(s))
        r.extend(s)
        return r
    else:
        return [0,0,0,0]

def _hash_input(cmk, enc, label, round=1, length=128, hashsize=256,
                epu="", epv=""):
    r = [0,0,0,round]
    r.extend(cmk)
    #- AlgorithmID
    #the output bit size as a 32 bit big endian number
    r.extend([0,0,0,length])
    # the bytes of the UTF-8 representation of the "enc" value
    r.extend([ord(c) for c in enc])
    #- PartyUInfo
    r.extend(party_value(epu))
    #- PartyVInfo
    r.extend(party_value(epv))
    #- SuppPubInfo
    r.extend(label)
    return r

def key_derivation(cmk, enc, label, round=1, hashsize=256, epu="", epv="",
                   bsize=128):
    """

    :param cmk: Content Master Key
    :param label: The label
    :param round: which round. An int (1-)
    :param hashsize:
    :param epu:
    :param epv:
    :param bsize:
    :return: a hash
    """
    r = [0,0,0,round]
    r.extend(cmk)
    #- AlgorithmID
    #the output bit size as a 32 bit big endian number
    r.extend(int2bigendian(bsize))
    # the bytes of the UTF-8 representation of the "enc" value
    r.extend([ord(c) for c in enc])
    #- PartyUInfo
    r.extend(party_value(epu))
    #- PartyVInfo
    r.extend(party_value(epv))
    #- SuppPubInfo
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
    return hd[:(bsize/8)]

def get_cek(cmk, enc, round=1, hashsize=256, epu="", epv="", bsize=0):
    if not bsize:
        bsize = len(cmk)*4
    return key_derivation(cmk, enc,
                          # "Encryption"
                          [69, 110, 99, 114, 121, 112, 116, 105, 111, 110],
                          round=round,
                          hashsize=hashsize, epu=epu, epv=epv, bsize=bsize)

def get_cik(cmk, enc, round=1, hashsize=256, epu="", epv="", bsize=0):
    if not bsize:
        bsize = len(cmk)*8
    return key_derivation(cmk, enc,
                          # "Integrity"
                          [73, 110, 116, 101, 103, 114, 105, 116, 121],
                          round=round,
                          hashsize=hashsize, epu=epu, epv=epv, bsize=bsize)

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

class ENV(object):
    def __init__(self, alg=None, enc=None, epk=None, zip=None, jku=None,
                 jwk=None, x5u=None, x5t=None, x5c=None, kid=None, typ=None,
                 cty=None, apu=None, apv=None, epu=None, epv=None, **kwargs):
        self.alg = alg
        self.enc = enc
        self.epk = epk
        self.zip = zip
        self.jku = jku
        self.jwk = jwk
        self.x5u = x5u
        self.x5t = x5t
        self.x5c = x5c
        self.kid = kid
        self.typ = typ
        self.cty = cty
        self.apu = apu
        self.apv = apv
        self.epu = epu
        self.epv = epv

    def to_json(self):
        return json.dumps(dict([(k,v) for k,v in self.__dict__.items() if v]))

    def from_json(self, txt):
        _dict = json.loads(txt)
        for key, val in _dict.items():
            setattr(self, key, val)
        self.verify()
        return self

    def verify(self):
        if self.zip:
            assert self.zip == "DEF"

# ---------------------------------------------------------------------------

def rsa_encrypt(msg, key, alg="RSA-OAEP", enc="A256GCM",
                context="public", kdf="CS256", iv="", cmk="",
                zip="", debug=False, epu="", epv="", **kwargs):

    _env = ENV(alg, enc, zip=zip, epu=epu, epv=epv, **kwargs)
    _env.verify()

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

        cek = get_cek(_dc, enc, hashsize=keysize(kdf), epu=epu, epv=epv,
                      bsize=keysize(ealg))
        cik = get_cik(_dc, enc, hashsize=keysize(kdf), epu=epu, epv=epv,
                      bsize=keysize(int))
        c = M2Crypto.EVP.Cipher(alg=ENC2ALG[ealg], key=cek, iv=iv, op=ENC)

        _env.typ = "JWE"

        if zip:
            msg = zlib.compress(msg)

        ctxt = aes_enc(c, msg)
        #t = None
        header = _env.to_json()

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
    _head, ejek, eiv, ctxt, tag = token.split(b".")
    _env = ENV().from_json(b64d(_head))
    iv = b64d(eiv)

    if context == "private":
        _decrypt = RSAEncrypter().private_decrypt
    else:
        _decrypt = RSAEncrypter().public_decrypt

    jek = b64d(ejek)

    if debug:
        print >> sys.stderr, "enc_key", hd2ia(hexlify(jek))

    if _env.alg == "RSA-OAEP":
        cmk = _decrypt(jek, key, 'pkcs1_oaep_padding')
    elif _env.alg == "RSA1_5":
        cmk = _decrypt(jek, key)
    else:
        raise NotSupportedAlgorithm(_env.alg)

    enc = _env.enc
    assert enc in SUPPORTED["enc"]

    if enc == "A256GCM":
        auth_data = _head + b'.' + ejek + b'.' + eiv
        msg = gcm_decrypt(cmk, iv, b64d(ctxt), auth_data, b64d(tag))
    elif enc.startswith("A128CBC+") or enc.startswith("A256CBC+"):
        enc, int = enc.split("+")

        _dc = hd2ia(hexlify(cmk))
        if debug:
            print >> sys.stderr, "_dc:", _dc

        cek = get_cek(_dc, _env.enc, bsize=keysize(enc), hashsize=keysize(int),
                      epu=_env.epu, epv=_env.epv)
        cik = get_cik(_dc, _env.enc, bsize=keysize(int), hashsize=keysize(int),
                      epu=_env.epu, epv=_env.epv)

        c = M2Crypto.EVP.Cipher(alg=ENC2ALG[enc], key=cek, iv=iv, op=DEC)

        msg = aes_dec(c, b64d(ctxt))
        if debug:
            print >> sys.stderr, "tag: '%s'" % tag

        verifier = SIGNER_ALGS[int]
        verifier.verify(b'.'.join([_head, ejek, eiv, ctxt]), b64d(tag), cik)
    else:
        raise MethodNotSupported(enc)

    if _env.zip == "DEF":
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