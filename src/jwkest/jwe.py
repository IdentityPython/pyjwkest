# JSON Web Encryption
# Implemented
# draft-ietf-jose-json-web-encryption-09

import os
import struct
import M2Crypto
import cStringIO
import logging
import zlib

from binascii import hexlify
import sys
from jwkest.aes_key_wrap_m2 import aes_wrap_key

from jwkest import b64d
from jwkest import b64e
from jwkest import hd2ia
from jwkest import safe_str_cmp
from jwkest import BadSignature
from jwkest.gcm import gcm_encrypt
from jwkest.gcm import gcm_decrypt
from jwkest.jws import SIGNER_ALGS, JWx

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


class ParameterError(Exception):
    pass


class NoSuitableEncryptionKey(Exception):
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
        return [0, 0, 0, 0]


def _hash_input(cmk, enc, label, rond=1, length=128, hashsize=256,
                epu="", epv=""):
    r = [0, 0, 0, rond]
    r.extend(cmk)
    #- AlgorithmID
    #the output bit size as a 32 bit big endian number
    r.extend([0, 0, 0, length])
    # the bytes of the UTF-8 representation of the "enc" value
    r.extend([ord(c) for c in enc])
    #- PartyUInfo
    r.extend(party_value(epu))
    #- PartyVInfo
    r.extend(party_value(epv))
    #- SuppPubInfo
    r.extend(label)
    return r


def str2intarr(txt):
    return [ord(c) for c in txt]


def intarr2str(arr):
    return "".join([chr(c) for c in arr])


def ciphertext_and_authentication_tag(msg, key, aad, iv, algo="A128CBC-HS256"):
    """
    Creates and returns Cipher text and the Authentication Tag.
    Default computed using AES_128_CBC_HMAC_SHA_256

    :param key: A key
    :param msg: The message to encrypt
    :param aad: The Additional Authenticated Data
    :param iv: The Initialization Vector
    :return: The Authentication Tag
    """

    # Assumed a 256 bit long key
    mac_key = key[:16]
    enc_key = key[16:]

    alg, hashf = algo.split("-")

    c = M2Crypto.EVP.Cipher(alg=ENC2ALG[alg], key=enc_key, iv=iv, op=1)
    ctxt = aes_enc(c, msg)

    al = int2bigendian(len(aad) * 8)
    while len(al) < 8:
        al.insert(0, 0)

    _inp = str2intarr(aad) + str2intarr(iv) + str2intarr(ctxt) + al

    func = SIGNER_ALGS[hashf]
    m = func.sign(intarr2str(_inp), mac_key)

    return ctxt, m[:16]


# ---------------------------------------------------------------------------

def cipher_filter(cipher, inf, outf):
    while 1:
        buf = inf.read()
        if not buf:
            break
        outf.write(cipher.update(buf))
    outf.write(cipher.final())
    return outf.getvalue()


def aes_enc(key, txt):
    pbuf = cStringIO.StringIO(txt)
    cbuf = cStringIO.StringIO()
    ciphertext = cipher_filter(key, pbuf, cbuf)
    pbuf.close()
    cbuf.close()
    return ciphertext


def aes_dec(key, ciptxt):
    pbuf = cStringIO.StringIO()
    cbuf = cStringIO.StringIO(ciptxt)
    plaintext = cipher_filter(key, cbuf, pbuf)
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
    "enc": ["A128CBC-HS256", "A256CBC-HS512", "A256GCM"],
}


# =============================================================================


class JWE_SYM(JWx):
    def encrypt(self, key, iv="", cek=""):
        """

        :param key: Shared symmetric key
        :param iv:
        :param cek:
        :return:
        """
        _msg = self.msg

        b64_header = self._encoded_header()

        # content master key 256 bit
        if not cek:
            cek = os.urandom(32)

        jek = aes_wrap_key(intarr2str(key), cek)
        auth_data = b64_header

        _enc = self["enc"]
        if _enc == "A256GCM":
            if not iv:
                iv = os.urandom(12)  # 96 bits
            ctxt, tag = gcm_encrypt(cek, iv, _msg, auth_data)
        elif _enc.startswith("A128CBC-") or _enc.startswith("A256CBC-"):
            assert _enc in SUPPORTED["enc"]
            ealg, hashf = _enc.split("-")
            if not iv:
                if ealg == "A128CBC":
                    iv = os.urandom(16)  # 128 bits
                else:  # ealg == "A256CBC"
                    iv = os.urandom(32)  # 256 bits


            ctxt, tag = ciphertext_and_authentication_tag(cek, _msg, auth_data,
                                                          iv,
                                                          algo="A128CBC-HS256")
        else:
            raise NotSupportedAlgorithm(_enc)

        res = b'.'.join([b64_header, b64e(jek), b64e(iv), b64e(ctxt),
                         b64e(tag)])

        return res

    def decrypt(self):
        pass


class JWE_RSA(JWx):
    args = ["msg", "alg", "enc", "epk", "zip", "jku", "jwk", "x5u", "x5t",
            "x5c", "kid", "typ", "cty", "apu", "crit"]

    def encrypt(self, key, context="public", iv="", cek="", **kwargs):
        """
        Produces a JWE using RSA algorithms

        :param key: RSA key
        :param context:
        :param iv:
        :param cek:
        :return: A jwe
        """

        _msg = self.msg
        if "zip" in self:
            if self["zip"] == "DEF":
                _msg = zlib.compress(_msg)
            else:
                raise ParameterError("Zip has unknown value: %s" % self["zip"])

        # content master key 256 bit
        if not cek:
            cek = os.urandom(32)

        if context == "private":
            _encrypt = RSAEncrypter().private_encrypt
        else:
            _encrypt = RSAEncrypter().public_encrypt

        _alg = self["alg"]
        if _alg == "RSA-OAEP":
            jwe_enc_key = _encrypt(cek, key, 'pkcs1_oaep_padding')
        elif _alg == "RSA1_5":
            jwe_enc_key = _encrypt(cek, key)
        else:
            raise NotSupportedAlgorithm(_alg)

        #if debug:
        #    print >> sys.stderr, "enc_key:", hd2ia(hexlify(jwe_enc_key))

        enc_header = self._encoded_header()
        auth_data = enc_header

        _enc = self["enc"]
        if _enc == "A256GCM":
            if not iv:
                iv = os.urandom(12)  # 96 bits
            ctxt, tag = gcm_encrypt(cek, iv, _msg, auth_data)
        elif _enc.startswith("A128CBC-") or _enc.startswith("A256CBC-"):
            assert _enc in SUPPORTED["enc"]
            ealg, hashf = _enc.split("-")
            if not iv:
                if ealg == "A128CBC":
                    iv = os.urandom(16)  # 128 bits
                else:  # ealg == "A256CBC"
                    iv = os.urandom(32)  # 256 bits

            ctxt, tag = ciphertext_and_authentication_tag(_msg, cek, auth_data,
                                                          iv, algo=_enc)
        else:
            raise NotSupportedAlgorithm(_enc)

        res = b'.'.join([enc_header, b64e(jwe_enc_key), b64e(iv), b64e(ctxt),
                         b64e(tag)])

        return res

    def decrypt(self, token, key, context, debug=False):
        """
        Does decryption according to the JWE proposal
        draft-ietf-jose-json-web-encryption-06

        :param token: The
        :param key:
        :return:
        """
        b64_head, b64_jek, b64_iv, b64_ctxt, b64_tag = token.split(b".")

        self.parse_header(b64_head)
        iv = b64d(str(b64_iv))

        if context == "private":
            _decrypt = RSAEncrypter().private_decrypt
        else:
            _decrypt = RSAEncrypter().public_decrypt

        jek = b64d(str(b64_jek))

        if debug:
            print >> sys.stderr, "enc_key", hd2ia(hexlify(jek))

        _alg = self["alg"]
        if _alg == "RSA-OAEP":
            cek = _decrypt(jek, key, 'pkcs1_oaep_padding')
        elif _alg == "RSA1_5":
            cek = _decrypt(jek, key)
        else:
            raise NotSupportedAlgorithm(_alg)

        enc = self["enc"]
        try:
            assert enc in SUPPORTED["enc"]
        except AssertionError:
            raise NotSupportedAlgorithm(enc)

        auth_data = b64_head

        _ctxt = b64d(str(b64_ctxt))
        _tag = b64d(str(b64_tag))
        if enc == "A256GCM":
            msg = gcm_decrypt(cek, iv, _ctxt, auth_data, _tag)
        elif enc.startswith("A128CBC-") or enc.startswith("A256CBC-"):
            enc, hashf = enc.split("-")
            mac_key = cek[:16]
            enc_key = cek[16:]
            c = M2Crypto.EVP.Cipher(alg=ENC2ALG[enc], key=enc_key, iv=iv,
                                    op=DEC)
            msg = aes_dec(c, _ctxt)

            al = int2bigendian(len(auth_data) * 8)
            while len(al) < 8:
                al.insert(0, 0)

            _inp = str(auth_data) + iv + _ctxt + intarr2str(al)

            verifier = SIGNER_ALGS[hashf]
            # Can't use the verify function directly since the tag I have only
            # are the first 128 bits of the signature
            if not safe_str_cmp(verifier.sign(_inp, mac_key)[:16], _tag):
                raise BadSignature()
        else:
            raise MethodNotSupported(enc)

        if "zip" in self and self["zip"] == "DEF":
            msg = zlib.decompress(msg)

        return msg


class JWE(JWx):
    args = ["alg", "enc", "epk", "zip", "jku", "jwk", "x5u", "x5t",
            "x5c", "kid", "typ", "cty", "apu", "crit"]

    """
    :param msg: The message
    :param alg: Algorithm
    :param enc: Encryption Method
    :param epk: Ephemeral Public Key
    :param zip: Compression Algorithm
    :param jku: a URI that refers to a resource for a set of JSON-encoded
        public keys, one of which corresponds to the key used to digitally
        sign the JWS
    :param jwk: A JSON Web Key that corresponds to the key used to
        digitally sign the JWS
    :param x5u: a URI that refers to a resource for the X.509 public key
        certificate or certificate chain [RFC5280] corresponding to the key
        used to digitally sign the JWS.
    :param x5t: a base64url encoded SHA-1 thumbprint (a.k.a. digest) of the
        DER encoding of the X.509 certificate [RFC5280] corresponding to
        the key used to digitally sign the JWS.
    :param x5c: the X.509 public key certificate or certificate chain
        corresponding to the key used to digitally sign the JWS.
    :param kid: Key ID a hint indicating which key was used to secure the
        JWS.
    :param typ: the type of this object. 'JWS' == JWS Compact Serialization
        'JWS+JSON' == JWS JSON Serialization
    :param cty: Content Type
    :param apu: Agreement PartyUInfo
    :param crit: indicates which extensions that are being used and MUST
        be understood and processed.
    :return: A class instance
    """

    def encrypt(self, keys=None, context="public", cek="", iv="", **kwargs):
        """

        :param keys: A set of possibly usable keys
        :param context: If the other party's public or my private key should be
            used for encryption
        :param cek: Content master key
        :param iv: Initialization vector
        :param kwargs: Extra key word arguments
        :return: Encrypted message
        """
        _alg = self["alg"]
        if _alg.startswith("RSA") and _alg in ["RSA-OAEP", "RSA1_5"]:
            encrypter = JWE_RSA(self.msg, **self._dict)

            if keys:
                keys = self._pick_keys(keys)
            else:
                keys = self._pick_keys(self._get_keys())

            if keys:
                key = keys[0]
            else:
                raise NoSuitableEncryptionKey(_alg)

            if cek:
                kwargs["cek"] = cek
            if iv:
                kwargs["iv"] = iv
        else:
            raise NotSupportedAlgorithm

        token = encrypter.encrypt(key.key, context, **kwargs)

        return token

    def decrypt(self, token, keys=None, context="public"):
        header, ek, eiv, ctxt, tag = token.split(b".")
        self.parse_header(header)

        if self["alg"].startswith("RSA") and \
                self["alg"] in ["RSA-OAEP", "RSA1_5"]:
            decrypter = JWE_RSA(**self._dict)

            if keys:
                keys = self._pick_keys(keys)
            else:
                keys = self._pick_keys(self._get_keys())

            if not keys:
                raise NoSuitableEncryptionKey(self.alg)

        else:
            raise NotSupportedAlgorithm

        for key in keys:
            try:
                msg = decrypter.decrypt(str(token), key.key, context)
                return msg
            except KeyError:
                pass

        raise
