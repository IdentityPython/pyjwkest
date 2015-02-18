# JSON Web Encryption

import struct
import cStringIO
import logging
import zlib

from Crypto import Random
from Crypto.Hash import SHA
from Crypto.Util.number import bytes_to_long
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP

from cryptlib.aes_gcm import AES_GCM
from cryptlib.aes_key_wrap import aes_wrap_key, aes_unwrap_key
from cryptlib.ecc import NISTEllipticCurve

from jwkest import b64d, JWKESTException, MissingKey
from jwkest import b64e
#from jwkest.aes_key_wrap_m2 import aes_wrap_key
from jwkest.extra import aes_cbc_hmac_encrypt
from jwkest.extra import ecdh_derive_key
from jwkest.extra import aes_cbc_hmac_decrypt
from jwkest.jwk import intarr2str, ECKey
from jwkest.jws import JWx

logger = logging.getLogger(__name__)

__author__ = 'rohe0002'

ENC = 1
DEC = 0


class JWEException(JWKESTException):
    pass


class CannotDecode(JWEException):
    pass


class NotSupportedAlgorithm(JWEException):
    pass


class MethodNotSupported(JWEException):
    pass


class ParameterError(JWEException):
    pass


class NoSuitableEncryptionKey(JWEException):
    pass


class NoSuitableDecryptionKey(JWEException):
    pass


class DecryptionFailed(JWEException):
    pass

# ---------------------------------------------------------------------------
# Base class

KEYLEN = {
    "A128GCM": 128,
    "A192GCM": 192,
    "A256GCM": 256,
    "A128CBC-HS256": 256,
    "A192CBC-HS384": 384,
    "A256CBC-HS512": 512
}


class Encrypter(object):
    """Abstract base class for encryption algorithms."""

    def __init__(self):
        pass

    def encrypt(self, msg, key):
        """Encrypt ``msg`` with ``key`` and return the encrypted message."""
        raise NotImplementedError

    def decrypt(self, msg, key):
        """Return decrypted message."""
        raise NotImplementedError


class RSAEncrypter(Encrypter):

    @staticmethod
    def encrypt(msg, key, padding="pkcs1_padding"):
        if padding == "pkcs1_padding":
            cipher = PKCS1_v1_5.new(key)
            h = SHA.new(msg)
            msg += h.digest()
        elif padding == "pkcs1_oaep_padding":
            cipher = PKCS1_OAEP.new(key)
        else:
            raise Exception("Unsupported padding")
        return cipher.encrypt(msg)

    @staticmethod
    def decrypt(msg, key, padding="pkcs1_padding"):
        dsize = SHA.digest_size
        if padding == "pkcs1_padding":
            cipher = PKCS1_v1_5.new(key)
            sentinel = Random.new().read(32+dsize)
            text = cipher.decrypt(msg, sentinel)
            _digest = text[-dsize:]
            _msg = text[:-dsize]
            digest = SHA.new(_msg).digest()
            if digest == _digest:
                text = _msg
            else:
                raise DecryptionFailed()
        elif padding == "pkcs1_oaep_padding":
            cipher = PKCS1_OAEP.new(key)
            text = cipher.decrypt(msg)
        else:
            raise Exception("Unsupported padding")

        return text

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

ENC2ALG = {"A128CBC": "aes_128_cbc", "A192CBC": "aes_192_cbc",
           "A256CBC": "aes_256_cbc"}

SUPPORTED = {
    "alg": ["RSA1_5", "RSA-OAEP", "A128KW", "A192KW", "A256KW",
            "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"],
    "enc": ["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
            "A128GCM", "A192GCM", "A256GCM"],
}


def alg2keytype(alg):
    if alg.startswith("RSA"):
        return "RSA"
    elif alg.startswith("A"):
        return "OCT"
    elif alg.startswith("ECDH"):
        return "EC"
    else:
        return None

# =============================================================================

ENCALGLEN1 = {
    "A128GCM": 16,
    "A192GCM": 24,
    "A256GCM": 32
}

ENCALGLEN2 = {
    "A128CBC-HS256": 32,
    "A192CBC-HS384": 48,
    "A256CBC-HS512": 64,
}


class JWe(JWx):
    @staticmethod
    def _generate_key_and_iv(encalg, cek="", iv=""):
        if cek and iv:
            return cek, iv

        try:
            _key = Random.get_random_bytes(ENCALGLEN1[encalg])
            _iv = Random.get_random_bytes(12)
        except KeyError:
            try:
                _key = Random.get_random_bytes(ENCALGLEN2[encalg])
                _iv = Random.get_random_bytes(16)
            except KeyError:
                raise Exception("Unsupported encryption algorithm %s" % encalg)
        if cek:
            _key = cek
        if iv:
            _iv = iv

        return _key, _iv

    def alg2keytype(self, alg):
        return alg2keytype(alg)

    def enc_setup(self, enc_alg, msg, auth_data, key=None, iv=""):
        """ Encrypt JWE content.

        :param enc_alg: The JWE "enc" value specifying the encryption algorithm
        :param msg: The plain text message
        :param auth_data: Additional authenticated data
        :param key: Key (CEK)
        :return: Tuple (ciphertext, tag), both as bytes
        """

        key, iv = self._generate_key_and_iv(enc_alg, key, iv)

        if enc_alg == "A256GCM":
            gcm = AES_GCM(bytes_to_long(key))
            ctxt, tag = gcm.encrypt(bytes_to_long(iv), msg, auth_data)
            tag = long_to_bytes(tag)
        elif enc_alg in ["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"]:
            assert enc_alg in SUPPORTED["enc"]
            #ealg, hashf = enc.split("-")
            ctxt, tag = aes_cbc_hmac_encrypt(key, iv, auth_data, msg)
        else:
            raise NotSupportedAlgorithm(enc_alg)

        return ctxt, tag, key

    @staticmethod
    def _decrypt(enc, key, ctxt, auth_data, iv, tag):
        """ Decrypt JWE content.

        :param enc: The JWE "enc" value specifying the encryption algorithm
        :param key: Key (CEK)
        :param iv : Initialization vector
        :param auth_data: Additional authenticated data
        :param ctxt : Ciphertext
        :param tag: Authentication tag
        :return: plain text message or None if decryption failed
        """
        if enc in ["A128GCM", "A192GCM", "A256GCM"]:
            gcm = AES_GCM(bytes_to_long(key))
            try:
                text = gcm.decrypt(bytes_to_long(iv), ctxt, bytes_to_long(tag),
                                   auth_data)
                return text, True
            except DecryptionFailed:
                return None, False
        elif enc in ["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"]:
            return aes_cbc_hmac_decrypt(key, iv, auth_data, ctxt, tag)
        else:
            raise Exception("Unsupported encryption algorithm %s" % enc)

    @staticmethod
    def pack(b64_header, jek, iv, ctxt, tag):
        res = b'.'.join([b64_header, b64e(jek), b64e(iv), b64e(ctxt),
                         b64e(tag)])

        return res


class JWE_SYM(JWe):
    args = JWe.args[:]
    args.append("enc")

    def encrypt(self, key, iv="", cek="", **kwargs):
        """

        :param key: Shared symmetric key
        :param iv: initialization vector
        :param cek:
        :param kwargs: Extra keyword arguments, just ignore for now.
        :return:
        """
        _msg = self.msg

        _args = {}
        try:
            _args["kid"] = kwargs["kid"]
        except KeyError:
            pass

        b64_header = self._encoded_header(_args)

        # If no iv and cek are given generate them
        cek, iv = self._generate_key_and_iv(self["enc"], cek, iv)
        if isinstance(key, basestring):
            kek = key
        else:
            kek = intarr2str(key)

        # The iv for this function must be 64 bit
        # Which is certainly different from the one above
        jek = aes_wrap_key(kek, cek)
        auth_data = b64_header

        _enc = self["enc"]

        ctxt, tag, cek = self.enc_setup(_enc, _msg, auth_data, cek, iv=iv)
        return self.pack(b64_header, jek, iv, ctxt, tag)

    def decrypt(self, token, key=None, cek=None):
        if not key and not cek:
            raise MissingKey("On of key or cek must be specified")

        b64_head, b64_jek, b64_iv, b64_ctxt, b64_tag = token.split(b".")

        self.parse_header(b64_head)
        iv = b64d(str(b64_iv))

        if not cek:
            jek = b64d(str(b64_jek))
            # The iv for this function must be 64 bit
            cek = aes_unwrap_key(key, jek)

        _ctxt = b64d(str(b64_ctxt))
        _tag = b64d(str(b64_tag))
        auth_data = b64_head

        msg = self._decrypt(self["enc"], cek, _ctxt, auth_data, iv, _tag)

        if "zip" in self and self["zip"] == "DEF":
            msg = zlib.decompress(msg)

        return msg


class JWE_RSA(JWe):
    args = ["msg", "alg", "enc", "epk", "zip", "jku", "jwk", "x5u", "x5t",
            "x5c", "kid", "typ", "cty", "apu", "crit"]

    def encrypt(self, key, iv="", cek="", **kwargs):
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

        cek, iv = self._generate_key_and_iv(self["enc"], cek, iv)

        _encrypt = RSAEncrypter().encrypt

        _alg = self["alg"]
        if _alg == "RSA-OAEP":
            jwe_enc_key = _encrypt(cek, key, 'pkcs1_oaep_padding')
        elif _alg == "RSA1_5":
            jwe_enc_key = _encrypt(cek, key)
        else:
            raise NotSupportedAlgorithm(_alg)

        enc_header = self._encoded_header()
        auth_data = enc_header

        _enc = self["enc"]

        ctxt, tag, key = self.enc_setup(_enc, _msg, auth_data, cek, iv)
        return self.pack(enc_header, jwe_enc_key, iv, ctxt, tag)

    def decrypt(self, token, key):
        """ Decrypts a JWT

        :param token: The JWT
        :param key: A key to use for decrypting
        :return: The decrypted message
        """
        b64_head, b64_jek, b64_iv, b64_ctxt, b64_tag = token.split(b".")

        self.parse_header(b64_head)
        iv = b64d(str(b64_iv))

        _decrypt = RSAEncrypter().decrypt
        jek = b64d(str(b64_jek))

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

        msg, flag = self._decrypt(enc, cek, _ctxt, auth_data, iv, _tag)
        if flag is False:
            raise DecryptionFailed()

        if "zip" in self and self["zip"] == "DEF":
            msg = zlib.decompress(msg)

        return msg


class JWE_EC(JWe):
    def enc_setup(self, msg, auth_data, key=None, **kwargs):

        encrypted_key = ""
        # Generate the input parameters
        try:
            apu = b64d(kwargs["apu"])
        except KeyError:
            apu = b64d(Random.get_random_bytes(16))
        try:
            apv = b64d(kwargs["apv"])
        except KeyError:
            apv = b64d(Random.get_random_bytes(16))

        # Generate an ephemeral key pair
        curve = NISTEllipticCurve.by_name(key.crv)
        if "epk" in kwargs:
            eprivk = ECKey(kwargs["epk"])
        else:
            (eprivk, epk) = curve.key_pair()
            # Derive the KEK and encrypt
        params = {
            "apu": b64e(apu),
            "apv": b64e(apv),
            #"epk": exportKey(epk, "EC", curve)
        }
        
        cek, iv = self._generate_key_and_iv(self.enc)
        if self.alg == "ECDH-ES":
            try:
                dk_len = KEYLEN[self.enc]
            except KeyError:
                raise Exception(
                    "Unknown key length for algorithm %s" % self.enc)
            
            cek = ecdh_derive_key(curve, eprivk, key, apu, apv, self.enc, 
                                  dk_len)
        elif self.alg in ["ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"]:
            _pre, _post = self.alg.split("+")
            klen = int(_post[1:4])
            kek = ecdh_derive_key(curve, eprivk, key, apu, apv, _post, klen)
            encrypted_key = aes_wrap_key(kek, cek)
        else:
            raise Exception("Unsupported algorithm %s" % self.alg)

        return cek, encrypted_key, iv, params


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

    def encrypt(self, keys=None, cek="", iv="", **kwargs):
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
        elif _alg.startswith("A") and _alg.endswith("KW"):
            encrypter = JWE_SYM(self.msg, **self._dict)
        else:
            raise NotSupportedAlgorithm

        if keys:
            keys = self._pick_keys(keys)
        else:
            keys = self._pick_keys(self._get_keys())

        if not keys:
            raise NoSuitableEncryptionKey(_alg)

        if cek:
            kwargs["cek"] = cek
        if iv:
            kwargs["iv"] = iv

        for key in keys:
            _key = key.encryption_key(alg=_alg, private=True)

            if key.kid:
                encrypter["kid"] = key.kid

            try:
                token = encrypter.encrypt(_key, **kwargs)
            except Exception as err:
                pass
            else:
                logger.debug(
                    "Encrypted message using key with kid=%s" % key.kid)
                return token

        raise NoSuitableEncryptionKey()

    def decrypt(self, token, keys=None):
        header, ek, eiv, ctxt, tag = token.split(b".")
        self.parse_header(header)

        _alg = self["alg"]
        if _alg in ["RSA-OAEP", "RSA1_5"]:
            decrypter = JWE_RSA(**self._dict)
        elif _alg.startswith("A") and _alg.endswith("KW"):
            decrypter = JWE_SYM(self.msg, **self._dict)
        else:
            raise NotSupportedAlgorithm

        if keys:
            keys = self._pick_keys(keys)
        else:
            keys = self._pick_keys(self._get_keys())

        if not keys:
            raise NoSuitableDecryptionKey(self.alg)

        for key in keys:
            _key = key.encryption_key(alg=_alg, private=False)
            try:
                msg = decrypter.decrypt(str(token), _key)
            except (KeyError, DecryptionFailed):
                pass
            else:
                logger.debug(
                    "Decrypted message using key with kid=%s" % key.kid)
                return msg

        raise DecryptionFailed()
