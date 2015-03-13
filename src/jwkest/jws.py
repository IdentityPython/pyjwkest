"""JSON Web Token"""

# Most of the code, ideas herein I have borrowed/stolen from other people
# Most notably Jeff Lindsay, Ryan Kelly and Richard Barnes

import json
import logging

import struct
from Crypto.Hash import SHA256
from Crypto.Hash import SHA384
from Crypto.Hash import SHA512
from Crypto.Hash import HMAC
from Crypto.Signature import PKCS1_v1_5
from Crypto.Signature import PKCS1_PSS
from Crypto.Util.number import bytes_to_long
from cryptlib.ecc import P256
from cryptlib.ecc import P384
from cryptlib.ecc import P521

from jwkest.jwk import load_x509_cert
from jwkest.jwk import sha256_digest
from jwkest.jwk import sha384_digest
from jwkest.jwk import sha512_digest
from jwkest.jwk import keyrep
from jwkest.jwk import load_jwks_from_url

from jwkest import b64e, MissingKey
from jwkest import b64d
from jwkest import JWKESTException
from jwkest import safe_str_cmp
from jwkest import BadSignature
from jwkest import UnknownAlgorithm

logger = logging.getLogger(__name__)


class JWSException(JWKESTException):
    pass


class NoSuitableSigningKeys(JWSException):
    pass


class FormatError(JWSException):
    pass


class WrongTypeOfKey(JWSException):
    pass


def left_hash(msg, func="HS256"):
    """ 128 bits == 16 bytes """
    if func == 'HS256':
        return b64e(sha256_digest(msg)[:16])
    elif func == 'HS384':
        return b64e(sha384_digest(msg)[:24])
    elif func == 'HS512':
        return b64e(sha512_digest(msg)[:32])


def mpint(b):
    b = b"\x00" + b
    return struct.pack(">L", len(b)) + b


def mp2bin(b):
    # just ignore the length...
    if b[4] == '\x00':
        return b[5:]
    else:
        return b[4:]


class Signer(object):
    """Abstract base class for signing algorithms."""
    def sign(self, msg, key):
        """Sign ``msg`` with ``key`` and return the signature."""
        raise NotImplementedError()

    def verify(self, msg, sig, key):
        """Return True if ``sig`` is a valid signature for ``msg``."""
        raise NotImplementedError()


class HMACSigner(Signer):
    def __init__(self, digest):
        self.digest = digest

    def sign(self, msg, key):
        h = HMAC.new(key, msg, digestmod=self.digest)
        return h.digest()
        #return hmac.new(key, msg, digestmod=self.digest).digest()

    def verify(self, msg, sig, key):
        if not safe_str_cmp(self.sign(msg, key), sig):
            raise BadSignature(repr(sig))
        return True


class RSASigner(Signer):
    def __init__(self, digest):
        self.digest = digest

    def sign(self, msg, key):
        h = self.digest.new(msg)
        signer = PKCS1_v1_5.new(key)
        return signer.sign(h)

    def verify(self, msg, sig, key):
        h = self.digest.new(msg)
        verifier = PKCS1_v1_5.new(key)
        if verifier.verify(h, sig):
            return True
        else:
            raise BadSignature()


class DSASigner(Signer):
    def __init__(self, digest, sign):
        self.digest = digest
        self._sign = sign

    def sign(self, msg, key):
        # verify the key
        h = bytes_to_long(self.digest.new(msg).digest())
        return self._sign.sign(h, key)

    def verify(self, msg, sig, key):
        h = bytes_to_long(self.digest.new(msg).digest())
        return self._sign.verify(h, sig, key)


class PSSSigner(Signer):
    def __init__(self, digest):
        self.digest = digest

    def sign(self, msg, key):
        h = self.digest.new(msg)
        signer = PKCS1_PSS.new(key)
        return signer.sign(h)

    def verify(self, msg, sig, key):
        h = self.digest.new(msg)
        verifier = PKCS1_PSS.new(key)
        res = verifier.verify(h, sig)
        if not res:
            raise BadSignature()
        else:
            return True


SIGNER_ALGS = {
    u'HS256': HMACSigner(SHA256),
    u'HS384': HMACSigner(SHA384),
    u'HS512': HMACSigner(SHA512),

    u'RS256': RSASigner(SHA256),
    u'RS384': RSASigner(SHA384),
    u'RS512': RSASigner(SHA512),

    u'ES256': DSASigner(SHA256, P256),
    u'ES384': DSASigner(SHA384, P384),
    u'ES512': DSASigner(SHA512, P521),

    u'PS256': PSSSigner(SHA256),
    u'PS384': PSSSigner(SHA384),
    u'PS521': PSSSigner(SHA512),

    u'none': None
}


def alg2keytype(alg):
    if not alg or alg.lower() == "none":
        return "none"
    elif alg.startswith("RS") or alg.startswith("PS"):
        return "RSA"
    elif alg.startswith("HS") or alg.startswith("A"):
        return "OCT"
    elif alg.startswith("ES"):
        return "EC"
    else:
        return None


class JWx(object):
    args = ["alg", "jku", "jwk", "x5u", "x5t", "x5c", "kid", "typ", "cty",
            "crit"]
    """
    :param alg: The signing algorithm
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
    :param kid: a hint indicating which key was used to secure the JWS.
    :param typ: the type of this object. 'JWS' == JWS Compact Serialization
        'JWS+JSON' == JWS JSON Serialization
    :param cty: the type of the secured content
    :param crit: indicates which extensions that are being used and MUST
        be understood and processed.
    :param kwargs: Extra header parameters
    :return: A class instance
    """

    def __init__(self, msg=None, **kwargs):
        self.msg = msg
        self._dict = {"kid": ""}
        if kwargs:
            for key in self.args:
                try:
                    _val = kwargs[key]
                except KeyError:
                    if key == "alg":
                        self._dict[key] = "none"
                    continue

                if key == "jwk":
                    if isinstance(_val, dict):
                        self._dict["jwk"] = keyrep(_val)
                    elif isinstance(_val, basestring):
                        self._dict["jwk"] = keyrep(json.loads(_val))
                    else:
                        self._dict["jwk"] = _val
                elif key == "x5c" or key == "crit":
                    self._dict["x5c"] = _val or []
                else:
                    self._dict[key] = _val

    def __contains__(self, item):
        return item in self._dict

    def __getitem__(self, item):
        return self._dict[item]

    def __setitem__(self, key, value):
        self._dict[key] = value

    def __getattr__(self, item):
        try:
            return self._dict[item]
        except KeyError:
            raise AttributeError(item)

    def keys(self):
        return self._dict.keys()

    def _encoded_payload(self):
        if isinstance(self.msg, basestring):
            return b64e(self.msg)
        else:
            return b64e(json.dumps(self.msg, separators=(",", ":")))

    def _header(self, extra=None):
        _extra = extra or {}
        _header = {}
        for param in self.args:
            try:
                _header[param] = _extra[param]
            except KeyError:
                try:
                    if self._dict[param]:
                        _header[param] = self._dict[param]
                except KeyError:
                    pass

        if "jwk" in self:
            _header["jwk"] = self["jwk"].to_dict()
        elif "jwk" in _extra:
            _header["jwk"] = extra["jwk"].to_dict()
        return _header

    def _encoded_header(self, extra=None):
        return b64e(json.dumps(self._header(extra), separators=(",", ":")))

    def parse_header(self, encheader):
        for attr, val in json.loads(b64d(str(encheader))).items():
            if attr == "jwk":
                self["jwk"] = keyrep(val)
            else:
                self[attr] = val

    def _get_keys(self):
        if "jwk" in self:
            return [self["jwk"]]
        elif "jku" in self:
            keys = load_jwks_from_url(self["jku"], {})
            return dict(keys)
        elif "x5u" in self:
            try:
                return {"rsa": [load_x509_cert(self["x5u"], {})]}
            except Exception:
                #ca_chain = load_x509_cert_chain(self["x5u"])
                pass

        return {}

    def alg2keytype(self, alg):
        return alg2keytype(alg)

    def _pick_keys(self, keys, use="", alg=""):
        """
        The assumption is that upper layer has made certain you only get
        keys you can use.

        :param keys: A list of KEY instances
        :return: A list of KEY instances that fulfill the requirements
        """
        if not alg:
            alg = self["alg"]

        if alg == "none":
            return []

        _k = self.alg2keytype(alg)
        if _k is None:
            logger.error("Unknown arlgorithm '%s'" % alg)
            return []

        _kty = [_k.lower(), _k.upper()]
        _keys = [k for k in keys if k.kty in _kty]

        pkey = []
        for _key in _keys:
            if self["kid"]:
                try:
                    assert self["kid"] == _key.kid
                except (KeyError, AttributeError):
                    pass
                except AssertionError:
                    continue

            if use and _key.use and _key.use != use:
                continue

            if alg and _key.alg and _key.alg != alg:
                continue

            pkey.append(_key)

        return pkey

    def _decode(self, payload):
        _msg = b64d(str(payload))
        if "cty" in self:
            if self["cty"] == "JWT":
                _msg = json.loads(_msg)
        return _msg


class JWS(JWx):

    def sign_compact(self, keys=None):
        """
        Produce a JWS using the JWS Compact Serialization

        :param keys: A dictionary of keys
        :return:
        """

        _alg = self["alg"]

        if keys:
            keys = self._pick_keys(keys, use="sig", alg=_alg)
        else:
            keys = self._pick_keys(self._get_keys(), use="sig", alg=_alg)

        xargs = {}

        if keys:
            key = keys[0]
            if key.kid:
                xargs = {"kid": key.kid}
        elif _alg == "none":
            key = None
        elif _alg:
            raise NoSuitableSigningKeys(_alg)
        else:
            raise NoSuitableSigningKeys("None")

        enc_head = self._encoded_header(xargs)
        enc_payload = self._encoded_payload()

        # Signing with alg == "none"
        if not _alg or _alg.lower() == "none":
            return enc_head + b"." + enc_payload + b"."

        # All other cases
        try:
            _signer = SIGNER_ALGS[_alg]
        except KeyError:
            raise UnknownAlgorithm(_alg)

        _input = b".".join([enc_head, enc_payload])
        sig = _signer.sign(_input, key.get_key(alg=_alg, private=True))
        logger.debug("Signed message using key with kid=%s" % key.kid)
        return b".".join([enc_head, enc_payload, b64e(sig)])

    def verify_compact(self, jws, keys=None):
        _header, _payload, _sig = jws.split(".")

        self.parse_header(_header)

        if "alg" in self:
            if self["alg"] == "none":
                self.msg = self._decode(_payload)
                return self.msg
        _alg = self["alg"]

        if keys:
            _keys = self._pick_keys(keys)
        else:
            _keys = self._pick_keys(self._get_keys())

        verifier = SIGNER_ALGS[self["alg"]]

        if not _keys:
            raise MissingKey("No suitable verification keys found")

        for key in _keys:
            try:
                res = verifier.verify(_header + '.' + _payload, b64d(str(_sig)),
                                      key.get_key(alg=_alg, private=False))
            except BadSignature:
                pass
            else:
                if res is True:
                    logger.debug(
                        "Verified message using key with kid=%s" % key.kid)
                    self.msg = self._decode(_payload)
                    return self.msg

        raise BadSignature()

    def sign_json(self, per_signature_header=None, **kwargs):
        """
        Produce JWS using the JWS JSON Serialization

        :param per_signature_header: Header parameter values that are to be
            applied to a specific signature
        :return:
        """
        res = {"signatures": []}

        if per_signature_header is None:
            per_signature_header = [{"alg": "none"}]

        for _kwa in per_signature_header:
            _kwa.update(kwargs)
            _jws = JWS(self.msg, **_kwa)
            header, payload, signature = _jws.sign_compact().split(".")
            res["signatures"].append({"header": header,
                                      "signature": signature})

        res["payload"] = self.msg

        return res

    def verify_json(self, jws, keys=None):
        """

        :param jws:
        :param keys:
        :return:
        """

        _jwss = json.load(jws)

        try:
            _payload = _jwss["payload"]
        except KeyError:
            raise FormatError("Missing payload")

        try:
            _signs = _jwss["signatures"]
        except KeyError:
            raise FormatError("Missing signatures")

        _claim = None
        for _sign in _signs:
            token = b".".join([_sign["header"], _payload, _sign["signature"]])
            _tmp = self.verify_compact(token, keys)
            if _claim is None:
                _claim = _tmp
            else:
                assert _claim == _tmp

        return _claim
