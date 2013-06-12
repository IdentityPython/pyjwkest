"""JSON Web Token"""

# Most of the code herein I have borrowed/stolen from other people
# Most notably Jeff Lindsay, Ryan Kelly

import json
import logging

import M2Crypto
import hashlib
import hmac
import struct
from M2Crypto.RSA import RSA_pub
from jwkest.jwk import load_x509_cert
from jwkest.jwk import load_x509_cert_chain
from jwkest.jwk import keyrep
from jwkest.jwk import load_jwks_from_url

from jwkest import b64e
from jwkest import b64d
from jwkest import safe_str_cmp
from jwkest import BadSignature
from jwkest import UnknownAlgorithm

logger = logging.getLogger(__name__)


class NoSuitableSigningKeys(Exception):
    pass


class FormatError(Exception):
    pass


class WrongTypeOfKey(Exception):
    pass


def sha256_digest(msg):
    return hashlib.sha256(msg).digest()


def sha384_digest(msg):
    return hashlib.sha384(msg).digest()


def sha512_digest(msg):
    return hashlib.sha512(msg).digest()


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
        raise NotImplementedError

    def verify(self, msg, sig, key):
        """Return True if ``sig`` is a valid signature for ``msg``."""
        raise NotImplementedError


class HMACSigner(Signer):
    def __init__(self, digest):
        self.digest = digest

    def sign(self, msg, key):
        return hmac.new(key, msg, digestmod=self.digest).digest()

    def verify(self, msg, sig, key):
        if not safe_str_cmp(self.sign(msg, key), sig):
            raise BadSignature(repr(sig))
        return


class RSASigner(Signer):
    def __init__(self, digest, algo):
        self.digest = digest
        self.algo = algo

    def sign(self, msg, key):
        if isinstance(key, RSA_pub):
            raise WrongTypeOfKey()
        return key.sign(self.digest(msg), self.algo)

    def verify(self, msg, sig, key):
        try:
            return key.verify(self.digest(msg), sig, self.algo)
        except M2Crypto.RSA.RSAError, e:
            raise BadSignature(e)


class ECDSASigner(Signer):
    def __init__(self, digest):
        self.digest = digest

    def sign(self, msg, key):
        r, s = key.sign_dsa(self.digest(msg))
        return mp2bin(r).rjust(32, '\x00') + mp2bin(s).rjust(32, '\x00')

    def verify(self, msg, sig, key):
        # XXX check sig length
        half = len(sig) // 2
        r = mpint(sig[:half])
        s = mpint(sig[half:])
        try:
            r = key.verify_dsa(self.digest(msg), r, s)
        except M2Crypto.EC.ECError, e:
            raise BadSignature(e)
        else:
            if not r:
                raise BadSignature

SIGNER_ALGS = {
    u'HS256': HMACSigner(hashlib.sha256),
    u'HS384': HMACSigner(hashlib.sha384),
    u'HS512': HMACSigner(hashlib.sha512),

    u'RS256': RSASigner(sha256_digest, 'sha256'),
    u'RS384': RSASigner(sha384_digest, 'sha384'),
    u'RS512': RSASigner(sha512_digest, 'sha512'),

    u'ES256': ECDSASigner(sha256_digest),
#    u'AES256': AESEncrypter
    u'none': None
}


def alg2keytype(alg):
    if alg.startswith("RS"):
        return "RSA"
    elif alg.startswith("HS"):
        return "oct"
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
        self._dict = {}
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
                ca_chain = load_x509_cert_chain(self["x5u"])

        return {}

    def _pick_keys(self, keys):
        """
        The assumption is that upper layer has made certain you only get
        keys you can use.

        :param keys: A list of KEY instances
        :return: A list of KEY instances that fulfill the requirements
        """
        _kty = alg2keytype(self["alg"])
        _keys = [k for k in keys if k.kty == _kty]

        if "kid" in self:
            for _key in _keys:
                if self["kid"] == _key["kid"]:
                    return [_key]
        else:
            return _keys

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

        enc_head = self._encoded_header()
        enc_payload = self._encoded_payload()

        _alg = self["alg"]
        if not _alg or _alg.lower() == "none":
            return enc_head + b"." + enc_payload + b"."

        try:
            _signer = SIGNER_ALGS[_alg]
        except KeyError:
            raise UnknownAlgorithm(_alg)

        if keys:
            keys = self._pick_keys(keys)
        else:
            keys = self._pick_keys(self._get_keys())

        if keys:
            key = keys[0]
        else:
            raise NoSuitableSigningKeys(_alg)

        _input = b".".join([enc_head, enc_payload])
        sig = _signer.sign(_input, key.key)
        return b".".join([enc_head, enc_payload, b64e(sig)])

    def verify_compact(self, jws, keys=None):
        _header, _payload, _sig = jws.split(".")

        self.parse_header(_header)

        if "alg" in self:
            if self["alg"] == "none":
                self.msg = self._decode(_payload)
                return self.msg

        if keys:
            _keys = self._pick_keys(keys)
        else:
            _keys = self._pick_keys(self._get_keys())

        verifier = SIGNER_ALGS[self["alg"]]

        for key in _keys:
            try:
                verifier.verify(_header + '.' + _payload, b64d(str(_sig)),
                                key.key)
            except BadSignature:
                pass
            else:
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
