import base64
import re
import struct
import logging
import json

from binascii import a2b_base64

from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import importKey, _RSAobj
from Crypto.Util.asn1 import DerSequence

from requests import request
from cryptlib.ecc import NISTEllipticCurve

from jwkest import intarr2long
from jwkest import b64d
from jwkest import b64e
from jwkest import dehexlify

__author__ = 'rohe0002'

logger = logging.getLogger(__name__)

PREFIX = "-----BEGIN CERTIFICATE-----"
POSTFIX = "-----END CERTIFICATE-----"


class FormatError(Exception):
    pass


def byte_arr(long_int):
    _bytes = []
    while long_int:
        long_int, r = divmod(long_int, 256)
        _bytes.insert(0, r)
    return _bytes


def long_to_base64(n):
    bys = byte_arr(n)
    data = struct.pack('%sB' % len(bys), *bys)
    if not len(data):
        data = '\x00'
    s = base64.urlsafe_b64encode(data).rstrip('=')
    return s


def b64_set_to_long(s):
    data = base64.urlsafe_b64decode(s + '==')
    n = struct.unpack('>Q', '\x00' * (8 - len(data)) + data)
    return n[0]


def base64_to_long(data):
    _d = base64.urlsafe_b64decode(data + '==')
    return intarr2long(dehexlify(_d))


def dicthash(d):
    return hash(repr(sorted(d.items())))


def intarr2str(arr):
    return "".join([chr(c) for c in arr])


# =============================================================================


def import_rsa_key_from_file(filename):
    return RSA.importKey(open(filename, 'r').read())


def import_rsa_key(key):
    """
    Extract an RSA key from a PEM-encoded certificate

    :param key: RSA key encoded in standard form
    :return: RSA key instance
    """
    return importKey(key)


def der2rsa(der):
    # Extract subjectPublicKeyInfo field from X.509 certificate (see RFC3280)
    cert = DerSequence()
    cert.decode(der)
    tbs_certificate = DerSequence()
    tbs_certificate.decode(cert[0])
    subject_public_key_info = tbs_certificate[6]

    # Initialize RSA key
    return RSA.importKey(subject_public_key_info)


def pem_cert2rsa(pem_file):
    # Convert from PEM to DER
    pem = open(pem_file).read()
    lines = pem.replace(" ", '').split()
    return der2rsa(a2b_base64(''.join(lines[1:-1])))


def der_cert2rsa(der):
    """
    Extract an RSA key from a DER certificate

    @param der: DER-encoded certificate
    @return: RSA instance
    """
    pem = re.sub(r'[^A-Za-z0-9+/]', '', der)
    return der2rsa(base64.b64decode(pem))


def load_x509_cert(url, spec2key):
    """
    Get and transform a X509 cert into a key

    :param url: Where the X509 cert can be found
    :param spec2key: A dictionary over keys already seen
    :return: List of 2-tuples (keytype, key)
    """
    try:
        r = request("GET", url, allow_redirects=True)
        if r.status_code == 200:
            cert = str(r.text)
            try:
                _key = spec2key[cert]
            except KeyError:
                _key = import_rsa_key(cert)
                spec2key[cert] = _key
            return [("rsa", _key)]
        else:
            raise Exception("HTTP Get error: %s" % r.status_code)
    except Exception, err:  # not a RSA key
        logger.warning("Can't load key: %s" % err)
        return []


def rsa_load(filename):
    """Read a PEM-encoded RSA key pair from a file."""
    pem = open(filename, 'r').read()
    return import_rsa_key(pem)


def rsa_eq(key1, key2):
    # Check if two RSA keys are in fact the same
    if key1.n == key2.n and key1.e == key2.e:
        return True
    else:
        return False


def key_eq(key1, key2):
    if type(key1) == type(key2):
        if isinstance(key1, basestring):
            return key1 == key2
        elif isinstance(key1, RSA):
            return rsa_eq(key1, key2)

    return False


def x509_rsa_load(txt):
    """ So I get the same output format as loads produces
    :param txt:
    :return:
    """
    return [("rsa", import_rsa_key(txt))]


class Key():
    members = ["kty", "alg", "use", "kid", "x5c", "x5t", "x5u"]

    def __init__(self, kty="", alg="", use="", kid="", key=None, x5c=None,
                 x5t="", x5u=""):
        self.key = key
        self.kty = kty
        self.alg = alg
        self.use = use
        self.kid = kid
        self.x5c = x5c or []
        self.x5t = x5t
        self.x5u = x5u

    def to_dict(self):
        res = {}
        for key in self.members:
            try:
                _val = getattr(self, key)
                if _val:
                    res[key] = _val
            except (KeyError, AttributeError):
                pass
        return res

    def __str__(self):
        return str(self.to_dict())

    def deserialize(self):
        """ Assumes that the parameters where set from a JWK object
        """
        pass

    def serialize(self):
        """ Converts attributes into a representation that is exportable
        """
        pass

    def get_key(self, **kwargs):
        return self.key

    def dc(self):
        pass


class RSAKey(Key):
    members = Key.members
    members.extend(["n", "e", "d", "p", "q"])

    def __init__(self, kty="RSA", alg="", use="", kid="", key=None,
                 x5c=None, x5t="", x5u="", n="", e="", d="", p=0, q=0,
                 private=False):
        Key.__init__(self, kty, alg, use, kid, key, x5c, x5t, x5u)
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q
        self.private = private

    def deserialize(self):
        if self.n and self.e:
            e = base64_to_long(str(self.e))
            n = base64_to_long(str(self.n))
            if self.d:
                d = base64_to_long(str(self.d))
                self.key = RSA.construct((n, e, d))
            else:
                self.key = RSA.construct((n, e))
        elif self.x5c:
            if self.x5t:  # verify the cert
                pass
            cert = "\n".join([PREFIX, str(self.x5c[0]), POSTFIX])
            self.key = import_rsa_key(cert)
            if len(self.x5c) > 1:  # verify chain
                pass

    def serialize(self, do_x5=False):
        self.n = long_to_base64(self.key.n)
        self.e = long_to_base64(self.key.e)
        if self.private:
            self.d = long_to_base64(self.key.d)
        if do_x5:  # construct the x5u, x5t members
            pass

    def load(self, filename):
        self.key = rsa_load(filename)

    def dc(self):
        if self.key:
            self.serialize()
        elif self.n and self.e:
            self.deserialize()
        else:  # do nothing
            pass


class ECKey(Key):
    members = ["kty", "alg", "use", "kid", "crv", "x", "y", "d"]

    def __init__(self, kty="EC", alg="", use="", kid="", key=None,
                 x5c=None, x5t="", x5u="", crv="", x="", y="", d="",
                 curve=None, private=False):
        Key.__init__(self, kty, alg, use, kid, key, x5c, x5t, x5u)
        self.crv = crv
        self.x = x
        self.y = y
        self.d = d
        self.curve = curve
        self.private = private

    def deserialize(self):
        self.x = base64_to_long(self.x)
        self.y = base64_to_long(self.y)
        self.curve = NISTEllipticCurve.by_name(self.crv)
        if self.d:
            self.d = base64_to_long(self.d)

    def get_key(self, private=True):
        if private:
            return self.d
        else:
            return self.x, self.y

    def serialize(self):
        if not self.crv and not self.curve:
            raise Exception("Curve must be provided for EC export")

        if self.curve and not self.crv:
            self.crv = self.curve.name()

        self.d = long_to_base64(self.d)
        self.x = long_to_base64(self.x)
        self.y = long_to_base64(self.y)


class SYMKey(Key):
    members = ["kty", "alg", "use", "kid", "k"]

    def __init__(self, kty="OCT", alg="", use="", kid="", key=None,
                 x5c=None, x5t="", x5u="", k=""):
        Key.__init__(self, kty, alg, use, kid, key, x5c, x5t, x5u)
        self.k = k

    def deserialize(self):
        self.key = b64d(str(self.k))

    def serialize(self):
        self.k = b64e(str(self.key))


class PKIXKey(Key):
    members = ["kty", "alg", "use", "kid", "n", "e"]

    def __init__(self, kty="RSA", alg="", use="", kid="", key=None,
                 x5c=None, x5t="", x5u=""):
        Key.__init__(self, kty, alg, use, kid, key, x5c, x5t, x5u)
        self.key = key

    def dc(self):
        if self.x5c:
            cert = "\n".join([PREFIX, str(self.x5c[0]), POSTFIX])
            self.key = import_rsa_key(cert)
        elif self.key:
            self.x5c = []
        else:  # do nothing
            pass

# -----------------------------------------------------------------------------


def keyitems2keyreps(keyitems):
    keys = []
    for key_type, _keys in keyitems.items():
        if key_type.upper() == "RSA":
            keys.extend([RSAKey(key=k) for k in _keys])
        elif key_type.upper() == "OCT":
            keys.extend([SYMKey(key=k) for k in _keys])
        elif key_type.upper() == "EC":
            keys.extend([ECKey(key=k) for k in _keys])
        else:
            keys.extend([Key(key=k) for k in _keys])
    return keys


def keyrep(kspec):
    if kspec["kty"] == "RSA":
        item = RSAKey(**kspec)
    elif kspec["kty"] == "OCT":
        item = SYMKey(**kspec)
    elif kspec["kty"] == "EC":
        item = ECKey(**kspec)
    else:
        item = Key(**kspec)
    item.deserialize()
    return item


def load_jwks(txt):
    """
    Load and create keys from a JWKS representation

    Expects something on this form
    {"keys":
        [
            {"kty":"EC",
             "crv":"P-256",
             "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
            "use":"enc",
            "kid":"1"},

            {"kty":"RSA",
            "mod": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFb....."
            "xpo":"AQAB",
            "kid":"2011-04-29"}
        ]
    }

    :param txt: The JWKS string representation
    :return: list of 2-tuples containing key, type
    """
    spec = json.loads(txt)
    res = []
    for kspec in spec["keys"]:
        res.append(keyrep(kspec))

    return res


def dump_jwk(key, use="", kid=""):
    """
    Dump to JWK dictionary representation

    :param key: The keys to dump
    :param use: What the key are expected to be use for
    :return: The JWK string representation or None
    """
    if isinstance(key, _RSAobj):
        kspec = RSAKey(key=key)
    elif isinstance(key, basestring):
        kspec = SYMKey(key=key)
    else:
        raise Exception("Unknown key type:key="+str(type(key)))

    kspec.serialize()

    if use:
        kspec.use = use
    if kid:
        kspec.kid = kid

    return kspec.to_dict()


def dump_jwks(keyspecs):
    """

    :param keyspecs: list of dictionaries describing keys
    :return:
    """
    res = []
    for keyspec in keyspecs:
        res.append(dump_jwk(**keyspec))

    return json.dumps({"keys": res})


def load_jwks_from_url(url, spec2key=None):
    """
    Get and transform a JWKS into keys

    :param url: Where the JWKS can be found
    :param spec2key: A dictionary over keys already seen
    :return: List of 2-tuples (keytype, key)
    """

    r = request("GET", url, allow_redirects=True)
    if r.status_code == 200:
        return load_jwks(r.text)
    else:
        raise Exception("HTTP Get error: %s" % r.status_code)
