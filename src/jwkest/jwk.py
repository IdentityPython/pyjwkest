import base64
import struct
import logging
import json
import M2Crypto
from M2Crypto.RSA import new_pub_key

from requests import request

from binascii import b2a_hex
from M2Crypto.__m2crypto import bn_to_mpi
from M2Crypto.__m2crypto import hex_to_bn
from jwkest import intarr2long, b64d, b64e
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


def long_to_mpi(num):
    """Converts a python integer or long to OpenSSL MPInt used by M2Crypto.
    Borrowed from Snowball.Shared.Crypto"""
    h = hex(num)[2:]  # strip leading 0x in string
    if len(h) % 2 == 1:
        h = '0' + h  # add leading 0 to get even number of hexdigits
    return bn_to_mpi(hex_to_bn(h))  # convert using OpenSSL BinNum


def mpi_to_long(mpi):
    """Converts an OpenSSL MPint used by M2Crypto to a python integer/long.
    Borrowed from Snowball.Shared.Crypto"""
    return eval("0x%s" % b2a_hex(mpi[4:]))


def dicthash(d):
    return hash(repr(sorted(d.items())))


# def kspec_rsa(key):
#     return {
#         "kty": "RSA",
#         "n": long_to_base64(mpi_to_long(key.n)),
#         "e": long_to_base64(mpi_to_long(key.e)),
#     }
#
#
# def kspec_ec(key):
#     """
#     TODO
#     :param key:
#     :return:
#     """
#     return {
#         "kty": "EC",
#         "crv": None,
#         "x": None,
#         "y": None
#     }
#
#
# def kspec_hmac(key, kid=""):
#     """
#     :param key:
#     :return:
#     """
#     res = {"kty": "oct", "k": key}
#     if kid:
#         res["kid"] = kid
#     return res
#
#
# def kspec(key):
#     if isinstance(key, M2Crypto.RSA.RSA):
#         return kspec_rsa(key)
#     elif isinstance(key, basestring):
#         return kspec_hmac(key)
#     else:
#         raise Exception("Unknown key type")


# =============================================================================

def x509_rsa_loads(string):
    cert = M2Crypto.X509.load_cert_string(string)
    return cert.get_pubkey().get_rsa()


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
                _key = x509_rsa_loads(cert)
                spec2key[cert] = _key
            return [("rsa", _key)]
        else:
            raise Exception("HTTP Get error: %s" % r.status_code)
    except Exception, err:  # not a RSA key
        logger.warning("Can't load key: %s" % err)
        return []


def load_x509_cert_chain(url):
    """
    Place holder
    """
    return []


def rsa_load(filename):
    """Read a PEM-encoded RSA key pair from a file."""
    return M2Crypto.RSA.load_key(filename, M2Crypto.util.no_passphrase_callback)


def rsa_loads(key):
    """Read a PEM-encoded RSA key pair from a string."""
    return M2Crypto.RSA.load_key_string(key,
                                        M2Crypto.util.no_passphrase_callback)


def rsa_pub_load(filename):
    """Read a PEM-encoded public RSA key from a file."""
    return M2Crypto.RSA.load_pub_key(filename)


def rsa_priv_to_pub(filename):
    _priv = rsa_load(filename)
    return new_pub_key((_priv.pub()))


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
        elif isinstance(key1, M2Crypto.RSA.RSA):
            return rsa_eq(key1, key2)

    return False


def ec_load(filename):
    return M2Crypto.EC.load_key(filename, M2Crypto.util.no_passphrase_callback)


def x509_rsa_load(txt):
    """ So I get the same output format as loads produces
    :param txt:
    :return:
    """
    return [("rsa", x509_rsa_loads(txt))]


class Key():
    members = ["kty", "alg", "use", "kid", "x5c", "x5t", "x5u"]

    def __init__(self, kty="", alg="", use="", kid="", key="", x5c=None,
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
            except KeyError:
                pass
        return res

    def __str__(self):
        return str(self.to_dict())

    def comp(self):
        """

        :return:
        """
        pass

    def decomp(self):
        pass

    def dc(self):
        pass


class RSA_key(Key):
    members = Key.members.extend(["n", "e"])

    def __init__(self, kty="RSA", alg="", use="", kid="", key="",
                 x5c=None, x5t="", x5u="", n="", e=""):
        Key.__init__(self, kty, alg, use, kid, key, x5c, x5t, x5u)
        self.n = n
        self.e = e

    def comp(self):
        if self.n and self.e:
            self.key = M2Crypto.RSA.new_pub_key(
                (long_to_mpi(base64_to_long(str(self.e))),
                 long_to_mpi(base64_to_long(str(self.n)))))
        elif self.x5c:
            if self.x5t:  # verify the cert
                pass
            cert = "\n".join([PREFIX, str(self.x5c[0]), POSTFIX])
            self.key = x509_rsa_loads(cert)
            if len(self.x5c) > 1:  # verify chain
                pass

    def decomp(self, do_x5=False):
        self.n = long_to_base64(mpi_to_long(self.key.n))
        self.e = long_to_base64(mpi_to_long(self.key.e))
        if do_x5:  # construct the x5u, x5t members
            pass

    def load(self, filename):
        self.key = rsa_load(filename)

    def dc(self):
        if self.key:
            self.decomp()
        elif self.n and self.e:
            self.comp()
        else:  # do nothing
            pass


class EC_key(Key):
    members = ["kty", "alg", "use", "kid", "crv", "x", "y"]

    def __init__(self, kty="EC", alg="", use="", kid="", key="",
                 x5c=None, x5t="", x5u="", crv="", x="", y=""):
        Key.__init__(self, kty, alg, use, kid, key, x5c, x5t, x5u)
        self.crv = crv
        self.x = x
        self.y = y


class SYM_key(Key):
    members = ["kty", "alg", "use", "kid", "k"]

    def __init__(self, kty="oct", alg="", use="", kid="", key="",
                 x5c=None, x5t="", x5u="", k=""):
        Key.__init__(self, kty, alg, use, kid, key, x5c, x5t, x5u)
        self.k = k

    def comp(self):
        self.key = b64d(str(self.k))

    def decomp(self):
        self.k = b64e(str(self.key))


class PKIX_key(Key):
    members = ["kty", "alg", "use", "kid", "n", "e"]

    def __init__(self, kty="RSA", alg="", use="", kid="", key="",
                 x5c=None, x5t="", x5u=""):
        Key.__init__(self, kty, alg, use, kid, key, x5c, x5t, x5u)
        self.key = key

    def dc(self):
        if self.x5c:
            cert = "\n".join([PREFIX, str(self.x5c[0]), POSTFIX])
            self.key = x509_rsa_loads(cert)
        elif self.key:
            self.x5c = []
        else:  # do nothing
            pass

# -----------------------------------------------------------------------------


def keyrep(kspec):
    if kspec["kty"] == "RSA":
        item = RSA_key(**kspec)
    elif kspec["kty"] == "oct":
        item = SYM_key(**kspec)
    elif kspec["kty"] == "EC":
        item = EC_key(**kspec)
    else:
        item = Key(**kspec)
    item.comp()
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
    if isinstance(key, M2Crypto.RSA.RSA):
        kspec = RSA_key(key=key)
    elif isinstance(key, basestring):
        kspec = SYM_key(key=key)
    else:
        raise Exception("Unknown key type:key="+str(type(key)))

    kspec.decomp()

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
