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
from jwkest import intarr2long
from jwkest import dehexlify

__author__ = 'rohe0002'

logger = logging.getLogger(__name__)


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


def kspec_rsa(key):
    return {
        "kty": "RSA",
        "n": long_to_base64(mpi_to_long(key.n)),
        "e": long_to_base64(mpi_to_long(key.e)),
    }


def kspec_ec(key):
    """
    TODO
    :param key:
    :return:
    """
    return {
        "kty": "EC",
        "crv": None,
        "x": None,
        "y": None
    }


def kspec_hmac(key):
    """
    !!! This is not according to any standard !!!

    :param key:
    :return:
    """
    return {
        "kty": "HMAC",
        "mod": key
    }


def kspec(key):
    if isinstance(key, M2Crypto.RSA.RSA):
        return kspec_rsa(key)
    elif isinstance(key, basestring):
        return kspec_hmac(key)
    else:
        raise Exception("Unknown key type")


# =============================================================================

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
        if kspec["kty"] == "RSA":
            try:
                e = base64_to_long(str(kspec["e"]))
                n = base64_to_long(str(kspec["n"]))
            except KeyError:
                raise FormatError("Wrong parameters in a JWK")

            k = M2Crypto.RSA.new_pub_key((long_to_mpi(e),
                                          long_to_mpi(n)))

            if "kid" in kspec:
                tag = "%s:%s" % ("rsa", kspec["kid"])
            else:
                tag = "rsa"

            res.append((tag, k))
        elif kspec["kty"] == "HMAC":
            res.append(("hmac", kspec["mod"]))

    return res


def dump_jwk(key, use="", kid=""):
    """
    Dump to JWK dictionary representation

    :param key: The keys to dump
    :param use: What the key are expected to be use for
    :return: The JWK string representation or None
    """
    if isinstance(key, M2Crypto.RSA.RSA):
        kspec = kspec_rsa(key)
    elif isinstance(key, basestring):
        kspec = kspec_hmac(key)
    else:
        raise Exception("Unknown key type:key="+str(type(key)))

    if use:
        kspec["use"] = use
    if kid:
        kspec["kid"] = kid

    return kspec


def dump_jwks(keyspecs):
    """

    :param keyspecs: list of dictionaries describing keys
    :return:
    """
    res = []
    for keyspec in keyspecs:
        res.append(dump_jwk(**keyspec))

    return json.dumps({"keys": res})


def load_jwks_from_url(url, spec2key):
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

#def load_x509_cert_or_cert_chain(url):
#    """
#    Get and transform a X509 cert into a key
#
#    :param url: Where the X509 cert or cert chain can be found
#    :return: List of 2-tuples (keytype, key)
#    """
#    try:
#        r = request("GET", url, allow_redirects=True)
#        if r.status_code == 200:
#            cert = str(r.text)
#            try:
#                _key = spec2key[cert]
#            except KeyError:
#                _key = x509_rsa_loads(cert)
#                spec2key[cert] = _key
#            return [("rsa", _key)]
#        else:
#            raise Exception("HTTP Get error: %s" % r.status_code)
#    except Exception, err: # not a RSA key
#        logger.warning("Can't load key: %s" % err)
#        return []


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
