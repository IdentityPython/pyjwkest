import base64
import struct
import logging
import json
import M2Crypto

from requests import request

from binascii import b2a_hex
from M2Crypto.__m2crypto import bn_to_mpi
from M2Crypto.__m2crypto import hex_to_bn
from jwkest import intarr2long
from jwkest import dehexlify

__author__ = 'rohe0002'

logger = logging.getLogger(__name__)

def bytes( long_int ):
    bytes = []
    while long_int:
        long_int, r = divmod(long_int, 256)
        bytes.insert(0, r)
    return bytes

def long_to_base64(n):
    bys = bytes(n)
    data = struct.pack('%sB' % len(bys), *bys)
    if not len(data):
        data = '\x00'
    s = base64.urlsafe_b64encode(data).rstrip('=')
    return s

def b64_set_to_long(s):
    data = base64.urlsafe_b64decode(s + '==')
    n = struct.unpack('>Q', '\x00'* (8-len(data)) + data )
    return n[0]

def base64_to_long(data):
    _d = base64.urlsafe_b64decode(data + '==')
    return intarr2long(dehexlify(_d))

def long_to_mpi(num):
    """Converts a python integer or long to OpenSSL MPInt used by M2Crypto.
    Borrowed from Snowball.Shared.Crypto"""
    h = hex(num)[2:] # strip leading 0x in string
    if len(h) % 2 == 1:
        h = '0' + h # add leading 0 to get even number of hexdigits
    return bn_to_mpi(hex_to_bn(h)) # convert using OpenSSL BinNum

def mpi_to_long(mpi):
    """Converts an OpenSSL MPint used by M2Crypto to a python integer/long.
    Borrowed from Snowball.Shared.Crypto"""
    return eval("0x%s" % b2a_hex(mpi[4:]))

def dicthash(d):
    return hash(repr(sorted(d.items())))

def kspec(key, usage):
    return {
        "alg": "RSA",
        "mod": long_to_base64(mpi_to_long(key.n)),
        "xpo": long_to_base64(mpi_to_long(key.e)),
        "use": usage
    }

# =============================================================================

def load_jwk(txt):
    """
    Load and create keys from a JWK representation

    Expects something on this form
    {"keys":
        [
            {"alg":"EC",
             "crv":"P-256",
             "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
             "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
             "use":"enc",
             "kid":"1"},

            {"alg":"RSA",
             "mod": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFb....."
             "xpo":"AQAB",
             "kid":"2011-04-29"}
        ]
    }

    :param txt: The JWK string representation
    :return: list of 2-tuples containing key, type
    """
    spec = json.loads(txt)
    res = []
    for kspec in spec["keys"]:
        if kspec["alg"] == "RSA":
            e = base64_to_long(str(kspec["xpo"]))
            n = base64_to_long(str(kspec["mod"]))

            k = M2Crypto.RSA.new_pub_key((long_to_mpi(e),
                                          long_to_mpi(n)))

            res.append(("rsa", k))
        elif kspec["alg"] == "HMAC":
            res.append(("hmac", kspec["mod"]))

    return res

def loads(txt):
    """
    Load and create keys from a JWK representation

    Expects something on this form
    {"keys":
        [
            {"alg":"EC",
             "crv":"P-256",
             "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
            "use":"enc",
            "kid":"1"},

            {"alg":"RSA",
            "mod": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFb....."
            "xpo":"AQAB",
            "kid":"2011-04-29"}
        ]
    }

    :param txt: The JWK string representation
    :return: list of 2-tuples containing key, type
    """
    spec = json.loads(txt)
    res = []
    for kspec in spec["keys"]:
        if kspec["alg"] == "RSA":
            try:
                e = base64_to_long(str(kspec["xpo"]))
            except KeyError:
                e = base64_to_long(str(kspec["exp"]))
            n = base64_to_long(str(kspec["mod"]))

            k = M2Crypto.RSA.new_pub_key((long_to_mpi(e),
                                          long_to_mpi(n)))

            if "kid" in kspec:
                tag = "%s:%s" % ("rsa", kspec["kid"])
            else:
                tag = "rsa"

            res.append((tag, k))
        elif kspec["alg"] == "HMAC":
            res.append(("hmac", kspec["mod"]))

    return res

def dumps(keys, use=""):
    """
    Dump to JWK string representation

    :param keys: The keys to dump
    :param use: What the key are expected to be use for
    :return: The JWK string representation or None
    """
    kspecs = []
    for key in keys:
        if isinstance(key, M2Crypto.RSA.RSA):
            kspecs.append(kspec(key, use))

    if kspecs:
        return json.dumps({"keys": kspecs})
    else:
        return None

def load_jwk(url, spec2key):
    """
    Get and transform a JWK into keys

    :param url: Where the JWK can be found
    :param spec2key: A dictionary over keys already seen
    :return: List of 2-tuples (keytype, key)
    """
    r = request("GET", url, allow_redirects=True)
    if r.status_code == 200:
        return loads(r.text)
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
    except Exception, err: # not a RSA key
        logger.warning("Can't load key: %s" % err)
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

