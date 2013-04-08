"""JSON Web Token"""

# Most of the code herein I have borrowed/stolen from other people
# Most notably Jeff Lindsay, Ryan Kelly

import base64
from binascii import unhexlify, hexlify
import json
import logging
import re

from itertools import izip

logger = logging.getLogger(__name__)

JWT_TYPES = (u"JWT", u"application/jws", u"JWS", u"JWE")


# XXX Should this be a subclass of ValueError?
class Invalid(Exception):
    """The JWT is invalid."""


class BadSyntax(Invalid):
    """The JWT could not be parsed because the syntax is invalid."""
    def __init__(self, value, msg):
        Invalid.__init__(self)
        self.value = value
        self.msg = msg

    def __str__(self):
        return "%s: %r" % (self.msg, self.value)


class BadSignature(Invalid):
    """The signature of the JWT is invalid."""


class Expired(Invalid):
    """The JWT claim has expired or is not yet valid."""


class UnknownAlgorithm(Invalid):
    """The JWT uses an unknown signing algorithm"""


class BadType(Invalid):
    """The JWT has an unexpected "typ" value."""


class MissingKey(Exception):
    """ No usable key """


def b64e(b):
    """Base64 encode some bytes.

    Uses the url-safe - and _ characters, and doesn't pad with = characters."""
    return base64.urlsafe_b64encode(b).rstrip(b"=")

_b64_re = re.compile(b"^[A-Za-z0-9_-]*$")


def add_padding(b):
    # add padding chars
    m = len(b) % 4
    if m == 1:
        # NOTE: for some reason b64decode raises *TypeError* if the
        # padding is incorrect.
        raise BadSyntax(b, "incorrect padding")
    elif m == 2:
        b += b"=="
    elif m == 3:
        b += b"="
    return b


def b64d(b):
    """Decode some base64-encoded bytes.

    Raises BadSyntax if the string contains invalid characters or padding."""

    if b.endswith("="):  # shouldn't but there you are
        cb = b.split("=")[0]
    else:
        cb = b

    # Python's base64 functions ignore invalid characters, so we need to
    # check for them explicitly.
    if not _b64_re.match(cb):
        raise BadSyntax(cb, "base64-encoded data contains illegal characters")

    if cb == b:
        b = add_padding(b)

    return base64.urlsafe_b64decode(b)


def split_token(token):
    if token.count(b".") != 2:
        raise BadSyntax(token,
                        "expected token to contain 2 dots, not %d" %
                        token.count(b"."))
    return tuple(token.split(b"."))


# Stolen from Werkzeug
def safe_str_cmp(a, b):
    """Compare two strings in constant time."""
    if len(a) != len(b):
        return False
    r = 0
    for c, d in izip(a, b):
        r |= ord(c) ^ ord(d)
    return r == 0


def unpack(token):
    """
    Unpacks a JWT into its parts and base64 decodes the parts individually

    :param token: The JWT
    :return: A tuple of the header, claim, crypto parts plus the header
        and claims part before base64 decoding
    """
    if isinstance(token, unicode):
        token = str(token)

    header_b64, claim_b64, crypto_b64 = split_token(token)

    header = b64d(header_b64)
    claim = b64d(claim_b64)
    crypto = b64d(crypto_b64)

    header = json.loads(header)

    return header, claim, crypto, header_b64, claim_b64


def pack(payload):
    """
    Unsigned JWT
    """
    header = {'alg': 'none'}

    header_b64 = b64e(json.dumps(header, separators=(",", ":")))
    if isinstance(payload, basestring):
        payload_b64 = b64e(payload)
    else:
        payload_b64 = b64e(json.dumps(payload, separators=(",", ":")))

    token = header_b64 + b"." + payload_b64 + b"."

    return token

# ---------------------------------------------------------------------------
# Helper functions


def intarr2bin(arr):
    return unhexlify(''.join(["%02x" % byte for byte in arr]))


def intarr2long(arr):
    return long(''.join(["%02x" % byte for byte in arr]), 16)


def hd2ia(s):
    #half = len(s)/2
    return [int(s[i] + s[i + 1], 16) for i in range(0, len(s), 2)]


def dehexlify(bi):
    s = hexlify(bi)
    return [int(s[i] + s[i + 1], 16) for i in range(0, len(s), 2)]
