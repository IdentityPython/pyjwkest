.. _jwk:

Key handling
============

This module defines classes that represents cryptographic keys.

Basic key
*********

There are some common properties for all cryptographic keys when
they are used in the JOSE https://tools.ietf.org/wg/jose/ context.
These properties are defined in the `JSON Web Key (JWK) Format`_.

Symmetric keys
**************

When the key type (as defined by JWK member "kty") is "oct", the
member "k" is used to represent a symmetric key, see e.g.
`symmetric key example`_.

A symmetric key instance can be created as::

    from jwkest.jwk import SYMKey
    symjwk = SYMKey(key="My hollow echo", alg="HS512")

RSA keys
********

When the key type is "RSA", the following members are used to
represent a public RSA key:

    * "n"
    * "e"

In addition, the following members are used to represent a private RSA key:

    * "d"
    * "p" (optional)
    * "q" (optional)
    * "dp" (optional)
    * "dq" (optional)
    * "qi" (optional)

See `public keys example`_ and `private keys example`_ for examples of
public/private RSA keys.

An RSA key instance can be created from file::

    from jwkest.jwk import RSAKey, import_rsa_key_from_file
    rsajwk = RSAKey(key=import_rsa_key_from_file("test.key"))

or from a new key::

    from Crypto.PublicKey import RSA
    from jwkest.jwk import RSAKey

    rsakey = RSA.generate(2048)
    rsajwk = RSAKey(key=rsakey)

Elliptic curve keys
*******************

When the key type is "EC", the following members are used to represent an
elliptic curve public key:

    * "crv"
    * "x"
    * "y" (required when "crv" is one of "P-256"/"P-384"/"P-521")

In addition, the member "d" must be used to represent an elliptic private key.
See `public keys example`_ and `private keys example`_ for examples of elliptic
curve public/private keys.

An elliptic curve key instance can be created as::

    from jwkest.jwk import ECKey
    from cryptlib.ecc import P521

    ecjwk = ECKey().load_key(P521)

Key import and export
*********************

A set of keys (specified as JSON Web Key Set, JWKS) can be **imported**
from file::

    from jwkest.jwk import jwks_load
    with open("keys.jwks") as f:
        key_set = jwks_load(f.read())

or from an URL::

    from jwkest.jwk import load_jwks_from_url
    key_set = load_jwks_from_url("https://example.com/jwks.json")

A list of keys can be **exported** as::

    from jwkest.jwk import jwks_dump

    jwks = jwks_dump([symjwk, rsajwk, ecjwk])
    with open("keys.jwks", "w") as f:
        f.write(jwks)




:mod:`jwk` Package
---------------------

.. automodule:: jwkest.jwk
    :members:
    :undoc-members:
    :show-inheritance:

.. _symmetric key example: https://tools.ietf.org/html/draft-ietf-jose-json-web-key#appendix-A.3
.. _public keys example: https://tools.ietf.org/html/draft-ietf-jose-json-web-key#appendix-A.1
.. _private keys example: https://tools.ietf.org/html/draft-ietf-jose-json-web-key#appendix-A.2
.. _JSON Web Key (JWK) Format: https://tools.ietf.org/html/draft-ietf-jose-json-web-key