.. pyjwkest documentation master file, created by
   sphinx-quickstart on Sun Mar 15 14:19:54 2015.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to pyjwkest's documentation!
====================================

Software to do the JOSE stuff, that is Javascript Object Signing and Encryption.

Contents:

.. toctree::
   :maxdepth: 1

   install
   keys
   signing
   encrypt
   examples

Algorithm support
-----------------

**JSON Web Keys (JWK) support**

.. list-table:: JWK support
    :header-rows: 1

    * - JWK "kty"
      - Key Type

    * - ``EC``
      - Elliptic Curve

    * - ``RSA``
      - RSA

    * - ``oct``
      - Symmetric

**JSON Web Signature (JWS) support**

.. list-table:: JWS support
    :header-rows: 1

    * - JWS "alg"
      - Digital Signature or MAC Algorithm

    * - ``HS256``, ``HS384``, ``HS512``
      - HMAC using SHA-2

    * - ``RS256``, ``RS384``, ``RS512``
      - RSASSA-PKCS-v1_5 with SHA-2

    * - ``ES256``, ``ES384``, ``ES512``
      - Elliptic Curve Digital Signatures (ECDSA) with SHA-2

    * - ``PS256``, ``PS384``, ``PS512``
      - RSASSA-PSS Digital Signatures with SHA-2

    * - ``none``
      - No signature ("Unsecured JWS")

**JSON Web Encryption (JWE) support**

.. list-table:: JWE Key Management support
    :header-rows: 1

    * - JWE "alg"
      - Key Management

    * - ``RSA1_5``
      - RSAES-PKCS1-V1_5 key encryption

    * - ``RSA-OAEP``, ``RSA-OAEP-256``
      - RSAES using OAEP key encryption

    * - ``A128KW``, ``A192KW``, ``A256KW``
      - AES Key Wrap

    * - ``ECDH-ES``
      - Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using
        Concat KDF

    * - ``ECDH-ES+A128KW``, ``ECDH-ES+A192KW``, ``ECDH-ES+A256KW``
      - Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using
        Concat KDF with AES key wrap

.. list-table:: JWE Content Encryption support
    :header-rows: 1

    * - JWE "enc"
      - Content Encryption Algorithm

    * - ``A128CBC-HS256``, ``A192CBC-HS384``, ``A256CBC-HS512``
      - Authenticated encryption with AES-CBC and HMAC-SHA2

    * - ``A128GCM``, ``A192GCM``, ``A256GCM``
      - Authenticated encryption with Advanced Encryption Standard (AES) in
        Galois/Counter Mode (GCM)


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

