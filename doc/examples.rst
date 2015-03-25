A couple of hopefully usable examples
=====================================

Exporting a key
***************

To export a key::

    from Crypto.PublicKey import RSA
    from jwkest.jwk import RSAKey

    # Mint a new RSA key
    _rsakey = RSA.generate(2048)

    # Wrap it in a JWK class
    _rsajwk = RSAKey(kid="rsa1", key=_rsakey)

    # print a JWK representation of the public key
    print _rsajwk


Import a key
************

To import a RSA key from file::

    from jwkest.jwk import RSAKey, import_rsa_key_from_file
    rsajwk = RSAKey(key=import_rsa_key_from_file("test.key"))

To import a JWKS (JSON Web Key Set) from file::

    from jwkest.jwk import jwks_load
    with open("keys.jwks") as f:
        key_set = jwks_load(f.read())

or from an URL::

    from jwkest.jwk import load_jwks_from_url
    key_set = load_jwks_from_url("https://example.com/jwks.json")


Signing a document
******************

Signing a JSON object using a newly minted RSA key::

    from Crypto.PublicKey import RSA
    from jwkest.jwk import RSAKey
    from jwkest.jws import JWS
    import json

    # Mint a new RSA key
    _rsakey = RSA.generate(2048)

    # Wrap it in a JWK class
    _rsajwk = RSAKey(kid="rsa1", key=_rsakey)

    # create the message
    msg = json.dumps({"foo":"bar"})

    # The class instance that sets up the signing operation
    _jws = JWS(msg, alg="RS256")

    # Create a JWS (signed JWT) using the provided key
    print _jws.sign_compact([_rsajwk])


Signed and encrypted (nested) JWT
*********************************

JSON Web Tokens can be both signed and encrypted (preferably in that order!).

To produce a nested JWT::

    from Crypto.PublicKey import RSA
    from cryptlib.ecc import P256
    from jwkest.jwe import JWE
    from jwkest.jwk import RSAKey, ECKey
    from jwkest.jws import JWS

    # Generate new elliptic curve key for signing
    signing_keys = [ECKey(use="sig").load_key(P256)]

    # Create JWS
    jws = JWS("Lorem ipsum dolor sit amet.", alg="ES256")

    # Serialize it, using the compact JWS serialization (which is URL-safe)
    signed_content = jws.sign_compact(keys=signing_keys)

    # Generate new RSA key for encryption
    encryption_keys = [RSAKey(use="enc", key=RSA.generate(2048))]

    # Create JWE
    jwe = JWE(signed_content, alg="RSA-OAEP", enc="A256CBC-HS512")

    # Encrypt the nested content
    encrypted_content = jwe.encrypt(keys=encryption_keys)

To consume a nested JWT::

    from jwkest.jwe import JWE
    from jwkest.jws import JWS

    decrypted_content = JWE().decrypt(encrypted_content, keys=encryption_keys)
    plain_text = JWS().verify_compact(decrypted_content, keys=signing_keys)

