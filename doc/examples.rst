A couple of hopefully usable examples
=====================================

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

