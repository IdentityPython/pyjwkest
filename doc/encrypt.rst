.. _jwe:

Encrypting and decrypting
=========================

A message can be encrypted as::

    from Crypto.PublicKey import RSA
    from jwkest.jwk import RSAKey
    from jwkest.jwe import JWE

    rsajwk = RSAKey(key=RSA.generate(2048))
    jwe = JWE("Lorem ipsum dolor sit amet.", alg="RSA-OAEP", enc="A256GCM")
    encrypted_content = jwe.encrypt([rsajwk])

See :ref:`JWE Support <jwe_support>` for all supported algorithms for key
management and content encryption.

A received JWE can be decrypted as::

    from jwkest.jwe import JWE

    jwe = JWE()
    decrypted_content = jwe.decrypt(encrypted_content, keys=decryption_keys)

:mod:`jwe` Package
---------------------

.. automodule:: jwkest.jwe
    :members:
    :undoc-members:
    :show-inheritance:
