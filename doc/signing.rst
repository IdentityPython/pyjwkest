.. _jws:

Signing and verifying signatures
================================

A message can be signed as::

    from cryptlib.ecc import P256
    from jwkest.jwk import ECKey
    from jwkest.jws import JWS

    ecjwk = ECKey(use="sig").load_key(P256)
    jws = JWS("Lorem ipsum dolor sit amet.", alg="ES256")
    signed_content = jws.sign_compact(keys=[ecjwk])

See See :ref:`JWS Support <jws_support>` for all supported algorithms for
signatures.

The signature of a received JWS can be verified as::

    from jwkest.jws import JWS

    jws = JWS()
    plain_text = jws.verify_compact(signed_content, keys=signing_keys)

:mod:`jws` Package
------------------

.. automodule:: jwkest.jws
    :members:
    :undoc-members:
    :show-inheritance:
