from jwkest.jwk import ECKey
from Cryptodome.PublicKey import ECC

ecc_key = ECC.generate(curve='P-256')
jwk = ECKey(key=ecc_key)
jwk.serialize(private=True)