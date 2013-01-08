__author__ = 'rohe0002'

from M2Crypto import RSA

from jwkest import jwe
from jwkest import dehexlify
from jwkest.jwe import rsa_encrypt
from jwkest.jwe import rsa_decrypt
from jwkest.jwe import encrypt
from jwkest.jwe import decrypt

cmk = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
       206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
       44, 207]

cmk2 = [148, 116, 199, 126, 2, 117, 233, 76, 150, 149, 89, 193, 61, 34, 239,
        226, 109, 71, 59, 160, 192, 140, 150, 235, 106, 204, 49, 176, 68,
        119, 13, 34, 49, 19, 41, 69, 5, 20, 252, 145, 104, 129, 137, 138, 67,
        23, 153, 83, 81, 234, 82, 247, 48, 211, 41, 130, 35, 124, 45, 156,
        249, 7, 225, 168]


# JWE test A.4.1 CEK generation
def test_a41():
    r = jwe.get_cek(cmk, "A128CBC+HS256")
    x = dehexlify(r)
    print x
    assert x == [203, 165, 180, 113, 62, 195, 22, 98, 91, 153, 210, 38, 112,
                 35, 230, 236]

# JWE test A.4.2
def test_a42():
    r = jwe.get_cik(cmk, "A128CBC+HS256")
    x = dehexlify(r)
    print x
    assert x ==  [218, 24, 160, 17, 160, 50, 235, 35, 216, 209, 100, 174, 155,
                  163, 10, 117, 180, 111, 172, 200, 127, 201, 206, 173, 40, 45,
                  58, 170, 35, 93, 9, 60]

# JWE test A.5.1
def test_a51():
    r = jwe.get_cek(cmk2, "A256CBC+HS512", bsize=256, hashsize=512)
    x = dehexlify(r)
    print x
    assert x == [157, 19, 75, 205, 31, 190, 110, 46, 117, 217, 137, 19, 116,
                 166, 126, 60, 18, 244, 226, 114, 38, 153, 78, 198, 26, 0, 181,
                 168, 113, 45, 149, 89]

# JWE test A.5.2
def test_a52():
    r = jwe.get_cik(cmk2, "A256CBC+HS512", bsize=512, hashsize=512)
    x = dehexlify(r)
    #r = jwe.get_cik(cmk2, "A256CBC+HS512", round=2, length=256, hashsize=512)
    #x.extend(dehexlify(r))
    print x
    assert x == [81, 249, 131, 194, 25, 166, 147, 155, 47, 249, 146, 160, 200,
                 236, 115, 72, 103, 248, 228, 30, 130, 225, 164, 61, 105, 172,
                 198, 31, 137, 170, 215, 141, 27, 247, 73, 236, 125, 113, 151,
                 33, 0, 251, 72, 53, 72, 63, 146, 117, 247, 13, 49, 20, 210,
                 169, 232, 156, 118, 1, 16, 45, 29, 21, 15, 208]


def gen_callback(*args):
    pass

rsa = RSA.gen_key(2048, 65537, gen_callback)
plain = "Now is the time for all good men to come to the aid of their country."

def test_rsa_encrypt_decrypt_rsa_cbc():
    jwt = rsa_encrypt(plain, rsa, alg="RSA1_5", enc="A128CBC+HS256")

    msg = rsa_decrypt(jwt, rsa, "private")

    assert msg == plain

def test_rsa_encrypt_decrypt_rsa_oaep_gcm():
    jwt = rsa_encrypt(plain, rsa, alg="RSA-OAEP", enc="A256GCM")

    msg = rsa_decrypt(jwt, rsa, "private")

    assert msg == plain

def test_encrypt_decrypt_rsa_cbc():
    jwt = encrypt(plain, {"rsa":[rsa]}, alg="RSA1_5", enc="A128CBC+HS256",
                  context="public")
    msg = decrypt(jwt, {"rsa":[rsa]}, "private")

    assert msg == plain
