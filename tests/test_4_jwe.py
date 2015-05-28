from __future__ import print_function
import array
import hashlib
import os
import sys
from Crypto.PublicKey import RSA

from jwkest.aes_gcm import AES_GCM
from jwkest.aes_key_wrap import aes_wrap_key
from jwkest import b64e, long2intarr
from jwkest import intarr2long
from jwkest import long2hexseq
from jwkest.jwk import RSAKey
from jwkest.jwe import JWE_RSA, factory
from jwkest.jwe import JWe
from jwkest.jwe import JWE

__author__ = 'rohe0002'


def intarr2bytes(arr):
    return array.array('B', arr).tostring()


def bytes2intarr(bts):
    return [b for b in bts]


def str2intarr(string):
    return array.array('B', string).tolist()


if sys.version < '3':
    to_intarr = str2intarr
else:
    to_intarr = bytes2intarr


def test_jwe_09_a1():
    # RSAES OAEP and AES GCM
    msg = b"The true sign of intelligence is not knowledge but imagination."

    # A.1.1
    header = b'{"alg":"RSA-OAEP","enc":"A256GCM"}'
    b64_header = b64e(header)

    # A.1.2
    assert b64_header == b"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ"

    # A.1.3
    cek = intarr2long([177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255,
                      107, 154, 212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47,
                      130, 203, 46, 122, 234, 64, 252])

    # A.1.4 Key Encryption
    enc_key = [
        56, 163, 154, 192, 58, 53, 222, 4, 105, 218, 136, 218, 29, 94, 203,
        22, 150, 92, 129, 94, 211, 232, 53, 89, 41, 60, 138, 56, 196, 216,
        82, 98, 168, 76, 37, 73, 70, 7, 36, 8, 191, 100, 136, 196, 244, 220,
        145, 158, 138, 155, 4, 117, 141, 230, 199, 247, 173, 45, 182, 214,
        74, 177, 107, 211, 153, 11, 205, 196, 171, 226, 162, 128, 171, 182,
        13, 237, 239, 99, 193, 4, 91, 219, 121, 223, 107, 167, 61, 119, 228,
        173, 156, 137, 134, 200, 80, 219, 74, 253, 56, 185, 91, 177, 34, 158,
        89, 154, 205, 96, 55, 18, 138, 43, 96, 218, 215, 128, 124, 75, 138,
        243, 85, 25, 109, 117, 140, 26, 155, 249, 67, 167, 149, 231, 100, 6,
        41, 65, 214, 251, 232, 87, 72, 40, 182, 149, 154, 168, 31, 193, 126,
        215, 89, 28, 111, 219, 125, 182, 139, 235, 195, 197, 23, 234, 55, 58,
        63, 180, 68, 202, 206, 149, 75, 205, 248, 176, 67, 39, 178, 60, 98,
        193, 32, 238, 122, 96, 158, 222, 57, 183, 111, 210, 55, 188, 215,
        206, 180, 166, 150, 166, 106, 250, 55, 229, 72, 40, 69, 214, 216,
        104, 23, 40, 135, 212, 28, 127, 41, 80, 175, 174, 168, 115, 171, 197,
        89, 116, 92, 103, 246, 83, 216, 182, 176, 84, 37, 147, 35, 45, 219,
        172, 99, 226, 233, 73, 37, 124, 42, 72, 49, 242, 35, 127, 184, 134,
        117, 114, 135, 206]

    b64_ejek = b'ApfOLCaDbqs_JXPYy2I937v_xmrzj-Iss1mG6NAHmeJViM6j2l0MHvfseIdHVyU2BIoGVu9ohvkkWiRq5DL2jYZTPA9TAdwq3FUIVyoH-Pedf6elHIVFi2KGDEspYMtQARMMSBcS7pslx6flh1Cfh3GBKysztVMEhZ_maFkm4PYVCsJsvq6Ct3fg2CJPOs0X1DHuxZKoIGIqcbeK4XEO5a0h5TAuJObKdfO0dKwfNSSbpu5sFrpRFwV2FTTYoqF4zI46N9-_hMIznlEpftRXhScEJuZ9HG8C8CHB1WRZ_J48PleqdhF4o7fB5J1wFqUXBtbtuGJ_A2Xe6AEhrlzCOw'

    iv = intarr2long([227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219])

    aadp = b64_header + b'.' + b64_ejek

    gcm = AES_GCM(cek)
    ctxt, tag = gcm.encrypt(iv, msg, aadp)

    _va = to_intarr(ctxt)
    assert _va == [229, 236, 166, 241, 53, 191, 115, 196, 174, 43, 73, 109, 39,
                   122, 233, 96, 140, 206, 120, 52, 51, 237, 48, 11, 190, 219,
                   186, 80, 111, 104, 50, 142, 47, 167, 59, 61, 181, 127, 196,
                   21, 40, 82, 242, 32, 123, 143, 168, 226, 73, 216, 176, 144,
                   138, 247, 106, 60, 16, 205, 160, 109, 64, 63, 192]

    assert long2intarr(tag) == [130, 17, 32, 198, 120, 167, 144, 113, 0,
                                50, 158, 49, 102, 208, 118, 152]

    tag = long2hexseq(tag)
    iv = long2hexseq(iv)
    res = b".".join([b64_header, b64_ejek, b64e(iv), b64e(ctxt), b64e(tag)])

    #print(res.split(b'.'))
    expected = b'.'.join([
        b'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ',
        b'ApfOLCaDbqs_JXPYy2I937v_xmrzj-Iss1mG6NAHmeJViM6j2l0MHvfseIdHVyU2BIoGVu9ohvkkWiRq5DL2jYZTPA9TAdwq3FUIVyoH-Pedf6elHIVFi2KGDEspYMtQARMMSBcS7pslx6flh1Cfh3GBKysztVMEhZ_maFkm4PYVCsJsvq6Ct3fg2CJPOs0X1DHuxZKoIGIqcbeK4XEO5a0h5TAuJObKdfO0dKwfNSSbpu5sFrpRFwV2FTTYoqF4zI46N9-_hMIznlEpftRXhScEJuZ9HG8C8CHB1WRZ_J48PleqdhF4o7fB5J1wFqUXBtbtuGJ_A2Xe6AEhrlzCOw',
        b'48V1_ALb6US04U3b',
        b'5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A',
        b'ghEgxninkHEAMp4xZtB2mA'])

    assert res == expected


def sha256_digest(msg):
    return hashlib.sha256(msg).digest()


def test_jwe_09_a3():
    #Example JWE using AES Key Wrap and AES GCM

    msg = b'Live long and prosper.'

    header = b'{"alg":"A128KW","enc":"A128CBC-HS256"}'
    b64_header = b64e(header)

    assert b64_header == b'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0'

    cek = intarr2bytes([4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250,
                      63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219,
                      200, 177, 0, 240, 143, 156, 44, 207])

    shared_key = [25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95,
                  133, 74, 82]

    jek = aes_wrap_key(intarr2bytes(shared_key), cek)

    assert to_intarr(jek) == [
        232, 160, 123, 211, 183, 76, 245, 132, 200, 128, 123, 75, 190, 216,
        22, 67, 201, 138, 193, 186, 9, 91, 122, 31, 246, 90, 28, 139, 57, 3,
        76, 124, 193, 11, 98, 37, 173, 61, 104, 57]

    b64_jek = b64e(jek)
    assert b64_jek == b'6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ'

    iv = intarr2bytes([3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111,
                       116, 104, 101])

    b64_iv = b64e(iv)
    assert b64_iv == b'AxY8DCtDaGlsbGljb3RoZQ'

    aadp = b64_header

    assert to_intarr(aadp) == [
        101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 66, 77, 84, 73, 52,
        83, 49, 99, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105, 74, 66, 77,
        84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85, 50, 73, 110,
        48]

    _jwe = JWe()
    ctxt, tag, key = _jwe.enc_setup("A128CBC-HS256", msg, aadp, cek, iv=iv)

    print(to_intarr(ctxt))

    assert to_intarr(ctxt) == [
        40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24, 152, 230, 6,
        75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215, 104, 143,
        112, 56, 102]

    assert to_intarr(tag) == [83, 73, 191, 98, 104, 205, 211, 128, 201, 189,
                                 199, 133, 32, 38, 194, 85]

    enc_cipher_text = b64e(ctxt)
    assert enc_cipher_text == b'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY'

    enc_authn_tag = b64e(tag)
    assert enc_authn_tag == b'U0m_YmjN04DJvceFICbCVQ'

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)

KEY = full_path("rsa.key")

rsa = RSA.importKey(open(KEY, 'r').read())
plain = b'Now is the time for all good men to come to the aid of their country.'


def test_rsa_encrypt_decrypt_rsa_cbc():
    _rsa = JWE_RSA(plain, alg="RSA1_5", enc="A128CBC-HS256")
    jwt = _rsa.encrypt(rsa)
    dec = JWE_RSA()
    msg = dec.decrypt(jwt, rsa)

    assert msg == plain


def test_rsa_encrypt_decrypt_rsa_oaep_gcm():
    jwt = JWE_RSA(plain, alg="RSA-OAEP", enc="A256GCM").encrypt(rsa)
    msg = JWE_RSA().decrypt(jwt, rsa)

    assert msg == plain


def test_encrypt_decrypt_rsa_cbc():
    _key = RSAKey(key=rsa)
    _key._keytype = "private"
    _jwe0 = JWE(plain, alg="RSA1_5", enc="A128CBC-HS256")

    jwt = _jwe0.encrypt([_key])

    _jwe1 = factory(jwt)
    msg = _jwe1.decrypt(jwt, [_key])

    assert msg == plain


if __name__ == "__main__":
    test_encrypt_decrypt_rsa_cbc()
