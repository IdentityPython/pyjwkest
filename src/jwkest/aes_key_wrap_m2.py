"""
Key wrapping and unwrapping as defined in RFC 3394.
Also a padding mechanism that was used in openssl at one time.
The purpose of this algorithm is to encrypt a key multiple times to add an
extra layer of security.
"""

import struct
import M2Crypto


QUAD = struct.Struct('>Q')


class AES(object):
    def __init__(self, key, iv, alg="aes_128_cbc"):
        """
        :param key: encryption key
        :param iv: init vector
        :param op: key usage: 1 (encryption) or 0 (decryption)
        :param alg: cipher algorithm
        :return: A Cipher instance
        """
        self.key = key
        self.iv = iv
        self.alg = alg

    def new_decrypt(self):
        self.cipher = M2Crypto.EVP.Cipher(alg=self.alg, key=self.key,
                                          iv=self.iv, op=0)

    def new_encrypt(self):
        self.cipher = M2Crypto.EVP.Cipher(alg=self.alg, key=self.key,
                                          iv=self.iv, op=0)

    def do(self, msg):
        v = self.cipher.update(msg)
        v = v + self.cipher.final()
        #v = b64encode(v)
        return v


def aes_unwrap_key_and_iv(kek, wrapped):
    n = len(wrapped) / 8 - 1
    #NOTE: R[0] is never accessed, left in for consistency with RFC indices
    R = [None] + [wrapped[i * 8:i * 8 + 8] for i in range(1, n + 1)]
    A = QUAD.unpack(wrapped[:8])[0]
    decrypt = AES.new(kek).decrypt
    for j in range(5, -1, -1):  # counting down
        for i in range(n, 0, -1):  # (n, n-1, ..., 1)
            ciphertext = QUAD.pack(A ^ (n * j + i)) + R[i]
            B = decrypt(ciphertext)
            A = QUAD.unpack(B[:8])[0]
            R[i] = B[8:]
    return "".join(R[1:]), A


def aes_unwrap_key(kek, wrapped, iv=0xa6a6a6a6a6a6a6a6):
    key, key_iv = aes_unwrap_key_and_iv(kek, wrapped)
    if key_iv != iv:
        raise ValueError(
            "Integrity Check Failed: " + hex(key_iv) + " (expected " + hex(
                iv) + ")")
    return key


def aes_unwrap_key_withpad(kek, wrapped):
    key, key_iv = aes_unwrap_key_and_iv(kek, wrapped)
    key_iv = "{0:016X}".format(key_iv)
    if key_iv[:8] != "A65959A6":
        raise ValueError(
            "Integrity Check Failed: " + key_iv[:8] + " (expected A65959A6)")
    key_len = int(key_iv[8:], 16)
    return key[:key_len]


def aes_wrap_key(kek, plaintext, iv=0xa6a6a6a6a6a6a6a6):
    n = len(plaintext) / 8
    R = [None] + [plaintext[i * 8:i * 8 + 8] for i in range(0, n)]
    A = iv
    aes = AES(kek, )
    for j in range(6):
        for i in range(1, n + 1):
            B = encrypt(QUAD.pack(A) + R[i])
            A = QUAD.unpack(B[:8])[0] ^ (n * j + i)
            R[i] = B[8:]
    return QUAD.pack(A) + "".join(R[1:])


def aes_wrap_key_withpad(kek, plaintext):
    iv = 0xA65959A600000000 + len(plaintext)
    plaintext += "\0" * (8 - len(plaintext) % 8)
    return aes_wrap_key(kek, plaintext, iv)


if __name__ == "__main__":
    #test vector from RFC 3394
    import binascii

    KEK = binascii.unhexlify("000102030405060708090A0B0C0D0E0F")
    CIPHER = binascii.unhexlify(
        "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
    PLAIN = binascii.unhexlify("00112233445566778899AABBCCDDEEFF")
    assert aes_unwrap_key(KEK, CIPHER) == PLAIN
    assert aes_wrap_key(KEK, PLAIN) == CIPHER