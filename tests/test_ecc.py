# pylint: disable=missing-docstring

import hashlib
import binascii

from jwkest.ecc import P256, P384, P521


def test_ecdh():
    # Try ECDH, see if we get the same answer
    (privA, pubA) = P256.key_pair()
    (privB, pubB) = P256.key_pair()

    Zab = P256.dh_z(privA, pubB)
    Zba = P256.dh_z(privB, pubA)

    assert Zab == Zba


def test_P256_verify():
    # Try ECDSA with one of the NIST test vectors
    _msg = ("5ff1fa17c2a67ce599a34688f6fb2d4a8af17532d15fa1868a598a8e6a0daf9b11"
            "edcc483d11ae003ed645c0aaccfb1e51cf448b737376d531a6dcf0429005f5e7be"
            "626b218011c6218ff32d00f30480b024ec9a3370d1d30a9c70c9f1ce6c61c9abe5"
            "08d6bc4d3f2a167756613af1778f3a94e7771d5989fe856fa4df8f8ae5")
    msg = binascii.unhexlify(_msg)

    Qx = 0xe9cd2e8f15bd90cb0707e05ed3b601aace7ef57142a64661ea1dd7199ebba9ac
    Qy = 0xc96b0115bed1c134b68f89584b040a194bfad94a404fdb37adad107d5a0b4c5e
    R = 0x15bf46937c7a1e2fa7adc65c89fe03ae602dd7dfa6722cdafa92d624b32b156e
    S = 0x59c591792ee94f0b202e7a590e70d01dd8a9774884e2b5ba9945437cfed01686

    h = int(hashlib.new("SHA1", msg).hexdigest(), 16)
    Q = (Qx, Qy)
    sig = P256.int2bytes(R) + P256.int2bytes(S)
    assert P256.verify(h, sig, Q)


def test_P256_sign_and_verify():
    d = 0x002a10b1b5b9fa0b78d38ed29cd9cec18520e0fe93023e3550bb7163ab4905c6
    _msg = ("5ff1fa17c2a67ce599a34688f6fb2d4a8af17532d15fa1868a598a8e6a0daf9b11"
            "edcc483d11ae003ed645c0aaccfb1e51cf448b737376d531a6dcf0429005f5e7be"
            "626b218011c6218ff32d00f30480b024ec9a3370d1d30a9c70c9f1ce6c61c9abe5"
            "08d6bc4d3f2a167756613af1778f3a94e7771d5989fe856fa4df8f8ae5")
    msg = binascii.unhexlify(_msg)
    Qx = 0xe9cd2e8f15bd90cb0707e05ed3b601aace7ef57142a64661ea1dd7199ebba9ac
    Qy = 0xc96b0115bed1c134b68f89584b040a194bfad94a404fdb37adad107d5a0b4c5e

    h = int(hashlib.new("SHA1", msg).hexdigest(), 16)
    Q = (Qx, Qy)
    sig = P256.sign(h, d)
    assert P256.verify(h, sig, Q)


def test_P384_verify_with_suite_B():
    # Try ECDSA with the Suite B test vectors
    _msg = ("54686973206973206f6e6c7920612074657374206d6573736167652e2049742069"
            "73203438206279746573206c6f6e67")
    msg = msg = binascii.unhexlify(_msg)
    Qx = 0x1fbac8eebd0cbf35640b39efe0808dd774debff20a2a329e91713baf7d7f3c3e81546d883730bee7e48678f857b02ca0
    Qy = 0xeb213103bd68ce343365a8a4c3d4555fa385f5330203bdd76ffad1f3affb95751c132007e1b240353cb0a4cf1693bdf9
    R = 0xa0c27ec893092dea1e1bd2ccfed3cf945c8134ed0c9f81311a0f4a05942db8dbed8dd59f267471d5462aa14fe72de856
    S = 0x20ab3f45b74f10b6e11f96a2c8eb694d206b9dda86d3c7e331c26b22c987b7537726577667adadf168ebbe803794a402

    h = int(hashlib.new("SHA384", msg).hexdigest(), 16)
    Q = (Qx, Qy)
    sig = P384.int2bytes(R) + P384.int2bytes(S)
    assert P384.verify(h, sig, Q)


def test_P256_verify_with_suite_B():
    _msg = ("54686973206973206f6e6c7920612074657374206d6573736167652e2049742069"
            "73203438206279746573206c6f6e67")
    msg = binascii.unhexlify(_msg)
    Qx = 0x8101ece47464a6ead70cf69a6e2bd3d88691a3262d22cba4f7635eaff26680a8
    Qy = 0xd8a12ba61d599235f67d9cb4d58f1783d3ca43e78f0a5abaa624079936c0c3a9
    R = 0x7214bc9647160bbd39ff2f80533f5dc6ddd70ddf86bb815661e805d5d4e6f27c
    S = 0x7d1ff961980f961bdaa3233b6209f4013317d3e3f9e1493592dbeaa1af2bc367

    h = int(hashlib.new("SHA256", msg).hexdigest(), 16)
    Q = (Qx, Qy)
    sig = P256.int2bytes(R) + P256.int2bytes(S)
    assert P256.verify(h, sig, Q)


def test_P521_verify_with_nist():
    # Try ECDSA with one of the NIST P-521 test vectors (should pass)
    _sg = ("f69417bead3b1e208c4c99236bf84474a00de7f0b9dd23f991b6b60ef0fb3c6207"
           "3a5a7abb1ef69dbbd8cf61e64200ca086dfd645b641e8d02397782da92d3542fbd"
           "df6349ac0b48b1b1d69fe462d1bb492f34dd40d137163843ac11bd099df719212c"
           "160cbebcb2ab6f3525e64846c887e1b52b52eced9447a3d31938593a87")
    msg = binascii.unhexlify(_sg)
    Qx = 0x153eb2be05438e5c1effb41b413efc2843b927cbf19f0bc9cc14b693eee26394a0d8880dc946a06656bcd09871544a5f15c7a1fa68e00cdc728c7cfb9c448034867
    Qy = 0x143ae8eecbce8fcf6b16e6159b2970a9ceb32c17c1d878c09317311b7519ed5ece3374e7929f338ddd0ec0522d81f2fa4fa47033ef0c0872dc049bb89233eef9bc1
    R = 0x0dd633947446d0d51a96a0173c01125858abb2bece670af922a92dedcec067136c1fa92e5fa73d7116ac9c1a42b9cb642e4ac19310b049e48c53011ffc6e7461c36
    S = 0x0efbdc6a414bb8d663bb5cdb7c586bccfe7589049076f98cee82cdb5d203fddb2e0ffb77954959dfa5ed0de850e42a86f5a63c5a6592e9b9b8bd1b40557b9cd0cc0

    h = int(hashlib.new("SHA512", msg).hexdigest(), 16)
    Q = (Qx, Qy)
    sig = P521.int2bytes(R) + P521.int2bytes(S)
    assert P521.verify(h, sig, Q)


def test_P521_negative_verify_with_nist():
    # Try ECDSA with one of the NIST P-521 test vectors (should fail)
    _sg = ("a0732a605c785a2cc9a3ff84cbaf29175040f7a0cc35f4ea8eeff267c1f92f06f4"
           "6d3b35437195185d322cbd775fd24741e86ee9236ba5b374a2ac29803554d715fa"
           "4656ac31778f103f88d68434dd2013d4c4e9848a11198b390c3d600d712893513e"
           "179cd3d31fb06c6e2a1016fb96ffd970b1489e36a556ab3b537eb29dff")
    msg = binascii.unhexlify(_sg)
    Qx = 0x12a593f568ca2571e543e00066ecd3a3272a57e1c94fe311e5df96afc1b792e5862720fc730e62052bbf3e118d3a078f0144fc00c9d8baaaa8298ff63981d09d911
    Qy = 0x17cea5ae75a74100ee03cdf2468393eef55ddabfe8fd5718e88903eb9fd241e8cbf9c68ae16f4a1db26c6352afcb1894a9812da6d32cb862021c86cd8aa483afc26
    R = 0x1aac7692baf3aa94a97907307010895efc1337cdd686f9ef2fd8404796a74701e55b03ceef41f3e6f50a0eeea11869c4789a3e8ab5b77324961d081e1a3377ccc91
    S = 0x009c1e7d93d056b5a97759458d58c49134a45071854b8a6b8272f9fe7e78e1f3d8097e8a6e731f7ab4851eb26d5aa4fdadba6296dc7af835fe3d1b6dba4b031d5f3

    h = int(hashlib.new("SHA512", msg).hexdigest(), 16)
    Q = (Qx, Qy)
    sig = P521.int2bytes(R) + P521.int2bytes(S)
    assert not P521.verify(h, sig, Q)


def test_P521_sign_verify():
    # Try ECDSA on our own signature with P-521
    _sg = ("9ce982c91af08a21d405f96abd6204588bb0ef1c8b78305b06f36a12d1914cae9d"
           "ce6a1f1a0b4c42b067667c457c3e90e56f34cff0116bbd350d27882dd6e47997c9"
           "44dcead9cb945f7c691078c1b533960a55f93d241970a1fdf4441107d8bc8af5aa"
           "8e088ea3aa82c7f3286e815dbb85d5cfae0aeeeb093468cb55201eeffb")
    msg = msg = binascii.unhexlify(_sg)

    (priv, pub) = P521.key_pair()
    h = int(hashlib.new("SHA512", msg).hexdigest(), 16)
    sig = P521.sign(h, priv)
    assert P521.verify(h, sig, pub)
