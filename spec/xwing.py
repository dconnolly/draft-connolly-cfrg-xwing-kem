# WARNING This is a specification of X-Wing; not a production-ready
# implementation. It is slow and does not run in constant time.

# Requires the CryptoDome for SHAKE, and pytest for testing. To install, run
#
#   pip install pycryptodome pytest

import binascii
import hashlib

import mlkem
import x25519

XWingLabel = br"""
                \./
                /^\
              """.replace(b'\n', b'').replace(b' ', b'')

assert len(XWingLabel) == 6
assert binascii.hexlify(XWingLabel) == b'5c2e2f2f5e5c'

def expandDecapsulationKey(seed):
    expanded = hashlib.shake_128(seed).digest(length=96)
    pkM, skM = mlkem.KeyGen(expanded[0:64], mlkem.params768)
    skX = expanded[64:96]
    pkX = x25519.X(skX, x25519.BASE)
    return skM, skX, pkM, pkX

def GenerateKeyPairDerand(seed):
    assert len(seed) == 32
    skM, skX, pkM, pkX = expandDecapsulationKey(seed)
    return seed, pkM + pkX

def Combiner(ssM, ssX, ctX, pkX):
    return hashlib.sha3_256(
        XWingLabel +
        ssM +
        ssX +
        ctX +
        pkX
    ).digest()

def EncapsulateDerand(pk, eseed):
    assert len(eseed) == 64
    assert len(pk) == 1216
    pkM = pk[0:1184]
    pkX = pk[1184:1216]
    ekX = eseed[32:64]
    ctX = x25519.X(ekX, x25519.BASE)
    ssX = x25519.X(ekX, pkX)
    ctM, ssM = mlkem.Enc(pkM, eseed[0:32], mlkem.params768)
    ss = Combiner(ssM, ssX, ctX, pkX)
    return ss, ctM + ctX

def Decapsulate(ct, sk):
    assert len(ct) == 1120
    assert len(sk) == 32
    ctM = ct[0:1088]
    ctX = ct[1088:1120]
    skM, skX, pkM, pkX = expandDecapsulationKey(sk)
    ssM = mlkem.Dec(skM, ctM, mlkem.params768)
    ssX = x25519.X(skX, ctX)
    return Combiner(ssM, ssX, ctX, pkX)
