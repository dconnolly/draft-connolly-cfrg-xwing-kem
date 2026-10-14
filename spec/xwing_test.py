from xwing import *

import binascii
import json
import io

import pytest
from Crypto.Hash import SHAKE128

@pytest.fixture
def setVectors(request):
    return request.config.getoption('--set-vectors')

def hex(s):
    return binascii.hexlify(s).decode('utf-8')

def test_vectors(setVectors):
    h = SHAKE128.new()

    print(setVectors)

    ret = []

    for i in range(3):
        seed = h.read(32)
        eseed = h.read(64)
        sk, pk = GenerateKeyPairDerand(seed)
        ss, ct = EncapsulateDerand(pk, eseed)
        ss2 = Decapsulate(ct, sk)
        assert ss == ss2

        ret.append({
            "seed":  hex(seed),
            "eseed": hex(eseed),
            "ss":    hex(ss),
            "sk":    hex(sk),
            "pk":    hex(pk),
            "ct":    hex(ct),
        })


    want = json.dumps(ret)
    if setVectors:
        with open('test-vectors.json', 'w') as f:
            f.write(want)
        with open('test-vectors.txt', 'w') as f:
            f.write(dump_vectors(ret))
    else:
        with open('test-vectors.json', 'r') as f:
            assert f.read() == want
        with open('test-vectors.txt', 'r') as f:
            assert f.read() == dump_vectors(ret)

def dump_val(f, name, val):
    f.write(name)
    width = 74
    if len(name) + 5 + len(val) < width:
        f.write('     ')
        f.write(val)
        f.write('\n')
        return
    f.write('\n')
    while val:
        f.write('  ')
        f.write(val[:width-2])
        val = val[width-2:]
        f.write('\n')

def dump_vectors(vecs):
    f = io.StringIO()
    for vec in vecs:
        for k in ['seed', 'sk', 'pk', 'eseed', 'ct', 'ss']:
            dump_val(f, k, vec[k])
        f.write('\n')
    return f.getvalue()

# Encodings of u-coordinates of small-order points on Curve25519 and its
# twist: 0, 1, the two points of order 8, p-1, p, and p+1.  X25519 ignores
# bit 255, so each also appears with that bit set.
LOW_ORDER = [binascii.unhexlify(u) for u in [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
]]
LOW_ORDER += [u[:31] + bytes([u[31] | 0x80]) for u in LOW_ORDER]

def test_reject_low_order(setVectors):
    vecs = json.load(open('test-vectors.json'))
    for vec in vecs:
        sk = binascii.unhexlify(vec['sk'])
        pk = binascii.unhexlify(vec['pk'])
        ct = binascii.unhexlify(vec['ct'])
        eseed = binascii.unhexlify(vec['eseed'])
        for u in LOW_ORDER:
            assert x25519.X(sk, u) == bytes(32)
            with pytest.raises(ValueError):
                Decapsulate(ct[:1088] + u, sk)
            with pytest.raises(ValueError):
                EncapsulateDerand(pk[:1184] + u, eseed)

    want = ''.join(binascii.hexlify(u).decode() + '\n' for u in LOW_ORDER)
    if setVectors:
        with open('low-order-points.txt', 'w') as f:
            f.write(want)
    else:
        with open('low-order-points.txt', 'r') as f:
            assert f.read() == want

if __name__ == '__main__':
    pytest.main(['xwing_test.py'])
