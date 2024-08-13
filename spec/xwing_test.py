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

if __name__ == '__main__':
    pytest.main(['xwing_test.py'])
