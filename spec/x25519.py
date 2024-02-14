# WARNING This is a specification of X25519; not a production-ready
# implementation. It is slow and does not run in constant time.

p = 2**255 - 19
a24 = 121665

BASE = b'\x09' + b'\x00'*31

def decode(bs):
    return sum(bs[i] << 8*i for i in range(32)) % p

def decodeScalar(k):
    bs = list(k)
    bs[0] &= 248
    bs[31] &= 127
    bs[31] |= 64
    return decode(bs)

# See rfc7748 §5.
def X(k, u):
    assert len(k) == 32
    assert len(u) == 32

    k = decodeScalar(k)
    u = decode(u)
    x1, x2, x3, z2, z3, swap = u, 1, u, 0, 1, 0

    for t in range(255, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap == 1:
            x3, x2 = x2, x3
            z3, z2 = z2, z3
        swap = kt

        A = x2 + z2
        AA = (A*A) % p
        B = x2 - z2
        BB = (B*B) % p
        E = AA - BB
        C = x3 + z3
        D = x3 - z3
        DA = (D*A) % p
        CB = (C*B) % p
        x3 = DA + CB
        x3 = (x3 * x3) % p
        z3 = DA - CB
        z3 = (x1 * z3 * z3) % p
        x2 = (AA * BB) % p
        z2 = (E * (AA + (a24 * E) % p)) % p

    if swap == 1:
        x3, x2 = x2, x3
        z2, z3 = z3, z2

    ret = (x2 * pow(z2, p-2, p)) % p
    return bytes((ret >> 8*i) & 255 for i in range(32))
