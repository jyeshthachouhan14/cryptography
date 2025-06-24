# Basics of Elliptic Curve Cryptography implementation on Python
import collections
import hashlib
from hashlib import md5


def inv(n, q):
    """div on PN modulo a/b mod q as a * inv(b, q) mod q
    >>> inv(3, 7)
    5
    >>> 3 * inv(3, 7) % 7 == 1
    True
    """
    for i in range(q):
        if (n * i) % q == 1:
            return i
    assert False, "unreached"


def sqrt(n, q):
    """sqrt on PN modulo: returns two numbers or exception if not exist
    >>> sqrt(36, 97)
    (6, 91)
    >>> (sqrt(36, 97)[0] ** 2) % 97 == 36
    True
    """
    assert n < q
    for i in range(1, q):
        if i * i % q == n:
            return (i, q - i)
    raise Exception("not found")


Coord = collections.namedtuple("Coord", ["x", "y"])


class EC(object):
    """System of Elliptic Curve"""

    def __init__(self, a, b, q):
        """sharred key algo in ecc_elliptic curve as: (y**2 = x**3 + a * x + b) mod q
        - a, b: params of curve formula
        - q: prime number
        """
        assert 0 < a and a < q and 0 < b and b < q and q > 2
        assert (4 * (a ** 3) + 27 * (b ** 2)) % q != 0
        self.a = a
        self.b = b
        self.q = q
        # just as unique ZERO value representation for "add": (not on curve)
        self.zero = Coord(0, 0)

    def is_valid(self, p):
        if p == self.zero:
            return True
        l = (p.y ** 2) % self.q
        r = ((p.x ** 3) + self.a * p.x + self.b) % self.q
        return l == r

    def at(self, x):
        """find points on curve at x
        >>> ec = EC(2, 3, 97)
        >>> a, ma = ec.at(3)
        >>> a
        Coord(x=3, y=6)
        >>> ma
        Coord(x=3, y=91)
        """
        assert x < self.q
        ysq = (x ** 3 + self.a * x + self.b) % self.q
        y, my = sqrt(ysq, self.q)
        return Coord(x, y), Coord(x, my)

    def neg(self, p):
        """negate p"""
        return Coord(p.x, -p.y % self.q)

    def add(self, p1, p2):
        """<add> of sharred key algo in ecc_elliptic curve: negate of 3rd cross point of (p1,p2) line"""
        if p1 == self.zero:
            return p2
        if p2 == self.zero:
            return p1
        if p1.x == p2.x and (p1.y != p2.y or p1.y == 0):
            return self.zero
        if p1.x == p2.x:
            l = (3 * p1.x * p1.x + self.a) * inv(2 * p1.y, self.q) % self.q
        else:
            l = (p2.y - p1.y) * inv(p2.x - p1.x, self.q) % self.q
        x = (l * l - p1.x - p2.x) % self.q
        y = (l * (p1.x - x) - p1.y) % self.q
        return Coord(x, y)

    def mul(self, p, n):
        """n times <mul> of sharred key algo in ecc_elliptic curve
        >>> ec = EC(2, 3, 97)
        >>> p, _ = ec.at(3)
        >>> m = ec.mul(p, 2)
        >>> ec.is_valid(m)
        True
        """
        r = self.zero
        m2 = p
        while 0 < n:
            if n & 1 == 1:
                r = self.add(r, m2)
            n, m2 = n >> 1, self.add(m2, m2)
        return r

    def order(self, g):
        """order of point g"""
        assert self.is_valid(g) and g != self.zero
        for i in range(1, self.q + 2):
            if self.mul(g, i) == self.zero:
                return i
        raise Exception("Invalid order")


class DSA(object):
    """ECDSA"""

    def __init__(self, ec, g):
        self.ec = ec
        self.g = g
        self.n = ec.order(g)

    def gen(self, priv):
        """generate pub key"""
        assert 0 < priv and priv < self.n
        return self.ec.mul(self.g, priv)

    def sign(self, hashval, priv, r):
        """generate signature"""
        assert 0 < r and r < self.n
        m = self.ec.mul(self.g, r)
        return (m.x, inv(r, self.n) * (hashval + m.x * priv) % self.n)

    def validate(self, hashval, sig, pub):
        """validate signature"""
        assert self.ec.is_valid(pub)
        assert self.ec.mul(pub, self.n) == self.ec.zero
        w = inv(sig[1], self.n)
        u1, u2 = hashval * w % self.n, sig[0] * w % self.n
        p = self.ec.add(self.ec.mul(self.g, u1), self.ec.mul(pub, u2))
        return p.x % self.n == sig[0]


if __name__ == "__main__":
    # Use input() for Python 3
    a = int(input("enter curve parameter 'a': "))
    b = int(input("enter curve parameter 'b': "))
    q = int(input("enter prime number 'q' (prime number): "))
    ec = EC(a, b, q)

    # A generator point can be found by testing points on the curve
    # We'll try to find one automatically
    try:
        g, _ = ec.at(0)  # starting at x=0
        i = 1
        while ec.order(g) is None:  # Find a point with a valid order
            g, _ = ec.at(i)
            i += 1
    except Exception:
        # Fallback if no simple generator is found
        print("Could not find a generator point automatically for this curve.")
        g, _ = ec.at(7)

    assert ec.order(g) <= ec.q

    dsa = DSA(ec, g)

    priv = int(input("enter private key: "))
    pub = dsa.gen(priv)
    msg = str(input("enter message: "))
    hashval = int("0x" + hashlib.md5(msg.encode()).hexdigest(), 16)

    # In a real scenario, r should be a new random number for each signature
    r = 11

    sig = dsa.sign(hashval, priv, r)
    print("signature generated: ")
    print(sig)

    msg_rec = str(input("enter the message received: "))
    hashval_rec = int("0x" + hashlib.md5(msg_rec.encode()).hexdigest(), 16)

    if dsa.validate(hashval_rec, sig, pub) == True:
        print("Message verified to be authentic.")
    else:
        print("Message not authentic!")