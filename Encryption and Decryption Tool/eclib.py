import collections
import random


def egcd(a, b):
    """extended GCD
    returns: (s, t, gcd) as a*s + b*t == gcd
    >>> s, t, gcd = egcd(240, 46)
    >>> assert 240 % gcd == 0 and 46 % gcd == 0
    >>> assert 240 * s + 46 * t == gcd
    """
    s0, s1, t0, t1 = 1, 0, 0, 1
    while b > 0:
        q, r = divmod(a, b)
        a, b = b, r
        s0, s1, t0, t1 = s1, s0 - q * s1, t1, t0 - q * t1
    return s0, t0, a


def inv(n, q):
    """div on PN modulo a/b mod q as a * inv(b, q) mod q
    >>> inv(3, 7)
    5
    >>> 3 * inv(3, 7) % 7 == 1
    True
    """
    s, _, gcd = egcd(n, q)
    if gcd != 1:
        raise ValueError(f'{n} has no inverse modulo {q}')
    return s % q


def sqrt(n, q):
    """sqrtmod for bigint
    - Algorithm 3.34 of http://www.cacr.math.uwaterloo.ca/hac/about/chap3.pdf
    """
    # b: some non-quadratic-residue
    b = 0
    while b == 0 or jacobi(b, q) != -1:
        b = random.randint(1, q - 1)

    # q = t * 2^s + 1, t is odd
    t, s = q - 1, 0
    while t & 1 == 0:
        t, s = t >> 1, s + 1

    assert q == t * pow(2, s) + 1 and t % 2 == 1
    ni = inv(n, q)
    c = pow(b, t, q)
    r = pow(n, (t + 1) // 2, q)
    for i in range(1, s):
        d = pow(pow(r, 2, q) * ni % q, pow(2, s - i - 1, q), q)
        if d == q - 1:
            r = r * c % q
        c = pow(c, 2, q)

    return (r, q - r)


def jacobi(a, q):
    """jacobi symbol: judge existing sqrtmod (1: exist, -1: not exist)"""
    if q <= 0 or q % 2 == 0:
        raise ValueError("q must be a positive odd integer")
    a %= q
    if a == 0:
        return 0
    if a == 1:
        return 1
    if a % 2 == 0:
        return jacobi(a // 2, q) * (1 if q % 8 in (1, 7) else -1)
    return jacobi(q, a) * (1 if a % 4 == 1 or q % 4 == 1 else -1)


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
        >>> assert ec.is_valid(a) and ec.is_valid(ma)
        """
        assert x < self.q
        ysq = (x ** 3 + self.a * x + self.b) % self.q
        y, my = sqrt(ysq, self.q)
        return Coord(x, y), Coord(x, my)

    def neg(self, p):
        """negate p
        >>> ec = EC(2, 3, 97)
        >>> p, _ = ec.at(3)
        >>> np = ec.neg(p)
        >>> assert ec.is_valid(np)
        """
        return Coord(p.x, -p.y % self.q)

    def add(self, p1, p2):
        """<add> of sharred key algo in ecc_elliptic curve: negate of 3rd cross point of (p1,p2) line
        >>> ec = EC(2, 3, 97)
        >>> p1, _ = ec.at(3)
        >>> p2, _ = ec.at(10)
        >>> p3 = ec.add(p1, p2)
        >>> assert ec.is_valid(p3)
        """
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
        >>> assert ec.is_valid(m)
        >>> assert ec.mul(p, 0) == ec.zero
        """
        r = self.zero
        m2 = p
        while 0 < n:
            if n & 1 == 1:
                r = self.add(r, m2)
            n, m2 = n >> 1, self.add(m2, m2)
        return r

    def order(self, g):
        """order of point g
        >>> ec = EC(2, 3, 97)
        >>> g, _ = ec.at(3)
        >>> o = ec.order(g)
        >>> assert ec.mul(g, o) == ec.zero
        """
        assert self.is_valid(g) and g != self.zero
        for i in range(1, self.q + 2):
            if self.mul(g, i) == self.zero:
                return i
        raise Exception("Invalid order")


class DiffieHellman(object):
    """Elliptic Curve Diffie Hellman (Key Agreement)"""

    def __init__(self, ec, g):
        self.ec = ec
        self.g = g
        self.n = ec.order(g)

    def gen(self, priv):
        """generate pub key"""
        assert 0 < priv and priv < self.n
        return self.ec.mul(self.g, priv)

    def secret(self, priv, pub):
        """calc shared secret key for the pair"""
        assert self.ec.is_valid(pub)
        assert self.ec.mul(pub, self.n) == self.ec.zero
        return self.ec.mul(pub, priv)