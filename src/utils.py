# src/utils.py
from math import gcd, isqrt

def extended_gcd(a, b):
    """Algorithme d'Euclide étendu"""
    if b == 0:
        return a, 1, 0
    g, x, y = extended_gcd(b, a % b)
    return g, y, x - (a // b) * y

def int_to_bytes(n):
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

def bytes_to_int(b):
    return int.from_bytes(b, 'big')

def iroot(n, k):
    """Racine k-ième entière de n"""
    if n < 0:
        raise ValueError("n doit être positif")
    if k == 1:
        return n
    u = n
    s = n + 1
    while u < s:
        s = u
        t = (k - 1) * s + n // pow(s, k - 1)
        u = t // k
    return s