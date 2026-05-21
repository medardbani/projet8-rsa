# src/common_modulus_attack.py
from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from utils import extended_gcd

def generate_common_modulus_keys():
    """
    Génère un module n commun avec
    deux exposants différents e1 et e2
    """
    print("[*] Génération du module commun n...")
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    phi = (p - 1) * (q - 1)

    e1 = 3
    e2 = 65537

    d1 = pow(e1, -1, phi)
    d2 = pow(e2, -1, phi)

    print(f"[+] n généré ({n.bit_length()} bits)")
    print(f"[+] e1 = {e1}, e2 = {e2}")
    return n, e1, e2, d1, d2

def chiffrer(message: bytes, e, n):
    m = bytes_to_long(message)
    assert m < n, "Message trop long"
    c = pow(m, e, n)
    return c

def attaque_module_commun(n, e1, e2, c1, c2):
    """
    Si gcd(e1, e2) = 1, on peut retrouver m
    sans connaître d1 ni d2
    """
    print("\n[*] Lancement de l'attaque par module commun...")
    g, s, t = extended_gcd(e1, e2)

    print(f"[*] gcd(e1, e2) = {g}")
    if g != 1:
        print("[-] Attaque impossible : gcd != 1")
        return None

    if s < 0:
        s = -s
        c1 = pow(c1, -1, n)
    if t < 0:
        t = -t
        c2 = pow(c2, -1, n)

    m = (pow(c1, s, n) * pow(c2, t, n)) % n
    return long_to_bytes(m)

if __name__ == "__main__":
    message = b"Message secret M1"
    print("=" * 50)
    print("ATTAQUE PAR MODULE COMMUN RSA")
    print("=" * 50)

    n, e1, e2, d1, d2 = generate_common_modulus_keys()

    c1 = chiffrer(message, e1, n)
    c2 = chiffrer(message, e2, n)
    print(f"\n[+] Message chiffré avec e1 et e2")

    m_retrouve = attaque_module_commun(n, e1, e2, c1, c2)

    print(f"\n[+] Message original  : {message}")
    print(f"[+] Message retrouvé  : {m_retrouve}")
    print(f"[+] Attaque réussie   : {message == m_retrouve}")