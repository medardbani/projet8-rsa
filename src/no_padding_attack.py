# src/no_padding_attack.py
from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from utils import iroot

def generate_rsa_keys(bits=1024):
    print("[*] Génération des clés RSA sans padding...")
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    n = p * q
    e = 3  # Petit exposant = vulnérable
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    print(f"[+] Clé RSA {bits} bits générée avec e={e}")
    return n, e, d

def chiffrer_sans_padding(message: bytes, e, n):
    m = bytes_to_long(message)
    assert m < n
    return pow(m, e, n)

def attaque_racine_cubique(c, e):
    """
    Si m^e < n (message court, petit e),
    alors c = m^e exactement → m = c^(1/e)
    """
    print("\n[*] Lancement de l'attaque par racine e-ième...")
    m = iroot(c, e)
    return long_to_bytes(m)

if __name__ == "__main__":
    # Message très court pour que m^3 < n
    message = b"Bonjour"
    print("=" * 50)
    print("ATTAQUE RSA SANS PADDING (RACINE E-IÈME)")
    print("=" * 50)

    n, e, d = generate_rsa_keys()

    c = chiffrer_sans_padding(message, e, n)
    print(f"[+] Message chiffré : {c}")

    m_retrouve = attaque_racine_cubique(c, e)

    print(f"\n[+] Message original : {message}")
    print(f"[+] Message retrouvé : {m_retrouve}")
    print(f"[+] Attaque réussie  : {message == m_retrouve}")