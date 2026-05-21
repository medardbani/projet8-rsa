"""
Projet 8 – Attaque par mauvais usage de clés (key reuse) sur RSA non sécurisé
=============================================================================
Objectif : Démontrer deux vulnérabilités classiques RSA :
  1. Attaque par module commun (Common Modulus Attack)
  2. Chiffrement déterministe sans padding (racine e-ième)

Couche : Données
"""

import math
import random
from typing import Tuple

# ─────────────────────────────────────────────
# UTILITAIRES MATHÉMATIQUES
# ─────────────────────────────────────────────

def pgcd(a: int, b: int) -> int:
    """Algorithme d'Euclide."""
    while b:
        a, b = b, a % b
    return a

def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """Algorithme d'Euclide étendu : retourne (gcd, x, y) tels que a*x + b*y = gcd."""
    if a == 0:
        return b, 0, 1
    g, x, y = egcd(b % a, a)
    return g, y - (b // a) * x, x

def mod_inverse(a: int, m: int) -> int:
    """Inverse modulaire de a mod m (via Euclide étendu)."""
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"Pas d'inverse : gcd({a}, {m}) = {g}")
    return x % m

def power_mod(base: int, exp: int, mod: int) -> int:
    """Exponentiation modulaire rapide."""
    return pow(base, exp, mod)

def is_prime(n: int, k: int = 20) -> bool:
    """Test de primalité de Miller-Rabin."""
    if n < 2: return False
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def gen_prime(bits: int) -> int:
    """Génère un nombre premier de `bits` bits."""
    while True:
        p = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(p):
            return p

def iroot(n: int, e: int) -> Tuple[int, bool]:
    """
    Racine e-ième entière de n.
    Retourne (r, exact) où r = floor(n^(1/e)) et exact = (r^e == n).
    """
    if n == 0:
        return 0, True
    # Estimation initiale
    x = int(round(n ** (1 / e)))
    # Affiner par la méthode de Newton
    for _ in range(100):
        x1 = ((e - 1) * x + n // pow(x, e - 1)) // e
        if x1 >= x:
            break
        x = x1
    # Vérifier x et ses voisins
    for candidate in [x - 1, x, x + 1]:
        if candidate > 0 and pow(candidate, e) == n:
            return candidate, True
    return x, False


# ─────────────────────────────────────────────
# GÉNÉRATION DES CLÉS RSA
# ─────────────────────────────────────────────

def gen_rsa_keypair(p: int, q: int, e: int) -> Tuple[Tuple[int,int], Tuple[int,int]]:
    """
    Génère une paire de clés RSA à partir de p, q, e.
    Retourne (public_key=(e,n), private_key=(d,n)).
    """
    n = p * q
    phi = (p - 1) * (q - 1)
    assert math.gcd(e, phi) == 1, f"e={e} n'est pas copremier avec phi(n)"
    d = mod_inverse(e, phi)
    return (e, n), (d, n)

def rsa_encrypt(m: int, pub: Tuple[int,int]) -> int:
    e, n = pub
    assert 0 < m < n, "Message hors plage [1, n-1]"
    return power_mod(m, e, n)

def rsa_decrypt(c: int, priv: Tuple[int,int]) -> int:
    d, n = priv
    return power_mod(c, d, n)


# ─────────────────────────────────────────────
# TÂCHE 1 : GÉNÉRATION D'UN MODULE COMMUN n
# ─────────────────────────────────────────────

def section1_common_modulus_setup(bits: int = 512):
    """
    Génère un module n partagé entre deux paires RSA :
      - Paire 1 : e1 = 3,     d1 calculé
      - Paire 2 : e2 = 65537, d2 calculé
    """
    print("=" * 65)
    print("TÂCHE 1 – Génération d'un module n commun (e1=3, e2=65537)")
    print("=" * 65)

    e1, e2 = 3, 65537

    # Générer p et q tels que gcd(e1, phi) = gcd(e2, phi) = 1
    print(f"[*] Génération de nombres premiers ({bits} bits)...")
    while True:
        p = gen_prime(bits // 2)
        q = gen_prime(bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(e1, phi) == 1 and math.gcd(e2, phi) == 1:
            break

    n = p * q
    pub1, priv1 = gen_rsa_keypair(p, q, e1)
    pub2, priv2 = gen_rsa_keypair(p, q, e2)

    print(f"\n  p  = {p}")
    print(f"  q  = {q}")
    print(f"  n  = {n}")
    print(f"\n  Clé publique 1  : (e1={e1},  n)")
    print(f"  Clé privée  1  : (d1={priv1[0]}, n)")
    print(f"\n  Clé publique 2  : (e2={e2}, n)")
    print(f"  Clé privée  2  : (d2={priv2[0]}, n)")
    print(f"\n  ✔  Module partagé confirmé : pub1[1] == pub2[1] == {n == pub1[1] == pub2[1]}")

    return n, pub1, priv1, pub2, priv2


# ─────────────────────────────────────────────
# TÂCHE 2 : ATTAQUE PAR MODULE COMMUN (CMA)
# Common Modulus Attack via Bézout + CRT
# ─────────────────────────────────────────────

def common_modulus_attack(c1: int, c2: int, e1: int, e2: int, n: int) -> int:
    """
    Attaque par module commun.
    Si m est chiffré avec deux exposants (e1, n) et (e2, n), on peut récupérer m
    SANS la clé privée, car gcd(e1, e2) = 1 et via Bézout :
        a*e1 + b*e2 = 1  =>  m = c1^a * c2^b  (mod n)
    """
    assert math.gcd(e1, e2) == 1, "L'attaque requiert gcd(e1, e2) = 1"

    g, a, b = egcd(e1, e2)
    # Gérer les exposants négatifs : c^(-k) = modular_inverse(c)^k
    if a < 0:
        c1_inv = mod_inverse(c1, n)
        m = (power_mod(c1_inv, -a, n) * power_mod(c2, b, n)) % n
    elif b < 0:
        c2_inv = mod_inverse(c2, n)
        m = (power_mod(c1, a, n) * power_mod(c2_inv, -b, n)) % n
    else:
        m = (power_mod(c1, a, n) * power_mod(c2, b, n)) % n

    return m

def section2_common_modulus_attack(n, pub1, priv1, pub2, priv2):
    """Démonstration complète de l'attaque par module commun."""
    print("\n" + "=" * 65)
    print("TÂCHE 2 – Attaque par module commun (Common Modulus Attack)")
    print("=" * 65)

    e1, _ = pub1
    e2, _ = pub2

    # Message à chiffrer (entier représentant "HELLO")
    m_original = int.from_bytes(b"HELLO RSA", "big")
    print(f"\n  Message original m = {m_original}")
    print(f"  (bytes : {m_original.to_bytes((m_original.bit_length()+7)//8, 'big')})")

    # Chiffrement avec les deux clés publiques
    c1 = rsa_encrypt(m_original, pub1)
    c2 = rsa_encrypt(m_original, pub2)
    print(f"\n  c1 = Enc(m, e1={e1})  = {c1}")
    print(f"  c2 = Enc(m, e2={e2}) = {c2}")

    # ─── ATTAQUE ───
    print("\n  [ATTAQUE] Bézout sur e1 et e2...")
    g, a, b = egcd(e1, e2)
    print(f"  gcd({e1}, {e2}) = {g}  →  {e1}×({a}) + {e2}×({b}) = {g}")
    print(f"  Formule : m = c1^a × c2^b  (mod n)")

    m_recovered = common_modulus_attack(c1, c2, e1, e2, n)
    print(f"\n  m récupéré = {m_recovered}")

    success = (m_recovered == m_original)
    print(f"\n  ✔  Attaque réussie : {success}")
    if success:
        recovered_bytes = m_recovered.to_bytes((m_recovered.bit_length()+7)//8, "big")
        print(f"  Message déchiffré : {recovered_bytes}")

    # Vérification via déchiffrement légitime
    m_legit = rsa_decrypt(c1, priv1)
    print(f"\n  [Contrôle] Déchiffrement légitime (d1) = {m_legit}")
    print(f"  Identiques : {m_legit == m_recovered}")

    return m_original, c1, c2


# ─────────────────────────────────────────────
# TÂCHE 3 : SANS PADDING – RACINE e-IÈME
# Small exponent attack (Håstad's Broadcast Attack, cas simple)
# ─────────────────────────────────────────────

def section3_no_padding_attack(n, pub1):
    """
    Sans padding et avec e petit (e=3), si m^e < n alors m^e n'est pas réduit
    modulo n : le chiffré c = m^e (sur les entiers), et on récupère m = c^(1/e).

    Plus généralement : si padding absent et m "petit", la racine e-ième entière
    de c suffit à retrouver m.
    """
    print("\n" + "=" * 65)
    print("TÂCHE 3 – Sans padding : déchiffrement par racine e-ième")
    print("=" * 65)

    e1, n1 = pub1

    # ── Cas 1 : message très court, m^e < n (racine exacte sur ℤ)
    m_short = int.from_bytes(b"Hi", "big")
    print(f"\n  [Cas 1] Message court : m = {m_short}  ({b'Hi'})")
    print(f"  e = {e1}")

    c = rsa_encrypt(m_short, pub1)
    print(f"  c = m^e mod n = {c}")

    # Vérifier si l'attaque directe est possible : m^e vs n
    m_e_exact = pow(m_short, e1)  # valeur exacte sans réduction
    print(f"\n  m^e (exact, sur ℤ)   = {m_e_exact}")
    print(f"  n                    = {n1}")
    print(f"  m^e < n ?            {m_e_exact < n1}")

    if m_e_exact < n1:
        # c == m^e exactement (pas de réduction mod n)
        m_recovered, exact = iroot(c, e1)
        print(f"\n  → Racine {e1}-ième de c : {m_recovered}")
        print(f"  → Racine exacte : {exact}")
    else:
        # Réduction mod n a eu lieu → utiliser Håstad multi-destinataires
        print(f"\n  m^e >= n, réduction mod n a eu lieu.")
        print(f"  → Dans ce cas, l'attaque Håstad nécessite {e1} chiffrés")
        print(f"    (un par destinataire, même n_i différents) via le CRT.")
        m_recovered, exact = None, False

    if exact and m_recovered == m_short:
        recovered_bytes = m_recovered.to_bytes((m_recovered.bit_length()+7)//8, "big")
        print(f"\n  ✔  Message retrouvé : {recovered_bytes}")
    elif m_e_exact < n1:
        print(f"\n  ✘  Échec de la racine exacte (inattendu).")

    # ── Cas 2 : message plus long, illustrer le déterminisme
    print("\n  " + "-" * 55)
    print("  [Cas 2] Chiffrement déterministe (absence de padding)")
    m_a = int.from_bytes(b"SECRET", "big")
    m_b = int.from_bytes(b"SECRET", "big")  # même message
    c_a = rsa_encrypt(m_a, pub1)
    c_b = rsa_encrypt(m_b, pub1)
    print(f"  Enc('SECRET', pub)  1ère fois : {c_a}")
    print(f"  Enc('SECRET', pub)  2ème fois : {c_b}")
    print(f"  Chiffrés identiques : {c_a == c_b}")
    print("  ⚠  Un attaquant peut donc détecter deux envois du même message !")
    print("     → Résolu par OAEP (randomized padding).")


# ─────────────────────────────────────────────
# PERSPECTIVE M2 – JWT / RSA sans padding
# ─────────────────────────────────────────────

def section4_jwt_perspective():
    print("\n" + "=" * 65)
    print("PERSPECTIVE M2 – JWT avec RSA sans padding (RS256 vulnérable)")
    print("=" * 65)
    print("""
  Un JWT signé en RS256 ressemble à :
    header.payload.signature

  Avec RSA textbook (sans padding PKCS#1 v1.5 ni PSS) :
    signature = m^d  mod n   (m = hash du header.payload)

  Vulnérabilités exploitables :
  ┌────────────────────────────────────────────────────────┐
  │ 1. Forge de signature si la clé privée fuite           │
  │    → Trivial, aucune protection par padding            │
  │                                                        │
  │ 2. Attaque "alg:none" (CVE standard OWASP)             │
  │    → Changer l'en-tête "alg" en "none", supprimer sig  │
  │    → Bibliothèques vulnérables acceptent le token       │
  │                                                        │
  │ 3. Confusion RS256 → HS256                             │
  │    → Signer avec la clé PUBLIQUE RSA comme secret HMAC  │
  │    → Serveur vérifie HMAC(clé_publique) au lieu de RSA │
  │                                                        │
  │ 4. Module commun partagé entre microservices           │
  │    → Si deux services partagent n, attaque CMA         │
  └────────────────────────────────────────────────────────┘

  Contre-mesures :
    • Toujours utiliser RSASSA-PKCS1-v1_5 ou PSS
    • Vérifier explicitement l'algorithme côté serveur
    • Ne jamais partager un module n entre deux usages
    • Utiliser des clés dédiées par service
""")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    print("\n" + "█" * 65)
    print("  PROJET 8 – Attaque par mauvais usage de clés RSA (key reuse)")
    print("█" * 65 + "\n")

    # Taille des clés réduite pour la démonstration (512 bits)
    BITS = 512

    # Tâche 1 : Génération du module commun
    n, pub1, priv1, pub2, priv2 = section1_common_modulus_setup(bits=BITS)

    # Tâche 2 : Attaque par module commun
    m_orig, c1, c2 = section2_common_modulus_attack(n, pub1, priv1, pub2, priv2)

    # Tâche 3 : Racine e-ième (sans padding)
    section3_no_padding_attack(n, pub1)

    # Perspective M2 : JWT
    section4_jwt_perspective()

    print("\n" + "█" * 65)
    print("  FIN DU PROJET 8")
    print("█" * 65 + "\n")


if __name__ == "__main__":
    main()
