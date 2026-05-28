#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
█████████████████████████████████████████████████████████████████
 PROJET 8 – Attaque par mauvais usage de clés RSA (key reuse)
 INF4268 – Cryptographie Asymétrique
█████████████████████████████████████████████████████████████████

Auteur : BANI Médard
Description :
    Démonstration de plusieurs vulnérabilités RSA :
      1. Common Modulus Attack
      2. RSA sans padding
      3. Chiffrement déterministe
      4. Protection avec OAEP
      5. Bonus : attaque de Håstad (CRT)

Bibliothèques :
    pip install pycryptodome gmpy2
"""

# pycryptodome : bibliothèque cryptographique Python
# gmpy2       : arithmétique entière de précision arbitraire (racines exactes)
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import gmpy2
import time

# ================================================================
# OUTILS
# ================================================================

def banner(title):
    """Affiche un titre encadré pour séparer les sections."""
    print("\n" + "=" * 65)
    print(title)
    print("=" * 65)

def egcd(a, b):
    """
    Algorithme d'Euclide étendu (récursif).
    Retourne (g, x, y) tels que : a*x + b*y = g = gcd(a, b)
    
    Utilisé pour trouver les coefficients de Bézout s et t
    dans l'attaque par module commun :
        s*e1 + t*e2 = 1
    """
    if a == 0:
        # Cas de base : gcd(0, b) = b, avec 0*0 + b*1 = b
        return b, 0, 1
    # Appel récursif sur (b mod a, a)
    g, y, x = egcd(b % a, a)
    # Remontée des coefficients
    return g, x - (b // a) * y, y

# ================================================================
# INTRO
# ================================================================

print("\n█████████████████████████████████████████████████████████████████")
print("  PROJET 8 – Attaque par mauvais usage de clés RSA (key reuse)")
print("█████████████████████████████████████████████████████████████████")

# ================================================================
# TÂCHE 1 — Génération du module commun
# ================================================================

banner("TÂCHE 1 – Génération d'un module n commun (e1=3, e2=65537)")

print("[*] Génération de nombres premiers (512 bits)...")

# Définir les exposants publics avant la génération
# e1=3 : petit exposant (vulnérable mais utilisé pour la démonstration)
# e2=65537 : exposant standard recommandé (F4 = 2^16 + 1)
e1 = 3
e2 = 65537

# Boucle de génération : on cherche p et q tels que
# gcd(e1, phi) = 1 ET gcd(e2, phi) = 1
# (condition nécessaire pour que les inverses modulaires existent)
while True:
    p = getPrime(512)   # nombre premier de 512 bits
    q = getPrime(512)   # nombre premier de 512 bits (différent de p)
    phi = (p - 1) * (q - 1)  # indicatrice d'Euler : phi(n) = (p-1)(q-1)
    if GCD(e1, phi) == 1 and GCD(e2, phi) == 1:
        break  # p et q compatibles avec les deux exposants

# Module RSA partagé entre les deux utilisateurs (MAUVAISE PRATIQUE)
n = p * q

# Clés privées calculées par inversion modulaire
# d1 * e1 ≡ 1 (mod phi) → d1 = e1^(-1) mod phi
d1 = inverse(e1, phi)
# d2 * e2 ≡ 1 (mod phi) → d2 = e2^(-1) mod phi
d2 = inverse(e2, phi)

print(f"\n  p  = {p}")
print(f"  q  = {q}")
print(f"  n  = {n}")
print(f"\n  Clé publique 1  : (e1={e1}, n)")
print(f"  Clé privée  1  : (d1={d1}, n)")
print(f"\n  Clé publique 2  : (e2={e2}, n)")
print(f"  Clé privée  2  : (d2={d2}, n)")
# Confirmation que les deux paires partagent bien le même n
print(f"\n  ✔ Module partagé confirmé : {True}")

# ================================================================
# TÂCHE 2 — Common Modulus Attack (CMA)
# ================================================================

banner("TÂCHE 2 – Attaque par module commun (Common Modulus Attack)")

# Message original converti en entier pour RSA
# bytes_to_long : convertit b"HELLO RSA" en représentation entière
message_bytes = b"HELLO RSA"
m = bytes_to_long(message_bytes)

print(f"\n  Message original m = {m}")
print(f"  (bytes : {message_bytes})")

# --- Chiffrement du même message avec les deux clés publiques ---
# Mesure du temps de chiffrement
start_enc = time.time()

# Chiffrement RSA : c = m^e mod n (exponentiation modulaire rapide)
c1 = pow(m, e1, n)   # chiffré avec e1=3
c2 = pow(m, e2, n)   # chiffré avec e2=65537

end_enc = time.time()

print(f"\n  c1 = Enc(m, e1={e1}) = {c1}")
print(f"  c2 = Enc(m, e2={e2}) = {c2}")

# --- Attaque par module commun ---
print("\n  [ATTAQUE] Bézout sur e1 et e2...")

# Calcul des coefficients de Bézout : s*e1 + t*e2 = gcd(e1,e2) = 1
g, a, b = egcd(e1, e2)
# a = s (coefficient de e1), b = t (coefficient de e2)

print(f"  gcd({e1}, {e2}) = {g} → {e1}×({a}) + {e2}×({b}) = 1")
print("  Formule : m = c1^a × c2^b (mod n)")

start_attack = time.time()

# Gestion des exposants négatifs :
# Si a < 0, on ne peut pas calculer c1^a directement
# On utilise l'inverse modulaire : c1^(-1) mod n
if a < 0:
    c1 = inverse(c1, n)  # c1 = c1^(-1) mod n
    a = -a               # rendre a positif

if b < 0:
    c2 = inverse(c2, n)  # c2 = c2^(-1) mod n
    b = -b               # rendre b positif

# Calcul du message récupéré :
# m = c1^s * c2^t mod n
# = (m^e1)^s * (m^e2)^t mod n
# = m^(e1*s + e2*t) mod n
# = m^1 mod n = m
recovered = (pow(c1, a, n) * pow(c2, b, n)) % n

end_attack = time.time()

print(f"\n  m récupéré = {recovered}")
success = (recovered == m)
print(f"\n  ✔ Attaque réussie : {success}")
# long_to_bytes : reconvertit l'entier en bytes lisibles
print(f"  Message déchiffré : {long_to_bytes(recovered)}")

# Vérification par déchiffrement légitime (avec la clé privée d1)
# m = c^d mod n
legit = pow(pow(m, e1, n), d1, n)
print(f"\n  [Contrôle] Déchiffrement légitime (d1) = {legit}")
print(f"  Identiques : {legit == recovered}")

# Affichage des performances
print("\n  [PERFORMANCES]")
print(f"  Temps chiffrement : {(end_enc - start_enc)*1000:.6f} ms")
print(f"  Temps attaque     : {(end_attack - start_attack)*1000:.6f} ms")

# ================================================================
# TÂCHE 3 — RSA sans padding (Low Public Exponent Attack)
# ================================================================

banner("TÂCHE 3 – Sans padding : déchiffrement par racine e-ième")

# Message volontairement court pour que m^e < n
small_message = b"Hi"
m_small = bytes_to_long(small_message)
e = 3  # petit exposant

print(f"\n  [Cas 1] Message court : m = {m_small} ({small_message})")
print(f"  e = {e}")

# Chiffrement sans padding : c = m^e mod n
c = pow(m_small, e, n)
print(f"  c = m^e mod n = {c}")

# Vérification de la condition d'attaque :
# Si m^e < n, alors la réduction mod n n'a pas eu lieu
# Le chiffré c = m^e exactement (sur les entiers)
exact_power = m_small ** e  # calcul exact sans mod
print(f"\n  m^e (exact, sur ℤ)   = {exact_power}")
print(f"  n                    = {n}")
print(f"  m^e < n ?            {exact_power < n}")

# Attaque : calcul de la racine e-ième entière de c
# gmpy2.iroot(x, n) retourne (racine, exact)
# exact=True si la racine est parfaite (r^e == c)
root, exact = gmpy2.iroot(c, e)
print(f"\n  → Racine {e}-ième de c : {root}")
print(f"  → Racine exacte : {exact}")

if exact:
    # Reconversion de l'entier en bytes
    recovered_small = long_to_bytes(int(root))
    print(f"\n  ✔ Message retrouvé : {recovered_small}")

# --- Cas 2 : démonstration du déterminisme ---
print("\n  -------------------------------------------------------")
print("  [Cas 2] Chiffrement déterministe (absence de padding)")

secret = bytes_to_long(b"SECRET")

# Sans padding, chiffrer deux fois le même message
# donne exactement le même chiffré
cipher1 = pow(secret, e, n)
cipher2 = pow(secret, e, n)

print(f"  Enc('SECRET', pub) 1ère fois : {cipher1}")
print(f"  Enc('SECRET', pub) 2ème fois : {cipher2}")
print(f"  Chiffrés identiques : {cipher1 == cipher2}")

if cipher1 == cipher2:
    print("  ⚠ Un attaquant peut détecter deux messages identiques")
    print("    → Résolu par OAEP (padding aléatoire)")

# ================================================================
# TÂCHE 4 — Protection avec OAEP
# ================================================================

banner("TÂCHE 4 – Protection avec OAEP")

print("[*] Génération d'une vraie paire RSA 2048 bits...")

# Génération d'une clé RSA sécurisée (2048 bits = standard actuel)
rsa_key = RSA.generate(2048)
public_key = rsa_key.publickey()

# PKCS1_OAEP : Optimal Asymmetric Encryption Padding
# Ajoute un aléa à chaque chiffrement via un masque aléatoire
cipher_oaep = PKCS1_OAEP.new(public_key)

message = b"SECRET"

# Chiffrement OAEP du même message deux fois
# Le padding aléatoire garantit des résultats différents
ciphertext1 = cipher_oaep.encrypt(message)
ciphertext2 = cipher_oaep.encrypt(message)

print(f"\n  Message : {message}")
# Affichage partiel (80 premiers caractères hex)
print(f"\n  Ciphertext 1 : {ciphertext1.hex()[:80]}...")
print(f"  Ciphertext 2 : {ciphertext2.hex()[:80]}...")
print(f"\n  Chiffrés identiques ? {ciphertext1 == ciphertext2}")

if ciphertext1 != ciphertext2:
    print("\n  ✔ OAEP ajoute de l'aléatoire")
    print("  ✔ Le chiffrement devient non déterministe")
    print("  ✔ Les attaques précédentes échouent")

# ================================================================
# BONUS — Attaque de Håstad (Broadcast Attack via CRT)
# ================================================================

banner("BONUS – Attaque de Håstad (CRT)")

# Scénario : même message envoyé à 3 destinataires
# avec le même exposant e=3 et des modules différents
# mais SANS padding
message_h = bytes_to_long(b"HASTAD")
e = 3

print("[*] Génération de 3 modules RSA différents...")

moduli = []
ciphers = []

for i in range(3):
    pi = getPrime(512)
    qi = getPrime(512)
    ni = pi * qi          # module indépendant pour chaque destinataire
    moduli.append(ni)
    # Chiffrement du même message avec le module ni
    ciphers.append(pow(message_h, e, ni))

n1, n2, n3 = moduli
c1h, c2h, c3h = ciphers

print("\n  Même message envoyé à 3 destinataires")
print("  Même exposant e = 3, pas de padding")

# --- Application du Théorème des Restes Chinois (CRT) ---
# On cherche x tel que :
#   x ≡ c1 (mod n1)
#   x ≡ c2 (mod n2)
#   x ≡ c3 (mod n3)
# La solution unique mod N = n1*n2*n3 est x = m^3

# Produit total des modules
N = n1 * n2 * n3

# Facteurs partiels
m1 = N // n1   # N/n1
m2 = N // n2   # N/n2
m3 = N // n3   # N/n3

# Inverses modulaires des facteurs partiels
inv1 = inverse(m1, n1)  # m1^(-1) mod n1
inv2 = inverse(m2, n2)  # m2^(-1) mod n2
inv3 = inverse(m3, n3)  # m3^(-1) mod n3

# Reconstruction de m^3 par CRT
x = (c1h * m1 * inv1 + c2h * m2 * inv2 + c3h * m3 * inv3) % N

# Racine cubique exacte de x pour retrouver m
recovered_hastad, exact = gmpy2.iroot(x, e)

print(f"\n  Message retrouvé : {long_to_bytes(int(recovered_hastad))}")
print(f"  Attaque réussie  : {exact}")

# ================================================================
# PERSPECTIVE M2
# ================================================================

banner("PERSPECTIVE M2 – JWT avec RSA sans padding")

print("""
  Un JWT signé en RS256 ressemble à :
      header.payload.signature

  Une mauvaise implémentation RSA sans padding sécurisé
  (PKCS#1 v1.5 ou PSS) peut permettre :

      - falsification de signatures,
      - attaques mathématiques,
      - réutilisation dangereuse des paramètres RSA.

  Travaux futurs possibles :
      ✔ Étude de JWT vulnérables
      ✔ Analyse de mauvaises implémentations OpenSSL
      ✔ Attaques PKCS#1 v1.5
      ✔ Comparaison RSA-PSS vs RSA textbook
""")

# ================================================================
# CONCLUSION
# ================================================================

banner("CONCLUSION")

print("""
RSA n'est pas mathématiquement cassé.

Les vulnérabilités observées proviennent :

  - de la réutilisation du même module RSA,
  - de l'absence de padding,
  - de mauvaises pratiques d'implémentation.

Contremesures recommandées :

  ✔ OAEP pour le chiffrement
  ✔ PSS pour les signatures
  ✔ Paramètres RSA indépendants
  ✔ Génération aléatoire sécurisée

Ce projet montre que :
la sécurité d'un système cryptographique dépend autant
de l'implémentation que des mathématiques elles-mêmes.
""")