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

from Crypto.Util.number import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import gmpy2
import time

# ================================================================
# OUTILS
# ================================================================

def banner(title):
    print("\n" + "=" * 65)
    print(title)
    print("=" * 65)

def egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y

# ================================================================
# INTRO
# ================================================================

print("\n█████████████████████████████████████████████████████████████████")
print("  PROJET 8 – Attaque par mauvais usage de clés RSA (key reuse)")
print("█████████████████████████████████████████████████████████████████")

# ================================================================
# TÂCHE 1 — Génération module commun
# ================================================================

banner("TÂCHE 1 – Génération d'un module n commun (e1=3, e2=65537)")

print("[*] Génération de nombres premiers (512 bits)...")

e1 = 3
e2 = 65537

# Générer p, q compatibles avec e1 ET e2
while True:
    p = getPrime(512)
    q = getPrime(512)
    phi = (p - 1) * (q - 1)
    if GCD(e1, phi) == 1 and GCD(e2, phi) == 1:
        break

n = p * q
d1 = inverse(e1, phi)
d2 = inverse(e2, phi)

print(f"\n  p  = {p}")
print(f"  q  = {q}")
print(f"  n  = {n}")
print(f"\n  Clé publique 1  : (e1={e1}, n)")
print(f"  Clé privée  1  : (d1={d1}, n)")
print(f"\n  Clé publique 2  : (e2={e2}, n)")
print(f"  Clé privée  2  : (d2={d2}, n)")
print(f"\n  ✔ Module partagé confirmé : {True}")

# ================================================================
# TÂCHE 2 — Common Modulus Attack
# ================================================================

banner("TÂCHE 2 – Attaque par module commun (Common Modulus Attack)")

message_bytes = b"HELLO RSA"
m = bytes_to_long(message_bytes)

print(f"\n  Message original m = {m}")
print(f"  (bytes : {message_bytes})")

start_enc = time.time()
c1 = pow(m, e1, n)
c2 = pow(m, e2, n)
end_enc = time.time()

print(f"\n  c1 = Enc(m, e1={e1}) = {c1}")
print(f"  c2 = Enc(m, e2={e2}) = {c2}")

print("\n  [ATTAQUE] Bézout sur e1 et e2...")
g, a, b = egcd(e1, e2)
print(f"  gcd({e1}, {e2}) = {g} → {e1}×({a}) + {e2}×({b}) = 1")
print("  Formule : m = c1^a × c2^b (mod n)")

start_attack = time.time()

if a < 0:
    c1 = inverse(c1, n)
    a = -a
if b < 0:
    c2 = inverse(c2, n)
    b = -b

recovered = (pow(c1, a, n) * pow(c2, b, n)) % n
end_attack = time.time()

print(f"\n  m récupéré = {recovered}")
success = (recovered == m)
print(f"\n  ✔ Attaque réussie : {success}")
print(f"  Message déchiffré : {long_to_bytes(recovered)}")

legit = pow(pow(m, e1, n), d1, n)
print(f"\n  [Contrôle] Déchiffrement légitime (d1) = {legit}")
print(f"  Identiques : {legit == recovered}")

print("\n  [PERFORMANCES]")
print(f"  Temps chiffrement : {(end_enc - start_enc)*1000:.6f} ms")
print(f"  Temps attaque     : {(end_attack - start_attack)*1000:.6f} ms")

# ================================================================
# TÂCHE 3 — RSA sans padding
# ================================================================

banner("TÂCHE 3 – Sans padding : déchiffrement par racine e-ième")

small_message = b"Hi"
m_small = bytes_to_long(small_message)
e = 3

print(f"\n  [Cas 1] Message court : m = {m_small} ({small_message})")
print(f"  e = {e}")

c = pow(m_small, e, n)
print(f"  c = m^e mod n = {c}")

exact_power = m_small ** e
print(f"\n  m^e (exact, sur ℤ)   = {exact_power}")
print(f"  n                    = {n}")
print(f"  m^e < n ?            {exact_power < n}")

root, exact = gmpy2.iroot(c, e)
print(f"\n  → Racine {e}-ième de c : {root}")
print(f"  → Racine exacte : {exact}")

if exact:
    recovered_small = long_to_bytes(int(root))
    print(f"\n  ✔ Message retrouvé : {recovered_small}")

print("\n  -------------------------------------------------------")
print("  [Cas 2] Chiffrement déterministe (absence de padding)")

secret = bytes_to_long(b"SECRET")
cipher1 = pow(secret, e, n)
cipher2 = pow(secret, e, n)

print(f"  Enc('SECRET', pub) 1ère fois : {cipher1}")
print(f"  Enc('SECRET', pub) 2ème fois : {cipher2}")
print(f"  Chiffrés identiques : {cipher1 == cipher2}")

if cipher1 == cipher2:
    print("  ⚠ Un attaquant peut détecter deux messages identiques")
    print("    → Résolu par OAEP (padding aléatoire)")

# ================================================================
# TÂCHE 4 — OAEP
# ================================================================

banner("TÂCHE 4 – Protection avec OAEP")

print("[*] Génération d'une vraie paire RSA 2048 bits...")

rsa_key = RSA.generate(2048)
public_key = rsa_key.publickey()
cipher_oaep = PKCS1_OAEP.new(public_key)

message = b"SECRET"
ciphertext1 = cipher_oaep.encrypt(message)
ciphertext2 = cipher_oaep.encrypt(message)

print(f"\n  Message : {message}")
print(f"\n  Ciphertext 1 : {ciphertext1.hex()[:80]}...")
print(f"  Ciphertext 2 : {ciphertext2.hex()[:80]}...")
print(f"\n  Chiffrés identiques ? {ciphertext1 == ciphertext2}")

if ciphertext1 != ciphertext2:
    print("\n  ✔ OAEP ajoute de l'aléatoire")
    print("  ✔ Le chiffrement devient non déterministe")
    print("  ✔ Les attaques précédentes échouent")

# ================================================================
# BONUS — Attaque de Håstad
# ================================================================

banner("BONUS – Attaque de Håstad (CRT)")

message_h = bytes_to_long(b"HASTAD")
e = 3

print("[*] Génération de 3 modules RSA différents...")

moduli = []
ciphers = []
for i in range(3):
    pi = getPrime(512)
    qi = getPrime(512)
    ni = pi * qi
    moduli.append(ni)
    ciphers.append(pow(message_h, e, ni))

n1, n2, n3 = moduli
c1h, c2h, c3h = ciphers

print("\n  Même message envoyé à 3 destinataires")
print("  Même exposant e = 3, pas de padding")

N = n1 * n2 * n3
m1 = N // n1
m2 = N // n2
m3 = N // n3

inv1 = inverse(m1, n1)
inv2 = inverse(m2, n2)
inv3 = inverse(m3, n3)

x = (c1h * m1 * inv1 + c2h * m2 * inv2 + c3h * m3 * inv3) % N

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