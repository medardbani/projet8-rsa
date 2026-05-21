from common_modulus_attack import *
from no_padding_attack import *

print("\n" + "=" * 50)
print("  PROJET 8 - ATTAQUES RSA PAR MAUVAIS USAGE")
print("=" * 50)

# Attaque 1
message = b"Message secret M1"
print("\n[1] ATTAQUE PAR MODULE COMMUN")
n, e1, e2, d1, d2 = generate_common_modulus_keys()
c1 = chiffrer(message, e1, n)
c2 = chiffrer(message, e2, n)
m_retrouve = attaque_module_commun(n, e1, e2, c1, c2)
print(f"Message original  : {message}")
print(f"Message retrouvé  : {m_retrouve}")
print(f"Succès : {message == m_retrouve}")

# Attaque 2
message2 = b"Bonjour"
print("\n[2] ATTAQUE SANS PADDING")
n2, e2_, d2_ = generate_rsa_keys()
c2 = chiffrer_sans_padding(message2, e2_, n2)
m2 = attaque_racine_cubique(c2, e2_)
print(f"Message original  : {message2}")
print(f"Message retrouvé  : {m2}")
print(f"Succès : {message2 == m2}")