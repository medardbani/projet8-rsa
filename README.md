# Projet 8 — Attaques par mauvais usage de clés RSA

> **INF4268 — Cryptographie Asymétrique**  
> Master 1 Sécurité Informatique — Université de Yaoundé I  
> Auteur : **BANI Médard**  
> Enseignant : Dr Ekodeck Stéphane Gaël R.

---

## Description

Ce projet démontre plusieurs vulnérabilités classiques de RSA liées au **mauvais usage des clés**, sans jamais attaquer RSA mathématiquement. Toutes les attaques exploitent des erreurs d'implémentation.

### Vulnérabilités démontrées

| # | Attaque | Condition | Résultat |
|---|---------|-----------|----------|
| 1 | Common Modulus Attack (CMA) | Même module n, deux exposants | Message retrouvé sans clé privée |
| 2 | Racine e-ième | e=3, message court, sans padding | Message retrouvé par racine cubique |
| 3 | Chiffrement déterministe | Sans padding | Deux chiffrés identiques détectés |
| 4 | Protection OAEP | Avec padding aléatoire | Attaques précédentes échouent |
| 5 | Attaque de Håstad (CRT) | e=3, 3 destinataires, sans padding | Message retrouvé par CRT |

---

## Structure du projet

```
projet8-rsa/
├── src/
│   └── projet8_rsa_key_reuse.py   # Code principal (5 tâches + bonus)
├── rapport/
│   └── Rapport_Projet8_RSA_Final.docx
└── README.md
```

---

## Prérequis

- Python 3.10+
- pip

---

## Installation

```bash
# Cloner le dépôt
git clone git@github.com:medardbani/projet8-rsa.git
cd projet8-rsa

# Créer l'environnement virtuel
python3 -m venv venv
source venv/bin/activate

# Installer les dépendances
pip install pycryptodome gmpy2
```

---

## Utilisation

```bash
# Activer l'environnement virtuel
source venv/bin/activate

# Lancer le projet
cd src
python3 projet8_rsa_key_reuse.py
```

### Résultat attendu

```
█████████████████████████████████████████████████████████████████
  PROJET 8 – Attaque par mauvais usage de clés RSA (key reuse)
█████████████████████████████████████████████████████████████████

TÂCHE 1 – Génération d'un module n commun (e1=3, e2=65537)
  ✔ Module partagé confirmé : True

TÂCHE 2 – Attaque par module commun (Common Modulus Attack)
  ✔ Attaque réussie : True
  Message déchiffré : b'HELLO RSA'

TÂCHE 3 – Sans padding : déchiffrement par racine e-ième
  ✔ Message retrouvé : b'Hi'
  Chiffrés identiques : True ⚠

TÂCHE 4 – Protection avec OAEP
  ✔ OAEP ajoute de l'aléatoire
  Chiffrés identiques ? False ✔

BONUS – Attaque de Håstad (CRT)
  Message retrouvé : b'HASTAD'
  Attaque réussie : True ✔
```

---

## Explication des attaques

### 1. Common Modulus Attack (CMA)

Si Alice (e1=3) et Bob (e2=65537) partagent le même module n, un attaquant interceptant les deux chiffrés peut retrouver m via le **théorème de Bézout** :

```
gcd(e1, e2) = 1  ⟹  ∃ s,t : s×e1 + t×e2 = 1
m = c1^s × c2^t mod n
```

**Contre-mesure :** Générer des modules n indépendants pour chaque utilisateur.

### 2. Racine e-ième (Håstad simple)

Avec e=3 et un message court m tel que **m³ < n** :
```
c = m³  (sur ℤ, sans réduction mod n)
m = ∛c  (racine cubique entière)
```

**Contre-mesure :** Utiliser e=65537 et toujours un padding OAEP.

### 3. Chiffrement déterministe

Sans padding aléatoire, `Enc(m)` produit toujours le même résultat. Un attaquant peut construire un dictionnaire avec la clé publique.

**Contre-mesure :** OAEP (Optimal Asymmetric Encryption Padding).

### 4. Attaque de Håstad (CRT)

Même message envoyé à 3 destinataires avec e=3 et modules différents. Le **Théorème des Restes Chinois** reconstruit m³, puis la racine cubique donne m.

**Contre-mesure :** OAEP — chaque chiffrement est unique même avec la même clé.

---

## Contre-mesures recommandées

| Vulnérabilité | Contre-mesure |
|---------------|---------------|
| Module commun | Modules n indépendants par utilisateur |
| Petit exposant | e = 65537 (standard F4) |
| Sans padding | OAEP pour le chiffrement |
| Signatures | RSA-PSS (Probabilistic Signature Scheme) |
| Taille de clé | 2048 bits minimum en production |

---

## Perspective M2

- Étude des **JWT vulnérables** en production (alg:none, RS256→HS256)
- Analyse de l'**attaque de Bleichenbacher** sur PKCS#1 v1.5
- Comparaison **RSA-PSS vs RSA textbook**
- Mauvaises implémentations OpenSSL

---

## Références

- Rivest, Shamir, Adleman (1978). *A Method for Obtaining Digital Signatures and Public-Key Cryptosystems.*
- Simmons (1983). *A weak privacy protocol using the RSA crypto algorithm.*
- Håstad (1986). *On using RSA with Low Exponent in a Public Key Network.*
- Boneh (1999). *Twenty Years of Attacks on the RSA Cryptosystem.*
- Bleichenbacher (1998). *Chosen Ciphertext Attacks Against Protocols Based on RSA PKCS#1.*

---

## Licence

MIT — Libre utilisation à des fins pédagogiques.
