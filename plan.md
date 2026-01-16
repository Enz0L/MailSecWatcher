# Plan des changements - MailSecWatcher v2.0.2

## Objectif
Refonte de la section recommandations pour améliorer la lisibilité et la priorisation des actions à entreprendre.

## Changements effectués

### 1. Nouvelle fonction `categorize_recommendations()` (lignes 1102-1197)

**Emplacement** : Avant la fonction `analyze_results()`

**Fonctionnalité** :
- Analyse les résultats de tous les protocoles (SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI)
- Catégorise les recommandations en 4 niveaux de priorité
- Retourne un dictionnaire structuré

**Paramètres** :
- `spf_result` : Résultats de l'analyse SPF
- `dmarc_result` : Résultats de l'analyse DMARC
- `dkim_score` : Score DKIM (0-21)
- `mta_sts_result` : Résultats MTA-STS
- `tlsrpt_result` : Résultats TLS-RPT
- `bimi_result` : Résultats BIMI

**Retour** :
```python
{
    'critical': [liste de strings],
    'high': [liste de strings],
    'medium': [liste de strings],
    'low': [liste de strings]
}
```

**Logique de catégorisation** :

#### 🔴 CRITICAL
- SPF absent
- SPF avec +all (mécanisme pass)
- SPF neutral (?all)
- SPF redirect cassé
- SPF > 10 DNS lookups
- DMARC absent
- DMARC p=none
- DMARC sans aggregate reporting (rua)
- DKIM absent (score = 0)

#### 🟠 HIGH PRIORITY
- SPF softfail (~all)
- SPF 8-10 DNS lookups
- DMARC p=quarantine (suggère reject)
- DMARC sans subdomain policy explicite
- DMARC sans forensic reporting (ruf)

#### 🟡 MEDIUM PRIORITY
- DMARC alignement DKIM non strict
- DMARC alignement SPF non strict
- MTA-STS en mode testing

#### 🟢 LOW PRIORITY
- MTA-STS absent
- TLS-RPT absent
- BIMI absent (avec note sur prérequis DMARC)

### 2. Refonte de l'affichage des recommandations (lignes 1403-1454)

**Ancien code** : Liste plate de recommandations avec emojis mélangés

**Nouveau code** :
- Appel à `categorize_recommendations()`
- Calcul du nombre total de recommandations
- Affichage par catégorie avec compteurs
- Séparation visuelle claire entre catégories
- Message spécial si aucune recommandation

**Structure d'affichage** :
```
📋 RECOMMENDATIONS:

🔴 CRITICAL ISSUES (N)
  • Recommandation 1
  • Recommandation 2

🟠 HIGH PRIORITY (N)
  • Recommandation 1

🟡 MEDIUM PRIORITY (N)
  • Recommandation 1

🟢 LOW PRIORITY (N)
  • Recommandation 1
```

### 3. Suppression de code redondant

**Lignes supprimées** : 1409-1485 (ancien code de recommandations)
- Liste `actions = []`
- Logique de construction des recommandations ligne par ligne
- Affichage avec emojis individuels

**Remplacé par** : Appel à fonction + affichage structuré (46 lignes au lieu de ~80)

## Architecture de la solution

### Carte des dépendances entre protocoles

```
Phase 1 - FONDATION
├─ SPF (20 pts) → Aucune dépendance
└─ DMARC (27 pts) → Dépendance soft sur SPF/DKIM

Phase 2 - AUTHENTIFICATION
└─ DKIM (21 pts) → Aucune dépendance

Phase 3 - TRANSPORT
├─ MTA-STS (12 pts) → Indépendant
└─ TLS-RPT (12 pts) → Complémentaire

Phase 4 - BRANDING
└─ BIMI (8 pts) → DÉPENDANCE CRITIQUE sur DMARC p=quarantine/reject
```

### Avantages de la nouvelle architecture

1. **Séparation des préoccupations**
   - Logique de catégorisation isolée dans une fonction
   - Affichage simplifié et maintenable

2. **Extensibilité**
   - Facile d'ajouter de nouvelles recommandations
   - Facile de modifier les critères de priorisation

3. **Testabilité**
   - Fonction pure (sans effets de bord)
   - Peut être testée indépendamment

4. **Lisibilité**
   - Code plus court (~150 lignes vs ~80 lignes dupliquées)
   - Logique claire et documentée

## Tests effectués

### Test 1 : google.com
- **Score** : 60/100 (Grade C)
- **Résultat** :
  - 1 CRITICAL (DKIM absent)
  - 3 HIGH PRIORITY
  - 2 MEDIUM PRIORITY
  - 1 LOW PRIORITY

### Test 2 : github.com
- **Score** : 57/100 (Grade D)
- **Résultat** :
  - 0 CRITICAL
  - 4 HIGH PRIORITY
  - 2 MEDIUM PRIORITY
  - 3 LOW PRIORITY

## Fichiers créés/modifiés

### Modifiés
- `mailsecw.py`
  - Lignes 1102-1197 : Nouvelle fonction `categorize_recommendations()`
  - Lignes 1403-1454 : Refonte de la section RECOMMENDATIONS

### Créés
- `releasenote.md` : Notes de version détaillées
- `plan.md` : Ce fichier (plan des changements)

## Points d'attention pour le futur

### Améliorations possibles
1. Ajouter des exemples de records DNS en mode verbose
2. Créer un mode "roadmap" qui suggère l'ordre d'implémentation
3. Ajouter des liens vers la documentation des protocoles
4. Exporter les recommandations en format JSON/HTML

### Maintenance
- Mettre à jour les critères de catégorisation si les RFCs évoluent
- Adapter les seuils DNS lookups si nécessaire
- Surveiller les nouvelles bonnes pratiques DMARC/BIMI

## Conformité CLAUDE.md

✅ Amélioration du code existant (pas de réécriture)
✅ Code simple et essentiel
✅ Commentaires sur une seule ligne
✅ Fichier releasenote.md créé
✅ Fichier plan.md créé
✅ Respect de la philosophie du projet

---

---

## Changement 2 : Ajout de la justification du score DKIM

### Objectif
Rendre le scoring DKIM transparent pour que l'utilisateur comprenne pourquoi il a obtenu ce score spécifique.

### Problème identifié
L'affichage DKIM montrait uniquement :
```
🔑 DKIM (17/21)
   Found 2 selector(s):
   ✅ protonmail
   ✅ protonmail2
```

L'utilisateur ne savait pas :
- Pourquoi 17/21 et non 21/21
- Combien de sélecteurs sont nécessaires pour le score maximum
- Comment améliorer son score

### Solution implémentée

#### Modification du code (lignes 1343-1349)

Ajout d'une ligne de justification du score après l'affichage des sélecteurs :

```python
#Display scoring justification
if selector_count == 1:
    print(f"   Scoring: 1 selector = 12pts (consider adding more for redundancy)")
elif selector_count == 2:
    print(f"   Scoring: 2 selectors = 17pts (3+ selectors = 21pts)")
elif selector_count >= 3:
    print(f"   Scoring: {selector_count} selectors = 21pts (maximum)")
```

#### Résultat

**Nouveau rendu** :
```
🔑 DKIM (17/21)
   Found 2 selector(s):
   ✅ protonmail
   ✅ protonmail2
   Scoring: 2 selectors = 17pts (3+ selectors = 21pts)
```

### Logique de scoring DKIM rappelée

Code source (lignes 714-728) :
```python
def calculate_dkim_score(dkim_result):
    if not dkim_result:
        return 0

    count = len(dkim_result)

    if count >= 3:
        return 21      # Score maximum
    elif count == 2:
        return 17      # Configuration solide
    elif count == 1:
        return 12      # Configuration basique

    return 0
```

### Bénéfices

✅ **Transparence** - L'utilisateur voit immédiatement comment le score est calculé
✅ **Guidance** - Indique clairement qu'il faut 3+ sélecteurs pour 21pts
✅ **Pédagogie** - Suggère l'ajout de sélecteurs pour la redondance (cas 1 sélecteur)
✅ **Cohérence** - Même approche que SPF qui affiche "DNS Lookups: ✅ 3/10"

### Fichiers modifiés

- `mailsecw.py` (lignes 1343-1349)
  - Ajout variable `selector_count`
  - Ajout bloc de justification du score

### Tests

✅ Test avec enzolenair.fr (2 sélecteurs)
- Affiche : "Scoring: 2 selectors = 17pts (3+ selectors = 21pts)"

---

---

## Changement 3 : Mise à jour du README.md

### Objectif
Documenter les nouvelles fonctionnalités de la v2.0.2 dans le README pour les utilisateurs.

### Modifications apportées

#### 1. Section Features (lignes 9-25)
**Ajouts** :
- Note "NEW" pour la justification du scoring DKIM
- Note "NEW" pour les recommandations catégorisées (3 points ajoutés)

#### 2. Section DKIM Resolution (lignes 121-131)
**Ajouts** :
- Ajout des sélecteurs ProtonMail dans la liste
- **Nouvelle sous-section "Scoring Logic"** :
  - 1 selector = 12pts (basic)
  - 2 selectors = 17pts (solid)
  - 3+ selectors = 21pts (maximum)

#### 3. Section Example Output (lignes 218-251)
**Modifications** :
- Mise à jour de l'affichage DKIM avec la nouvelle justification
- Remplacement de la section "SCORE BREAKDOWN" par "RECOMMENDATIONS"
- Affichage du nouveau format avec catégories et compteurs

#### 4. Section Version (lignes 272-292)
**Modifications** :
- Mise à jour du numéro de version : v1.4.5 → **v2.0.2**
- **Nouvelle section "What's New in v2.0.2"** :
  - Description des recommandations catégorisées
  - Description de la transparence du scoring DKIM
- Ajout d'un historique des versions précédentes

### Bénéfices

✅ **Documentation à jour** - Les utilisateurs voient les nouvelles fonctionnalités
✅ **Exemples visuels** - Comprennent le nouveau format de sortie
✅ **Historique clair** - Savent ce qui a changé entre les versions
✅ **SEO amélioré** - Les mots-clés "categorized", "transparent scoring" apparaissent

### Fichiers modifiés

- `readme.md`
  - Lignes 9-25 : Features enrichies
  - Lignes 121-131 : DKIM scoring logic ajoutée
  - Lignes 218-251 : Exemple de sortie mis à jour
  - Lignes 272-292 : Version et "What's New"

---

## Changement 4 : Ajout de l'option -ns (Custom Nameserver)

### Objectif
Permettre à l'utilisateur de spécifier un serveur DNS personnalisé pour toutes les requêtes DNS via l'option `-ns`.

### Contexte

**Demande utilisateur** : "Est-ce que tu crois qu'il est possible de rajouter la possibilité pour l'utilisateur à travers un -ns la possibilité de spécifier un DNS spécifique ?"

**Analyse de faisabilité** : TRÈS FACILE (2/10)
- 7 appels à `dns.resolver.resolve()` identifiés dans le code
- Pattern cohérent et bien structuré
- API dnspython supporte facilement les resolvers personnalisés

### Solution implémentée

#### 1. Imports ajoutés (lignes 28-29)
```python
import ipaddress
import sys
```

#### 2. Variable globale DNS_RESOLVER (ligne 31-32)
```python
#Global DNS resolver (can be customized via -ns option)
DNS_RESOLVER = dns.resolver
```

#### 3. Argument CLI ajouté (lignes 80-83)
```python
parser.add_argument(
    "-ns", "--nameserver",
    help="Custom DNS nameserver to use (e.g., 8.8.8.8)"
)
```

#### 4. Configuration dans main() (lignes 1484-1494)
```python
#Configure custom nameserver if provided
if options.nameserver:
    global DNS_RESOLVER
    try:
        ipaddress.ip_address(options.nameserver)
        DNS_RESOLVER = dns.resolver.Resolver()
        DNS_RESOLVER.nameservers = [options.nameserver]
        print(f"🌐 Using nameserver: {options.nameserver}")
    except ValueError:
        print(f"❌ Error: '{options.nameserver}' is not a valid IP address")
        sys.exit(1)
```

#### 5. Modification des 7 fonctions DNS

Remplacement de `dns.resolver.resolve()` par `DNS_RESOLVER.resolve()` :

1. **resolve_spf_redirect()** - ligne 224
2. **spf_resolver()** - ligne 453
3. **dmarc_resolver()** - ligne 631
4. **dkim_resolver()** - ligne 708
5. **mta_sts_resolver()** - ligne 755
6. **tlsrpt_resolver()** - ligne 823
7. **bimi_resolver()** - ligne 1018

### Tests effectués

#### Test 1 : Google DNS (8.8.8.8)
```bash
python mailsecw.py -d google.com -ns 8.8.8.8
```
✅ **Résultat** : Affiche "🌐 Using nameserver: 8.8.8.8" et analyse correctement

#### Test 2 : Cloudflare DNS (1.1.1.1)
```bash
python mailsecw.py -d github.com -ns 1.1.1.1
```
✅ **Résultat** : Fonctionne correctement avec Cloudflare DNS

#### Test 3 : Sans option -ns (défaut)
```bash
python mailsecw.py -d enzolenair.fr
```
✅ **Résultat** : Fonctionne comme avant (DNS système)

#### Test 4 : IP invalide
```bash
python mailsecw.py -d google.com -ns 999.999.999.999
```
✅ **Résultat** : Affiche "❌ Error: '999.999.999.999' is not a valid IP address" et quitte

### Documentation mise à jour

#### README.md
- Ajout section "With Custom DNS Nameserver" (lignes 58-60)
- Ajout de l'option dans le tableau "Command Line Options" (ligne 69)
- Nouvelle section "Using Custom DNS Nameserver" (lignes 71-90)
  - Exemples d'utilisation
  - Liste des DNS publics courants
  - Cas d'usage

#### releasenote.md
- Nouvelle section complète pour v2.0.3
- Description détaillée des changements
- Exemples d'utilisation
- Cas d'usage
- Tests effectués

#### Version
- Mise à jour de v2.0.2 → **v2.0.3**

### Bénéfices

✅ **Flexibilité** - L'utilisateur peut choisir n'importe quel serveur DNS
✅ **Testing** - Vérifier la propagation DNS sur différents serveurs
✅ **Corporate** - Utiliser le DNS interne de l'entreprise
✅ **Debugging** - Isoler les problèmes DNS
✅ **Validation** - Validation d'IP incluse pour éviter les erreurs

### Conformité CLAUDE.md

✅ **Amélioration du code existant** - Pas de réécriture, seulement ajout d'une option
✅ **Code simple et essentiel** - ~10 lignes ajoutées, 7 lignes modifiées
✅ **Commentaires sur une seule ligne** - Style respecté
✅ **Release note en anglais** - Créée
✅ **plan.md adapté** - Ce fichier mis à jour

### Fichiers modifiés

- `mailsecw.py`
  - Ligne 2 : Version mise à jour v2.0.3
  - Lignes 28-29 : Imports ajoutés
  - Lignes 31-32 : Variable globale DNS_RESOLVER
  - Lignes 80-83 : Argument CLI -ns
  - Lignes 1484-1494 : Configuration nameserver
  - 7 lignes : Appels DNS mis à jour

- `readme.md`
  - Version mise à jour v2.0.3
  - Section "With Custom DNS Nameserver" ajoutée
  - Option -ns ajoutée au tableau
  - Section complète "Using Custom DNS Nameserver"

- `releasenote.md`
  - Nouvelle section pour v2.0.3

---

**Date** : 2026-01-12
**Version** : v2.0.3
**Développeur** : Enzo LE NAIR

---

## Changement 5 : Modification du scoring DKIM (v2.0.4)

### Objectif
Simplifier le scoring DKIM pour attribuer le score maximum (21 points) dès qu'il y a 2 sélecteurs ou plus.

### Contexte

**Demande utilisateur** : "J'aimerais qu'on score à 100% dès lors qu'il y a au moins 2 dkim"

**Justification** :
- 2 sélecteurs DKIM assurent déjà une bonne redondance pour la production
- La plupart des domaines bien configurés utilisent 2 sélecteurs
- Alignement avec les best practices de l'industrie
- Simplifie la logique de scoring

### Solution implémentée

#### 1. Version (ligne 2)
```python
# Avant
# Version: V2.0.3ab

# Après
# Version: V2.0.4
```

#### 2. Fonction calculate_dkim_score() (lignes 723-735)
**Avant** :
```python
if count >= 3:
    return 21
elif count == 2:
    return 17
elif count == 1:
    return 12
```

**Après** :
```python
if count >= 2:
    return 21
elif count == 1:
    return 12
```

#### 3. Justification du scoring (lignes 1351-1354)
**Avant** :
```python
if selector_count == 1:
    print(f"   Scoring: 1 selector = 12pts (consider adding more for redundancy)")
elif selector_count == 2:
    print(f"   Scoring: 2 selectors = 17pts (3+ selectors = 21pts)")
elif selector_count >= 3:
    print(f"   Scoring: {selector_count} selectors = 21pts (maximum)")
```

**Après** :
```python
if selector_count == 1:
    print(f"   Scoring: 1 selector = 12pts (add at least 1 more for redundancy)")
elif selector_count >= 2:
    print(f"   Scoring: {selector_count} selectors = 21pts (maximum - excellent redundancy)")
```

### Documentation mise à jour

#### README.md
- Ligne 300 : Version mise à jour v2.0.4
- Lignes 154-156 : DKIM Scoring Logic simplifiée
- Lignes 243-247 : Exemple de sortie mis à jour (21/21)
- Lignes 301-308 : Nouvelle section "What's New in v2.0.4"

#### releasenote.md
- Nouvelle section complète pour v2.0.4 (lignes 1-68)
- Exemples Before/After
- Justification du changement
- Impact sur les scores (+4 points pour domaines avec 2 sélecteurs)

### Bénéfices

✅ **Scoring réaliste** - Reflète les best practices de l'industrie
✅ **Logique simplifiée** - Seuil clair à 2 sélecteurs au lieu de 3
✅ **Meilleure UX** - Les utilisateurs avec 2 sélecteurs obtiennent le score maximum
✅ **Encourage la redondance** - Valorise toujours la présence de multiples sélecteurs

### Impact

**Pour les domaines avec 2 sélecteurs DKIM** :
- Avant : DKIM 17/21 (81%)
- Après : DKIM 21/21 (100%)
- Gain : +4 points sur le score global

**Exemple avec enzolenair.fr** :
- Possède 2 sélecteurs (protonmail, protonmail2)
- Score DKIM passe de 17/21 à 21/21
- Score global augmente de 4 points

### Conformité CLAUDE.md

✅ **Amélioration du code existant** - Simplification de la logique
✅ **Code simple et essentiel** - Réduction de la complexité
✅ **Commentaires sur une seule ligne** - Style respecté
✅ **Release note en anglais** - Créée pour v2.0.4
✅ **plan.md adapté** - Ce fichier mis à jour
✅ **Pas de mention interdite** - Conformité respectée

### Fichiers modifiés

- `mailsecw.py`
  - Ligne 2 : Version mise à jour v2.0.4
  - Lignes 723-735 : Fonction calculate_dkim_score() simplifiée
  - Lignes 1351-1354 : Justification du scoring mise à jour

- `readme.md`
  - Ligne 300 : Version mise à jour v2.0.4
  - Lignes 154-156 : DKIM Scoring Logic simplifiée
  - Lignes 243-247 : Exemple de sortie mis à jour (21/21)
  - Lignes 301-328 : Section "What's New in v2.0.4" ajoutée

- `releasenote.md`
  - Lignes 1-68 : Nouvelle section pour v2.0.4 (ajoutée au début)

- `plan.md`
  - Ajout de ce "Changement 5"

---

**Date** : 2026-01-14
**Version** : v2.0.4
**Développeur** : Enzo LE NAIR

---

## Changement 6 : Export HTML avec Jinja2 et YAML (v2.0.5)

### Objectif
Ajouter une option `-o html` pour générer des rapports HTML personnalisables avec Jinja2 et configuration YAML.

### Contexte

**Demande utilisateur** :
- "Il faudrait ajouter une fonctionnalité pour faire un fichier HTML de 'report'. Je verrais bien une option -o html qui sort un report.html avec un nom horodaté"
- "J'aimerais que l'on utilise JINJA2 pour le templating, l'idée est d'avoir un fichier de configuration au format YAML pour permettre à l'utilisateur de customiser son fichier HTML: logo, couleurs, footer"

### Architecture implementee

#### Arborescence
```
MailSecWatcher/
├── mailsecw.py                 # Script principal (modifié)
├── templates/                  # Dossier des templates Jinja2
│   └── report.html            # Template HTML principal
├── config/                     # Dossier de configuration
│   └── report_config.yaml     # Configuration personnalisable
├── output/                     # Dossier des rapports générés
│   └── domain_YYYYMMDD_HHMMSS.html
└── ...
```

### Modifications apportées

#### 1. Nouvelles dépendances
```
jinja2
pyyaml
```
Installées dans le .venv existant.

#### 2. mailsecw.py - Imports ajoutés (lignes 30-32)
```python
import os
import yaml
from jinja2 import Environment, FileSystemLoader
```

#### 3. mailsecw.py - Version (ligne 2)
```python
# Version: V2.0.5
```

#### 4. mailsecw.py - Argument CLI (lignes 84-88)
```python
parser.add_argument(
    "-o", "--output",
    choices=["html"],
    help="Output format (html generates timestamped report file)"
)
```

#### 5. mailsecw.py - Fonction load_report_config() (lignes 1215-1250)
- Charge la configuration depuis `config/report_config.yaml`
- Fournit des valeurs par défaut si le fichier n'existe pas
- Merge la config utilisateur avec les défauts

#### 6. mailsecw.py - Fonction generate_html_report() (lignes 1253-1315)
- Configure l'environnement Jinja2
- Prépare les données pour le template
- Génère le fichier HTML avec nom horodaté
- Crée le dossier output si nécessaire

#### 7. mailsecw.py - Modification de main() (lignes 1641-1656)
```python
if options.output == "html":
    # Calcul des scores
    # Appel à generate_html_report()
    print(f"\n📄 HTML report generated: {report_path}")
```

### Fichiers créés

#### config/report_config.yaml
Configuration YAML avec sections :
- `branding` : logo_url, company_name, footer_text
- `colors` : primary, secondary, accent, background, danger, grade_*
- `output` : directory, filename_format

#### templates/report.html
Template Jinja2 complet avec :
- CSS moderne et responsive
- Variables de couleurs CSS (--primary, --secondary, etc.)
- Structure : Header, Score global, Protocoles (6 cartes), Recommandations, Footer
- Design 2026 avec gradients, shadows, hover effects
- Support d'impression

### Tests effectués

#### Test 1 : Génération avec enzolenair.fr
```bash
python mailsecw.py -d enzolenair.fr -o html
```
✅ Fichier généré : `output/enzolenair.fr_20260116_192338.html`

#### Test 2 : Combinaison avec -ns
```bash
python mailsecw.py -d google.com -ns 8.8.8.8 -o html
```
✅ Fonctionne correctement

#### Test 3 : Sans option -o
```bash
python mailsecw.py -d enzolenair.fr
```
✅ Comportement normal (affichage terminal uniquement)

### Bénéfices

✅ **Rapports professionnels** - Partageables avec des parties prenantes
✅ **Personnalisation complète** - Logo, couleurs, textes via YAML
✅ **Fichiers autonomes** - HTML avec CSS inline, aucune dépendance
✅ **Design moderne** - Esthétique 2026, responsive, print-ready
✅ **Extensible** - Facile d'ajouter d'autres formats (PDF, JSON) plus tard

### Conformité CLAUDE.md

✅ **Amélioration du code existant** - Ajout modulaire, pas de réécriture
✅ **Code simple et essentiel** - Architecture claire et maintenable
✅ **Palette de couleurs** - Utilisée par défaut (#e63946, #f1faee, #a8dadc, #457b9d, #1d3557)
✅ **Design contemporain** - Template HTML moderne
✅ **Commentaires sur une seule ligne** - Style respecté
✅ **Release note en anglais** - Créée pour v2.0.5
✅ **plan.md adapté** - Ce fichier mis à jour
✅ **Pas de mention interdite** - Conformité respectée
✅ **Utilise le .venv existant** - pip install dans le venv

### Fichiers modifiés

- `mailsecw.py`
  - Ligne 2 : Version mise à jour v2.0.5
  - Lignes 30-32 : Imports ajoutés
  - Lignes 84-88 : Argument -o ajouté
  - Lignes 1215-1315 : Fonctions load_report_config() et generate_html_report()
  - Lignes 1641-1656 : Appel conditionnel dans main()

- `config/report_config.yaml` (créé)
- `templates/report.html` (créé)
- `releasenote.md` - Section v2.0.5 ajoutée
- `plan.md` - Ce "Changement 6"

---

**Date** : 2026-01-16
**Version** : v2.0.5
**Développeur** : Enzo LE NAIR
