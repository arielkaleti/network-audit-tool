# SecureAudit v2.0 — Documentation Technique
## CSC 242 | Projet Fin de Semestre

---

## 1. Installation des dépendances

```bash
pip install -r requirements.txt
```

**Prérequis système :**
- Python 3.x
- Nmap installé sur la machine hôte → https://nmap.org/download.html
- MySQL Server démarré (port 3306, user root, mot de passe vide)
- Droits administrateur/root pour le scan OS Fingerprinting (-O)

---

## 2. Structure du projet

```
secureaudit/
├── audit_reseau.py        # Interface graphique principale (Tkinter)
├── scanner.py             # Logique de scan réseau (Nmap)
├── database.py            # Accès MySQL (CRUD)
├── requirements.txt       # Dépendances Python
└── DOCUMENTATION_TECHNIQUE.md
```

**Séparation stricte UI / Logique / Données :**
- `audit_reseau.py` → uniquement l'interface (Tkinter)
- `scanner.py`      → uniquement les appels Nmap et calculs
- `database.py`     → uniquement les requêtes SQL MySQL

---

## 3. Schéma de la base de données MySQL

### Table `scans` — Historique des audits
| Champ      | Type         | Description                   |
|------------|--------------|-------------------------------|
| id         | INT (PK)     | Identifiant auto-incrémenté   |
| date_scan  | DATETIME     | Date et heure du scan         |
| cible      | VARCHAR(100) | IP ou plage réseau scannée    |
| type_scan  | VARCHAR(50)  | Type : Ping/OS/Port           |
| nb_hotes   | INT          | Nombre d'hôtes détectés       |
| nb_ports   | INT          | Nombre de ports ouverts       |
| score      | INT          | Score de risque global (0-100)|
| niveau     | VARCHAR(20)  | Faible / Moyen / Élevé        |

### Table `ports` — Résultats détaillés (FK → scans)
| Champ      | Type         | Description                   |
|------------|--------------|-------------------------------|
| id         | INT (PK)     | Identifiant                   |
| scan_id    | INT (FK)     | Référence au scan parent      |
| port       | INT          | Numéro de port                |
| protocole  | VARCHAR(10)  | tcp / udp                     |
| statut     | VARCHAR(20)  | open / closed / filtered      |
| service    | VARCHAR(100) | Nom du service détecté        |
| version    | VARCHAR(100) | Version du service            |
| risque     | VARCHAR(20)  | Faible / Moyen / Élevé        |
| score_port | INT          | Score individuel (0-100)      |

### Table `os_results` — OS Fingerprinting (FK → scans)
| Champ       | Type         | Description                   |
|-------------|--------------|-------------------------------|
| id          | INT (PK)     | Identifiant                   |
| scan_id     | INT (FK)     | Référence au scan parent      |
| ip          | VARCHAR(50)  | Adresse IP de l'hôte          |
| hostname    | VARCHAR(150) | Nom d'hôte résolu             |
| statut      | VARCHAR(20)  | up / down                     |
| os_name     | VARCHAR(200) | OS détecté (ex: Windows 10)   |
| os_accuracy | INT          | Fiabilité de détection (%)    |
| os_family   | VARCHAR(100) | Famille OS (Windows/Linux/...) |

### Table `equipements` — Gestion manuelle
| Champ      | Type         | Description                   |
|------------|--------------|-------------------------------|
| id         | INT (PK)     | Identifiant                   |
| nom        | VARCHAR(100) | Nom de l'équipement           |
| adresse_ip | VARCHAR(50)  | Adresse IP                    |
| type_eq    | VARCHAR(50)  | Routeur / Switch / Serveur... |
| os         | VARCHAR(100) | Système d'exploitation        |
| statut     | VARCHAR(20)  | Actif / Inactif               |
| date_ajout | DATETIME     | Date d'ajout                  |

---

## 4. Choix des arguments Nmap

| Fonctionnalité     | Argument Nmap            | Justification                                      |
|--------------------|--------------------------|---------------------------------------------------|
| Host Discovery (A) | `-sn`                    | Ping Sweep sans scan de ports → rapide            |
| OS Fingerprinting (B) | `-O --osscan-guess`   | Analyse pile TCP/IP + estimation si incertaine    |
| Port Scanner (C)   | `-sV --top-ports 1000`   | Détection version service sur 1000 ports courants |

---

## 5. Score de risque — Méthode de calcul

```
score_global = min(100, moyenne(scores_ports) × 1.5)
```

- Chaque port a un score individuel (10 à 90) selon sa dangerosité
- La multiplication par 1.5 amplifie l'effet des ports critiques
- Seuils : Élevé ≥ 70 | Moyen ≥ 40 | Faible < 40

---

## 6. Justification des choix techniques

**POO (classe SecureAuditApp) :**
Encapsule l'état global (widgets, résultats, navigation) et évite les variables globales.
Chaque méthode a une responsabilité unique (SRP).

**Threading :**
Les scans Nmap sont exécutés dans un thread daemon pour ne pas bloquer l'UI Tkinter.
Les mises à jour UI se font via `root.after(0, callback)` (thread-safe).

**MySQL vs SQLite :**
MySQL choisi pour sa robustesse en environnement multi-utilisateurs et sa compatibilité
avec les environnements de production réseau d'entreprise.

**reportlab pour l'export PDF :**
Bibliothèque Python native, sans dépendance externe (pas besoin de LibreOffice/Word).
Permet un contrôle précis de la mise en page du rapport d'audit.
