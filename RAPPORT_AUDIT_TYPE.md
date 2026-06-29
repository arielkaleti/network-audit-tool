# Rapport d'Audit Réseau — Exemple de Sortie
## SecureAudit v2.0 | CSC 242

---

**Date du scan :** 25/06/2026 à 14:32:07  
**Réseau cible :** 192.168.1.0/24 (réseau de laboratoire)  
**Opérateur :** Arikuise  
**Type de scan :** Port + Services (-sV) + OS Fingerprinting (-O)

---

## A — Inventaire des hôtes actifs

| IP             | Statut | Hostname            |
|----------------|--------|---------------------|
| 192.168.1.1    | up     | gateway.local       |
| 192.168.1.10   | up     | serveur-web.local   |
| 192.168.1.15   | up     | poste-admin.local   |
| 192.168.1.22   | up     | imprimante.local    |

**4 hôtes actifs détectés** sur le segment 192.168.1.0/24.

---

## B — Identification des systèmes d'exploitation

| IP           | OS détecté                    | Fiabilité | Famille  |
|--------------|-------------------------------|-----------|----------|
| 192.168.1.1  | Linux 4.15 - 5.6              | 95 %      | Linux    |
| 192.168.1.10 | Ubuntu 20.04 LTS              | 92 %      | Linux    |
| 192.168.1.15 | Windows 10 Pro (Build 19041)  | 88 %      | Windows  |
| 192.168.1.22 | HP JetDirect (embedded Linux) | 75 %      | Linux    |

**Observation :** Aucun système obsolète (ex: Windows XP/7) détecté.  
Mettre à jour Ubuntu 20.04 vers 22.04 LTS recommandé.

---

## C — Analyse des services et ports ouverts

### Hôte 192.168.1.10 (serveur-web.local)

| Port | Proto | Statut | Service / Version      | Risque | Score |
|------|-------|--------|------------------------|--------|-------|
| 22   | tcp   | open   | OpenSSH 8.2p1          | Moyen  | 40    |
| 80   | tcp   | open   | Apache httpd 2.4.41    | Faible | 20    |
| 443  | tcp   | open   | Apache httpd 2.4.41 SSL| Faible | 10    |
| 3306 | tcp   | open   | MySQL 8.0.28           | Élevé  | 80    |
| 5900 | tcp   | open   | VNC (protocol 3.8)     | Élevé  | 80    |

**Score de risque global : 72 / 100 — RISQUE ÉLEVÉ**

---

## Recommandations de sécurité

- **URGENT :** Fermer le port 3306 (MySQL) — ne jamais exposer une base de données sur le réseau. Restreindre à 127.0.0.1 dans `/etc/mysql/mysql.conf.d/mysqld.cnf`
- **URGENT :** Désactiver VNC (port 5900) ou le remplacer par un tunnel SSH chiffré
- **MOYEN :** Vérifier la version de SSH et désactiver l'accès root (`PermitRootLogin no` dans `/etc/ssh/sshd_config`)
- **INFO :** HTTPS est bien activé — vérifier la validité du certificat SSL

---

## Conclusion

Le réseau présente **2 vulnérabilités critiques** sur le serveur web :
le port MySQL exposé publiquement et le service VNC non chiffré constituent
des vecteurs d'entrée majeurs pour un attaquant.

Actions immédiates recommandées :
1. Fermer le port 3306 en production
2. Remplacer VNC par SSH avec tunneling X11
3. Planifier la mise à jour Ubuntu 20.04 → 22.04

*Rapport généré automatiquement par SecureAudit v2.0*
