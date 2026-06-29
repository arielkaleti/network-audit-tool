# =============================================================
#  scanner.py — Logique de scan réseau via Nmap
#  SecureAudit v2.0 — CSC 242
#  Séparation stricte UI / Logique (exigé par la grille)
#  Auteur : Arikuise
# =============================================================




import nmap
import re

# ── Table des scores de risque par port ──────────────────────
SCORES_PORTS = {
    21:   ("FTP",        80, "Élevé"),
    22:   ("SSH",        40, "Moyen"),
    23:   ("Telnet",     90, "Élevé"),
    25:   ("SMTP",       50, "Moyen"),
    53:   ("DNS",        30, "Faible"),
    80:   ("HTTP",       20, "Faible"),
    110:  ("POP3",       50, "Moyen"),
    135:  ("RPC",        70, "Élevé"),
    139:  ("NetBIOS",    75, "Élevé"),
    143:  ("IMAP",       50, "Moyen"),
    443:  ("HTTPS",      10, "Faible"),
    445:  ("SMB",        90, "Élevé"),
    1433: ("MSSQL",      85, "Élevé"),
    1521: ("Oracle DB",  85, "Élevé"),
    3306: ("MySQL",      80, "Élevé"),
    3389: ("RDP",        75, "Élevé"),
    5900: ("VNC",        80, "Élevé"),
    6379: ("Redis",      85, "Élevé"),
    8080: ("HTTP-Alt",   25, "Faible"),
    8443: ("HTTPS-Alt",  15, "Faible"),
    27017:("MongoDB",    85, "Élevé"),
}


# =============================================================
#  VALIDATION DE L'ADRESSE IP / PLAGE
# =============================================================
def valider_cible(cible):
    """
    Valide une adresse IP ou une plage réseau CIDR.
    Retourne (True, "") si valide, (False, message) sinon.
    """
    cible = cible.strip()
    if not cible:
        return False, "Le champ cible est vide."

    # Plage CIDR : ex 192.168.1.0/24
    if "/" in cible:
        parties = cible.split("/")
        if len(parties) != 2:
            return False, "Format CIDR invalide. Ex : 192.168.1.0/24"
        try:
            masque = int(parties[1])
            if masque < 0 or masque > 32:
                return False, "Masque CIDR invalide (0-32)."
        except ValueError:
            return False, "Masque CIDR doit être un nombre."
        cible = parties[0]

    # Validation IP
    pattern = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
    match = re.match(pattern, cible)
    if not match:
        return False, "Adresse IP invalide. Ex : 192.168.1.1"
    for groupe in match.groups():
        if int(groupe) > 255:
            return False, "Chaque octet doit être entre 0 et 255."
    return True, ""


# =============================================================
#  A — SCAN HOST DISCOVERY (Ping Sweep)
# =============================================================
def scan_hotes(plage):
    """
    Découverte des hôtes actifs sur une plage réseau.
    Technique : Ping Sweep (-sn) — ICMP Echo Request.
    Retourne une liste de dicts {ip, statut, hostname}.
    """
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=plage, arguments="-sn")
        hotes = []
        for host in nm.all_hosts():
            hotes.append({
                "ip":       host,
                "statut":   nm[host].state(),
                "hostname": nm[host].hostname() or "—",
            })
        return hotes
    except Exception as e:
        raise Exception(f"Erreur scan hôtes : {e}")


# =============================================================
#  B — OS FINGERPRINTING
# =============================================================
def scan_os(cible):
    """
    Identification du système d'exploitation via analyse TCP/IP.
    Technique : Nmap -O (OS detection) — nécessite les droits root/admin.
    Retourne une liste de dicts {ip, os_name, os_accuracy, os_family}.
    """
    try:
        nm = nmap.PortScanner()
        # -O  : détection OS
        # --osscan-guess : forcer une estimation même si incertaine
        nm.scan(hosts=cible, arguments="-O --osscan-guess")
        resultats = []
        for host in nm.all_hosts():
            os_name     = "Inconnu"
            os_accuracy = 0
            os_family   = "Inconnu"
            # Récupération des infos OS si disponibles
            if "osmatch" in nm[host] and nm[host]["osmatch"]:
                best = nm[host]["osmatch"][0]
                os_name     = best.get("name", "Inconnu")
                os_accuracy = int(best.get("accuracy", 0))
                if best.get("osclass"):
                    os_family = best["osclass"][0].get("osfamily", "Inconnu")
            resultats.append({
                "ip":          host,
                "statut":      nm[host].state(),
                "hostname":    nm[host].hostname() or "—",
                "os_name":     os_name,
                "os_accuracy": os_accuracy,
                "os_family":   os_family,
            })
        return resultats
    except Exception as e:
        raise Exception(f"Erreur OS Fingerprinting : {e}")


# =============================================================
#  C — SCAN DES PORTS ET SERVICES
# =============================================================
def scan_ports(cible):
    """
    Scan des ports ouverts et identification des services.
    Technique : Banner Grabbing + Version Detection (-sV).
    Analyse les 1000 ports les plus courants (--top-ports 1000).
    Retourne une liste de tuples pour la base de données.
    """
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=cible, arguments="-sV --top-ports 1000")
        resultats = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    info    = nm[host][proto][port]
                    statut  = info["state"]
                    service = info["name"]    or "inconnu"
                   # Récupération des résultats des scripts vuln
                    scripts = info.get("script", {})
                    vulns = " | ".join(scripts.values()) if scripts else "—"
                    # Attribution du score de risque
                    if port in SCORES_PORTS:
                        _, score, risque = SCORES_PORTS[port]
                    else:
                        score  = 15
                        risque = "Faible"
                    # Tuple : (port, protocole, statut, service, version, risque, score, vulns)
                    resultats.append((port, proto, statut, service, version, risque, score, vulns))
        return resultats
    except Exception as e:
        raise Exception(f"Erreur scan ports : {e}")


# =============================================================
#  CALCUL DU SCORE DE RISQUE GLOBAL
# =============================================================
def calculer_score(liste_ports):
    """
    Calcule le score de risque global (0-100) à partir
    de la liste des ports scannés.
    Retourne (score, niveau, recommandations).
    """
    if not liste_ports:
        return 0, "Faible", []

    scores       = [p[6] for p in liste_ports]
    score_global = min(100, int(sum(scores) / len(scores) * 1.5))

    if score_global >= 70:
        niveau = "Élevé"
    elif score_global >= 40:
        niveau = "Moyen"
    else:
        niveau = "Faible"

    # Recommandations automatiques basées sur les ports ouverts
    recos         = []
    ports_ouverts = [p[0] for p in liste_ports if p[2] == "open"]

    if 3306 in ports_ouverts:
        recos.append("URGENT : Fermer le port 3306 (MySQL) — ne jamais exposer une BDD sur le réseau")
    if 445 in ports_ouverts:
        recos.append("URGENT : Filtrer le port 445 (SMB) par pare-feu — vulnérable à WannaCry")
    if 23 in ports_ouverts:
        recos.append("URGENT : Désactiver Telnet (port 23) — remplacer par SSH")
    if 21 in ports_ouverts:
        recos.append("URGENT : Sécuriser FTP (port 21) — utiliser SFTP à la place")
    if 3389 in ports_ouverts:
        recos.append("MOYEN : Restreindre RDP (port 3389) aux adresses IP autorisées")
    if 22 in ports_ouverts:
        recos.append("MOYEN : Vérifier la version de SSH et désactiver l'accès root")
    if 80 in ports_ouverts and 443 not in ports_ouverts:
        recos.append("MOYEN : Activer HTTPS (port 443) et rediriger HTTP vers HTTPS")

    if not recos:
        recos.append("Aucune vulnérabilité critique détectée. Continuez à surveiller.")

    return score_global, niveau, recos
