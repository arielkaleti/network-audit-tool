# =============================================================
#  database.py — Gestion de la base de données MySQL
#  SecureAudit v2.0 — CSC 242
#  Séparation stricte UI / Logique (exigé par la grille)
#  Auteur : Arikuise
# =============================================================

import mysql.connector
from mysql.connector import Error

# ── Paramètres de connexion MySQL ────────────────────────────
DB_CONFIG = {
    "host":     "127.0.0.1",
    "port":     3306,
    "user":     "root",
    "password": "@Arikuise2008",          
    "database": "secureaudit"
}


# =============================================================
#  CONNEXION
# =============================================================
def get_connection():
    """
    Crée et retourne une connexion MySQL.
    Lève une exception si la connexion échoue.
    Utilisation : conn = get_connection() → toujours fermer après usage.
    """
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except Error as e:
        raise Exception(f"Erreur de connexion MySQL : {e}")


# =============================================================
#  INITIALISATION — Créer la base et les tables si nécessaire
# =============================================================
def initialiser_base():
    """
    Crée la base de données 'secureaudit' et toutes les tables
    si elles n'existent pas encore (idempotent).
    Retourne (True, message) ou (False, message_erreur).
    """
    try:
        # Connexion sans spécifier la base pour pouvoir la créer
        conn = mysql.connector.connect(
            host=DB_CONFIG["host"],
            port=DB_CONFIG["port"],
            user=DB_CONFIG["user"],
            password=DB_CONFIG["password"]
        )
        cursor = conn.cursor()

        cursor.execute("CREATE DATABASE IF NOT EXISTS secureaudit")
        cursor.execute("USE secureaudit")

        # Table des scans (historique principal)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id          INT AUTO_INCREMENT PRIMARY KEY,
                date_scan   DATETIME DEFAULT CURRENT_TIMESTAMP,
                cible       VARCHAR(100) NOT NULL,
                type_scan   VARCHAR(50),
                nb_hotes    INT DEFAULT 0,
                nb_ports    INT DEFAULT 0,
                score       INT DEFAULT 0,
                niveau      VARCHAR(20)
            )
        """)

        # Table des ports (résultats détaillés par scan)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ports (
                id          INT AUTO_INCREMENT PRIMARY KEY,
                scan_id     INT NOT NULL,
                port        INT,
                protocole   VARCHAR(10),
                statut      VARCHAR(20),
                service     VARCHAR(100),
                version     VARCHAR(100),
                risque      VARCHAR(20),
                score_port  INT DEFAULT 0,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
                    ON DELETE CASCADE
            )
        """)

        # Table OS (résultats fingerprinting)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS os_results (
                id          INT AUTO_INCREMENT PRIMARY KEY,
                scan_id     INT NOT NULL,
                ip          VARCHAR(50),
                hostname    VARCHAR(150),
                statut      VARCHAR(20),
                os_name     VARCHAR(200),
                os_accuracy INT DEFAULT 0,
                os_family   VARCHAR(100),
                FOREIGN KEY (scan_id) REFERENCES scans(id)
                    ON DELETE CASCADE
            )
        """)

        # Table des équipements (gestion manuelle)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS equipements (
                id          INT AUTO_INCREMENT PRIMARY KEY,
                nom         VARCHAR(100) NOT NULL,
                adresse_ip  VARCHAR(50),
                type_eq     VARCHAR(50),
                os          VARCHAR(100),
                statut      VARCHAR(20) DEFAULT 'Actif',
                date_ajout  DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()
        cursor.close()
        conn.close()
        return True, "Base initialisée avec succès"

    except Error as e:
        return False, f"Erreur initialisation : {e}"


# =============================================================
#  CRUD — SCANS
# =============================================================

def creer_scan(cible, type_scan, nb_hotes, nb_ports, score, niveau):
    """CREATE — Enregistre un nouveau scan dans l'historique."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scans (cible, type_scan, nb_hotes, nb_ports, score, niveau)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (cible, type_scan, nb_hotes, nb_ports, score, niveau))
        conn.commit()
        scan_id = cursor.lastrowid
        cursor.close()
        conn.close()
        return scan_id
    except Error as e:
        raise Exception(f"Erreur création scan : {e}")


def lire_scans():
    """READ — Retourne tous les scans triés par date décroissante."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, date_scan, cible, type_scan,
                   nb_hotes, nb_ports, score, niveau
            FROM scans
            ORDER BY date_scan DESC
        """)
        resultats = cursor.fetchall()
        cursor.close()
        conn.close()
        return resultats
    except Error as e:
        raise Exception(f"Erreur lecture scans : {e}")


def supprimer_scan(scan_id):
    """DELETE — Supprime un scan et ses ports/OS associés (CASCADE)."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans WHERE id = %s", (scan_id,))
        conn.commit()
        cursor.close()
        conn.close()
    except Error as e:
        raise Exception(f"Erreur suppression scan : {e}")


# =============================================================
#  CRUD — PORTS
# =============================================================

def creer_ports(scan_id, liste_ports):
    """
    CREATE — Enregistre la liste des ports d'un scan.
    liste_ports : liste de tuples
        (port, protocole, statut, service, version, risque, score_port)
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        for port in liste_ports:
            cursor.execute("""
                INSERT INTO ports
                    (scan_id, port, protocole, statut,
                     service, version, risque, score_port)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (scan_id, *port))
        conn.commit()
        cursor.close()
        conn.close()
    except Error as e:
        raise Exception(f"Erreur création ports : {e}")


def lire_ports(scan_id):
    """READ — Retourne les ports d'un scan spécifique."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT port, protocole, statut, service,
                   version, risque, score_port
            FROM ports
            WHERE scan_id = %s
            ORDER BY score_port DESC
        """, (scan_id,))
        resultats = cursor.fetchall()
        cursor.close()
        conn.close()
        return resultats
    except Error as e:
        raise Exception(f"Erreur lecture ports : {e}")


# =============================================================
#  CRUD — OS FINGERPRINTING
# =============================================================

def creer_os_results(scan_id, liste_os):
    """
    CREATE — Enregistre les résultats OS d'un scan.
    liste_os : liste de dicts {ip, hostname, statut, os_name, os_accuracy, os_family}
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        for h in liste_os:
            cursor.execute("""
                INSERT INTO os_results
                    (scan_id, ip, hostname, statut, os_name, os_accuracy, os_family)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (scan_id,
                  h.get("ip", ""),
                  h.get("hostname", "—"),
                  h.get("statut", ""),
                  h.get("os_name", "Inconnu"),
                  h.get("os_accuracy", 0),
                  h.get("os_family", "Inconnu")))
        conn.commit()
        cursor.close()
        conn.close()
    except Error as e:
        raise Exception(f"Erreur création OS results : {e}")


def lire_os_results(scan_id):
    """READ — Retourne les résultats OS d'un scan."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ip, hostname, statut, os_name, os_accuracy, os_family
            FROM os_results
            WHERE scan_id = %s
            ORDER BY os_accuracy DESC
        """, (scan_id,))
        resultats = cursor.fetchall()
        cursor.close()
        conn.close()
        return resultats
    except Error as e:
        raise Exception(f"Erreur lecture OS results : {e}")


# =============================================================
#  CRUD — ÉQUIPEMENTS
# =============================================================

def creer_equipement(nom, adresse_ip, type_eq, os, statut):
    """CREATE — Ajoute un équipement manuellement."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO equipements (nom, adresse_ip, type_eq, os, statut)
            VALUES (%s, %s, %s, %s, %s)
        """, (nom, adresse_ip, type_eq, os, statut))
        conn.commit()
        cursor.close()
        conn.close()
    except Error as e:
        raise Exception(f"Erreur création équipement : {e}")


def lire_equipements():
    """READ — Retourne tous les équipements triés par date d'ajout."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, nom, adresse_ip, type_eq, os, statut
            FROM equipements
            ORDER BY date_ajout DESC
        """)
        resultats = cursor.fetchall()
        cursor.close()
        conn.close()
        return resultats
    except Error as e:
        raise Exception(f"Erreur lecture équipements : {e}")


def modifier_equipement(eq_id, nom, adresse_ip, type_eq, os, statut):
    """UPDATE — Modifie un équipement existant."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE equipements
            SET nom=%s, adresse_ip=%s, type_eq=%s, os=%s, statut=%s
            WHERE id=%s
        """, (nom, adresse_ip, type_eq, os, statut, eq_id))
        conn.commit()
        cursor.close()
        conn.close()
    except Error as e:
        raise Exception(f"Erreur modification équipement : {e}")


def supprimer_equipement(eq_id):
    """DELETE — Supprime un équipement."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM equipements WHERE id = %s", (eq_id,))
        conn.commit()
        cursor.close()
        conn.close()
    except Error as e:
        raise Exception(f"Erreur suppression équipement : {e}")


def tester_connexion():
    """Teste si la connexion MySQL fonctionne. Retourne True/False."""
    try:
        conn = get_connection()
        conn.close()
        return True
    except Exception:
        return False
