# =============================================================
#  audit_reseau.py — Interface graphique principale
#  SecureAudit v2.0 — CSC 242
#  Auteur : Arikuise
#  Bibliothèques : tkinter, mysql-connector-python, python-nmap,
#                  reportlab (export PDF)
# =============================================================

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import datetime
import database as db
import scanner as sc

# ── Palette : Blanc + Bleu Marine professionnel ───────────────
MARINE      = "#1a3a5c"   # sidebar, accents forts
MARINE_DARK = "#0f2540"   # hover sidebar
MARINE_MID  = "#254d7a"   # boutons secondaires
MARINE_LIGHT= "#dce8f5"   # badges, fonds légers
BLANC       = "#ffffff"
GRIS_CLAIR  = "#f4f6f9"
GRIS_BORD   = "#e0e6ed"
TEXTE       = "#000000"   # police noire
TEXTE_MUTED = "#5a6a7a"
FONT        = "Courier"

# Couleurs sémantiques (risques)
ROUGE       = "#c0392b"
ORANGE      = "#d35400"
VERT_OK     = "#1a7a4a"


# =============================================================
#  CLASSE PRINCIPALE
# =============================================================
class SecureAuditApp:
    """
    Classe principale de l'application SecureAudit.
    Gère l'interface graphique Tkinter et orchestre les appels
    aux modules scanner.py et database.py.
    Justification POO : encapsule l'état global (widgets, données
    en cours, navigation) et évite les variables globales.
    """

    def __init__(self, root):
        self.root = root
        self.root.title("SecureAudit v2.0 — Audit & Pentest Réseau")
        self.root.geometry("1050x650")
        self.root.resizable(True, True)
        try:
            self.root.state("zoomed")
        except Exception:
            pass

        # État interne
        self.nav_buttons      = {}
        self.tab_buttons      = {}
        self.tab_frames       = {}
        self.active_nav       = None
        self.derniers_ports   = []   # résultats du dernier scan ports
        self.derniers_os      = []   # résultats du dernier scan OS
        self.derniere_cible   = ""
        self._placeholder     = ""

        self._init_base()
        self._build_menu()
        self._build_ui()
        self._switch_nav("hosts")
        self._charger_historique()

    # ----------------------------------------------------------
    #  INITIALISATION BASE
    # ----------------------------------------------------------
    def _init_base(self):
        """Initialise la base MySQL au démarrage."""
        ok, msg = db.initialiser_base()
        if not ok:
            messagebox.showerror("Erreur MySQL",
                f"Impossible d'initialiser MySQL :\n{msg}\n\n"
                "Vérifiez que MySQL est démarré.")

    # ----------------------------------------------------------
    #  MENU PRINCIPAL
    # ----------------------------------------------------------
    def _build_menu(self):
        menubar = tk.Menu(self.root)

        m_fichier = tk.Menu(menubar, tearoff=0)
        m_fichier.add_command(label="Nouveau scan",
            command=lambda: self._switch_nav("hosts"))
        m_fichier.add_separator()
        m_fichier.add_command(label="Exporter le rapport PDF",
            command=self._exporter_pdf)
        m_fichier.add_separator()
        m_fichier.add_command(label="Quitter", command=self.root.quit)
        menubar.add_cascade(label="Fichier", menu=m_fichier)

        m_bdd = tk.Menu(menubar, tearoff=0)
        m_bdd.add_command(label="Tester la connexion MySQL",
            command=self._tester_connexion)
        m_bdd.add_separator()
        m_bdd.add_command(label="Gérer les équipements",
            command=lambda: self._switch_nav("equip"))
        m_bdd.add_command(label="Voir l'historique",
            command=lambda: self._switch_nav("hist"))
        m_bdd.add_separator()
        m_bdd.add_command(label="Vider l'historique",
            command=self._vider_historique)
        menubar.add_cascade(label="Base de données", menu=m_bdd)

        m_aide = tk.Menu(menubar, tearoff=0)
        m_aide.add_command(label="À propos", command=self._a_propos)
        menubar.add_cascade(label="Aide", menu=m_aide)

        self.root.config(menu=menubar)

    # ----------------------------------------------------------
    #  CONSTRUCTION UI
    # ----------------------------------------------------------
    def _build_ui(self):
        self._build_sidebar()
        self._build_main()

    def _build_sidebar(self):
        """Sidebar de navigation — bleu marine professionnel."""
        self.sidebar = tk.Frame(self.root, bg=MARINE, width=210)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # Logo
        logo = tk.Frame(self.sidebar, bg=MARINE, padx=14, pady=14)
        logo.pack(fill="x")
        tk.Label(logo, text="SecureAudit",
                 bg=MARINE, fg=BLANC,
                 font=(FONT, 13, "bold")).pack(anchor="w")
        tk.Label(logo, text="v2.0 — Pentest Réseau",
                 bg=MARINE, fg=MARINE_LIGHT,
                 font=(FONT, 8)).pack(anchor="w")
        tk.Frame(self.sidebar, bg=MARINE_DARK, height=1).pack(fill="x")

        nav = tk.Frame(self.sidebar, bg=MARINE)
        nav.pack(fill="both", expand=True, pady=6)

        # Section SCAN — 3 fonctionnalités du sujet
        self._nav_section(nav, "SCAN")
        self._nav_btn(nav, "hosts", "A", "Host Discovery")
        self._nav_btn(nav, "os",    "B", "OS Fingerprinting")
        self._nav_btn(nav, "ports", "C", "Audit Services & Vulnérabilités")

        # Section ANALYSE
        self._nav_section(nav, "ANALYSE")
        self._nav_btn(nav, "risk",  "*", "Score de risque")
        self._nav_btn(nav, "hist",  "~", "Historique")

        # Section GESTION
        self._nav_section(nav, "GESTION")
        self._nav_btn(nav, "equip", "=", "Équipements")

        # Statuts en bas
        tk.Frame(self.sidebar, bg=MARINE_DARK, height=1).pack(
            fill="x", side="bottom")
        bot = tk.Frame(self.sidebar, bg=MARINE, pady=10)
        bot.pack(side="bottom", fill="x")

        self.lbl_mysql = tk.Label(bot, text="● MySQL non connecté",
            bg=MARINE, fg="#ffffff", font=(FONT, 8))
        self.lbl_mysql.pack(anchor="w", padx=14)

        self.lbl_nmap = tk.Label(bot, text="● Nmap non connecté",
            bg=MARINE, fg="#ffffff", font=(FONT, 8))
        self.lbl_nmap.pack(anchor="w", padx=14)

        self._maj_statut_mysql()

    def _nav_section(self, parent, label):
        tk.Label(parent, text=label,
                 bg=MARINE, fg=MARINE_LIGHT,
                 font=(FONT, 8)).pack(anchor="w", padx=14, pady=(10, 2))

    def _nav_btn(self, parent, key, icon, label):
        btn = tk.Button(parent,
            text=f"  [{icon}]  {label}", anchor="w",
            bg=MARINE, fg=BLANC,
            activebackground=MARINE_DARK, activeforeground=BLANC,
            relief="flat", bd=0, padx=10, pady=7,
            font=(FONT, 9), cursor="hand2",
            command=lambda k=key: self._switch_nav(k))
        btn.pack(fill="x", padx=8, pady=1)
        self.nav_buttons[key] = btn

    # ----------------------------------------------------------
    def _build_main(self):
        self.main = tk.Frame(self.root, bg=GRIS_CLAIR)
        self.main.pack(side="left", fill="both", expand=True)
        self._build_topbar()
        self._build_metrics()
        self._build_input_row()
        self._build_content_area()
        self._build_statusbar()

    def _build_topbar(self):
        bar = tk.Frame(self.main, bg=BLANC, height=48)
        bar.pack(fill="x")
        bar.pack_propagate(False)
        self.lbl_title = tk.Label(bar, text="",
            bg=BLANC, fg=TEXTE, font=(FONT, 11, "bold"), padx=16)
        self.lbl_title.pack(side="left", pady=12)
        self.lbl_badge = tk.Label(bar, text="Prêt",
            bg=MARINE, fg=BLANC, font=(FONT, 8), padx=10, pady=3)
        self.lbl_badge.pack(side="right", padx=16)
        tk.Frame(self.main, bg=GRIS_BORD, height=1).pack(fill="x")

    def _build_metrics(self):
        bar = tk.Frame(self.main, bg=GRIS_CLAIR, pady=10)
        bar.pack(fill="x")
        tk.Frame(self.main, bg=GRIS_BORD, height=1).pack(fill="x")
        inner = tk.Frame(bar, bg=GRIS_CLAIR)
        inner.pack(padx=14)
        specs = [
            ("Hôtes actifs",   "m_hosts", MARINE),
            ("Ports ouverts",  "m_ports", MARINE),
            ("Risques élevés", "m_risks", MARINE),
            ("Score global",   "m_score", TEXTE),
        ]
        for i, (label, attr, color) in enumerate(specs):
            card = tk.Frame(inner, bg=BLANC, padx=18, pady=8)
            card.grid(row=0, column=i, padx=6)
            tk.Label(card, text=label, bg=BLANC, fg=TEXTE_MUTED,
                     font=(FONT, 8)).pack(anchor="w")
            lbl = tk.Label(card, text="0", bg=BLANC, fg=color,
                           font=(FONT, 22, "bold"))
            lbl.pack(anchor="w")
            setattr(self, attr, lbl)
        self.m_score.configure(text="--", fg=TEXTE)

    def _build_input_row(self):
        row = tk.Frame(self.main, bg=BLANC, pady=9)
        row.pack(fill="x")
        tk.Frame(self.main, bg=GRIS_BORD, height=1).pack(fill="x")
        inner = tk.Frame(row, bg=BLANC)
        inner.pack(padx=14, fill="x")

        self.entry_target = tk.Entry(inner, font=(FONT, 10),
            fg=TEXTE_MUTED, bg=GRIS_CLAIR, relief="flat", bd=4, width=26)
        self.entry_target.insert(0, "Ex : 192.168.1.0/24")
        self.entry_target.bind("<FocusIn>",  self._focus_in)
        self.entry_target.bind("<FocusOut>", self._focus_out)
        self.entry_target.pack(side="left", ipady=4, padx=(0, 8))

        self.scan_var = tk.StringVar(value="Ping Sweep (-sn)")
        self.combo = ttk.Combobox(inner, textvariable=self.scan_var,
            font=(FONT, 9), state="readonly", width=22)
        self.combo["values"] = ["Ping Sweep (-sn)", "OS Fingerprinting (-O)",
                                "Port + Services (-sV)"]
        self.combo.pack(side="left", ipady=3, padx=(0, 8))

        tk.Button(inner, text="▶  Scanner",
            bg=MARINE, fg=BLANC, activebackground=MARINE_DARK,
            activeforeground=BLANC, relief="flat",
            font=(FONT, 9, "bold"), padx=14, pady=5, cursor="hand2",
            command=self._on_scan).pack(side="left", padx=(0, 6))

        tk.Button(inner, text="X  Effacer",
            bg=GRIS_CLAIR, fg=TEXTE, activebackground=GRIS_BORD,
            relief="flat", font=(FONT, 9), padx=10, pady=5, cursor="hand2",
            command=self._on_clear).pack(side="left", padx=(0, 6))

        tk.Button(inner, text="⬇  Export PDF",
            bg=MARINE_LIGHT, fg=MARINE, activebackground=GRIS_BORD,
            relief="flat", font=(FONT, 9), padx=10, pady=5, cursor="hand2",
            command=self._exporter_pdf).pack(side="left")

    def _build_content_area(self):
        self.content = tk.Frame(self.main, bg=BLANC)
        self.content.pack(fill="both", expand=True)

        self.tabs_bar = tk.Frame(self.content, bg=BLANC)
        self.tabs_bar.pack(fill="x")
        tk.Frame(self.content, bg=GRIS_BORD, height=1).pack(fill="x")

        onglets = [
            ("hosts_tab", "Hôtes actifs"),
            ("os_tab",    "OS Fingerprinting"),
            ("ports_tab", "Ports & Services"),
            ("risk_tab",  "Score de risque"),
            ("hist_tab",  "Historique"),
            ("equip_tab", "Équipements"),
        ]
        for key, label in onglets:
            btn = tk.Button(self.tabs_bar, text=label,
                bg=BLANC, fg=TEXTE_MUTED, activebackground=BLANC,
                relief="flat", bd=0, font=(FONT, 9),
                padx=14, pady=8, cursor="hand2",
                command=lambda k=key: self._switch_tab(k))
            btn.pack(side="left")
            self.tab_buttons[key] = btn

        self.tab_area = tk.Frame(self.content, bg=BLANC)
        self.tab_area.pack(fill="both", expand=True)

        self._build_tab_hosts()
        self._build_tab_os()
        self._build_tab_ports()
        self._build_tab_risk()
        self._build_tab_hist()
        self._build_tab_equip()
        self._switch_tab("hosts_tab")

    # ----------------------------------------------------------
    #  ONGLETS
    # ----------------------------------------------------------
    def _build_tab_hosts(self):
        f = tk.Frame(self.tab_area, bg=BLANC)
        self.tab_frames["hosts_tab"] = f
        cols   = ["IP", "Statut", "Hostname"]
        widths = [150, 80, 300]
        self.tree_hosts = self._make_treeview(f, cols, widths)

    def _build_tab_os(self):
        """Onglet B — OS Fingerprinting."""
        f = tk.Frame(self.tab_area, bg=BLANC)
        self.tab_frames["os_tab"] = f
        cols   = ["IP", "Hostname", "Statut", "OS détecté", "Fiabilité (%)", "Famille OS"]
        widths = [120, 160, 70, 250, 90, 120]
        self.tree_os = self._make_treeview(f, cols, widths)

    def _build_tab_ports(self):
        f = tk.Frame(self.tab_area, bg=BLANC)
        self.tab_frames["ports_tab"] = f
        cols   = ["Port", "Protocole", "Statut", "Service / Version", "Risque", "Score", "Vulnérabilités"]
        widths = [55, 75, 75, 200, 80, 60, 400]
        self.tree_ports = self._make_treeview(f, cols, widths)

    def _build_tab_risk(self):
        f = tk.Frame(self.tab_area, bg=BLANC)
        self.tab_frames["risk_tab"] = f

        top = tk.Frame(f, bg=BLANC)
        top.pack(fill="x", padx=14, pady=12)

        score_card = tk.Frame(top, bg=GRIS_CLAIR, padx=20, pady=14)
        score_card.pack(side="left", fill="y", padx=(0, 12))
        tk.Label(score_card, text="Score de risque global",
                 bg=GRIS_CLAIR, fg=TEXTE_MUTED, font=(FONT, 8)).pack(anchor="w")
        self.lbl_score_big = tk.Label(score_card, text="--",
            bg=GRIS_CLAIR, fg=TEXTE, font=(FONT, 38, "bold"))
        self.lbl_score_big.pack(anchor="w")
        self.lbl_score_level = tk.Label(score_card, text="EN ATTENTE",
            bg=GRIS_CLAIR, fg=TEXTE_MUTED, font=(FONT, 8, "bold"))
        self.lbl_score_level.pack(anchor="w")

        stats = tk.Frame(top, bg=BLANC)
        stats.pack(side="left", fill="both", expand=True)
        mini = [
            ("Ports critiques",    "s_critical", ROUGE),
            ("Services obsolètes", "s_obsolete", ORANGE),
            ("Recommandations",    "s_reco",     VERT_OK),
        ]
        for label, attr, color in mini:
            card = tk.Frame(stats, bg=GRIS_CLAIR, padx=12, pady=6)
            card.pack(fill="x", pady=3)
            tk.Label(card, text=label, bg=GRIS_CLAIR, fg=TEXTE_MUTED,
                     font=(FONT, 8)).pack(anchor="w")
            lbl = tk.Label(card, text="--", bg=GRIS_CLAIR, fg=color,
                           font=(FONT, 15, "bold"))
            lbl.pack(anchor="w")
            setattr(self, attr, lbl)

        tk.Frame(f, bg=GRIS_BORD, height=1).pack(fill="x", padx=14)
        reco_frame = tk.Frame(f, bg=GRIS_CLAIR, padx=14, pady=10)
        reco_frame.pack(fill="both", expand=True, padx=14, pady=8)
        tk.Label(reco_frame, text="RECOMMANDATIONS",
                 bg=GRIS_CLAIR, fg=TEXTE_MUTED, font=(FONT, 8)).pack(
                     anchor="w", pady=(0, 6))
        self.txt_reco = scrolledtext.ScrolledText(reco_frame,
            font=(FONT, 9), bg=GRIS_CLAIR, fg=TEXTE,
            relief="flat", bd=0, height=6, state="disabled")
        self.txt_reco.pack(fill="both", expand=True)
        self._set_reco("Lancez un scan pour voir les recommandations.")

    def _build_tab_hist(self):
        f = tk.Frame(self.tab_area, bg=BLANC)
        self.tab_frames["hist_tab"] = f

        btn_frame = tk.Frame(f, bg=BLANC)
        btn_frame.pack(fill="x", padx=14, pady=6)
        tk.Button(btn_frame, text="Supprimer la sélection",
            bg="#FCEBEB", fg=ROUGE, relief="flat",
            font=(FONT, 9), padx=10, pady=4, cursor="hand2",
            command=self._supprimer_scan_selectionne).pack(side="left")

        cols   = ["ID", "Date", "Cible", "Type", "Hôtes", "Ports", "Score", "Niveau"]
        widths = [40, 140, 130, 130, 55, 55, 60, 80]
        self.tree_hist = self._make_treeview(f, cols, widths)

    def _build_tab_equip(self):
        f = tk.Frame(self.tab_area, bg=BLANC)
        self.tab_frames["equip_tab"] = f

        btn_frame = tk.Frame(f, bg=BLANC)
        btn_frame.pack(fill="x", padx=14, pady=6)
        tk.Button(btn_frame, text="+ Ajouter",
            bg=MARINE, fg=BLANC, relief="flat",
            font=(FONT, 9, "bold"), padx=10, pady=4, cursor="hand2",
            command=self._ajouter_equipement).pack(side="left", padx=(0, 6))
        tk.Button(btn_frame, text="Modifier",
            bg=GRIS_CLAIR, fg=TEXTE, relief="flat",
            font=(FONT, 9), padx=10, pady=4, cursor="hand2",
            command=self._modifier_equipement).pack(side="left", padx=(0, 6))
        tk.Button(btn_frame, text="Supprimer",
            bg="#FCEBEB", fg=ROUGE, relief="flat",
            font=(FONT, 9), padx=10, pady=4, cursor="hand2",
            command=self._supprimer_equipement).pack(side="left")

        cols   = ["ID", "Nom", "Adresse IP", "Type", "OS", "Statut"]
        widths = [40, 160, 120, 100, 150, 80]
        self.tree_equip = self._make_treeview(f, cols, widths)

    def _build_statusbar(self):
        tk.Frame(self.main, bg=GRIS_BORD, height=1).pack(
            fill="x", side="bottom")
        bar = tk.Frame(self.main, bg=BLANC, height=26)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)
        self.lbl_status = tk.Label(bar, text="En attente",
            bg=BLANC, fg=TEXTE_MUTED, font=(FONT, 8), padx=14)
        self.lbl_status.pack(side="left", pady=4)
        self.lbl_count = tk.Label(bar, text="0 résultats",
            bg=BLANC, fg=TEXTE_MUTED, font=(FONT, 8), padx=14)
        self.lbl_count.pack(side="right", pady=4)

    # ----------------------------------------------------------
    def _make_treeview(self, parent, cols, widths):
        frame = tk.Frame(parent, bg=BLANC)
        frame.pack(fill="both", expand=True, padx=14, pady=6)
        tree = ttk.Treeview(frame, columns=cols, show="headings", height=14)
        for col, w in zip(cols, widths):
            tree.heading(col, text=col)
            tree.column(col, width=w, anchor="w", stretch=False)
        sb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        return tree

    # ----------------------------------------------------------
    #  NAVIGATION
    # ----------------------------------------------------------
    NAV_META = {
        "hosts": ("A — Inventaire des hôtes actifs",
                  ["Ping Sweep (-sn)", "OS Fingerprinting (-O)", "Port + Services (-sV)"],
                  "Ex : 192.168.1.0/24"),
        "os":    ("B — Identification des systèmes d'exploitation",
                  ["OS Fingerprinting (-O)", "Ping Sweep (-sn)"],
                  "Ex : 192.168.1.10"),
        "ports": ("C — Analyse des services et ports ouverts",
                  ["Port + Services (-sV)", "Ping Sweep (-sn)"],
                  "Ex : 192.168.1.10"),
        "risk":  ("Score de risque global",
                  ["Port + Services (-sV)", "OS Fingerprinting (-O)"],
                  "IP ou plage analysée"),
        "hist":  ("Historique des scans",
                  ["Port + Services (-sV)", "OS Fingerprinting (-O)"], ""),
        "equip": ("Gestion des équipements réseau",
                  ["Port + Services (-sV)", "OS Fingerprinting (-O)"], ""),
    }

    def _switch_nav(self, key):
        self.active_nav = key
        meta = self.NAV_META.get(key, ("", [], ""))
        for k, btn in self.nav_buttons.items():
            btn.configure(
                bg=MARINE_MID if k == key else MARINE,
                fg=BLANC)
        self.lbl_title.configure(text=meta[0])
        self.lbl_badge.configure(text="Prêt", bg=MARINE_LIGHT, fg=MARINE)
        self.entry_target.delete(0, "end")
        self.entry_target.configure(fg=TEXTE_MUTED if meta[2] else TEXTE)
        self.entry_target.insert(0, meta[2])
        self._placeholder = meta[2]
        self.combo["values"] = meta[1]
        self.scan_var.set(meta[1][0])
        self.lbl_status.configure(text="En attente")
        self.lbl_count.configure(text="0 résultats")
        tab_map = {
            "hosts": "hosts_tab",
            "os":    "os_tab",
            "ports": "ports_tab",
            "risk":  "risk_tab",
            "hist":  "hist_tab",
            "equip": "equip_tab",
        }
        if key in tab_map:
            self._switch_tab(tab_map[key])
        if key == "hist":
            self._charger_historique()
        elif key == "equip":
            self._charger_equipements()

    def _switch_tab(self, key):
        for f in self.tab_frames.values():
            f.pack_forget()
        if key in self.tab_frames:
            self.tab_frames[key].pack(fill="both", expand=True)
        for k, btn in self.tab_buttons.items():
            btn.configure(
                fg=MARINE if k == key else TEXTE_MUTED,
                font=(FONT, 9, "bold") if k == key else (FONT, 9))

    def _focus_in(self, _):
        if self.entry_target.get() == self._placeholder:
            self.entry_target.delete(0, "end")
            self.entry_target.configure(fg=TEXTE)

    def _focus_out(self, _):
        if self.entry_target.get() == "":
            self.entry_target.configure(fg=TEXTE_MUTED)
            self.entry_target.insert(0, self._placeholder)

    # ----------------------------------------------------------
    #  SCAN — ORCHESTRATION
    # ----------------------------------------------------------
    def _on_scan(self):
        """Valide la cible et lance le scan dans un thread dédié."""
        cible = self.entry_target.get().strip()
        if not cible or cible == self._placeholder:
            messagebox.showwarning("Champ vide",
                "Veuillez entrer une adresse IP ou une plage réseau.")
            return
        valide, msg_erreur = sc.valider_cible(cible)
        if not valide:
            messagebox.showerror("Adresse invalide", msg_erreur)
            return
        self.derniere_cible = cible
        self.lbl_badge.configure(text="Scan en cours...",
            bg="#fff3cd", fg="#856404")
        self.lbl_status.configure(text=f"Scan en cours : {cible}")
        self.lbl_count.configure(text="--")
        threading.Thread(target=self._executer_scan,
                         args=(cible,), daemon=True).start()

    def _executer_scan(self, cible):
        """Exécuté dans un thread — appelle le bon scanner selon le mode."""
        try:
            type_scan = self.scan_var.get()

            if type_scan == "Ping Sweep (-sn)":
                # Fonctionnalité A — Host Discovery
                hotes = sc.scan_hotes(cible)
                scan_id = db.creer_scan(cible, type_scan, len(hotes), 0, 0, "—")
                self.root.after(0, lambda h=hotes, sid=scan_id:
                    self._afficher_hotes(h, sid))

            elif type_scan == "OS Fingerprinting (-O)":
                # Fonctionnalité B — OS Fingerprinting
                resultats_os = sc.scan_os(cible)
                scan_id = db.creer_scan(cible, type_scan,
                                        len(resultats_os), 0, 0, "—")
                if resultats_os:
                    db.creer_os_results(scan_id, resultats_os)
                self.derniers_os = resultats_os
                self.root.after(0, lambda r=resultats_os:
                    self._afficher_os(r))
                self.root.after(0, lambda: self.lbl_nmap.configure(
                    text="● Nmap connecté", fg="#1a7a4a"))

            else:
                # Fonctionnalité C — Port Scanner
                liste_ports = sc.scan_ports(cible)
                self.derniers_ports = liste_ports
                score, niveau, recos = sc.calculer_score(liste_ports)
                ports_ouverts = [p for p in liste_ports if p[2] == "open"]
                nb_risques    = len([p for p in liste_ports if p[5] == "Élevé"])
                scan_id = db.creer_scan(cible, type_scan, 1,
                                        len(ports_ouverts), score, niveau)
                if liste_ports:
                    db.creer_ports(scan_id, liste_ports)
                self.root.after(0, lambda lp=liste_ports, s=score,
                    n=niveau, r=recos, nb=nb_risques:
                    self._afficher_resultats(lp, s, n, r, nb))
                self.root.after(0, lambda: self.lbl_nmap.configure(
                    text="● Nmap connecté", fg="#1a7a4a"))

            self.root.after(0, self._charger_historique)

        except Exception as e:
            self.root.after(0, lambda err=e: messagebox.showerror(
                "Erreur de scan",
                f"Le scan a échoué :\n{err}\n\n"
                "Vérifiez que Nmap est installé (et droits root pour -O)."))
            self.root.after(0, lambda: self.lbl_badge.configure(
                text="Erreur", bg="#FCEBEB", fg=ROUGE))

    # ----------------------------------------------------------
    #  AFFICHAGE DES RÉSULTATS
    # ----------------------------------------------------------
    def _afficher_hotes(self, hotes, scan_id):
        """Affiche les hôtes actifs dans l'onglet Hôtes."""
        for row in self.tree_hosts.get_children():
            self.tree_hosts.delete(row)
        for h in hotes:
            self.tree_hosts.insert("", "end",
                values=(h["ip"], h["statut"], h["hostname"]))
        self.m_hosts.configure(text=str(len(hotes)))
        self.lbl_badge.configure(text="Scan terminé",
            bg=MARINE_LIGHT, fg=MARINE)
        self.lbl_status.configure(text="Host Discovery terminé")
        self.lbl_count.configure(text=f"{len(hotes)} hôtes actifs")
        self._switch_tab("hosts_tab")
        self.lbl_nmap.configure(text="● Nmap connecté", fg="#1a7a4a")

    def _afficher_os(self, resultats):
        """Affiche les résultats OS Fingerprinting."""
        for row in self.tree_os.get_children():
            self.tree_os.delete(row)
        for r in resultats:
            self.tree_os.insert("", "end", values=(
                r["ip"], r["hostname"], r["statut"],
                r["os_name"], f"{r['os_accuracy']} %", r["os_family"]))
        self.m_hosts.configure(text=str(len(resultats)))
        self.lbl_badge.configure(text="Scan terminé",
            bg=MARINE_LIGHT, fg=MARINE)
        self.lbl_status.configure(text="OS Fingerprinting terminé")
        self.lbl_count.configure(text=f"{len(resultats)} hôtes analysés")
        self._switch_tab("os_tab")

    def _afficher_resultats(self, liste_ports, score, niveau, recos, nb_risques):
        """Affiche les résultats Port Scanner + Score de risque."""
        for row in self.tree_ports.get_children():
            self.tree_ports.delete(row)
        ports_ouverts = 0
        for port in liste_ports:
            if port[2] == "open":
                ports_ouverts += 1
            self.tree_ports.insert("", "end", values=(
                port[0], port[1], port[2],
                f"{port[3]} {port[4]}".strip(),
                port[5], port[6]))
        self.m_hosts.configure(text="1")
        self.m_ports.configure(text=str(ports_ouverts))
        self.m_risks.configure(text=str(nb_risques))
        couleur = (ROUGE if score >= 70 else ORANGE if score >= 40 else VERT_OK)
        self.m_score.configure(text=str(score), fg=couleur)
        self.lbl_score_big.configure(text=str(score), fg=couleur)
        self.lbl_score_level.configure(
            text=f"RISQUE {niveau.upper()}", fg=couleur)
        self.s_critical.configure(text=str(nb_risques))
        self.s_obsolete.configure(text=str(
            len([p for p in liste_ports if p[0] in [21, 23, 110]])))
        self.s_reco.configure(text=str(len(recos)))
        self._set_reco("\n".join(f"- {r}" for r in recos))
        self.lbl_badge.configure(text="Scan terminé",
            bg=MARINE_LIGHT, fg=MARINE)
        self.lbl_status.configure(text="Scan terminé avec succès")
        self.lbl_count.configure(text=f"{len(liste_ports)} résultats")
        self._charger_historique()

    def _on_clear(self):
        """Réinitialise tous les affichages."""
        for tree in [self.tree_hosts, self.tree_ports, self.tree_os]:
            for row in tree.get_children():
                tree.delete(row)
        self.m_hosts.configure(text="0")
        self.m_ports.configure(text="0")
        self.m_risks.configure(text="0")
        self.m_score.configure(text="--", fg=TEXTE)
        self.lbl_score_big.configure(text="--", fg=TEXTE)
        self.lbl_score_level.configure(text="EN ATTENTE", fg=TEXTE_MUTED)
        self.s_critical.configure(text="--")
        self.s_obsolete.configure(text="--")
        self.s_reco.configure(text="--")
        self._set_reco("Lancez un scan pour voir les recommandations.")
        self.lbl_status.configure(text="En attente")
        self.lbl_count.configure(text="0 résultats")
        self.lbl_badge.configure(text="Prêt", bg=MARINE_LIGHT, fg=MARINE)

    # ----------------------------------------------------------
    #  HISTORIQUE
    # ----------------------------------------------------------
    def _charger_historique(self):
        try:
            for row in self.tree_hist.get_children():
                self.tree_hist.delete(row)
            for s in db.lire_scans():
                self.tree_hist.insert("", "end", values=(
                    s[0], str(s[1])[:16], s[2], s[3],
                    s[4], s[5], s[6], s[7]))
            self.lbl_mysql.configure(text="● MySQL connecté", fg="#ffffff")
        except Exception:
            self.lbl_mysql.configure(text="● MySQL non connecté", fg="#ffffff")

    def _supprimer_scan_selectionne(self):
        sel = self.tree_hist.selection()
        if not sel:
            messagebox.showwarning("Aucune sélection",
                "Sélectionnez un scan à supprimer.")
            return
        if not messagebox.askyesno("Confirmer",
                "Supprimer ce scan de l'historique ?"):
            return
        try:
            scan_id = self.tree_hist.item(sel[0])["values"][0]
            db.supprimer_scan(scan_id)
            self._charger_historique()
            messagebox.showinfo("Succès", "Scan supprimé.")
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def _vider_historique(self):
        if not messagebox.askyesno("Confirmer",
                "Vider tout l'historique des scans ?"):
            return
        try:
            for s in db.lire_scans():
                db.supprimer_scan(s[0])
            self._charger_historique()
            messagebox.showinfo("Succès", "Historique vidé.")
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    # ----------------------------------------------------------
    #  ÉQUIPEMENTS
    # ----------------------------------------------------------
    def _charger_equipements(self):
        try:
            for row in self.tree_equip.get_children():
                self.tree_equip.delete(row)
            for eq in db.lire_equipements():
                self.tree_equip.insert("", "end", values=eq)
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def _form_equipement(self, titre, valeurs=None):
        """Formulaire modal pour ajouter/modifier un équipement."""
        fenetre = tk.Toplevel(self.root)
        fenetre.title(titre)
        fenetre.geometry("380x310")
        fenetre.configure(bg=BLANC)
        fenetre.resizable(False, False)
        fenetre.grab_set()

        champs  = ["Nom", "Adresse IP", "Type", "OS", "Statut"]
        defauts = valeurs or ["", "", "", "", "Actif"]
        entrees = {}

        for i, (champ, defaut) in enumerate(zip(champs, defauts)):
            tk.Label(fenetre, text=champ, bg=BLANC, fg=TEXTE,
                     font=(FONT, 9)).grid(row=i, column=0,
                         padx=16, pady=8, sticky="w")
            e = tk.Entry(fenetre, font=(FONT, 9),
                         bg=GRIS_CLAIR, relief="flat", bd=4, width=24)
            e.insert(0, str(defaut))
            e.grid(row=i, column=1, padx=8, pady=8)
            entrees[champ] = e

        return fenetre, entrees

    def _ajouter_equipement(self):
        fenetre, entrees = self._form_equipement("Ajouter un équipement")

        def valider():
            nom = entrees["Nom"].get().strip()
            ip  = entrees["Adresse IP"].get().strip()
            if not nom:
                messagebox.showwarning("Champ requis",
                    "Le nom est obligatoire.", parent=fenetre)
                return
            if ip:
                ok, msg = sc.valider_cible(ip)
                if not ok:
                    messagebox.showerror("IP invalide", msg, parent=fenetre)
                    return
            try:
                db.creer_equipement(nom, ip,
                    entrees["Type"].get().strip(),
                    entrees["OS"].get().strip(),
                    entrees["Statut"].get().strip() or "Actif")
                self._charger_equipements()
                fenetre.destroy()
                messagebox.showinfo("Succès", "Équipement ajouté.")
            except Exception as e:
                messagebox.showerror("Erreur", str(e), parent=fenetre)

        tk.Button(fenetre, text="Enregistrer",
            bg=MARINE, fg=BLANC, relief="flat",
            font=(FONT, 9, "bold"), padx=14, pady=5, cursor="hand2",
            command=valider).grid(row=5, column=0, columnspan=2, pady=14)

    def _modifier_equipement(self):
        sel = self.tree_equip.selection()
        if not sel:
            messagebox.showwarning("Aucune sélection",
                "Sélectionnez un équipement à modifier.")
            return
        vals  = self.tree_equip.item(sel[0])["values"]
        eq_id = vals[0]
        fenetre, entrees = self._form_equipement(
            "Modifier un équipement",
            valeurs=[vals[1], vals[2], vals[3], vals[4], vals[5]])

        def valider():
            nom = entrees["Nom"].get().strip()
            ip  = entrees["Adresse IP"].get().strip()
            if not nom:
                messagebox.showwarning("Champ requis",
                    "Le nom est obligatoire.", parent=fenetre)
                return
            if ip:
                ok, msg = sc.valider_cible(ip)
                if not ok:
                    messagebox.showerror("IP invalide", msg, parent=fenetre)
                    return
            try:
                db.modifier_equipement(eq_id, nom, ip,
                    entrees["Type"].get().strip(),
                    entrees["OS"].get().strip(),
                    entrees["Statut"].get().strip())
                self._charger_equipements()
                fenetre.destroy()
                messagebox.showinfo("Succès", "Équipement modifié.")
            except Exception as e:
                messagebox.showerror("Erreur", str(e), parent=fenetre)

        tk.Button(fenetre, text="Enregistrer",
            bg=MARINE, fg=BLANC, relief="flat",
            font=(FONT, 9, "bold"), padx=14, pady=5, cursor="hand2",
            command=valider).grid(row=5, column=0, columnspan=2, pady=14)

    def _supprimer_equipement(self):
        sel = self.tree_equip.selection()
        if not sel:
            messagebox.showwarning("Aucune sélection",
                "Sélectionnez un équipement à supprimer.")
            return
        if not messagebox.askyesno("Confirmer", "Supprimer cet équipement ?"):
            return
        try:
            eq_id = self.tree_equip.item(sel[0])["values"][0]
            db.supprimer_equipement(eq_id)
            self._charger_equipements()
            messagebox.showinfo("Succès", "Équipement supprimé.")
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    # ----------------------------------------------------------
    #  EXPORT PDF — LIVRABLE 3 (Rapport d'audit type)
    # ----------------------------------------------------------
    def _exporter_pdf(self):
        """
        Génère un rapport d'audit PDF professionnel.
        Livrable 3 du sujet : rapport d'audit type avec analyse des risques.
        Utilise reportlab (installé via requirements.txt).
        """
        try:
            from reportlab.lib.pagesizes import A4 # type: ignore
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.platypus import (SimpleDocTemplate, Paragraph,
                                            Spacer, Table, TableStyle,
                                            HRFlowable)
            from reportlab.lib.units import cm
        except ImportError:
            messagebox.showerror("Module manquant",
                "reportlab n'est pas installé.\n"
                "Exécutez : pip install reportlab")
            return

        chemin = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF", "*.pdf")],
            initialfile=f"rapport_audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            title="Enregistrer le rapport PDF")
        if not chemin:
            return

        # ── Couleurs ─────────────────────────────────────────
        C_MARINE = colors.HexColor("#1a3a5c")
        C_GRIS   = colors.HexColor("#f4f6f9")
        C_ROUGE  = colors.HexColor("#c0392b")
        C_ORANGE = colors.HexColor("#d35400")
        C_VERT   = colors.HexColor("#1a7a4a")
        C_BLANC  = colors.white
        C_BORD   = colors.HexColor("#e0e6ed")

        doc  = SimpleDocTemplate(chemin, pagesize=A4,
                                 leftMargin=2*cm, rightMargin=2*cm,
                                 topMargin=2*cm, bottomMargin=2*cm)
        st   = getSampleStyleSheet()
        elems = []

        def h1(txt):
            return Paragraph(txt, ParagraphStyle("h1",
                fontName="Helvetica-Bold", fontSize=18,
                textColor=C_MARINE, spaceAfter=6))

        def h2(txt):
            return Paragraph(txt, ParagraphStyle("h2",
                fontName="Helvetica-Bold", fontSize=13,
                textColor=C_MARINE, spaceBefore=12, spaceAfter=4))

        def para(txt, color=colors.black):
            return Paragraph(txt, ParagraphStyle("p",
                fontName="Helvetica", fontSize=10,
                textColor=color, spaceAfter=4, leading=14))

        # ── En-tête ───────────────────────────────────────────
        elems.append(h1("SecureAudit v2.0 — Rapport d'Audit Réseau"))
        elems.append(para(
            f"Généré le : {datetime.datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}"))
        if self.derniere_cible:
            elems.append(para(f"Cible analysée : <b>{self.derniere_cible}</b>"))
        elems.append(HRFlowable(width="100%", thickness=1,
                                color=C_MARINE, spaceAfter=10))

        # ── Section Score ─────────────────────────────────────
        score_txt = self.m_score.cget("text")
        niveau_txt = self.lbl_score_level.cget("text")
        elems.append(h2("Score de risque global"))
        score_color = (C_ROUGE if score_txt.isdigit() and int(score_txt) >= 70
                       else C_ORANGE if score_txt.isdigit() and int(score_txt) >= 40
                       else C_VERT)
        elems.append(para(f"Score : <b>{score_txt} / 100</b> — {niveau_txt}",
                          color=score_color))
        elems.append(Spacer(1, 6))

        # ── Section Ports ─────────────────────────────────────
        if self.derniers_ports:
            elems.append(h2("C — Analyse des services et ports ouverts"))
            data = [["Port", "Proto", "Statut", "Service / Version", "Risque", "Score"]]
            for p in self.derniers_ports:
                data.append([str(p[0]), p[1], p[2],
                              f"{p[3]} {p[4]}".strip()[:40], p[5], str(p[6])])
            t = Table(data, colWidths=[1.2*cm, 1.5*cm, 1.5*cm, 7*cm, 1.8*cm, 1.5*cm])
            t.setStyle(TableStyle([
                ("BACKGROUND",   (0,0), (-1,0), C_MARINE),
                ("TEXTCOLOR",    (0,0), (-1,0), C_BLANC),
                ("FONTNAME",     (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE",     (0,0), (-1,-1), 8),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_BLANC, C_GRIS]),
                ("GRID",         (0,0), (-1,-1), 0.3, C_BORD),
                ("ALIGN",        (0,0), (-1,-1), "LEFT"),
                ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
                ("TOPPADDING",   (0,0), (-1,-1), 4),
                ("BOTTOMPADDING",(0,0), (-1,-1), 4),
            ]))
            elems.append(t)
            elems.append(Spacer(1, 10))

        # ── Section OS ────────────────────────────────────────
        if self.derniers_os:
            elems.append(h2("B — Identification des systèmes d'exploitation"))
            data_os = [["IP", "Hostname", "OS détecté", "Fiabilité", "Famille"]]
            for r in self.derniers_os:
                data_os.append([r["ip"], r["hostname"][:20],
                                 r["os_name"][:35],
                                 f"{r['os_accuracy']} %", r["os_family"]])
            t2 = Table(data_os, colWidths=[2.5*cm, 3*cm, 6*cm, 1.8*cm, 2.5*cm])
            t2.setStyle(TableStyle([
                ("BACKGROUND",   (0,0), (-1,0), C_MARINE),
                ("TEXTCOLOR",    (0,0), (-1,0), C_BLANC),
                ("FONTNAME",     (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE",     (0,0), (-1,-1), 8),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_BLANC, C_GRIS]),
                ("GRID",         (0,0), (-1,-1), 0.3, C_BORD),
                ("ALIGN",        (0,0), (-1,-1), "LEFT"),
                ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
                ("TOPPADDING",   (0,0), (-1,-1), 4),
                ("BOTTOMPADDING",(0,0), (-1,-1), 4),
            ]))
            elems.append(t2)
            elems.append(Spacer(1, 10))

        # ── Section Recommandations ───────────────────────────
        reco_txt = self.txt_reco.get("1.0", "end").strip()
        if reco_txt and reco_txt != "Lancez un scan pour voir les recommandations.":
            elems.append(h2("Recommandations de sécurité"))
            for ligne in reco_txt.split("\n"):
                if ligne.strip():
                    color = (C_ROUGE if "URGENT" in ligne
                             else C_ORANGE if "MOYEN" in ligne else colors.black)
                    elems.append(para(ligne.strip(), color=color))

        # ── Historique ────────────────────────────────────────
        elems.append(h2("Historique des scans"))
        try:
            scans = db.lire_scans()
            if scans:
                data_h = [["ID", "Date", "Cible", "Type", "Hôtes", "Ports",
                            "Score", "Niveau"]]
                for s in scans[:20]:  # max 20 lignes
                    data_h.append([str(s[0]), str(s[1])[:16], s[2], s[3],
                                   str(s[4]), str(s[5]), str(s[6]), s[7]])
                th = Table(data_h,
                           colWidths=[1*cm,3.5*cm,3*cm,3*cm,1.2*cm,1.2*cm,1.2*cm,1.8*cm])
                th.setStyle(TableStyle([
                    ("BACKGROUND",   (0,0), (-1,0), C_MARINE),
                    ("TEXTCOLOR",    (0,0), (-1,0), C_BLANC),
                    ("FONTNAME",     (0,0), (-1,0), "Helvetica-Bold"),
                    ("FONTSIZE",     (0,0), (-1,-1), 7),
                    ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_BLANC, C_GRIS]),
                    ("GRID",         (0,0), (-1,-1), 0.3, C_BORD),
                    ("ALIGN",        (0,0), (-1,-1), "LEFT"),
                    ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
                    ("TOPPADDING",   (0,0), (-1,-1), 3),
                    ("BOTTOMPADDING",(0,0), (-1,-1), 3),
                ]))
                elems.append(th)
            else:
                elems.append(para("Aucun scan enregistré."))
        except Exception:
            elems.append(para("Historique non disponible (MySQL déconnecté)."))

        # ── Pied de page ─────────────────────────────────────
        elems.append(Spacer(1, 20))
        elems.append(HRFlowable(width="100%", thickness=0.5,
                                color=C_BORD, spaceAfter=6))
        elems.append(para(
            "SecureAudit v2.0 — CSC 242 | Outil d'audit et de pentest réseau",
            color=colors.HexColor("#5a6a7a")))

        doc.build(elems)
        messagebox.showinfo("Export réussi",
            f"Rapport PDF généré :\n{chemin}")

    # ----------------------------------------------------------
    #  UTILITAIRES
    # ----------------------------------------------------------
    def _tester_connexion(self):
        if db.tester_connexion():
            messagebox.showinfo("Connexion MySQL",
                "Connexion à MySQL réussie !\nHost : 127.0.0.1 | User : root")
            self.lbl_mysql.configure(text="● MySQL connecté", fg="#1a7a4a")
        else:
            messagebox.showerror("Connexion MySQL",
                "Impossible de se connecter à MySQL.\n"
                "Vérifiez que le service MySQL est démarré.")

    def _a_propos(self):
        messagebox.showinfo("À propos",
            "SecureAudit v2.0\n"
            "Outil d'audit et de pentest réseau\n\n"
            "CSC 242 — Projet fin de semestre\n"
            "Bibliothèques : tkinter, mysql-connector-python,\n"
            "                python-nmap, reportlab")

    def _maj_statut_mysql(self):
        if db.tester_connexion():
            self.lbl_mysql.configure(text="● MySQL connecté", fg="#1a7a4a")

    def _set_reco(self, text):
        self.txt_reco.configure(state="normal")
        self.txt_reco.delete("1.0", "end")
        self.txt_reco.insert("end", text)
        self.txt_reco.configure(state="disabled")


# =============================================================
#  STYLES TTK
# =============================================================
def apply_styles():
    s = ttk.Style()
    s.theme_use("clam")
    s.configure("Treeview",
                background=BLANC, foreground=TEXTE,
                rowheight=26, fieldbackground=BLANC,
                font=(FONT, 9), borderwidth=0)
    s.configure("Treeview.Heading",
                background=MARINE, foreground=BLANC,
                font=(FONT, 8, "bold"), relief="flat")
    s.map("Treeview",
          background=[("selected", MARINE)],
          foreground=[("selected", BLANC)])
    s.configure("TScrollbar",
                troughcolor=GRIS_CLAIR, background=GRIS_BORD, borderwidth=0)
    s.configure("TCombobox",
            fieldbackground=MARINE, background=MARINE,
            foreground="#ffffff")

# =============================================================
if __name__ == "__main__":
    root = tk.Tk()
    apply_styles()
    app = SecureAuditApp(root)
    root.mainloop()
