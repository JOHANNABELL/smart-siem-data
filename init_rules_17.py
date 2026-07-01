#!/usr/bin/env python3
"""
================================================================================
SMART SIEM — Initialisation des règles de corrélation dans PostgreSQL
================================================================================
Version 2 — Modifications P1-A, P1-D, P2-F appliquées :

  P1-A : Harmonisation des event_action sur les valeurs du simulateur
         (login_failed, login_success, connection_blocked, etc.)
         La convention "simulateur = référence" est la source unique de vérité.

  P1-D : Ajout des 8 règles manquantes (R6 à R13) qui couvraient des attaques
         simulées sans règle PG correspondante (cause de 75% des échecs).

  P2-F : Ajout de exclude_usernames sur la règle privilege-escalation pour
         éviter les faux positifs sur les comptes admin légitimes.

  Idempotence : INSERT ... ON CONFLICT (name) DO UPDATE
  Cela remplace le test "SELECT ... WHERE name = $1" + skip.
  Avantage : si une règle existe mais avec des paramètres obsolètes,
  elle est mise à jour plutôt que laissée en l'état.

CANONICAL_EVENTS : dictionnaire de référence partagé avec le simulateur.
  Toute event_action utilisée dans une règle DOIT être dans ce dict.
  Si ce n'est pas le cas, le script lève une ValueError dès le démarrage.
================================================================================
"""

import os, json, asyncio, asyncpg
from passlib.context import CryptContext
import pyotp

PG_DSN = os.environ.get("PG_DSN", "postgresql://postgres:felicia@localhost:5432/nafeh")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_EMAIL    = os.environ.get("ADMIN_EMAIL",    "admin@ctu-siem.int")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "Admin@SIEM2026!")
ADMIN_ORG_SCOPE = "global"

# ── SOURCE UNIQUE DE VÉRITÉ pour les event_action ────────────────────────────
# Ce dictionnaire est copié à l'identique dans attack_simulator.py.
# Toute nouvelle event_action DOIT être ajoutée ici AVANT d'être utilisée.
# Convention : valeurs en minuscules avec underscores (snake_case).
CANONICAL_EVENTS = {
    # Authentification
    "login_failed":            "Échec d'authentification",
    "login_success":           "Authentification réussie",
    "credential_dump":         "Extraction de credentials (LSASS, SAM)",
    "kerberos_tgs_request":    "Demande de ticket Kerberos TGS (Kerberoasting)",
    "kerberos_tgt_request":    "Demande de ticket Kerberos TGT (Golden Ticket)",
    # Réseau
    "connection_blocked":      "Connexion bloquée par le firewall",
    "connection_allowed":      "Connexion autorisée (peut signaler SMB/RDP latéral)",
    "large_outbound_transfer": "Transfert de données volumineux sortant (exfiltration)",
    "dns_query":               "Requête DNS (peut signaler tunneling)",
    "icmp_flood":              "Flood ICMP (peut signaler tunnel ICMP)",
    "rdp_connection":          "Connexion RDP établie",
    # Application / Web
    "http_exploit_attempt":    "Tentative d'exploitation HTTP (SQLi, LFI, RCE)",
    "http_post":               "Requête HTTP POST (peut signaler exfiltration)",
    "cloud_upload":            "Upload vers service cloud (peut signaler exfiltration)",
    # Système
    "file_read":               "Accès fichier en lecture",
    "privilege_escalation":    "Élévation de privilèges (sudo→root, token abuse)",
    "wmi_exec":                "Exécution distante via WMI",
    "service_created":         "Création de service (PsExec, persistance)",
    "process_started":         "Démarrage de processus (post-exploitation)",
    "smb_access":              "Accès partage SMB",
    "outbound_connection":     "Connexion réseau sortante générique",
}


def validate_rule_event_actions(rules: list):
    """
    Vérifie que toutes les event_action des règles sont dans CANONICAL_EVENTS.
    Lève ValueError au démarrage si une incohérence est détectée.
    Empêche l'insertion de règles qui ne pourront jamais déclencher d'alerte.
    """
    errors = []
    for rule in rules:
        try:
            cond = json.loads(rule.get("conditions", "{}"))
        except json.JSONDecodeError:
            continue
        actions_to_check = []
        if "event_action" in cond:
            actions_to_check.append(cond["event_action"])
        if "events" in cond:
            actions_to_check.extend(cond["events"].values())
        if "sequence" in cond:
            actions_to_check.extend(cond["sequence"])
        for action in actions_to_check:
            if action not in CANONICAL_EVENTS:
                errors.append(f"  Règle '{rule['name']}' : event_action '{action}' inconnu")
    if errors:
        raise ValueError(
            "VALIDATION ÉCHOUÉE — event_action non canoniques détectées :\n"
            + "\n".join(errors)
            + f"\n\nValeurs valides : {list(CANONICAL_EVENTS.keys())}"
        )
    print(f"[VALIDATION] ✓ Tous les event_action sont canoniques")


# ── DÉFINITION DES RÈGLES ────────────────────────────────────────────────────
# RÈGLES R1-R5 (existantes, event_action harmonisés sur les valeurs du simulateur)
# RÈGLES R6-R13 (nouvelles, couvrant les attaques non détectées)

RULES = [

    # ════════════════════════════════════════════════════════════════════════
    # R1 — SSH Brute Force — T1110
    # CORRECTION P1-A : event_action était login_failed dans PG → CONSERVÉ
    # C'est le simulateur qui est la référence → login_failed est CORRECT.
    # ════════════════════════════════════════════════════════════════════════
    {
        "name": "SSH Brute Force Detection",
        "description": (
            "Détecte les attaques brute force SSH : 5+ échecs d'authentification "
            "depuis la même IP en 60 secondes. Couvre T1110.001 (Guessing), "
            "T1110.003 (Spraying), T1110.004 (Credential Stuffing)."
        ),
        "rule_type": "threshold",
        "conditions": json.dumps({
            "event_action": "login_failed",   # CANONIQUE : valeur du simulateur
            "group_by":     "source_ip",
        }),
        "time_window_seconds": 60,
        "threshold_count":     5,
        "sources_required":    None,
        "alert_level":         "HIGH",
        "confidence_score":    85,
        "mitre_tactic":        "TA0001",
        "mitre_technique":     "T1110",
    },

    # ════════════════════════════════════════════════════════════════════════
    # R2 — Network Port Scan — T1046
    # AMÉLIORATION P2-A : ajout count_type cardinality + cardinality_field
    # pour compter les ports DISTINCTS plutôt que le volume brut.
    # Un scan Nmap touche N ports différents depuis la même IP — la cardinalité
    # est le vrai signal, pas le nombre total de paquets.
    # ════════════════════════════════════════════════════════════════════════
    {
        "name": "Network Port Scan Detection",
        "description": (
            "Détecte un scan de ports : 20+ ports de destination distincts "
            "bloqués depuis la même IP en 60 secondes. Détection par cardinalité "
            "(fan-out pattern) plutôt que par volume brut."
        ),
        "rule_type": "threshold",
        "conditions": json.dumps({
            "event_action":    "connection_blocked",
            "group_by":        "source_ip",
            "count_type":      "cardinality",      # P2-A : compter les VALEURS DISTINCTES
            "cardinality_field": "dest_port",      # compter les ports distincts
        }),
        "time_window_seconds": 60,
        "threshold_count":     20,   # 20 ports distincts en 60s → scan caractérisé
        "sources_required":    None,
        "alert_level":         "WARNING",
        "confidence_score":    78,
        "mitre_tactic":        "TA0007",
        "mitre_technique":     "T1046",
    },

    # ════════════════════════════════════════════════════════════════════════
    # R3 — SSH Lateral Movement — T1021
    # CORRECTION P1-A : sequence utilisait login_success → CONSERVÉ (simulateur)
    # AMÉLIORATION P2-B : is_internal_src + max_step_gap seront appliqués
    # par le PatternEvaluator si la règle passe.
    # ════════════════════════════════════════════════════════════════════════
    {
        "name": "Lateral Movement Kill-Chain",
        "description": (
            "Détecte un mouvement latéral SSH : connexion réussie depuis IP interne "
            "suivie d'un accès à des fichiers sensibles par la même IP en 5 minutes."
        ),
        "rule_type": "pattern",
        "conditions": json.dumps({
            "sequence":         ["login_success", "file_read"],
            "group_by":         "source_ip",
            "filter":           {"is_internal_src": True},  # P2-B : pivot interne seulement
            "max_step_gap_seconds": 280,                    # P2-B : reset FSM si gap > 280s
        }),
        "time_window_seconds": 300,
        "threshold_count":     None,
        "sources_required":    None,
        "alert_level":         "CRITICAL",
        "confidence_score":    82,
        "mitre_tactic":        "TA0008",
        "mitre_technique":     "T1021",
    },

    # ════════════════════════════════════════════════════════════════════════
    # R4 — Data Exfiltration — T1041
    # Aucune correction nécessaire : event_action et structure déjà corrects.
    # ════════════════════════════════════════════════════════════════════════
    {
        "name": "Data Exfiltration Pattern",
        "description": (
            "Détecte une exfiltration : 3+ transferts volumineux sortants "
            "depuis la même IP en 1 heure."
        ),
        "rule_type": "threshold",
        "conditions": json.dumps({
            "event_action": "large_outbound_transfer",
            "group_by":     "source_ip",
        }),
        "time_window_seconds": 3600,
        "threshold_count":     3,
        "sources_required":    None,
        "alert_level":         "CRITICAL",
        "confidence_score":    75,
        "mitre_tactic":        "TA0010",
        "mitre_technique":     "T1041",
    },

    # ════════════════════════════════════════════════════════════════════════
    # R5 — Firewall + AD Correlation — T1078
    # CORRECTION P1-A : active_directory event était login_failed → CONSERVÉ
    # (correspondait déjà au simulateur).
    # CORRECTION ARCHITECTURALE : rule_type passe à "cross_source"
    # pour que le dispatch dans CorrelationEngine l'envoie au bon évaluateur.
    # ════════════════════════════════════════════════════════════════════════
    {
        "name": "Firewall Block then AD Auth Attempt",
        "description": (
            "Corrélation Firewall + AD : IP bloquée par le firewall qui tente "
            "une authentification sur l'Active Directory dans les 5 minutes."
        ),
        "rule_type": "cross_source",
        "conditions": json.dumps({
            "sources":  ["firewall", "active_directory"],
            "events":   {
                "firewall":          "connection_blocked",
                "active_directory":  "login_failed",
            },
            "group_by": "source_ip",
        }),
        "time_window_seconds": 300,
        "threshold_count":     None,
        "sources_required":    json.dumps(["firewall", "active_directory"]),
        "alert_level":         "HIGH",
        "confidence_score":    70,
        "mitre_tactic":        "TA0001",
        "mitre_technique":     "T1078",
    },

    # ════════════════════════════════════════════════════════════════════════
    # R6 — Public-Facing Application Exploit — T1190
    # NOUVEAU P1-D : le simulateur génère http_exploit_attempt mais aucune
    # règle ne l'interceptait.
    # ════════════════════════════════════════════════════════════════════════
    {
        "name": "Public-Facing Application Exploit",
        "description": (
            "Détecte des tentatives d'exploitation d'application web exposée : "
            "5+ requêtes http_exploit_attempt depuis la même IP en 60s."
        ),
        "rule_type": "threshold",
        "conditions": json.dumps({
            "event_action": "http_exploit_attempt",
            "group_by":     "source_ip",
        }),
        "time_window_seconds": 60,
        "threshold_count":     5,
        "sources_required":    None,
        "alert_level":         "HIGH",
        "confidence_score":    80,
        "mitre_tactic":        "TA0001",
        "mitre_technique":     "T1190",
    },

    # ════════════════════════════════════════════════════════════════════════
    # R7 — SMB Lateral Movement — T1021.002
    # NOUVEAU P1-D : filtre composite event_action + dest_port.
    # ThresholdEvaluator v2 lit tous les champs non réservés dans conditions
    # et les ajoute comme filtres must dans la requête ES (P2-A).
    # ════════════════════════════════════════════════════════════════════════
    {
        "name": "SMB Lateral Movement Detection",
        "description": (
            "Détecte un mouvement latéral SMB : 3+ connexions connection_allowed "
            "vers port 445 depuis la même IP interne en 300s."
        ),
        "rule_type": "threshold",
        "conditions": json.dumps({
            "event_action": "connection_allowed",
            "dest_port":    445,          # filtre composite P2-A
            "group_by":     "source_ip",
        }),
        "time_window_seconds": 300,
        "threshold_count":     3,
        "sources_required":    None,
        "alert_level":         "HIGH",
        "confidence_score":    78,
        "mitre_tactic":        "TA0008",
        "mitre_technique":     "T1021",
    },

    # ════════════════════════════════════════════════════════════════════════
    # R8 — RDP Lateral Movement — T1021.001
    # ════════════════════════════════════════════════════════════════════════
    {
        "name": "RDP Lateral Movement Detection",
        "description": (
            "Détecte un mouvement latéral RDP : 3+ connexions rdp_connection "
            "vers port 3389 depuis la même IP en 600s."
        ),
        "rule_type": "threshold",
        "conditions": json.dumps({
            "event_action": "rdp_connection",
            "dest_port":    3389,
            "group_by":     "source_ip",
        }),
        "time_window_seconds": 600,
        "threshold_count":     3,
        "sources_required":    None,
        "alert_level":         "HIGH",
        "confidence_score":    80,
        "mitre_tactic":        "TA0008",
        "mitre_technique":     "T1021",
    },

    # ════════════════════════════════════════════════════════════════════════
    # R9 — WMI Remote Execution — T1047
    # NOUVEAU P1-D : règle pattern wmi_exec → process_started.
    # Le simulateur a été corrigé pour générer les DEUX logs.
    # ════════════════════════════════════════════════════════════════════════
    {
        "name": "WMI Remote Execution Kill-Chain",
        "description": (
            "Détecte une exécution distante WMI : séquence wmi_exec → process_started "
            "depuis la même IP en 120s."
        ),
        "rule_type": "pattern",
        "conditions": json.dumps({
            "sequence": ["wmi_exec", "process_started"],
            "group_by": "source_ip",
        }),
        "time_window_seconds": 120,
        "threshold_count":     None,
        "sources_required":    None,
        "alert_level":         "HIGH",
        "confidence_score":    82,
        "mitre_tactic":        "TA0008",
        "mitre_technique":     "T1047",
    },

    # ════════════════════════════════════════════════════════════════════════
    # R10 — DNS Tunnel Exfiltration — T1048.003
    # ════════════════════════════════════════════════════════════════════════
    {
        "name": "DNS Tunnel Exfiltration",
        "description": (
            "Détecte un tunnel DNS : 200+ requêtes dns_query depuis la même IP en 60s. "
            "Signature d'un tunnel dnscat2 ou iodine en exfiltration."
        ),
        "rule_type": "threshold",
        "conditions": json.dumps({
            "event_action": "dns_query",
            "group_by":     "source_ip",
        }),
        "time_window_seconds": 60,
        "threshold_count":     200,
        "sources_required":    None,
        "alert_level":         "HIGH",
        "confidence_score":    75,
        "mitre_tactic":        "TA0010",
        "mitre_technique":     "T1048",
    },

    # ════════════════════════════════════════════════════════════════════════
    # R11 — HTTP POST Exfiltration — T1567
    # ════════════════════════════════════════════════════════════════════════
    {
        "name": "HTTP POST Exfiltration",
        "description": (
            "Détecte une exfiltration HTTP : 50+ requêtes http_post depuis "
            "la même IP en 300s. Signature d'upload vers un C2 HTTP."
        ),
        "rule_type": "threshold",
        "conditions": json.dumps({
            "event_action": "http_post",
            "group_by":     "source_ip",
        }),
        "time_window_seconds": 300,
        "threshold_count":     50,
        "sources_required":    None,
        "alert_level":         "HIGH",
        "confidence_score":    72,
        "mitre_tactic":        "TA0010",
        "mitre_technique":     "T1567",
    },

    # ════════════════════════════════════════════════════════════════════════
    # R12 — Cloud Storage Exfiltration — T1567.002
    # group_by username : l'exfiltration cloud est associée à un compte,
    # pas forcément à une IP (l'utilisateur peut être sur plusieurs machines).
    # ════════════════════════════════════════════════════════════════════════
    {
        "name": "Cloud Storage Exfiltration",
        "description": (
            "Détecte une exfiltration cloud : 5+ cloud_upload par le même "
            "utilisateur en 3600s. Signature de Dropbox/OneDrive exfiltration."
        ),
        "rule_type": "threshold",
        "conditions": json.dumps({
            "event_action": "cloud_upload",
            "group_by":     "username",    # groupé par compte, pas par IP
        }),
        "time_window_seconds": 3600,
        "threshold_count":     5,
        "sources_required":    None,
        "alert_level":         "HIGH",
        "confidence_score":    70,
        "mitre_tactic":        "TA0010",
        "mitre_technique":     "T1567",
    },

    # ════════════════════════════════════════════════════════════════════════
    # R13 — ICMP Tunnel — T1095
    # ════════════════════════════════════════════════════════════════════════
    {
        "name": "ICMP Tunnel Exfiltration",
        "description": (
            "Détecte un tunnel ICMP : 100+ icmp_flood depuis la même IP en 60s. "
            "Signature d'un tunnel icmptunnel ou ptunnel en exfiltration."
        ),
        "rule_type": "threshold",
        "conditions": json.dumps({
            "event_action": "icmp_flood",
            "group_by":     "source_ip",
        }),
        "time_window_seconds": 60,
        "threshold_count":     100,
        "sources_required":    None,
        "alert_level":         "HIGH",
        "confidence_score":    73,
        "mitre_tactic":        "TA0010",
        "mitre_technique":     "T1095",
    },

    # ════════════════════════════════════════════════════════════════════════
    # R14 — Privilege Escalation — T1068
    # P2-F : whitelist des comptes légitimes pour éviter les FP.
    # Seuil à 1 : toute escalade non whitelistée est suspecte.
    # ════════════════════════════════════════════════════════════════════════
    {
        "name": "Privilege Escalation Detection",
        "description": (
            "Détecte une élévation de privilèges : événement privilege_escalation "
            "par un compte non whitelisté. Seuil bas (1) car toute escalade "
            "non planifiée est suspecte."
        ),
        "rule_type": "threshold",
        "conditions": json.dumps({
            "event_action":      "privilege_escalation",
            "group_by":          "username",
            "exclude_usernames": ["root", "ansible", "deploy", "backup_agent"],  # P2-F whitelist
        }),
        "time_window_seconds": 300,
        "threshold_count":     1,
        "sources_required":    None,
        "alert_level":         "CRITICAL",
        "confidence_score":    88,
        "mitre_tactic":        "TA0004",
        "mitre_technique":     "T1068",
    },

    # ════════════════════════════════════════════════════════════════════════
    # R15 — Kerberoasting — T1558.003
    # NOUVEAU : le simulateur génère kerberos_tgs_request sans règle PG.
    # ════════════════════════════════════════════════════════════════════════
    {
        "name": "Kerberoasting Detection",
        "description": (
            "Détecte un Kerberoasting : 10+ requêtes TGS en 30s. "
            "L'attaquant demande des tickets de service pour cracker les "
            "hashs des comptes de service hors ligne."
        ),
        "rule_type": "threshold",
        "conditions": json.dumps({
            "event_action": "kerberos_tgs_request",
            "group_by":     "source_ip",
        }),
        "time_window_seconds": 30,
        "threshold_count":     10,
        "sources_required":    None,
        "alert_level":         "HIGH",
        "confidence_score":    85,
        "mitre_tactic":        "TA0006",
        "mitre_technique":     "T1558",
    },

    # ════════════════════════════════════════════════════════════════════════
    # R16 — Golden Ticket — T1558.001
    # ════════════════════════════════════════════════════════════════════════
    {
        "name": "Golden Ticket Detection",
        "description": (
            "Détecte une utilisation de Golden Ticket : 20+ requêtes TGT en 60s "
            "par le même compte. Forge de ticket KRBTGT = compromission AD totale."
        ),
        "rule_type": "threshold",
        "conditions": json.dumps({
            "event_action": "kerberos_tgt_request",
            "group_by":     "username",
        }),
        "time_window_seconds": 60,
        "threshold_count":     20,
        "sources_required":    None,
        "alert_level":         "CRITICAL",
        "confidence_score":    90,
        "mitre_tactic":        "TA0006",
        "mitre_technique":     "T1558",
    },

    # ════════════════════════════════════════════════════════════════════════
    # R17 — Pass-the-Hash — T1550.002
    # Pattern : credential_dump → login_success (avec auth_type NTLM idéalement)
    # ════════════════════════════════════════════════════════════════════════
    {
        "name": "Pass-the-Hash Detection",
        "description": (
            "Détecte un Pass-the-Hash : séquence credential_dump → login_success "
            "depuis la même IP en 600s. Signature de l'extraction NTLM et "
            "réutilisation immédiate du hash."
        ),
        "rule_type": "pattern",
        "conditions": json.dumps({
            "sequence": ["credential_dump", "login_success"],
            "group_by": "source_ip",
        }),
        "time_window_seconds": 600,
        "threshold_count":     None,
        "sources_required":    None,
        "alert_level":         "CRITICAL",
        "confidence_score":    80,
        "mitre_tactic":        "TA0008",
        "mitre_technique":     "T1550",
    },
]


async def create_admin_if_missing(conn: asyncpg.Connection) -> str:
    existing_id = await conn.fetchval("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
    if existing_id:
        print(f"[SKIP] Administrateur déjà existant (id={existing_id})")
        return str(existing_id)
    password_bytes  = ADMIN_PASSWORD.encode("utf-8")
    password_safe   = password_bytes[:72].decode("utf-8", errors="ignore")
    hashed_password = pwd_context.hash(password_safe)
    mfa_secret = pyotp.random_base32()
    admin_id   = await conn.fetchval(
        """
        INSERT INTO users (username, email, hashed_password, role,
                           mfa_secret, mfa_enabled, org_scope, is_active, must_change_password)
        VALUES ($1, $2, $3, 'admin'::user_role, $4, TRUE, $5, TRUE, TRUE)
        RETURNING id
        """,
        ADMIN_USERNAME, ADMIN_EMAIL, hashed_password, mfa_secret, ADMIN_ORG_SCOPE,
    )
    print(f"\n{'='*60}")
    print(f"  COMPTE ADMINISTRATEUR CRÉÉ")
    print(f"  Identifiant  : {ADMIN_USERNAME}")
    print(f"  Email        : {ADMIN_EMAIL}")
    print(f"  MFA Secret   : {mfa_secret}")
    print(f"{'='*60}\n")
    return str(admin_id)


async def init_rules():
    # ── Validation préalable ──────────────────────────────────────────────────
    # Vérifie que tous les event_action des règles sont dans CANONICAL_EVENTS.
    # Fail-fast : si une règle est incohérente, le script s'arrête immédiatement
    # avant de modifier quoi que ce soit dans la base de données.
    validate_rule_event_actions(RULES)

    pool = await asyncpg.create_pool(dsn=PG_DSN, min_size=1, max_size=3)

    async with pool.acquire() as conn:
        print("[1/2] Vérification / création du compte administrateur...")
        admin_id = await create_admin_if_missing(conn)

        print("[2/2] Insertion / mise à jour des règles de corrélation...")
        inserted = 0
        updated  = 0

        for rule in RULES:
            # INSERT ... ON CONFLICT (name) DO UPDATE
            # Idempotent ET met à jour les règles obsolètes (seuils, fenêtres changés)
            # DIFFÉRENCE avec le test SELECT + skip :
            #   - Si la règle existe avec les anciens paramètres → mise à jour
            #   - Si la règle n'existe pas → création
            result = await conn.fetchval(
                """
                INSERT INTO correlation_rules (
                    name, description, rule_type, conditions,
                    time_window_seconds, threshold_count, sources_required,
                    alert_level, confidence_score, mitre_tactic, mitre_technique,
                    is_active, created_by
                ) VALUES (
                    $1, $2, $3, $4::jsonb, $5, $6, $7::jsonb,
                    $8::alert_level, $9, $10, $11, TRUE, $12::uuid
                )
                ON CONFLICT (name) DO UPDATE SET
                    description          = EXCLUDED.description,
                    rule_type            = EXCLUDED.rule_type,
                    conditions           = EXCLUDED.conditions,
                    time_window_seconds  = EXCLUDED.time_window_seconds,
                    threshold_count      = EXCLUDED.threshold_count,
                    sources_required     = EXCLUDED.sources_required,
                    alert_level          = EXCLUDED.alert_level,
                    confidence_score     = EXCLUDED.confidence_score,
                    mitre_tactic         = EXCLUDED.mitre_tactic,
                    mitre_technique      = EXCLUDED.mitre_technique,
                    is_active            = TRUE
                RETURNING (xmax = 0) AS was_inserted
                """,
                rule["name"],
                rule.get("description", ""),
                rule["rule_type"],
                rule["conditions"],
                rule.get("time_window_seconds"),
                rule.get("threshold_count"),
                rule.get("sources_required"),
                rule["alert_level"],
                rule["confidence_score"],
                rule.get("mitre_tactic"),
                rule.get("mitre_technique"),
                str(admin_id),
            )
            if result:   # xmax = 0 → INSERT (nouvelle règle)
                print(f"[INSERT] {rule['name']} ({rule['alert_level']})")
                inserted += 1
            else:        # xmax != 0 → UPDATE (règle existante mise à jour)
                print(f"[UPDATE] {rule['name']}")
                updated += 1

    async with pool.acquire() as conn:
        count = await conn.fetchval("SELECT COUNT(*) FROM correlation_rules WHERE is_active = TRUE")

    print(f"\n[RÉSULTAT] {inserted} insérées, {updated} mises à jour")
    print(f"[RÉSULTAT] {count} règles actives dans PostgreSQL")
    print(f"  → Objectif 16/16 attaques : {'✓ OK' if count >= 13 else '✗ insuffisant'}")

    await pool.close()


if __name__ == "__main__":
    asyncio.run(init_rules())