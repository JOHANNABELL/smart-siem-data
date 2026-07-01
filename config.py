"""
correlation_engine/config.py
────────────────────────────
Rôle unique : centraliser TOUTES les constantes de configuration.
Aucune logique métier ici. Tout le reste importe depuis ce fichier.

Modifier une valeur ici = elle change dans tout le système.
"""
import os

# ── Elasticsearch ─────────────────────────────────────────────────────────────
ES_HOST     = os.environ.get("ES_HOST",     "https://localhost:9200")
ES_USER     = os.environ.get("ES_USER",     "elastic")
ES_PASSWORD = os.environ.get("ES_PASSWORD", "8-0Il66xvSeGnK=COySu")
ES_CACERT   = os.environ.get("ES_CACERT",   "http_ca.crt")

# Pattern couvrant tous les index mensuels (siem-logs-2026.06, etc.)
ES_INDEX    = "siem-logs-*"

# ── PostgreSQL ────────────────────────────────────────────────────────────────
PG_DSN = os.environ.get("PG_DSN",
    "postgresql://postgres:felicia@localhost:5432/nafeh")

# ── Timing du worker ──────────────────────────────────────────────────────────
# Intervalle entre deux cycles d'évaluation (secondes)
WORKER_INTERVAL_SEC = 10

# Toutes les N secondes, recharger les règles depuis PG
# (permet de modifier une règle sans redémarrer le worker)
RULES_RELOAD_INTERVAL_SEC = 60

# Fenêtre de lookback globale pour les requêtes ES (secondes)
# Doit être >= à la plus grande fenêtre de règle
LOOKBACK_SEC = 7200   # 2h — couvre les règles exfiltration (3600s) + buffer

# ── Déduplication des alertes ─────────────────────────────────────────────────
# Durée pendant laquelle une alerte identique est considérée comme doublon
DEDUP_WINDOW_SEC = 300   # 5 minutes

# Taille max du cache de déduplication avant nettoyage
DEDUP_CACHE_MAX = 10_000

# ── Convention des event_actions normalisés ───────────────────────────────────
# SOURCE UNIQUE DE VÉRITÉ pour tous les event_action du système.
# Le simulateur, les YAML, et le moteur utilisent TOUS ces valeurs.
# Ajouter un nouveau type d'événement ici AVANT de l'utiliser ailleurs.
EVENT_ACTIONS = {
    # Authentification SSH
    "ssh_auth_failure": "Échec d'authentification SSH",
    "ssh_auth_success": "Succès d'authentification SSH",
    # Réseau
    "connection_blocked":        "Connexion bloquée par le firewall",
    "connection_allowed":        "Connexion autorisée",
    "large_outbound_transfer":   "Transfert de données volumineux sortant",
    "dns_query":                 "Requête DNS",
    "icmp_flood":                "Flood ICMP (tunnel probable)",
    # Système
    "file_read":                 "Accès fichier en lecture",
    "privilege_escalation":      "Escalade de privilèges détectée",
    "sudo_exec":                 "Exécution via sudo",
    "account_created":           "Création de compte",
    "service_created":           "Création de service",
    "process_started":           "Démarrage de processus",
    # Active Directory / Kerberos
    "kerberos_tgs_request":      "Demande de ticket Kerberos TGS",
    "kerberos_tgt_request":      "Demande de ticket Kerberos TGT",
    "admin_share_access":        "Accès à un partage administratif",
    # Web / application
    "http_post":                 "Requête HTTP POST",
    "http_exploit_attempt":      "Tentative d'exploit HTTP",
    "cloud_upload":              "Upload vers service cloud",
    "email_sent":                "Email envoyé",
    # WMI / PowerShell
    "wmi_exec":                  "Exécution distante WMI",
    "rdp_connection":            "Connexion RDP",
    "credential_dump":           "Dump de credentials",
    "smb_access":                "Accès SMB",
    "outbound_connection":       "Connexion sortante",
}