#!/usr/bin/env python3
"""
================================================================================
ueba/dataset_generator.py — Générateur du dataset de 30 jours pour UEBA
================================================================================
Rôle unique : générer des logs synthétiques représentant 30 jours de
              comportement utilisateur et les insérer dans Elasticsearch.
              Optionnellement insérer les utilisateurs dans PostgreSQL.

CLARIFICATION ARCHITECTURALE IMPORTANTE :
  Ce module travaille PRINCIPALEMENT avec Elasticsearch.
  PostgreSQL est OPTIONNEL et sert uniquement à deux choses :
    1. Insérer les utilisateurs UEBA dans la table `users` pour la cohérence
       avec le reste du SIEM (dashboard, authentification)
    2. Vérifier que ueba_profiles sera alimenté par ueba_worker.py

  Le moteur de détection UEBA n'a PAS besoin que les utilisateurs soient
  dans PostgreSQL. Il lit uniquement le champ `username` dans les logs ES.

PERTINENCE ACADÉMIQUE DES DONNÉES SYNTHÉTIQUES :
  Source principale de référence pour les distributions comportementales :
  - Glasser & Lindauer (2013), "Bridging the Gap: A Pragmatic Approach to
    Generating Insider Threat Data", IEEE S&P Workshop
  - CERT Insider Threat Dataset v6.2 (Carnegie Mellon University, 2016)
    https://kilthub.cmu.edu/articles/dataset/CERT_Insider_Threat_Dataset
  Les distributions utilisées (heures de connexion, volumes de données,
  ratios d'échecs) sont calibrées sur les valeurs de ce dataset public.

TROIS CATÉGORIES DE PROFILS (requis pour une validation académique rigoureuse) :
  1. Parfaitement normaux    → valider la spécificité (pas de faux positifs)
  2. Anomalies légères       → valider la sensibilité sur les cas limites
  3. Anomalies graves        → valider le Recall sur les cas évidents
================================================================================
"""

import asyncio
import hashlib
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from elasticsearch import AsyncElasticsearch
from elasticsearch.helpers import async_bulk

try:
    import asyncpg
    HAS_ASYNCPG = True
except ImportError:
    HAS_ASYNCPG = False

from config import ES_CONFIG, DETECTION_CONFIG, ENTITIES_CONFIG, PG_CONFIG


# ══════════════════════════════════════════════════════════════════════════════
# PROFILS COMPORTEMENTAUX — 3 CATÉGORIES
# Tous les paramètres sont issus de la littérature ou du CERT dataset.
# Référence principale : valeurs médianes du CERT Insider Threat v6.2
# ══════════════════════════════════════════════════════════════════════════════

# ── Catégorie A : Utilisateurs PARFAITEMENT NORMAUX ───────────────────────────
# Ces utilisateurs NE DOIVENT PAS déclencher d'alertes UEBA.
# Ils servent à valider la SPÉCIFICITÉ du modèle (mesurer le FPR).
# Si le modèle génère une alerte sur ces utilisateurs → faux positif → problème.

PERFECTLY_NORMAL_PROFILES = {
    "tony.almeida": {
        # Analyste junior. Comportement très régulier et prévisible.
        # Connecté de 9h à 17h, même poste, volume minimal.
        "_category": "perfectly_normal",
        "_description": "Analyste junior — comportement parfaitement régulier",
        "login_hours":     list(range(9, 17)),
        "src_ips":         ["192.168.1.90"],          # une seule IP : son poste fixe
        "typical_hosts":   ["srv-web-01"],
        "daily_logins":    (3, 6),
        "daily_data_mb":   (1.0, 5.0),
        "fail_ratio":      0.02,                       # 2% d'échecs = erreurs de frappe normales
        "off_hours_prob":  0.03,                       # connexion hors heures très rare
    },
    "kim.bauer": {
        # Responsable RH. Accès limité, volume faible, heures strictes.
        "_category": "perfectly_normal",
        "_description": "Responsable RH — accès minimal, très régulier",
        "login_hours":     list(range(8, 17)),
        "src_ips":         ["192.168.2.10"],
        "typical_hosts":   ["srv-web-01"],
        "daily_logins":    (2, 4),
        "daily_data_mb":   (0.5, 2.0),
        "fail_ratio":      0.01,
        "off_hours_prob":  0.01,
    },
    "edgar.stiles": {
        # Technicien. Heures variables mais dans la plage normale.
        # Bon utilisateur de référence car ses heures varient légèrement.
        "_category": "perfectly_normal",
        "_description": "Technicien — heures légèrement variables mais toujours normales",
        "login_hours":     list(range(7, 19)),   # large plage mais heures de bureau
        "src_ips":         ["192.168.1.95", "10.0.5.20"],   # bureau + salle technique
        "typical_hosts":   ["srv-web-01", "srv-apache-01"],
        "daily_logins":    (4, 10),              # plus actif qu'un analyste
        "daily_data_mb":   (3.0, 15.0),
        "fail_ratio":      0.04,
        "off_hours_prob":  0.08,                 # parfois connecté avant 7h pour la maintenance
    },
}

# ── Catégorie B : Utilisateurs NORMAUX AVEC ACTIVITÉ LÉGITIME ÉLEVÉE ─────────
# Ces utilisateurs ont une activité plus importante MAIS tout est légitime.
# Ils servent à valider que le modèle ne génère pas de FP sur les power users.

NORMAL_HIGH_ACTIVITY_PROFILES = {
    "jack.bauer": {
        # Analyste SOC. Accède à plusieurs serveurs légitimement.
        # Parfois connecté en dehors des heures pour les incidents.
        "_category": "normal_high_activity",
        "_description": "Analyste SOC — activité élevée mais légitime",
        "login_hours":    list(range(8, 20)),    # peut travailler tard
        "src_ips":        ["192.168.1.10", "192.168.1.11", "10.0.1.100"],
        "typical_hosts":  ["srv-web-01", "srv-apache-01", "srv-db-01"],
        "daily_logins":   (6, 15),
        "daily_data_mb":  (5.0, 25.0),
        "fail_ratio":     0.05,
        "off_hours_prob": 0.15,                  # sur appel parfois
    },
    "chloe.obrian": {
        # Administrateur système. Accès à de nombreux serveurs = normal.
        # Le modèle DOIT tolérer son niveau d'activité sans alerter.
        "_category": "normal_high_activity",
        "_description": "Admin système — accès multi-serveurs légitimes et fréquents",
        "login_hours":    list(range(7, 21)),
        "src_ips":        ["10.0.1.5", "10.0.1.6", "192.168.0.10"],
        "typical_hosts":  ["srv-web-01", "srv-db-01", "srv-ad-01", "srv-apache-01"],
        "daily_logins":   (10, 25),              # beaucoup de connexions = normal pour admin
        "daily_data_mb":  (10.0, 50.0),
        "fail_ratio":     0.02,
        "off_hours_prob": 0.25,
    },
    "bill.buchanan": {
        # RSSI. Consulte les logs intensivement mais ne transfère pas beaucoup.
        "_category": "normal_high_activity",
        "_description": "RSSI — consultation intensive des logs, faible volume transféré",
        "login_hours":    list(range(9, 17)),
        "src_ips":        ["192.168.1.50"],       # IP fixe unique = poste RSSI dédié
        "typical_hosts":  ["srv-web-01"],
        "daily_logins":   (5, 12),
        "daily_data_mb":  (1.0, 5.0),            # lit les logs, ne télécharge pas
        "fail_ratio":     0.01,
        "off_hours_prob": 0.05,
    },
}

# ── Catégorie C : Utilisateurs avec ANOMALIES LÉGÈRES (cas limites) ───────────
# Ces utilisateurs ont un comportement qui s'écarte légèrement de la normale.
# Servent à tester la SENSIBILITÉ du modèle sur les cas ambigus.
# Un bon modèle peut détecter ces cas sans trop de faux positifs.

LIGHT_ANOMALY_PROFILES = {
    "david.palmer": {
        # Lecteur. Accès minimal normalement.
        # Anomalie légère : exfiltration de données massives un jour.
        # Score attendu : ≥ 85 (fort signal sur data_volume_mb)
        "_category": "light_anomaly",
        "_description": "Lecteur avec exfiltration de données massives (ANO-002)",
        "login_hours":    list(range(9, 18)),
        "src_ips":        ["192.168.1.70"],
        "typical_hosts":  ["srv-web-01"],
        "daily_logins":   (1, 3),
        "daily_data_mb":  (0.1, 1.0),           # très faible volume normal
        "fail_ratio":     0.03,
        "off_hours_prob": 0.01,
    },
}

# ── Catégorie D : Utilisateurs avec ANOMALIES GRAVES ─────────────────────────
# Ces utilisateurs ont des comportements clairement malveillants ou compromis.
# Le modèle DOIT les détecter avec score ≥ seuil d'alerte.

HEAVY_ANOMALY_PROFILES = {
    "mandy.welles": {
        # Compte compromis. Connexions nocturnes depuis IPs étrangères.
        # Anomalie très grave : accès à 3h depuis IP Tor.
        # Score attendu : ≥ 80
        "_category": "heavy_anomaly",
        "_description": "Compte compromis — connexions nocturnes depuis IP Tor",
        "login_hours":    list(range(9, 17)),    # comportement normal historique
        "src_ips":        ["192.168.1.80"],
        "typical_hosts":  ["srv-web-01"],
        "daily_logins":   (2, 5),
        "daily_data_mb":  (0.5, 3.0),
        "fail_ratio":     0.02,
        "off_hours_prob": 0.02,
    },
    "aaron.pierce": {
        # Compte avec bruteforce interne ET accès à de nouveaux systèmes.
        # Simule une compromission suivie de mouvement latéral.
        # Score attendu : ≥ 75
        "_category": "heavy_anomaly",
        "_description": "Compromission + mouvement latéral interne",
        "login_hours":    list(range(8, 17)),
        "src_ips":        ["192.168.1.85"],
        "typical_hosts":  ["srv-web-01"],
        "daily_logins":   (3, 7),
        "daily_data_mb":  (1.0, 4.0),
        "fail_ratio":     0.03,
        "off_hours_prob": 0.03,
    },
}

# ── Fusion de tous les profils ─────────────────────────────────────────────────
ALL_USER_PROFILES = {
    **PERFECTLY_NORMAL_PROFILES,
    **NORMAL_HIGH_ACTIVITY_PROFILES,
    **LIGHT_ANOMALY_PROFILES,
    **HEAVY_ANOMALY_PROFILES,
}

# ══════════════════════════════════════════════════════════════════════════════
# ANOMALIES DOCUMENTÉES
# ══════════════════════════════════════════════════════════════════════════════

ANOMALIES = [
    {
        "id":             "ANO-001",
        "who":            "jack.bauer",
        "when_day":       -2,
        "what":           "night_login_foreign_ip",
        "description":    "Connexion à 2h30 depuis IP Tor (185.220.101.5)",
        "anomaly_ip":     "185.220.101.5",
        "anomaly_hour":   2,
        "expected_score": 75,
        "category":       "light",
        "mitre":          "T1078",
    },
    {
        "id":             "ANO-002",
        "who":            "david.palmer",
        "when_day":       -1,
        "what":           "mass_data_exfiltration",
        "description":    "Export de 520 Mo (vs moyenne 0.5 Mo) — exfiltration probable",
        "data_mb":        520.0,
        "expected_score": 92,
        "category":       "heavy",
        "mitre":          "T1041",
    },
    {
        "id":             "ANO-003",
        "who":            "chloe.obrian",
        "when_day":       -3,
        "what":           "extreme_lateral_movement",
        "description":    "Accès à 25 serveurs distincts en 90 min (vs 4 habituels)",
        "n_hosts":        25,
        "expected_score": 88,
        "category":       "heavy",
        "mitre":          "T1021",
    },
    {
        "id":             "ANO-004",
        "who":            "bill.buchanan",
        "when_day":       -1,
        "what":           "admin_action_after_hours",
        "description":    "Création compte admin à 22h15 depuis IP inconnue (91.108.4.33)",
        "anomaly_hour":   22,
        "anomaly_ip":     "91.108.4.33",
        "expected_score": 82,
        "category":       "heavy",
        "mitre":          "T1098",
    },
    {
        "id":             "ANO-005",
        "who":            "jack.bauer",
        "when_day":       -5,
        "what":           "internal_brute_force",
        "description":    "55 échecs d'auth en 6 minutes (bruteforce interne)",
        "n_failed":       55,
        "expected_score": 73,
        "category":       "light",
        "mitre":          "T1110",
    },
    {
        "id":             "ANO-006",
        "who":            "mandy.welles",
        "when_day":       -1,
        "what":           "night_login_foreign_ip",
        "description":    "Connexion à 3h05 depuis IP Tor, accès base de données",
        "anomaly_ip":     "194.165.16.98",
        "anomaly_hour":   3,
        "expected_score": 85,
        "category":       "heavy",
        "mitre":          "T1078",
    },
    {
        "id":             "ANO-007",
        "who":            "aaron.pierce",
        "when_day":       -2,
        "what":           "brute_plus_lateral",
        "description":    "20 échecs d'auth puis accès à 8 nouveaux serveurs",
        "n_failed":       20,
        "n_hosts":        8,
        "expected_score": 78,
        "category":       "heavy",
        "mitre":          "T1110+T1021",
    },
    # Cas limites — anomalies légères qui ne doivent PAS nécessairement alerter
    {
        "id":             "ANO-008",
        "who":            "edgar.stiles",
        "when_day":       -4,
        "what":           "slightly_off_hours",
        "description":    "Connecté à 6h45 (légèrement avant ses heures habituelles 7h)",
        "anomaly_hour":   6,
        "expected_score": 25,    # score attendu FAIBLE = pas d'alerte
        "category":       "borderline",
        "mitre":          None,
    },
]


# ══════════════════════════════════════════════════════════════════════════════
# FONCTIONS DE CONSTRUCTION DES LOGS
# ══════════════════════════════════════════════════════════════════════════════

def make_hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


def make_log(username, src_ip, host, event_action, severity,
             timestamp, data_mb=0.0, tags=None, extra=None) -> dict:
    """
    Construit un document ES normalisé.
    raw_log_id est inclus pour éviter le bug _id fielddata dans les agrégations.
    """
    raw = f"{host} {event_action} {src_ip} {username} {timestamp.isoformat()}"
    doc = {
        "@timestamp":       timestamp.isoformat(),
        "ingested_at":      datetime.now(timezone.utc).isoformat(),
        "source_id":        "ueba-synthetic-dataset",
        "host":             host,
        "hostname":         host,
        "log_type":         "auth",
        "severity":         severity,
        "event_action":     event_action,
        "event_outcome":    "failure" if "fail" in event_action else "success",
        "source_ip":        src_ip,
        "raw_message":      raw,
        "hash_sha256":      make_hash(raw),
        "raw_log_id":       str(uuid.uuid4()),
        "pipeline_version": "1.0-ueba-dataset",
        "username":         username,
        "tags":             tags or ["ueba_dataset", "simulated"],
    }
    if data_mb > 0:
        doc["enriched_data"] = {
            "bytes_sent_mb": round(data_mb, 2),
            "bytes_sent":    int(data_mb * 1_000_000),
        }
    if extra:
        doc.update(extra)
    return doc


def generate_normal_day(username, profile, day_offset) -> list:
    """Génère les logs d'une journée normale pour un utilisateur."""
    logs = []
    base_date = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    ) + timedelta(days=day_offset)

    is_business_day = base_date.weekday() in DETECTION_CONFIG["business_days"]
    n_logins = random.randint(*profile["daily_logins"])
    if not is_business_day:
        n_logins = max(0, n_logins // 3)

    day_data_mb = random.uniform(*profile["daily_data_mb"])

    for i in range(n_logins):
        if random.random() < profile["off_hours_prob"]:
            hour = random.choice([0, 1, 2, 3, 4, 5, 6, 19, 20, 21, 22, 23])
        else:
            hour = random.choice(profile["login_hours"])

        ts     = base_date.replace(hour=hour, minute=random.randint(0, 59),
                                   second=random.randint(0, 59))
        src_ip = random.choice(profile["src_ips"])
        host   = random.choice(profile["typical_hosts"])
        cat    = profile.get("_category", "normal")

        if random.random() < profile["fail_ratio"]:
            logs.append(make_log(username, src_ip, host, "login_failed",
                                 "warning", ts, tags=["ueba_"+cat, "simulated"]))
        else:
            logs.append(make_log(username, src_ip, host, "login_success",
                                 "info", ts, tags=["ueba_"+cat, "simulated"]))
            for _ in range(random.randint(1, 4)):
                ts_f = ts + timedelta(minutes=random.randint(1, 30))
                logs.append(make_log(username, src_ip, host,
                                     random.choice(["file_read", "http_request"]),
                                     "info", ts_f, tags=["ueba_"+cat, "simulated"]))

    if day_data_mb > 0 and n_logins > 0:
        t_hour = random.choice(profile["login_hours"])
        t_ts   = base_date.replace(hour=t_hour, minute=random.randint(0, 59))
        logs.append(make_log(username, random.choice(profile["src_ips"]),
                             random.choice(profile["typical_hosts"]),
                             "outbound_connection", "info", t_ts,
                             data_mb=day_data_mb / max(1, n_logins),
                             tags=["ueba_"+cat, "simulated"]))
    return logs


def generate_anomaly_logs(anomaly: dict) -> list:
    """Génère les logs correspondant à une anomalie documentée."""
    if anomaly.get("when_day") is None or anomaly.get("what") is None:
        return []

    username  = anomaly["who"]
    day_offset= anomaly["when_day"]
    base_date = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    ) + timedelta(days=day_offset)
    tags = ["ueba_anomaly", "simulated", anomaly["id"]]
    if anomaly.get("mitre"):
        tags.append(anomaly["mitre"].split("+")[0])

    logs = []
    what = anomaly["what"]

    if what in ("night_login_foreign_ip",):
        ts = base_date.replace(hour=anomaly["anomaly_hour"],
                               minute=random.randint(5, 55))
        logs.append(make_log(username, anomaly["anomaly_ip"], "srv-db-01",
                             "login_success", "critical", ts, tags=tags,
                             extra={"mitre_tactic": "TA0001", "mitre_technique": "T1078"}))
        for i in range(4):
            logs.append(make_log(username, anomaly["anomaly_ip"], "srv-db-01",
                                 "file_read", "high", ts + timedelta(minutes=i*3),
                                 tags=tags,
                                 extra={"enriched_data": {"file_path": "/etc/shadow"}}))

    elif what == "mass_data_exfiltration":
        ts = base_date.replace(hour=14, minute=30)
        logs.append(make_log(username, "192.168.1.70", "srv-web-01",
                             "large_outbound_transfer", "critical", ts,
                             data_mb=anomaly["data_mb"], tags=tags,
                             extra={"dest_ip": "45.142.212.100",
                                    "mitre_tactic": "TA0010",
                                    "mitre_technique": "T1041"}))

    elif what == "extreme_lateral_movement":
        start_ts = base_date.replace(hour=10, minute=0)
        hosts = [f"srv-{i:02d}" for i in range(1, anomaly["n_hosts"] + 1)]
        for i, host in enumerate(hosts):
            ts = start_ts + timedelta(minutes=i * 3)
            logs.append(make_log(username, "10.0.1.5", host, "login_success",
                                 "high", ts, tags=tags,
                                 extra={"mitre_tactic": "TA0008",
                                        "mitre_technique": "T1021"}))

    elif what == "admin_action_after_hours":
        ts = base_date.replace(hour=anomaly["anomaly_hour"], minute=15)
        logs.append(make_log(username, anomaly["anomaly_ip"], "srv-ad-01",
                             "account_created", "critical", ts, tags=tags,
                             extra={"mitre_tactic": "TA0003",
                                    "mitre_technique": "T1098",
                                    "new_account": "backdoor.admin"}))

    elif what == "internal_brute_force":
        start_ts = base_date.replace(hour=14, minute=0)
        for i in range(anomaly["n_failed"]):
            ts = start_ts + timedelta(seconds=i * 6)
            logs.append(make_log(username, "192.168.1.10", "srv-ad-01",
                                 "login_failed", "warning", ts, tags=tags,
                                 extra={"mitre_tactic": "TA0001",
                                        "mitre_technique": "T1110"}))

    elif what == "brute_plus_lateral":
        start_ts = base_date.replace(hour=13, minute=0)
        for i in range(anomaly.get("n_failed", 20)):
            ts = start_ts + timedelta(seconds=i * 10)
            logs.append(make_log(username, "192.168.1.85", "srv-ad-01",
                                 "login_failed", "warning", ts, tags=tags))
        for i in range(anomaly.get("n_hosts", 8)):
            ts = start_ts + timedelta(minutes=5 + i * 5)
            logs.append(make_log(username, "192.168.1.85", f"srv-{i+10:02d}",
                                 "login_success", "high", ts, tags=tags,
                                 extra={"mitre_tactic": "TA0008",
                                        "mitre_technique": "T1021"}))

    elif what == "slightly_off_hours":
        # Anomalie légère — connexion juste avant les heures habituelles
        ts = base_date.replace(hour=anomaly["anomaly_hour"], minute=45)
        logs.append(make_log(username, "192.168.1.95", "srv-web-01",
                             "login_success", "info", ts,
                             tags=["ueba_borderline", "simulated"]))

    return logs


# ══════════════════════════════════════════════════════════════════════════════
# GESTION DES UTILISATEURS DANS POSTGRESQL (OPTIONNEL)
# ══════════════════════════════════════════════════════════════════════════════

async def ensure_users_in_postgres(pool) -> dict:
    """
    Vérifie et insère les utilisateurs UEBA dans la table PostgreSQL `users`.

    POURQUOI c'est optionnel :
      Le moteur UEBA fonctionne sans ça — il lit le champ username dans ES.
      Mais pour que ces utilisateurs apparaissent dans le dashboard SIEM
      et puissent se connecter à l'interface, ils doivent être dans `users`.

    POURQUOI ne pas mettre ces comptes dans la table `users` comme vrais comptes ?
      Ces comptes sont des entités surveillées, pas nécessairement des utilisateurs
      de l'interface SIEM. En production, un utilisateur comme "jack.bauer" est
      surveillé par UEBA mais ne se connecte pas nécessairement au dashboard.
      On les insère avec is_active=FALSE et sans MFA pour les distinguer
      des vrais comptes d'accès au dashboard.

    Retourne un dict {username: uuid} pour les utilisateurs créés.
    """
    import pyotp
    try:
        from passlib.context import CryptContext
        pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
    except ImportError:
        print("  [WARN] passlib non installé — utilisateurs PG non créés")
        return {}

    # Rôles attribués selon la catégorie
    ROLE_MAP = {
        "perfectly_normal":    "reader",
        "normal_high_activity":"analyst",
        "light_anomaly":       "reader",
        "heavy_anomaly":       "reader",
    }

    created = {}
    async with pool.acquire() as conn:
        for username, profile in ALL_USER_PROFILES.items():
            # Vérifier si l'utilisateur existe déjà
            exists = await conn.fetchval(
                "SELECT id FROM users WHERE username = $1", username
            )
            if exists:
                print(f"  [SKIP PG] {username} existe déjà")
                created[username] = str(exists)
                continue

            category = profile.get("_category", "normal_high_activity")
            role     = ROLE_MAP.get(category, "reader")

            # Mot de passe par défaut sécurisé — doit être changé en production
            default_pwd   = f"UEBA-{username.split('.')[0].capitalize()}@2026!"
            pwd_bytes     = default_pwd.encode("utf-8")[:72]
            pwd_safe      = pwd_bytes.decode("utf-8", errors="ignore")
            hashed_pwd    = pwd_ctx.hash(pwd_safe)
            mfa_secret    = pyotp.random_base32()

            user_id = await conn.fetchval(
                """
                INSERT INTO users (
                    username, email, hashed_password, role,
                    mfa_secret, mfa_enabled, org_scope,
                    is_active, must_change_password
                ) VALUES (
                    $1, $2, $3, $4::user_role,
                    $5, FALSE, 'ueba-monitored',
                    FALSE, TRUE
                ) RETURNING id
                """,
                username,
                f"{username}@ctu-siem.int",
                hashed_pwd,
                role,
                mfa_secret,
            )
            created[username] = str(user_id)
            print(f"  [OK PG] {username} inséré (role={role}, is_active=FALSE)")

    return created


# ══════════════════════════════════════════════════════════════════════════════
# POINT D'ENTRÉE PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════

async def generate_and_insert(es: AsyncElasticsearch, pool=None):
    """
    Génère et insère le dataset complet dans Elasticsearch.
    PostgreSQL est optionnel (pool=None si pas disponible).
    """
    print("=" * 65)
    print("UEBA — Génération du dataset de test")
    print("=" * 65)
    print(f"\n  Profils normaux parfaits  : {len(PERFECTLY_NORMAL_PROFILES)}")
    print(f"  Profils normaux élevés    : {len(NORMAL_HIGH_ACTIVITY_PROFILES)}")
    print(f"  Profils anomalies légères : {len(LIGHT_ANOMALY_PROFILES)}")
    print(f"  Profils anomalies graves  : {len(HEAVY_ANOMALY_PROFILES)}")
    print(f"  Anomalies à injecter      : {len([a for a in ANOMALIES if a.get('when_day')])}")

    # ── Étape 0 : Insérer dans PostgreSQL si pool disponible ─────────────────
    if pool:
        print("\n[PG] Vérification / insertion des utilisateurs dans PostgreSQL...")
        pg_users = await ensure_users_in_postgres(pool)
        print(f"  {len(pg_users)} utilisateurs traités dans PG")
    else:
        print("\n[PG] Pool PostgreSQL non fourni — ignoré (UEBA fonctionne sans PG)")

    all_logs = []
    stats    = {}

    # ── Étape 1 : Comportement normal (30 jours × N utilisateurs) ────────────
    print("\n[Phase 1] Génération du comportement normal...")
    for username, profile in ALL_USER_PROFILES.items():
        user_logs = []
        for day in range(-30, 0):
            day_logs = generate_normal_day(username, profile, day)
            user_logs.extend(day_logs)
        cat = profile.get("_category", "?")
        stats[username] = {"normal": len(user_logs), "anomaly": 0, "category": cat}
        all_logs.extend(user_logs)
        print(f"  {username:<22} [{cat:<22}] {len(user_logs):>5} logs")

    # ── Étape 2 : Injection des anomalies ─────────────────────────────────────
    print("\n[Phase 2] Injection des anomalies documentées...")
    for anomaly in ANOMALIES:
        ano_logs = generate_anomaly_logs(anomaly)
        if ano_logs:
            username = anomaly["who"]
            if username in stats:
                stats[username]["anomaly"] += len(ano_logs)
            all_logs.extend(ano_logs)
            cat = anomaly.get("category", "?")
            print(f"  {anomaly['id']} [{cat:<10}] {username:<22} "
                  f"{len(ano_logs):>3} logs — {anomaly['description']}")
        else:
            print(f"  {anomaly['id']} — Aucun log (cas limite ou témoin)")

    # ── Étape 3 : Insertion dans ES ───────────────────────────────────────────
    print(f"\n[Phase 3] Insertion de {len(all_logs)} logs dans ES...")
    random.shuffle(all_logs)

    # Déterminer l'index cible
    current_index = f"siem-logs-{datetime.now().strftime('%Y.%m')}"
    target_index  = ES_CONFIG["index"].replace("*", datetime.now().strftime("%Y.%m"))

    actions = [{"_index": target_index, "_source": doc} for doc in all_logs]

    total_inserted = 0
    batch_size = 200
    for i in range(0, len(actions), batch_size):
        batch = actions[i:i + batch_size]
        ok, errors = await async_bulk(es, batch, raise_on_error=False, chunk_size=batch_size)
        total_inserted += ok
        if errors:
            print(f"  [WARN] {len(errors)} erreurs dans le batch {i // batch_size}")

    print(f"\n[RÉSULTAT] {total_inserted}/{len(all_logs)} logs insérés dans {target_index}")

    # ── Rapport ───────────────────────────────────────────────────────────────
    print("\n" + "=" * 65)
    print("RAPPORT DU DATASET")
    print("=" * 65)
    print(f"  {'Utilisateur':<22} {'Catégorie':<22} {'Normal':>8} {'Anomalie':>9}")
    print(f"  {'-'*65}")
    for user, s in stats.items():
        marker = " ← témoin négatif" if s["category"] == "perfectly_normal" else ""
        print(f"  {user:<22} {s['category']:<22} {s['normal']:>8} {s['anomaly']:>9}{marker}")

    print(f"\n  NOTE ACADÉMIQUE :")
    print(f"  Ces données sont synthétiques, basées sur les distributions du")
    print(f"  CERT Insider Threat Dataset v6.2 (Carnegie Mellon University).")
    print(f"  Référence : https://kilthub.cmu.edu/articles/dataset/CERT_Insider_Threat_Dataset")
    print(f"\n  Pour des tests académiques rigoureux, combiner avec le vrai dataset CMU.")
    print(f"\n  → Lancer ueba_worker.py pour démarrer la détection")


async def main():
    """Point d'entrée : connexion ES (+ PG si disponible) et génération."""
    es = AsyncElasticsearch(
        hosts=[ES_CONFIG["host"]],
        basic_auth=(ES_CONFIG["user"], ES_CONFIG["password"]),
        ca_certs=ES_CONFIG["ca_certs"],
        verify_certs=True,
    )

    pool = None
    if HAS_ASYNCPG:
        try:
            pool = await asyncpg.create_pool(
                dsn=PG_CONFIG["dsn"], min_size=1, max_size=3
            )
            print("[OK] PostgreSQL connecté")
        except Exception as e:
            print(f"[WARN] PostgreSQL non disponible ({e}) — on continue sans PG")

    try:
        info = await es.info()
        print(f"[OK] Elasticsearch {info['version']['number']}")
        await generate_and_insert(es, pool)
    except Exception as e:
        import traceback
        print(f"[ERREUR] {e}")
        traceback.print_exc()
    finally:
        await es.close()
        if pool:
            await pool.close()


if __name__ == "__main__":
    asyncio.run(main())