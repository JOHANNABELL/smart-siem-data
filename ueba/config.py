#!/usr/bin/env python3
"""
================================================================================
ueba/config.py — Configuration centralisée du module UEBA
================================================================================
Rôle unique : être le seul endroit où modifier les paramètres du module.
              Tous les autres fichiers importent depuis config.py.
              Ne contient AUCUNE logique métier.

Principe    : "Configuration as Code" — les paramètres sont versionnés avec
              le code, lisibles par un humain, et modifiables sans toucher
              à la logique de détection.

Pour modifier un paramètre : changer sa valeur ici et redémarrer le worker.
================================================================================
"""

import os

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — CONNEXIONS AUX BASES DE DONNÉES
# Ces valeurs sont lues depuis les variables d'environnement (bonne pratique
# de sécurité : ne jamais écrire les credentials en dur dans le code).
# Valeur après le "or" = défaut pour le développement local uniquement.
# ══════════════════════════════════════════════════════════════════════════════

ES_CONFIG = {
    # URL du cluster Elasticsearch. "https" obligatoire en ES 8.x (TLS activé par défaut).
    "host":        os.environ.get("ES_HOST",     "https://localhost:9200"),

    # Compte superutilisateur ES. En production : utiliser un compte dédié avec
    # droits restreints (indices:data/read seulement sur siem-logs-*).
    "user":        os.environ.get("ES_USER",     "elastic"),
    "password":    os.environ.get("ES_PASSWORD", "8-0Il66xvSeGnK=COySu"),

    # Certificat CA généré lors de l'installation ES 8.x.
    # Chemin standard Linux : /etc/elasticsearch/certs/http_ca.crt
    "ca_certs":    os.environ.get("ES_CACERT",   "http_ca.crt"),

    # Pattern d'index pour tous les logs de tous les mois.
    # "siem-logs-*" couvre siem-logs-2026.06, siem-logs-2026.07, etc.
    "index":       "siem-logs-*",

    # Index dédié aux profils comportementaux UEBA.
    # Séparé des logs pour des raisons de performance et de rétention distincte.
    "ueba_index":  "ueba-profiles",
}

PG_CONFIG = {
    # DSN (Data Source Name) PostgreSQL au format standard.
    # Format : postgresql://user:password@host:port/database
    "dsn": os.environ.get(
        "PG_DSN",
        "postgresql://postgres:felicia@localhost:5432/nafeh"
    ),
    # Taille du pool de connexions asynchrones.
    # min_size : connexions toujours ouvertes (évite la latence d'ouverture).
    # max_size : plafond pour éviter de surcharger PostgreSQL.
    "pool_min": 1,
    "pool_max": 5,
}

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — PARAMÈTRES DE LA BASELINE COMPORTEMENTALE
# La baseline = le "profil normal" d'un utilisateur ou d'une machine.
# Elle est construite sur une fenêtre glissante de N jours.
# ══════════════════════════════════════════════════════════════════════════════

BASELINE_CONFIG = {
    # Nombre de jours d'historique utilisés pour construire le profil de référence.
    # Valeur standard en industrie : 30 jours (couvre les cycles hebdomadaires).
    # Minimum viable : 7 jours (une semaine de comportement).
    # Augmenter à 60 ou 90 jours pour les environnements très stables.
    "window_days": 30,

    # Nombre minimum d'événements requis pour construire un profil fiable.
    # Un profil avec moins de 50 events est statistiquement peu représentatif.
    # En dessous de ce seuil : le worker marque l'entité comme "profil insuffisant"
    # et ne génère pas d'alerte UEBA pour éviter les faux positifs.
    "min_events_required": 50,

    # Heure de lancement du worker UEBA (format 24h).
    # 3h du matin : activité minimale sur les systèmes, pas de concurrence.
    # Changer à 1 ou 2 si d'autres jobs tournent à 3h.
    "worker_hour": 3,

    # Taille des batches pour les requêtes Elasticsearch.
    # 1000 = compromis entre performance (moins de requêtes) et mémoire.
    # Réduire à 500 si le serveur ES manque de RAM.
    "es_batch_size": 1000,
}

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — CONFIGURATION DES FEATURES
# Une feature = une mesure numérique du comportement d'une entité sur une journée.
# L'Isolation Forest et le Z-Score travaillent sur ces features.
#
# Structure de chaque feature :
#   "nom_feature": {
#       "description"  : texte explicatif pour les humains
#       "source"       : champ ES source (comment la calculer)
#       "weight"       : poids dans le score final (somme des poids = 1.0)
#                        Un poids élevé = cette feature contribue plus au score
#       "zscore_threshold" : au-delà de combien d'écarts-types = anomalie
#                            Standard : 3.0 (règle des 3-sigma, 99.7% de la normale)
#                            Réduire à 2.5 pour être plus sensible
#                            Augmenter à 3.5 pour réduire les faux positifs
#       "anomaly_direction": "high" = un haut score est suspect
#                            "low"  = un bas score est suspect
#                            "both" = les deux extrêmes sont suspects
#   }
# ══════════════════════════════════════════════════════════════════════════════

FEATURES_CONFIG = {
    # ── Feature 1 : Heure de connexion ────────────────────────────────────────
    # Pourquoi : une connexion à 3h du matin pour un utilisateur qui se connecte
    # normalement entre 8h et 18h est fortement suspecte.
    # Source : heure extraite du champ @timestamp WHERE event_action=login_success
    # Anomalie type : compromission de compte depuis un fuseau horaire différent
    "login_hour_mean": {
        "description":       "Heure moyenne de connexion dans la journée (0–23)",
        "source":            "@timestamp.hour WHERE event_action=login_success",
        "weight":            0.13,
        "zscore_threshold":  2.5,
        "anomaly_direction": "both",  # connexion trop tôt ET trop tard sont suspectes
    },

    # ── Feature 2 : Nombre de connexions par jour ──────────────────────────────
    # Pourquoi : un pic inhabituel de connexions peut indiquer un accès automatisé
    # (malware, credential stuffing) ou un mouvement latéral.
    # Source : count(event_action=login_success) GROUP BY date
    # Anomalie type : 50 connexions en un jour vs moyenne de 5
    "login_count_per_day": {
        "description":       "Nombre de connexions réussies par jour",
        "source":            "count(login_success) par date",
        "weight":            0.12,
        "zscore_threshold":  3.0,
        "anomaly_direction": "high",   # trop de connexions = suspect
    },

    # ── Feature 3 : Nombre d'IPs sources distinctes ───────────────────────────
    # Pourquoi : un utilisateur normal se connecte depuis 1 ou 2 IPs (bureau, domicile).
    # Plusieurs IPs inconnues = account sharing, VPN exfiltration ou compromission.
    # Source : cardinality(source_ip) par utilisateur par jour
    # Anomalie type : 8 IPs différentes en un jour vs moyenne de 1.2
    "unique_source_ips": {
        "description":       "Nombre d'adresses IP sources distinctes par jour",
        "source":            "cardinality(source_ip)",
        "weight":            0.10,
        "zscore_threshold":  2.5,
        "anomaly_direction": "high",
    },

    # ── Feature 4 : Nombre de machines accédées ───────────────────────────────
    # Pourquoi : signature classique du mouvement latéral. Un analyste accède
    # normalement à 2–3 serveurs. Accéder à 15 serveurs en une heure = pivot.
    # Source : cardinality(host) par utilisateur par jour
    # Anomalie type : 12 hôtes distincts vs moyenne de 2
    "unique_hosts_accessed": {
        "description":       "Nombre de machines/serveurs distincts accédés par jour",
        "source":            "cardinality(host)",
        "weight":            0.15,
        "zscore_threshold":  2.5,
        "anomaly_direction": "high",
    },

    # ── Feature 5 : Ratio d'échecs d'authentification ─────────────────────────
    # Pourquoi : un ratio élevé login_failed/total_logins indique soit une
    # attaque brute force INTERNE, soit un compte compromis qui teste des mots de passe.
    # Source : count(login_failed) / count(login_failed + login_success)
    # Anomalie type : ratio de 0.8 vs moyenne de 0.02
    "failed_login_ratio": {
        "description":       "Ratio échecs auth / total tentatives auth (0.0 à 1.0)",
        "source":            "count(login_failed) / (count(login_failed) + count(login_success))",
        "weight":            0.10,
        "zscore_threshold":  3.0,
        "anomaly_direction": "high",
    },

    # ── Feature 6 : Volume de données transférées (Mo) ────────────────────────
    # Pourquoi : la feature d'exfiltration la plus directe. Un pic de volume
    # sortant est le signal le plus fort d'une exfiltration de données.
    # Source : sum(enriched_data.bytes_sent_mb) par utilisateur par jour
    # Anomalie type : 500 Mo vs moyenne de 5 Mo
    "data_volume_mb": {
        "description":       "Volume total de données transférées en Mo par jour",
        "source":            "sum(enriched_data.bytes_sent_mb)",
        "weight":            0.20,    # poids le plus élevé car signal d'exfiltration direct
        "zscore_threshold":  3.0,
        "anomaly_direction": "high",
    },

    # ── Feature 7 : Ratio d'activité hors heures ouvrées ─────────────────────
    # Pourquoi : les attaques se produisent souvent la nuit ou le week-end
    # quand la surveillance humaine est minimale.
    # Heures ouvrées définies dans BASELINE_CONFIG["business_hours"]
    # Source : count(events WHERE hour NOT IN 8–18) / count(all events)
    # Anomalie type : 100% d'activité entre 23h et 5h
    "off_hours_activity_ratio": {
        "description":       "Ratio d'événements hors heures ouvrées (8h–18h) par jour",
        "source":            "count(events WHERE hour < 8 OR hour >= 18) / count(all)",
        "weight":            0.10,
        "zscore_threshold":  2.5,
        "anomaly_direction": "high",
    },

    # ── Feature 8 : Accès à de nouveaux systèmes ──────────────────────────────
    # Pourquoi : si un utilisateur accède pour la première fois à un serveur
    # sensible (base de données de paie, serveur AD), c'est un signal fort.
    # Source : count(hosts NOT IN profil.typical_hosts) par jour
    # Anomalie type : un lecteur accède au serveur de production pour la première fois
    "new_system_access_count": {
        "description":       "Nombre de systèmes jamais accédés auparavant par jour",
        "source":            "count(host NOT IN baseline.typical_hosts)",
        "weight":            0.10,    # complément des autres features
        "zscore_threshold":  2.0,     # seuil bas car même 1 accès nouveau est suspect
        "anomaly_direction": "high",
    },
}

# Vérification d'intégrité : la somme des poids doit être 1.0
_total_weight = sum(f["weight"] for f in FEATURES_CONFIG.values())
assert abs(_total_weight - 1.0) < 0.01, \
    f"La somme des poids des features doit être 1.0, actuelle: {_total_weight}"

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — PARAMÈTRES DE DÉTECTION DES ANOMALIES
# ══════════════════════════════════════════════════════════════════════════════

DETECTION_CONFIG = {
    # ── Isolation Forest ──────────────────────────────────────────────────────
    # n_estimators : nombre d'arbres dans la forêt.
    # Plus d'arbres = plus précis mais plus lent.
    # 100 est le standard pour un bon équilibre performance/vitesse.
    "isolation_forest_n_estimators": 100,

    # contamination : proportion attendue d'anomalies dans les données d'entraînement.
    # 0.05 = on s'attend à ce que 5% des journées soient anormales.
    # Augmenter (0.10) pour détecter plus d'anomalies (plus de faux positifs).
    # Réduire (0.02) pour être plus strict (moins de faux positifs mais risque de rater).
    "isolation_forest_contamination": 0.05,

    # random_state : graine aléatoire pour la reproductibilité.
    # Même graine = mêmes résultats à chaque exécution.
    # Important pour déboguer et comparer des runs.
    "isolation_forest_random_state": 42,

    # ── Scoring du risque ────────────────────────────────────────────────────
    # Seuil à partir duquel un score de risque génère une alerte UEBA.
    # Score 0 = comportement parfaitement normal.
    # Score 100 = anomalie certaine.
    # 70 est le seuil standard : assez haut pour éviter les faux positifs,
    # assez bas pour capturer les menaces réelles.
    "alert_threshold": 70,

    # ── Pondération du score final ────────────────────────────────────────────
    # Le score final est un mélange pondéré de deux signaux :
    # - isolation_forest_score : signal ML (bonne détection des patterns complexes)
    # - zscore_contribution    : signal statistique (bon pour l'explicabilité)
    # La somme doit être 1.0
    "if_score_weight":     0.6,   # Isolation Forest contribue à 60% du score
    "zscore_weight":       0.4,   # Z-Score contribue à 40% du score

    # ── Heures ouvrées ────────────────────────────────────────────────────────
    # Définit "normal" vs "hors heures" pour la feature off_hours_activity_ratio.
    # Modifier selon les horaires de ton organisation.
    "business_hours_start": 8,    # 8h00
    "business_hours_end":   18,   # 18h00
    # Jours ouvrés (0=lundi, 4=vendredi, 5=samedi, 6=dimanche)
    "business_days": [0, 1, 2, 3, 4],  # lundi à vendredi
}

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — ENTITÉS À SURVEILLER
# Définit les utilisateurs et machines du dataset CTU.
# À modifier pour ajouter de vraies entités de production.
# ══════════════════════════════════════════════════════════════════════════════

ENTITIES_CONFIG = {
    # Utilisateurs à profiler (doivent correspondre au champ "username" dans ES)
    "users": [
        "jack.bauer",       # Analyste SOC — comportement normal de référence
        "chloe.obrian",     # Administrateur — accès multi-serveurs légitimes
        "bill.buchanan",    # RSSI — consultation logs, heures fixes
        "david.palmer",     # Lecteur — accès minimal, données sensibles
        "tony.almeida",     # Utilisateur normal — profil parfaitement normal
    ],
    # Machines à profiler (doivent correspondre au champ "host" dans ES)
    "machines": [
        "srv-web-01",
        "srv-db-01",
        "srv-ad-01",
    ],
}