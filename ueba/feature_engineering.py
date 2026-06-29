#!/usr/bin/env python3
"""
================================================================================
ueba/feature_engineering.py — Extraction des features comportementales
================================================================================
Rôle unique : interroger Elasticsearch et calculer les 8 features numériques
              pour chaque entité (utilisateur ou machine) sur une période donnée.

Entrée  : identifiant d'entité + fenêtre temporelle
Sortie  : dictionnaire {feature_name: valeur_numérique}

Pourquoi séparer l'extraction des features de la détection ?
  - Testabilité : on peut vérifier les features sans lancer le modèle
  - Réutilisabilité : les mêmes features servent à la baseline ET à la détection
  - Modularité : remplacer ES par une autre source ne touche que ce fichier
================================================================================
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Optional

from elasticsearch import AsyncElasticsearch

from config import ES_CONFIG, FEATURES_CONFIG, DETECTION_CONFIG, BASELINE_CONFIG


async def get_features_for_entity(
    es: AsyncElasticsearch,
    entity_id: str,
    entity_type: str,
    day: datetime,
) -> Optional[dict]:
    """
    Calcule les 8 features comportementales pour une entité sur une journée.

    Paramètres :
      es          : client Elasticsearch async
      entity_id   : username (pour les users) ou hostname (pour les machines)
      entity_type : "user" ou "machine"
      day         : datetime du jour à analyser (minuit UTC)

    Retourne :
      dict {feature_name: float} si assez de données,
      None si moins de min_events_required événements (profil insuffisant)
    """
    # Bornes de la journée à analyser (00:00:00 → 23:59:59)
    day_start = day.replace(hour=0,  minute=0,  second=0,  microsecond=0)
    day_end   = day.replace(hour=23, minute=59, second=59, microsecond=999999)

    # Champ de filtrage selon le type d'entité
    # Pour les users : filtrer sur "username"
    # Pour les machines : filtrer sur "host"
    filter_field = "username" if entity_type == "user" else "host"

    # ── Requête ES principale : toutes les agrégations en une seule requête ──
    # Regrouper plusieurs agrégations en une requête = moins de round-trips réseau
    query = {
        "query": {
            "bool": {
                "must": [
                    # Filtrer sur l'entité concernée
                    {"term":  {filter_field: entity_id}},
                    # Filtrer sur la journée analysée
                    {"range": {"@timestamp": {
                        "gte": day_start.isoformat(),
                        "lte": day_end.isoformat(),
                    }}},
                ]
            }
        },
        "aggs": {
            # ── Agg 1 : Comptage des connexions réussies ──────────────────────
            # Utilisée pour : login_count_per_day
            "login_success_count": {
                "filter": {"term": {"event_action": "login_success"}}
            },

            # ── Agg 2 : Comptage des connexions échouées ──────────────────────
            # Utilisée pour : failed_login_ratio = failed / (failed + success)
            "login_failed_count": {
                "filter": {"term": {"event_action": "login_failed"}}
            },

            # ── Agg 3 : Heures de connexion ───────────────────────────────────
            # Histogramme par heure pour calculer l'heure moyenne de connexion
            # et le ratio hors-heures
            "login_hours_histogram": {
                "filter": {"term": {"event_action": "login_success"}},
                "aggs": {
                    "by_hour": {
                        "date_histogram": {
                            "field":           "@timestamp",
                            "calendar_interval": "hour",
                            "format":          "HH",  # retourne l'heure 00–23
                        }
                    }
                }
            },

            # ── Agg 4 : IPs sources distinctes ────────────────────────────────
            # Cardinalité = nombre de valeurs uniques
            # precision_threshold=40 : précision suffisante pour de petits ensembles
            "unique_ips": {
                "cardinality": {
                    "field":              "source_ip",
                    "precision_threshold": 40,
                }
            },

            # ── Agg 5 : Machines accédées distinctes ──────────────────────────
            "unique_hosts": {
                "cardinality": {
                    "field":              "host",
                    "precision_threshold": 100,
                }
            },

            # ── Agg 6 : Volume de données transféré ───────────────────────────
            # avg sur bytes_sent_mb du sous-objet enriched_data
            # ignore_missing=True : ne pas échouer si le champ est absent
            "total_data_mb": {
                "sum": {
                    "field":          "enriched_data.bytes_sent_mb",
                    "missing":        0.0,  # valeur si champ absent = 0 Mo
                }
            },

            # ── Agg 7 : Liste des hôtes accédés (pour new_system_access) ──────
            # Les 20 premiers hôtes distincts accédés ce jour
            "hosts_list": {
                "terms": {
                    "field": "host",
                    "size":  20,
                }
            },
        },
        "size": 0,  # on ne veut que les agrégations, pas les documents bruts
    }

    try:
        resp = await es.search(index=ES_CONFIG["index"], body=query)
    except Exception as e:
        print(f"  [ERREUR ES] feature_engineering pour {entity_id} : {e}")
        return None

    aggs = resp.get("aggregations", {})
    total_events = resp["hits"]["total"]["value"]

    # ── Vérification du seuil minimum de données ──────────────────────────────
    # Un profil avec moins de N événements est statistiquement non fiable.
    # Il vaut mieux ne pas détecter que générer de faux positifs.
    if total_events < BASELINE_CONFIG["min_events_required"]:
        return None   # Signal "données insuffisantes"

    # ── Extraction des valeurs brutes des agrégations ─────────────────────────

    login_success = aggs["login_success_count"]["doc_count"]
    login_failed  = aggs["login_failed_count"]["doc_count"]
    unique_ips    = aggs["unique_ips"]["value"]
    unique_hosts  = aggs["unique_hosts"]["value"]
    total_data_mb = aggs["total_data_mb"]["value"] or 0.0
    hosts_today   = {b["key"] for b in aggs["hosts_list"]["buckets"]}

    # ── Calcul des features dérivées ──────────────────────────────────────────

    # Feature 1 : heure moyenne de connexion
    # Extraire les heures depuis l'histogramme et calculer la moyenne pondérée
    hour_buckets = aggs["login_hours_histogram"]["by_hour"]["buckets"]
    if hour_buckets:
        total_logins_with_hour = sum(b["doc_count"] for b in hour_buckets)
        weighted_hours = sum(
            int(b["key_as_string"])   # heure 0–23
            * b["doc_count"]           # pondérée par le nombre de connexions
            for b in hour_buckets
        )
        login_hour_mean = (weighted_hours / total_logins_with_hour
                           if total_logins_with_hour > 0 else 12.0)
    else:
        login_hour_mean = 12.0   # midi par défaut si aucune connexion

    # Feature 5 : ratio d'échecs d'authentification
    total_auth = login_success + login_failed
    failed_login_ratio = (login_failed / total_auth) if total_auth > 0 else 0.0

    # Feature 7 : ratio d'activité hors heures ouvrées
    biz_start = DETECTION_CONFIG["business_hours_start"]
    biz_end   = DETECTION_CONFIG["business_hours_end"]
    off_hours_count = sum(
        b["doc_count"]
        for b in hour_buckets
        if int(b["key_as_string"]) < biz_start
        or int(b["key_as_string"]) >= biz_end
    )
    off_hours_ratio = (off_hours_count / total_events) if total_events > 0 else 0.0

    # Feature 8 : accès à de nouveaux systèmes
    # Cette feature nécessite de connaître les hôtes habituels de l'entité.
    # Pour le premier calcul (bootstrap), on ne peut pas savoir ce qui est "nouveau".
    # → On retourne 0 ici ; baseline.py met à jour typical_hosts au fil des jours.
    new_system_access_count = 0  # sera enrichi par baseline.py

    # ── Construction du dictionnaire de features ──────────────────────────────
    features = {
        "login_hour_mean":         round(login_hour_mean, 2),
        "login_count_per_day":     login_success,
        "unique_source_ips":       unique_ips,
        "unique_hosts_accessed":   unique_hosts,
        "failed_login_ratio":      round(failed_login_ratio, 4),
        "data_volume_mb":          round(total_data_mb, 2),
        "off_hours_activity_ratio":round(off_hours_ratio, 4),
        "new_system_access_count": new_system_access_count,   # complété par baseline.py
        # Métadonnées pour le débogage et la traçabilité
        "_meta": {
            "entity_id":     entity_id,
            "entity_type":   entity_type,
            "date":          day_start.date().isoformat(),
            "total_events":  total_events,
            "hosts_today":   list(hosts_today),
        }
    }

    return features


async def get_features_window(
    es: AsyncElasticsearch,
    entity_id: str,
    entity_type: str,
    window_days: int = 30,
) -> list[dict]:
    """
    Calcule les features sur une fenêtre glissante de N jours.
    Retourne une liste de dictionnaires de features, un par jour disponible.

    Utilisée par baseline.py pour construire le profil historique.
    Utilisée par anomaly_detector.py pour l'entraînement du modèle.

    Paramètres :
      window_days : nombre de jours dans la fenêtre (défaut 30 depuis config.py)
    """
    today  = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    results = []

    for day_offset in range(-window_days, 0):
        # Journée à analyser (J-30, J-29, ..., J-1)
        day = today + timedelta(days=day_offset)

        features = await get_features_for_entity(
            es, entity_id, entity_type, day
        )

        if features is not None:
            results.append(features)

    return results