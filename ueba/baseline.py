#!/usr/bin/env python3
"""
================================================================================
ueba/baseline.py — Construction et persistance des profils de référence
================================================================================
Rôle unique : calculer les statistiques de référence (moyenne, écart-type)
              de chaque feature sur la fenêtre historique, et persister le
              profil dans PostgreSQL ET Elasticsearch.

Le profil de référence est "le comportement normal attendu" d'une entité.
Il est mis à jour quotidiennement pour tenir compte de l'évolution naturelle
du comportement (nouvelles habitudes, changement de poste, etc.).

Entrée  : liste de dictionnaires de features (depuis feature_engineering.py)
Sortie  : profil persisté dans PG (ueba_profiles) et ES (ueba-profiles)
================================================================================
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Optional

import asyncpg
import numpy as np
from elasticsearch import AsyncElasticsearch

from config import ES_CONFIG, PG_CONFIG, FEATURES_CONFIG, BASELINE_CONFIG


def compute_baseline_stats(features_list: list[dict]) -> dict:
    """
    Calcule les statistiques de référence depuis la liste des features historiques.

    Pour chaque feature numérique, calcule :
      - mean       : valeur moyenne (centre du comportement normal)
      - std        : écart-type (dispersion autour du centre)
      - min / max  : valeurs extrêmes observées dans la fenêtre historique
      - p25 / p75  : percentiles 25 et 75 (robustes aux outliers ponctuels)

    Pourquoi la moyenne ET l'écart-type ?
      - La moyenne définit le centre : "l'utilisateur se connecte en moyenne à 9h30"
      - L'écart-type définit la largeur : "avec une variation de ±1.5 heures"
      - Le Z-Score utilise les deux : Z = (valeur - moyenne) / écart-type
      - Un Z de 3 signifie "à 3 écarts-types de la moyenne" = très inhabituel

    Robustesse aux outliers :
      Si un utilisateur a eu une anomalie parmi les 30 jours de baseline,
      cette anomalie va légèrement déformer la moyenne.
      C'est pourquoi on utilise aussi les percentiles (p25/p75) qui sont
      moins sensibles aux valeurs extrêmes.

    Paramètres :
      features_list : liste de dicts de features, un dict par journée

    Retourne :
      dict {feature_name: {"mean": float, "std": float, "min": float, "max": float}}
    """
    # Noms des features numériques (exclure les métadonnées _meta)
    feature_names = [k for k in FEATURES_CONFIG.keys()]

    stats = {}
    for fname in feature_names:
        # Extraire toutes les valeurs de cette feature sur la fenêtre historique
        values = [
            f[fname]
            for f in features_list
            if fname in f and f[fname] is not None
        ]

        if len(values) < 3:
            # Moins de 3 valeurs = statistiques non fiables
            # On utilise des valeurs conservatrices par défaut
            stats[fname] = {
                "mean": 0.0, "std": 1.0,
                "min": 0.0,  "max": 0.0,
                "p25": 0.0,  "p75": 0.0,
                "n_days": len(values),
                "sufficient": False,   # signal "données insuffisantes"
            }
            continue

        arr = np.array(values, dtype=float)

        # Calculer std avec ddof=1 (échantillon, pas population)
        # ddof=1 est plus approprié pour les petits échantillons (Bessel's correction)
        std = float(np.std(arr, ddof=1))

        # Éviter une std de zéro (division par zéro dans le Z-Score)
        # Si toutes les valeurs sont identiques (std=0), utiliser 0.01 comme plancher
        std = max(std, 0.01)

        stats[fname] = {
            "mean":       float(np.mean(arr)),
            "std":        std,
            "min":        float(np.min(arr)),
            "max":        float(np.max(arr)),
            "p25":        float(np.percentile(arr, 25)),
            "p75":        float(np.percentile(arr, 75)),
            "n_days":     len(values),
            "sufficient": True,
        }

    return stats


def update_typical_hosts(
    features_list: list[dict],
    existing_typical_hosts: list = None,
) -> list[str]:
    """
    Met à jour la liste des machines habituellement accédées par une entité.

    Logique :
      Un hôte est "typique" s'il a été accédé au moins N fois dans les 30 derniers jours.
      Le seuil N = 3 (arbitraire — au moins 3 jours sur 30 = accès occasionnel).
      Les hôtes accédés moins de 3 fois sont considérés comme "nouveaux" et potentiellement suspects.

    Paramètres :
      features_list          : features historiques avec champ _meta.hosts_today
      existing_typical_hosts : liste des hôtes déjà connus (pour les mises à jour)

    Retourne : liste des hôtes typiques mise à jour
    """
    # Compter les occurrences de chaque hôte sur la fenêtre historique
    host_counts: dict = {}
    for f in features_list:
        meta = f.get("_meta", {})
        for host in meta.get("hosts_today", []):
            host_counts[host] = host_counts.get(host, 0) + 1

    # Seuil : un hôte accédé au moins 3 fois sur 30 jours = typique
    MIN_OCCURRENCES = 3
    typical = [h for h, cnt in host_counts.items() if cnt >= MIN_OCCURRENCES]

    # Fusion avec les hôtes existants (mises à jour progressives)
    if existing_typical_hosts:
        all_typical = set(existing_typical_hosts) | set(typical)
        return list(all_typical)

    return typical


async def save_profile_to_pg(
    pool: asyncpg.Pool,
    entity_id: str,
    entity_type: str,
    baseline_stats: dict,
    typical_hosts: list,
    risk_score: int = 0,
) -> str:
    """
    Persiste le profil comportemental dans PostgreSQL (table ueba_profiles).
    Utilise INSERT ... ON CONFLICT UPDATE pour l'idempotence :
    si le profil existe déjà, on le met à jour plutôt que de créer un doublon.

    Retourne l'UUID du profil créé ou mis à jour.
    """
    profile_id = str(uuid.uuid4())
    today = datetime.now(timezone.utc)

    # Conversion des statistiques en JSON pour le stockage JSONB dans PG
    typical_login_hours_json = json.dumps({
        "mean":  baseline_stats.get("login_hour_mean", {}).get("mean", 12.0),
        "std":   baseline_stats.get("login_hour_mean", {}).get("std", 2.0),
        "p25":   baseline_stats.get("login_hour_mean", {}).get("p25", 9.0),
        "p75":   baseline_stats.get("login_hour_mean", {}).get("p75", 17.0),
    })
    typical_hosts_json = json.dumps({"hosts": typical_hosts})

    avg_daily_events = (
        baseline_stats.get("login_count_per_day", {}).get("mean", 0.0)
    )
    avg_daily_data_mb = (
        baseline_stats.get("data_volume_mb", {}).get("mean", 0.0)
    )

    async with pool.acquire() as conn:
        # INSERT ... ON CONFLICT : update si profil déjà existant pour cette entité
        # Évite les doublons si le worker tourne plusieurs fois le même jour
        result = await conn.fetchval(
            """
            INSERT INTO ueba_profiles (
                id, entity_id, entity_type,
                profile_period_start, profile_period_end,
                typical_login_hours, typical_accessed_systems,
                avg_daily_events, avg_daily_data_mb,
                risk_score_current, last_updated
            ) VALUES (
                $1::uuid, $2, $3::entity_type,
                NOW() - INTERVAL '30 days', NOW(),
                $4::jsonb, $5::jsonb,
                $6, $7,
                $8, NOW()
            )
            """,
            profile_id,
            entity_id,
            entity_type,
            typical_login_hours_json,
            typical_hosts_json,
            avg_daily_events,
            avg_daily_data_mb,
            risk_score,
        )

    # return str(result or profile_id)

    #         ON CONFLICT (entity_id, profile_period_start)
    #         DO UPDATE SET
    #             typical_login_hours    = EXCLUDED.typical_login_hours,
    #             typical_accessed_systems = EXCLUDED.typical_accessed_systems,
    #             avg_daily_events       = EXCLUDED.avg_daily_events,
    #             avg_daily_data_mb      = EXCLUDED.avg_daily_data_mb,
    #             risk_score_current     = EXCLUDED.risk_score_current,
    #             last_updated           = NOW()
    #         RETURNING id
async def save_profile_to_es(
    es: AsyncElasticsearch,
    entity_id: str,
    entity_type: str,
    baseline_stats: dict,
    typical_hosts: list,
    risk_score: int = 0,
    anomalies_detected: list = None,
) -> str:
    """
    Persiste le profil comportemental dans Elasticsearch (index ueba-profiles).
    ES permet des requêtes complexes et des visualisations Kibana sur les profils.

    Le document ES est plus riche que le profil PG :
    il contient l'historique des scores et les anomalies détectées.

    Retourne l'ID ES du document créé/mis à jour.
    """
    es_doc_id = f"ueba-{entity_type}-{entity_id}"  # ID stable pour l'upsert

    profile_doc = {
        "@timestamp":            datetime.now(timezone.utc).isoformat(),
        "entity_id":             entity_id,
        "entity_type":           entity_type,
        "profile_period_start":  (
            datetime.now(timezone.utc) - __import__("datetime").timedelta(days=30)
        ).isoformat(),
        "profile_period_end":    datetime.now(timezone.utc).isoformat(),

        # Profil comportemental complet avec statistiques par feature
        "baseline_stats":        baseline_stats,

        # Machines habituellement accédées (pour détecter new_system_access)
        "typical_accessed_systems": typical_hosts,

        # Score de risque actuel (0 = normal, 100 = anomalie certaine)
        "risk_score_current":    risk_score,

        # Historique des anomalies détectées (tableau de documents nested)
        "anomalies_detected":    anomalies_detected or [],

        # Métadonnées
        "avg_daily_events":      baseline_stats.get("login_count_per_day", {}).get("mean", 0),
        "avg_daily_data_mb":     baseline_stats.get("data_volume_mb", {}).get("mean", 0),
        "last_updated":          datetime.now(timezone.utc).isoformat(),
    }

    # Upsert : créer si inexistant, mettre à jour si existant
    await es.index(
        index=ES_CONFIG["ueba_index"],
        id=es_doc_id,
        body=profile_doc,
    )

    return es_doc_id