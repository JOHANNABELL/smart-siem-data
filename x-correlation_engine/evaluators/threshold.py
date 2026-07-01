"""
correlation_engine/evaluators/threshold.py
────────────────────────────────────────────
Rôle unique : détecter les attaques par dépassement de seuil.

Principe : pour chaque entité (IP ou username), compter combien de fois
un event_action apparaît dans la fenêtre temporelle. Si count ≥ seuil → alerte.

Deux modes de comptage selon conditions.count_type :
  "count"       (défaut) → count(*) — nombre d'occurrences totales
  "cardinality" (nouveau) → count(DISTINCT champ) — valeurs uniques
                            Indispensable pour T1046 Port Scan (ports distincts)
"""
import logging
from datetime import datetime, timedelta, timezone

from elasticsearch import AsyncElasticsearch

from ..models import CorrelationRule, AlertCandidate
from ..config import ES_INDEX

log = logging.getLogger("evaluator.threshold")


async def evaluate(rule: CorrelationRule,
                   es: AsyncElasticsearch) -> list[AlertCandidate]:
    """
    Évalue une règle threshold et retourne les alertes candidates.

    Signature : (rule, es) → list[AlertCandidate]
    C'est le contrat commun à tous les évaluateurs.
    En cas d'erreur ES → retourner [] (jamais lever d'exception).
    """
    conditions   = rule.conditions
    event_action = conditions.get("event_action")
    group_by     = conditions.get("group_by", "source_ip")
    min_count    = rule.threshold_count or 5
    window_sec   = rule.time_window_seconds or 60
    count_type   = conditions.get("count_type", "count")  # "count" ou "cardinality"
    cardinality_field = conditions.get("cardinality_field", "dest_port")

    # Si pas d'event_action défini, la règle est aveugle → skip
    if not event_action:
        log.warning(f"Règle '{rule.name}' sans event_action — ignorée")
        return []

    now   = datetime.now(timezone.utc)
    since = now - timedelta(seconds=window_sec)

    # ── Construction de la requête ES ─────────────────────────────────────────
    # Les sous-agrégations varient selon le mode de comptage.

    if count_type == "cardinality":
        # Mode cardinalité : compter les valeurs DISTINCTES du champ cible
        # Cas d'usage : Port Scan → compter les dest_port distincts par source_ip
        # Un attaquant qui scanne génère beaucoup de ports distincts, pas de répétitions
        sub_aggs = {
            # Compte les valeurs distinctes du champ cible
            # precision_threshold=40 → précision HyperLogLog suffisante pour de petits sets
            "cardinality_count": {
                "cardinality": {
                    "field":              cardinality_field,
                    "precision_threshold": 40
                }
            },
            # Hôtes touchés (pour les preuves dans l'alerte)
            "hosts": {"terms": {"field": "host", "size": 5}},
        }
    else:
        # Mode count standard : compter les occurrences totales
        # Cas d'usage : Brute Force → compter les login_failed par source_ip
        sub_aggs = {
            # raw_log_id est notre champ applicatif — évite le bug _id fielddata
            "event_ids": {"terms": {"field": "raw_log_id", "size": 20}},
            "hosts":     {"terms": {"field": "host",       "size": 5}},
            "usernames": {"terms": {"field": "username",   "size": 5}},
        }

    query = {
        "query": {
            "bool": {
                "must": [
                    {"term":  {"event_action": event_action}},
                    {"range": {"@timestamp": {"gte": since.isoformat()}}}
                ]
            }
        },
        "aggs": {
            "by_entity": {
                "terms": {
                    "field":         group_by,
                    # En mode cardinalité, on ne peut pas filtrer avec min_doc_count
                    # sur la cardinalité — on filtre en Python après
                    "min_doc_count": 1 if count_type == "cardinality" else min_count,
                    "size":          50
                },
                "aggs": sub_aggs
            }
        },
        "size": 0
    }

    try:
        resp = await es.search(index=ES_INDEX, body=query)
    except Exception as e:
        log.error(f"Erreur ES (threshold {rule.name}): {e}")
        return []

    # ── Traitement des résultats ──────────────────────────────────────────────
    buckets    = resp.get("aggregations", {}).get("by_entity", {}).get("buckets", [])
    candidates = []

    for bucket in buckets:
        entity_value = bucket["key"]

        # Déterminer le compte effectif selon le mode
        if count_type == "cardinality":
            effective_count = bucket.get("cardinality_count", {}).get("value", 0)
        else:
            effective_count = bucket["doc_count"]

        # Vérification du seuil
        if effective_count < min_count:
            continue

        # Extraction des preuves
        event_ids = [b["key"] for b in bucket.get("event_ids", {}).get("buckets", [])]
        hosts     = [b["key"] for b in bucket.get("hosts", {}).get("buckets", [])]
        usernames = [b["key"] for b in bucket.get("usernames", {}).get("buckets", [])]

        # Titre adapté selon le mode
        if count_type == "cardinality":
            title = (
                f"[{rule.name}] {effective_count} {cardinality_field}s distincts "
                f"depuis {entity_value} en {window_sec}s"
            )
        else:
            title = (
                f"[{rule.name}] {effective_count} occurrences de '{event_action}' "
                f"depuis {entity_value} en {window_sec}s"
            )

        candidates.append(AlertCandidate(
            rule_id=rule.id,
            rule_name=rule.name,
            level=rule.alert_level,
            title=title,
            correlated_event_ids=event_ids,
            source_ips=[entity_value] if group_by == "source_ip" else [],
            affected_hosts=hosts,
            usernames=usernames,
            mitre_tactic=rule.mitre_tactic,
            confidence_score=rule.confidence_score,
        ))

        log.warning(
            f"[THRESHOLD HIT] {rule.name} | {group_by}={entity_value} | "
            f"count={effective_count} ({'cardinality' if count_type == 'cardinality' else 'total'})"
        )

    return candidates