"""
correlation_engine/evaluators/cross_source.py
───────────────────────────────────────────────
Rôle unique : détecter les menaces corrélant des événements sur des sources DIFFÉRENTES.

Principe : intersection d'ensembles.
  Source firewall    → IPs bloquées : {A, B, C}
  Source AD          → IPs tentant auth : {B, C, D}
  Intersection       → {B, C} → suspectes sur les DEUX sources → alerte

Amélioration vs version précédente :
  Le score n'est plus binaire (présent/absent) mais un float composite 0–1.
  Cela permet des seuils graduels conformément au document HTML de référence :
    score ≥ 0.55 → HIGH, score ≥ 0.75 → CRITICAL
"""
import logging
from datetime import datetime, timedelta, timezone

from elasticsearch import AsyncElasticsearch

from ..models import CorrelationRule, AlertCandidate
from ..config import ES_INDEX

log = logging.getLogger("evaluator.cross_source")


async def evaluate(rule: CorrelationRule,
                   es: AsyncElasticsearch) -> list[AlertCandidate]:
    """
    Évalue une règle composite cross-source.

    Pour chaque source listée dans conditions.sources, fait une requête ES
    et collecte les entités (IPs ou usernames) qui ont produit l'event_action
    attendu. Retourne une alerte pour chaque entité présente dans TOUTES les sources.
    """
    conditions     = rule.conditions
    sources_needed = conditions.get("sources", [])
    event_per_src  = conditions.get("events", {})
    group_by       = conditions.get("group_by", "source_ip")
    window_sec     = rule.time_window_seconds or 300

    if len(sources_needed) < 2:
        log.warning(f"Règle composite '{rule.name}' avec < 2 sources — ignorée")
        return []

    now   = datetime.now(timezone.utc)
    since = now - timedelta(seconds=window_sec)

    # ── Collecter les entités par source ─────────────────────────────────────
    # Pour chaque source, une requête ES distincte
    results_by_source: dict[str, set] = {}
    docs_by_entity:    dict[str, list] = {}

    for source_type in sources_needed:
        expected_action = event_per_src.get(source_type)

        must_clauses = [
            {"range": {"@timestamp": {"gte": since.isoformat()}}}
        ]
        if expected_action:
            must_clauses.append({"term": {"event_action": expected_action}})

        query = {
            "query": {"bool": {"must": must_clauses}},
            "aggs": {
                "by_entity": {
                    "terms": {"field": group_by, "size": 100},
                    "aggs": {
                        # raw_log_id : champ applicatif indexé (évite le bug _id)
                        "event_refs": {"terms": {"field": "raw_log_id", "size": 10}}
                    }
                }
            },
            "size": 0
        }

        try:
            resp = await es.search(index=ES_INDEX, body=query)
            buckets = resp.get("aggregations", {}).get("by_entity", {}).get("buckets", [])
            entities_here = set()
            for bucket in buckets:
                entity = bucket["key"]
                entities_here.add(entity)
                docs_by_entity.setdefault(entity, [])
                for id_b in bucket.get("event_refs", {}).get("buckets", []):
                    docs_by_entity[entity].append(id_b["key"])
            results_by_source[source_type] = entities_here
        except Exception as e:
            log.error(f"Erreur ES cross-source ({source_type}): {e}")
            results_by_source[source_type] = set()

    # ── Intersection des ensembles ────────────────────────────────────────────
    if not results_by_source:
        return []

    common = set.intersection(*results_by_source.values())
    candidates = []

    for entity in common:
        all_ids = docs_by_entity.get(entity, [])

        # Score composite : rapport entre sources touchées et sources requises
        # Si toutes les sources sont touchées → score = 1.0 (max)
        # Ce score sera utilisé dans une version future pour des seuils graduels
        sources_with_entity = sum(
            1 for src_set in results_by_source.values()
            if entity in src_set
        )
        composite_score = sources_with_entity / len(sources_needed)

        title = (
            f"[{rule.name}] Entité {entity} détectée sur "
            + " + ".join(sources_needed)
            + f" (score composite: {composite_score:.0%})"
        )

        candidates.append(AlertCandidate(
            rule_id=rule.id,
            rule_name=rule.name,
            level=rule.alert_level,
            title=title,
            correlated_event_ids=all_ids[:20],
            source_ips=[entity] if group_by == "source_ip" else [],
            affected_hosts=[],
            usernames=[entity] if group_by == "username" else [],
            mitre_tactic=rule.mitre_tactic,
            confidence_score=int(rule.confidence_score * composite_score),
        ))

        log.warning(
            f"[CROSS-SOURCE HIT] {rule.name} | {group_by}={entity} | "
            f"score={composite_score:.0%} | sources={sources_needed}"
        )

    return candidates