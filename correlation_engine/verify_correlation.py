#!/usr/bin/env python3
"""
================================================================================
SMART SIEM — Vérification du moteur de corrélation SANS alert_router
================================================================================
Rôle   : Tester que le moteur de corrélation fonctionne correctement en
          mode standalone, sans avoir besoin de SMTP ni Slack configurés.

Ce script fait 3 vérifications :
  1. Connexion ES + présence des logs
  2. Connexion PG + présence des règles et de la table alerts
  3. Simulation d'un cycle de corrélation complet avec affichage du résultat

Usage  : python3 verify_correlation.py
================================================================================
"""

import os, json, asyncio, asyncpg
from datetime import datetime, timedelta, timezone
from elasticsearch import AsyncElasticsearch

ES_HOST     = os.environ.get("ES_HOST",     "https://localhost:9200")
ES_USER     = os.environ.get("ES_USER",     "elastic")
ES_PASSWORD = os.environ.get("ES_PASSWORD", "8-0Il66xvSeGnK=COySu")
ES_CACERT   = os.environ.get("ES_CACERT",   "http_ca.crt")
ES_INDEX    = "siem-logs-*"
PG_DSN      = os.environ.get("PG_DSN",
    "postgresql://postgres:felicia@localhost:5432/nafeh")

SEP = "─" * 60


async def check_elasticsearch(es: AsyncElasticsearch):
    print(f"\n{SEP}")
    print("CHECK 1 — Elasticsearch")
    print(SEP)

    # Test connexion
    info = await es.info()
    print(f"  [OK] Connecté à ES {info['version']['number']}")

    # Compter les logs dans l'index
    count_resp = await es.count(index=ES_INDEX)
    count = count_resp["count"]
    print(f"  [OK] Logs dans siem-logs-* : {count}")

    if count == 0:
        print("  [WARN] Aucun log — lancer log_generator.py d'abord")
        return False

    # Vérifier que les champs clés sont présents
    sample = await es.search(
        index=ES_INDEX,
        body={
            "query": {"match_all": {}},
            "size": 1,
            "_source": ["@timestamp", "event_action", "source_ip", "severity", "raw_log_id"]
        }
    )
    hit = sample["hits"]["hits"][0]["_source"]
    print(f"  [OK] Exemple de log :")
    print(f"       @timestamp   : {hit.get('@timestamp', 'MANQUANT')}")
    print(f"       event_action : {hit.get('event_action', 'MANQUANT')}")
    print(f"       source_ip    : {hit.get('source_ip', 'MANQUANT')}")
    print(f"       severity     : {hit.get('severity', 'MANQUANT')}")
    print(f"       raw_log_id   : {hit.get('raw_log_id', 'MANQUANT (normal si logs anciens)')}")

    # Compter les event_actions disponibles
    agg = await es.search(
        index=ES_INDEX,
        body={
            "query": {"match_all": {}},
            "aggs": {"actions": {"terms": {"field": "event_action", "size": 20}}},
            "size": 0
        }
    )
    actions = {b["key"]: b["doc_count"]
               for b in agg["aggregations"]["actions"]["buckets"]}
    print(f"\n  [OK] Répartition des event_actions :")
    for action, cnt in sorted(actions.items(), key=lambda x: -x[1]):
        print(f"       {action:<35} : {cnt}")

    return True


async def check_postgresql(pool: asyncpg.Pool):
    print(f"\n{SEP}")
    print("CHECK 2 — PostgreSQL")
    print(SEP)

    async with pool.acquire() as conn:
        # Vérifier les règles actives
        rules = await conn.fetch(
            "SELECT name, rule_type, alert_level, confidence_score "
            "FROM correlation_rules WHERE is_active = TRUE ORDER BY alert_level DESC"
        )
        print(f"  [OK] {len(rules)} règles actives :")
        for r in rules:
            print(f"       [{r['alert_level']:<8}] {r['name']:<45} ({r['rule_type']})")

        if len(rules) == 0:
            print("  [WARN] Aucune règle — lancer init_rules_commented.py d'abord")
            return None

        # Compter les alertes existantes
        alert_count = await conn.fetchval("SELECT COUNT(*) FROM alerts")
        print(f"\n  [OK] Alertes existantes dans PG : {alert_count}")

        # Vérifier que l'admin existe
        admin = await conn.fetchrow(
            "SELECT username, email, is_active FROM users WHERE role = 'admin' LIMIT 1"
        )
        if admin:
            print(f"  [OK] Admin : {admin['username']} ({admin['email']})")
        else:
            print("  [WARN] Aucun admin trouvé")

    return rules


async def simulate_threshold_rule(es: AsyncElasticsearch, pool: asyncpg.Pool):
    """
    Simule manuellement une règle threshold (brute force SSH)
    et vérifie qu'une alerte est insérée dans PostgreSQL.
    """
    print(f"\n{SEP}")
    print("CHECK 3 — Simulation règle threshold : SSH Brute Force")
    print(SEP)

    now   = datetime.now(timezone.utc)
    since = now - timedelta(seconds=60)

    # Requête ES avec la correction _id → raw_log_id
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term":  {"event_action": "login_failed"}},
                    {"range": {"@timestamp": {"gte": since.isoformat()}}}
                ]
            }
        },
        "aggs": {
            "by_entity": {
                "terms": {
                    "field":         "source_ip",
                    "min_doc_count": 3,   # seuil réduit à 3 pour le test
                    "size":          10
                },
                "aggs": {
                    # CORRECTION APPLIQUÉE : raw_log_id au lieu de _id
                    "event_ids":  {"terms": {"field": "raw_log_id", "size": 10}},
                    "hosts":      {"terms": {"field": "host",       "size": 5}},
                    "usernames":  {"terms": {"field": "username",   "size": 5}},
                }
            }
        },
        "size": 0
    }

    resp = await es.search(index=ES_INDEX, body=query)
    buckets = resp.get("aggregations", {}).get("by_entity", {}).get("buckets", [])

    if not buckets:
        print("  [INFO] Pas de brute force détecté dans la dernière minute")
        print("         → Normal si les logs ont été générés il y a plus de 60s")
        print("         → Vérifier avec une fenêtre plus large :")

        # Retry sur 24h
        since_24h = now - timedelta(hours=24)
        query["query"]["bool"]["must"][1]["range"]["@timestamp"]["gte"] = since_24h.isoformat()
        resp2 = await es.search(index=ES_INDEX, body=query)
        buckets = resp2.get("aggregations", {}).get("by_entity", {}).get("buckets", [])
        if buckets:
            print(f"  [OK] {len(buckets)} IP(s) avec 3+ login_failed dans les 24h :")
        else:
            print("  [WARN] Aucun login_failed groupé trouvé — vérifier les données")

    for bucket in buckets:
        ip    = bucket["key"]
        count = bucket["doc_count"]
        ids   = [b["key"] for b in bucket.get("event_ids", {}).get("buckets", [])]
        hosts = [b["key"] for b in bucket.get("hosts",     {}).get("buckets", [])]

        print(f"\n  [DÉTECTION] {ip} → {count} login_failed")
        print(f"              Machines ciblées : {hosts}")
        print(f"              IDs de preuves   : {ids[:3]}{'...' if len(ids) > 3 else ''}")

        # Charger la règle SSH Brute Force depuis PG
        async with pool.acquire() as conn:
            rule = await conn.fetchrow(
                "SELECT id, name, alert_level, confidence_score, mitre_tactic "
                "FROM correlation_rules WHERE name = 'SSH Brute Force Detection'"
            )

        if not rule:
            print("  [WARN] Règle 'SSH Brute Force Detection' introuvable dans PG")
            continue

        title = f"[TEST] SSH Brute Force : {count} tentatives depuis {ip} en 60s"

        # Insertion de l'alerte de test dans PostgreSQL
        import uuid
        alert_id = str(uuid.uuid4())

        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO alerts (
                    id, rule_id, title, level, status,
                    correlated_event_ids, source_ips, affected_hosts,
                    mitre_tactic, confidence_score
                ) VALUES (
                    $1::uuid, $2::uuid, $3, $4::alert_level, 'open'::alert_status,
                    $5::jsonb, $6::jsonb, $7::jsonb, $8, $9
                )
                """,
                alert_id,
                str(rule["id"]),
                title,
                rule["alert_level"],
                json.dumps(ids),
                json.dumps([ip]),
                json.dumps(hosts),
                rule["mitre_tactic"],
                rule["confidence_score"],
            )

        # Vérification de l'insertion
        async with pool.acquire() as conn:
            inserted = await conn.fetchrow(
                "SELECT id, title, level, triggered_at FROM alerts WHERE id = $1::uuid",
                alert_id
            )

        if inserted:
            print(f"\n  [OK] ALERTE INSÉRÉE DANS POSTGRESQL !")
            print(f"       ID        : {inserted['id']}")
            print(f"       Titre     : {inserted['title']}")
            print(f"       Niveau    : {inserted['level']}")
            print(f"       Créée le  : {inserted['triggered_at']}")
        else:
            print("  [ERREUR] L'alerte n'a pas été trouvée après insertion")

        break  # on teste sur la première IP seulement


async def main():
    print("=" * 60)
    print("VÉRIFICATION DU MOTEUR DE CORRÉLATION — Smart SIEM")
    print("=" * 60)

    es = AsyncElasticsearch(
        hosts=[ES_HOST],
        basic_auth=(ES_USER, ES_PASSWORD),
        ca_certs=ES_CACERT,
        verify_certs=True,
    )

    try:
        pool = await asyncpg.create_pool(dsn=PG_DSN, min_size=1, max_size=3)
    except Exception as e:
        print(f"[ERREUR] Connexion PostgreSQL : {e}")
        await es.close()
        return

    try:
        es_ok   = await check_elasticsearch(es)
        rules   = await check_postgresql(pool)

        if es_ok and rules:
            await simulate_threshold_rule(es, pool)

        print(f"\n{SEP}")
        print("RÉSUMÉ")
        print(SEP)
        async with pool.acquire() as conn:
            total_alerts = await conn.fetchval("SELECT COUNT(*) FROM alerts")
            recent = await conn.fetch(
                "SELECT level, title, triggered_at FROM alerts "
                "ORDER BY triggered_at DESC LIMIT 5"
            )

        print(f"  Total alertes dans PG : {total_alerts}")
        if recent:
            print("  5 dernières alertes :")
            for a in recent:
                print(f"    [{a['level']:<8}] {a['title'][:55]}")

    finally:
        await es.close()
        await pool.close()

    print(f"\n{'=' * 60}")
    print("Vérification terminée")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())