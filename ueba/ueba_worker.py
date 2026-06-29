#!/usr/bin/env python3
"""
================================================================================
ueba/ueba_worker.py — Orchestrateur principal du module UEBA
================================================================================
Rôle unique : coordonner les 4 autres modules dans le bon ordre,
              gérer les erreurs, et produire le rapport de run.

Cycle quotidien (lancé par cron à 3h) :
  Pour chaque entité (user/machine) :
    1. Extraire les features des 30 derniers jours (feature_engineering)
    2. Calculer les statistiques de référence (baseline)
    3. Extraire les features du jour courant (feature_engineering)
    4. Détecter les anomalies : Z-Score + Isolation Forest (anomaly_detector)
    5. Calculer le score de risque 0–100 (anomaly_detector)
    6. Si score > seuil : créer une alerte dans PG (table alerts)
    7. Persister le profil dans PG et ES (baseline)
    8. Produire le rapport de run

Ce fichier est le SEUL point d'entrée. Lancer :
  python3 ueba_worker.py
  ou en continu : while true; do python3 ueba_worker.py; sleep 86400; done
================================================================================
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Optional

import asyncpg
from elasticsearch import AsyncElasticsearch

# Import de tous les modules du dossier ueba/
from config import (
    ES_CONFIG, PG_CONFIG, ENTITIES_CONFIG,
    BASELINE_CONFIG, DETECTION_CONFIG,
)
from feature_engineering import get_features_for_entity, get_features_window
from baseline import (
    compute_baseline_stats, update_typical_hosts,
    save_profile_to_pg, save_profile_to_es,
)
from anomaly_detector import (
    train_isolation_forest, compute_if_score,
    compute_zscore_anomaly_score, compute_final_risk_score,
    explain_anomaly,
)


async def create_ueba_alert(
    pool: asyncpg.Pool,
    entity_id: str,
    entity_type: str,
    score: int,
    level: str,
    anomalous_features: list,
    explanation: str,
    rule_id: Optional[str] = None,
) -> Optional[str]:
    """
    Crée une alerte UEBA dans la table alerts de PostgreSQL.
    L'alerte est identique structurellement aux alertes de corrélation
    pour qu'elle apparaisse dans le même dashboard et le même monitoring.

    Paramètres :
      pool               : pool de connexions PG
      entity_id          : utilisateur ou machine concerné
      entity_type        : "user" ou "machine"
      score              : score de risque 0–100
      level              : INFO / WARNING / HIGH / CRITICAL
      anomalous_features : liste des features anormales (pour les preuves)
      explanation        : texte d'explication pour l'analyste
      rule_id            : UUID de la règle UEBA dans correlation_rules (si existante)

    Retourne :
      UUID de l'alerte créée, ou None si création impossible
    """
    alert_id = str(uuid.uuid4())

    try:
        # Récupérer la règle UEBA générique si rule_id non fourni
        async with pool.acquire() as conn:
            if not rule_id:
                rule_id = await conn.fetchval(
                    "SELECT id FROM correlation_rules "
                    "WHERE rule_type = 'behavioral' AND is_active = TRUE LIMIT 1"
                )

            if not rule_id:
                # Pas de règle behavioral dans PG → créer une entrée minimale
                rule_id = await conn.fetchval(
                    """
                    INSERT INTO correlation_rules (
                        name, rule_type, conditions, alert_level,
                        confidence_score, is_active
                    ) VALUES (
                        'UEBA Behavioral Anomaly', 'behavioral',
                        '{"type": "ueba_anomaly"}'::jsonb,
                        'WARNING'::alert_level, 75, TRUE
                    )
                    ON CONFLICT (name) DO UPDATE SET is_active = TRUE
                    RETURNING id
                    """
                )

            # Insérer l'alerte
            await conn.execute(
                """
                INSERT INTO alerts (
                    id, rule_id, title, level, status,
                    correlated_event_ids, source_ips, affected_hosts, usernames,
                    mitre_tactic, confidence_score, notes
                ) VALUES (
                    $1::uuid, $2::uuid, $3, $4::alert_level, 'open'::alert_status,
                    '[]'::jsonb,
                    '[]'::jsonb,
                    $5::jsonb,
                    $6::jsonb,
                    'TA0000',
                    $7,
                    $8
                )
                """,
                alert_id,
                str(rule_id),
                f"[UEBA] Anomalie comportementale — {entity_id} (score={score}/100)",
                level,
                json.dumps([entity_id] if entity_type == "machine" else []),
                json.dumps([entity_id] if entity_type == "user" else []),
                score,
                explanation[:500],  # limite PG TEXT
            )

        return alert_id

    except Exception as e:
        print(f"  [ERREUR] Création alerte UEBA pour {entity_id}: {e}")
        return None


async def process_entity(
    es: AsyncElasticsearch,
    pool: asyncpg.Pool,
    entity_id: str,
    entity_type: str,
    run_report: dict,
):
    """
    Traite une entité complète : extraction features → baseline → détection → alerte.
    Chaque entité est traitée indépendamment pour éviter qu'une erreur
    sur un utilisateur bloque le traitement des autres.

    Paramètres :
      es          : client ES async
      pool        : pool PG async
      entity_id   : username ou hostname
      entity_type : "user" ou "machine"
      run_report  : dictionnaire de rapport mis à jour in-place
    """
    print(f"\n  [{entity_type.upper()}] {entity_id}")

    try:
        # ── Étape 1 : Extraire les features historiques (30 jours) ───────────
        print(f"    → Extraction des features historiques ({BASELINE_CONFIG['window_days']} jours)...")
        historical_features = await get_features_window(
            es, entity_id, entity_type,
            window_days=BASELINE_CONFIG["window_days"]
        )

        if len(historical_features) < 7:
            print(f"    ⚠ Données insuffisantes : {len(historical_features)} jours "
                  f"(minimum 7). Profil ignoré.")
            run_report["skipped"].append(
                {"entity": entity_id, "reason": f"seulement {len(historical_features)} jours"}
            )
            return

        print(f"    ✓ {len(historical_features)} jours de données disponibles")

        # ── Étape 2 : Calculer la baseline statistique ────────────────────────
        baseline_stats  = compute_baseline_stats(historical_features)
        typical_hosts   = update_typical_hosts(historical_features)

        # ── Étape 3 : Extraire les features du jour courant ──────────────────
        today = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        today_features = await get_features_for_entity(
            es, entity_id, entity_type, today
        )

        if today_features is None:
            print(f"    ⚠ Pas assez d'activité aujourd'hui — profil mis à jour, score inchangé")
            # Mettre à jour le profil dans PG/ES avec score inchangé
            await save_profile_to_pg(pool, entity_id, entity_type, baseline_stats, typical_hosts)
            await save_profile_to_es(es, entity_id, entity_type, baseline_stats, typical_hosts)
            run_report["no_activity_today"].append(entity_id)
            return

        # ── Étape 4 : Mettre à jour new_system_access dans today_features ────
        hosts_today = set(today_features["_meta"].get("hosts_today", []))
        new_hosts   = hosts_today - set(typical_hosts)
        today_features["new_system_access_count"] = len(new_hosts)

        # ── Étape 5 : Calculer le score Z-Score (explicable) ─────────────────
        zscore_score, anomalous_features = compute_zscore_anomaly_score(
            today_features, baseline_stats
        )

        # ── Étape 6 : Entraîner et appliquer l'Isolation Forest ──────────────
        model, scaler = train_isolation_forest(historical_features)
        if_score      = compute_if_score(model, scaler, today_features)

        # ── Étape 7 : Calculer le score final et le niveau d'alerte ──────────
        final_score, alert_level = compute_final_risk_score(
            if_score, zscore_score, anomalous_features
        )

        # ── Étape 8 : Générer l'explication textuelle ─────────────────────────
        explanation = explain_anomaly(anomalous_features, entity_id, final_score)

        # Affichage du résultat
        score_display = f"Score: {final_score}/100 [{alert_level}]"
        if anomalous_features:
            features_str = ", ".join(f["feature"] for f in anomalous_features[:3])
            print(f"    {score_display} — Anomalies: {features_str}")
        else:
            print(f"    {score_display} — Comportement normal")

        # ── Étape 9 : Créer une alerte si score dépasse le seuil ─────────────
        alert_id = None
        if final_score >= DETECTION_CONFIG["alert_threshold"]:
            alert_id = await create_ueba_alert(
                pool, entity_id, entity_type,
                final_score, alert_level,
                anomalous_features, explanation,
            )
            if alert_id:
                print(f"    🚨 Alerte créée dans PG : {alert_id}")

        # ── Étape 10 : Persister le profil mis à jour ─────────────────────────
        pg_profile_id = await save_profile_to_pg(
            pool, entity_id, entity_type,
            baseline_stats, typical_hosts,
            risk_score=final_score,
        )
        es_profile_id = await save_profile_to_es(
            es, entity_id, entity_type,
            baseline_stats, typical_hosts,
            risk_score=final_score,
            anomalies_detected=[
                {"feature": f["feature"], "z_score": f["z_score"],
                 "explanation": f["explanation"],
                 "detected_at": datetime.now(timezone.utc).isoformat()}
                for f in anomalous_features
            ],
        )

        # Ajouter au rapport de run
        entity_result = {
            "entity":             entity_id,
            "entity_type":        entity_type,
            "risk_score":         final_score,
            "alert_level":        alert_level,
            "anomalous_features": [f["feature"] for f in anomalous_features],
            "alert_created":      alert_id is not None,
            "alert_id":           alert_id,
            "historical_days":    len(historical_features),
        }
        run_report["processed"].append(entity_result)

        if final_score >= DETECTION_CONFIG["alert_threshold"]:
            run_report["alerts_created"].append(entity_result)

    except Exception as e:
        import traceback
        print(f"    ❌ Erreur : {e}")
        traceback.print_exc()
        run_report["errors"].append({"entity": entity_id, "error": str(e)})


async def run_ueba_cycle(es: AsyncElasticsearch, pool: asyncpg.Pool) -> dict:
    """
    Lance un cycle complet du worker UEBA sur toutes les entités configurées.
    Retourne le rapport de run complet.
    """
    print("=" * 60)
    print(f"UEBA WORKER — Cycle du {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    run_report = {
        "started_at":       datetime.now(timezone.utc).isoformat(),
        "processed":        [],
        "skipped":          [],
        "errors":           [],
        "alerts_created":   [],
        "no_activity_today":[],
    }

    # Traitement de tous les utilisateurs configurés
    print(f"\n[USERS] {len(ENTITIES_CONFIG['users'])} utilisateurs à analyser")
    for username in ENTITIES_CONFIG["users"]:
        await process_entity(es, pool, username, "user", run_report)

    # Traitement de toutes les machines configurées
    print(f"\n[MACHINES] {len(ENTITIES_CONFIG['machines'])} machines à analyser")
    for hostname in ENTITIES_CONFIG["machines"]:
        await process_entity(es, pool, hostname, "machine", run_report)

    run_report["ended_at"] = datetime.now(timezone.utc).isoformat()
    return run_report


def print_run_summary(report: dict):
    """Affiche un résumé lisible du cycle de run."""
    print("\n" + "=" * 60)
    print("RÉSUMÉ DU CYCLE UEBA")
    print("=" * 60)
    print(f"  Entités traitées    : {len(report['processed'])}")
    print(f"  Entités ignorées    : {len(report['skipped'])}")
    print(f"  Erreurs             : {len(report['errors'])}")
    print(f"  Alertes créées      : {len(report['alerts_created'])}")

    if report["alerts_created"]:
        print(f"\n  🚨 Alertes UEBA :")
        for a in report["alerts_created"]:
            print(f"    [{a['alert_level']:<8}] {a['entity']:<20} score={a['risk_score']}/100 "
                  f"features={a['anomalous_features'][:2]}")

    if report["errors"]:
        print(f"\n  ❌ Erreurs :")
        for e in report["errors"]:
            print(f"    {e['entity']} : {e['error'][:80]}")

    # Calcul du recall si des anomalies sont attendues (pour les tests)
    n_alerts = len(report["alerts_created"])
    expected = 5  # nombre d'anomalies injectées dans le dataset (hors tony.almeida)
    recall   = min(1.0, n_alerts / expected) if expected > 0 else 0.0
    print(f"\n  Recall estimé       : {recall:.0%} ({n_alerts}/{expected} anomalies détectées)")
    print(f"  Objectif            : ≥ 80%")


async def main():
    """Point d'entrée principal du worker."""
    # Connexion Elasticsearch
    es = AsyncElasticsearch(
        hosts=[ES_CONFIG["host"]],
        basic_auth=(ES_CONFIG["user"], ES_CONFIG["password"]),
        ca_certs=ES_CONFIG["ca_certs"],
        verify_certs=True,
    )
    # Connexion PostgreSQL
    pool = await asyncpg.create_pool(
        dsn=PG_CONFIG["dsn"],
        min_size=PG_CONFIG["pool_min"],
        max_size=PG_CONFIG["pool_max"],
    )

    try:
        report = await run_ueba_cycle(es, pool)
        print_run_summary(report)

        # Sauvegarder le rapport en JSON
        import json
        from pathlib import Path
        reports_dir = Path("ueba_reports")
        reports_dir.mkdir(exist_ok=True)
        report_file = reports_dir / f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n  📄 Rapport sauvegardé : {report_file}")

    finally:
        await es.close()
        await pool.close()


if __name__ == "__main__":
    asyncio.run(main())