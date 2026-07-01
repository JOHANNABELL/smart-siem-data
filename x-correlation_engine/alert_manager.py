"""
correlation_engine/alert_manager.py
──────────────────────────────────────
Rôle unique : dédupliquer les alertes candidates et persister les nouvelles dans PG.

Ce module est le seul à écrire dans la table alerts de PostgreSQL.
Aucun évaluateur ne doit écrire directement en base.

Séquence pour chaque AlertCandidate :
  1. Calculer la clé de déduplication (rule_id::entité)
  2. Vérifier si une alerte identique a été émise récemment
  3. Si non-doublon → INSERT dans alerts + UPDATE trigger_count de la règle
  4. Enregistrer dans le cache de déduplication
  5. Notifier l'API FastAPI pour les playbooks et les notifications
"""
import json
import logging
import uuid
from datetime import datetime, timezone

import aiohttp
import asyncpg

from .models import AlertCandidate
from .config import DEDUP_WINDOW_SEC, DEDUP_CACHE_MAX

log = logging.getLogger("alert_manager")


class AlertManager:
    """
    Gère le cycle de vie des alertes : déduplication → persistance → notification.

    Le cache de déduplication est un dict en mémoire :
      clé : "rule_id::entité"
      valeur : datetime de la dernière émission
    Les alertes avec la même clé dans les DEDUP_WINDOW_SEC secondes sont ignorées.
    """

    def __init__(self, pg_pool: asyncpg.Pool):
        self.pg_pool = pg_pool
        # Cache de déduplication en mémoire
        # Reset au redémarrage du worker — comportement intentionnel
        self._dedup_cache: dict[str, datetime] = {}

    def _is_duplicate(self, candidate: AlertCandidate) -> bool:
        """
        Vérifie si une alerte similaire a été émise dans la fenêtre de déduplication.
        """
        key  = candidate.dedup_key()
        last = self._dedup_cache.get(key)
        if last is None:
            return False
        elapsed = (datetime.now(timezone.utc) - last).total_seconds()
        return elapsed < DEDUP_WINDOW_SEC

    def _mark_emitted(self, candidate: AlertCandidate):
        """Enregistre l'émission de cette alerte dans le cache."""
        key = candidate.dedup_key()
        self._dedup_cache[key] = datetime.now(timezone.utc)

        # Nettoyage périodique si le cache devient trop grand
        if len(self._dedup_cache) > DEDUP_CACHE_MAX:
            cutoff = datetime.now(timezone.utc)
            self._dedup_cache = {
                k: v for k, v in self._dedup_cache.items()
                if (cutoff - v).total_seconds() < DEDUP_WINDOW_SEC
            }

    async def process(self, candidate: AlertCandidate) -> str | None:
        """
        Traite une alerte candidate :
          - Si doublon → log DEBUG et retourner None
          - Sinon → INSERT PG + notification API + retourner l'UUID de l'alerte

        Retourne l'UUID de l'alerte insérée, ou None si doublon/erreur.
        """
        if self._is_duplicate(candidate):
            log.debug(f"[DEDUP] Ignoré : {candidate.title[:60]}")
            return None

        alert_id = await self._insert_alert(candidate)
        if alert_id:
            self._mark_emitted(candidate)
            await self._update_rule_stats(candidate.rule_id)
            await self._notify_api(alert_id)

        return alert_id

    async def _insert_alert(self, candidate: AlertCandidate) -> str | None:
        """
        Insère l'alerte dans la table alerts de PostgreSQL.
        Retourne l'UUID de l'alerte ou None en cas d'erreur.
        """
        alert_id = str(uuid.uuid4())
        try:
            async with self.pg_pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO alerts (
                        id, rule_id, title, level, status,
                        correlated_event_ids, source_ips, affected_hosts, usernames,
                        mitre_tactic, confidence_score
                    ) VALUES (
                        $1::uuid, $2::uuid, $3, $4::alert_level, 'open'::alert_status,
                        $5::jsonb, $6::jsonb, $7::jsonb, $8::jsonb,
                        $9, $10
                    )
                    """,
                    alert_id,
                    candidate.rule_id,
                    candidate.title,
                    candidate.level,
                    json.dumps(candidate.correlated_event_ids),
                    json.dumps(candidate.source_ips),
                    json.dumps(candidate.affected_hosts),
                    json.dumps(candidate.usernames),
                    candidate.mitre_tactic,
                    candidate.confidence_score,
                )
            log.info(
                f"[ALERT] {alert_id[:8]}... | {candidate.level} | {candidate.title[:60]}"
            )
            return alert_id
        except Exception as e:
            log.error(f"Erreur INSERT alerte : {e}")
            return None

    async def _update_rule_stats(self, rule_id: str):
        """
        Incrémente trigger_count et met à jour last_triggered_at pour la règle.
        Ces stats sont affichées dans le dashboard.
        """
        try:
            async with self.pg_pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE correlation_rules
                    SET trigger_count     = trigger_count + 1,
                        last_triggered_at = NOW()
                    WHERE id = $1::uuid
                    """,
                    rule_id
                )
        except Exception as e:
            log.debug(f"Mise à jour stats règle échouée (non critique) : {e}")

    async def _notify_api(self, alert_id: str):
        """
        Notifie FastAPI qu'une nouvelle alerte est disponible.
        FastAPI déclenche ensuite les playbooks SOAR et les notifications.
        Si l'API n'est pas démarrée → log debug et continuer (non bloquant).
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "http://localhost:8000/internal/alert-triggered",
                    json={"alert_id": alert_id},
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    if resp.status not in (200, 202):
                        log.debug(f"API retourné {resp.status} pour alerte {alert_id[:8]}")
        except Exception as e:
            log.debug(f"Notification API non disponible (non bloquant) : {e}")