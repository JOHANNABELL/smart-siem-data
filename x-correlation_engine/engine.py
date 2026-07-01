"""
correlation_engine/engine.py
──────────────────────────────
Rôle unique : orchestrer la boucle principale du worker de corrélation.

Ce module est le "chef d'orchestre" — il ne fait aucun calcul lui-même.
Il délègue :
  - Le chargement des règles    → rule_loader
  - L'évaluation des règles     → evaluators/{threshold, eql, cross_source}
  - La persistance des alertes  → alert_manager

Boucle principale (toutes les WORKER_INTERVAL_SEC secondes) :
  1. Recharger les règles si RULES_RELOAD_INTERVAL_SEC écoulées
  2. Pour chaque règle → dispatch vers l'évaluateur approprié
  3. Pour chaque AlertCandidate → alert_manager.process()
"""
import asyncio
import logging
import time
from datetime import datetime

import asyncpg
from elasticsearch import AsyncElasticsearch

from .config import (
    ES_HOST, ES_USER, ES_PASSWORD, ES_CACERT,
    PG_DSN, WORKER_INTERVAL_SEC, RULES_RELOAD_INTERVAL_SEC
)
from .models import CorrelationRule, AlertCandidate
from .rule_loader import load_active_rules
from .alert_manager import AlertManager
from .evaluators import threshold, eql, cross_source

log = logging.getLogger("engine")


async def _dispatch(rule: CorrelationRule,
                    es: AsyncElasticsearch) -> list[AlertCandidate]:
    """
    Dispatch une règle vers l'évaluateur approprié selon rule.rule_type.

    Table de dispatch :
      threshold  → ThresholdEvaluator (comptage dans fenêtre glissante)
      pattern    → EQLEvaluator si use_eql=True, sinon PatternEvaluator FSM
      composite  → CrossSourceEvaluator si type=cross_source
      behavioral → [] (géré par le worker UEBA séparé)
    """
    try:
        if rule.rule_type == "threshold":
            return await threshold.evaluate(rule, es)

        elif rule.rule_type == "pattern":
            if rule.use_eql:
                return await eql.evaluate(rule, es)
            else:
                # Fallback sur le FSM Python si use_eql=False dans les conditions
                from .evaluators import pattern as fsm_pattern
                return await fsm_pattern.evaluate(rule, es)

        elif rule.rule_type == "composite":
            sub_type = rule.conditions.get("type", "")
            if sub_type == "cross_source":
                return await cross_source.evaluate(rule, es)
            else:
                log.warning(
                    f"Sous-type composite inconnu : '{sub_type}' (règle: {rule.name}). "
                    f"Valeurs supportées : cross_source"
                )
                return []

        elif rule.rule_type == "behavioral":
            # Les anomalies comportementales sont gérées par ueba/ueba_worker.py
            # Le moteur de corrélation n'évalue pas ces règles
            return []

        else:
            log.warning(
                f"Type de règle inconnu : '{rule.rule_type}' (règle: {rule.name}). "
                f"Valeurs acceptées : threshold, pattern, composite, behavioral"
            )
            return []

    except Exception as e:
        # Erreur sur une règle isolée → log et continuer
        # Le worker ne doit JAMAIS s'arrêter à cause d'une règle
        log.error(f"Erreur évaluation règle '{rule.name}' : {e}", exc_info=True)
        return []


class CorrelationEngine:
    """
    Orchestrateur principal du moteur de corrélation.

    Cycle de vie :
      initialize() → établit les connexions ES et PG
      run()        → boucle infinie (toutes les WORKER_INTERVAL_SEC secondes)
      close()      → fermeture propre des connexions
    """

    def __init__(self):
        self.es:            AsyncElasticsearch | None = None
        self.pg_pool:       asyncpg.Pool | None       = None
        self.alert_manager: AlertManager | None       = None
        self._rules_cache:  list[CorrelationRule]     = []
        self._rules_loaded_at: datetime               = datetime.min

    async def initialize(self):
        """Établit les connexions aux bases de données."""
        log.info("Initialisation du moteur de corrélation...")

        self.es = AsyncElasticsearch(
            hosts=[ES_HOST],
            basic_auth=(ES_USER, ES_PASSWORD),
            ca_certs=ES_CACERT,
            verify_certs=True,
        )

        self.pg_pool = await asyncpg.create_pool(
            dsn=PG_DSN,
            min_size=2,
            max_size=10
        )

        self.alert_manager = AlertManager(self.pg_pool)
        log.info("[OK] Connexions ES et PG établies")

    async def _reload_rules_if_needed(self):
        """Recharge les règles depuis PG si l'intervalle est dépassé."""
        elapsed = (datetime.now() - self._rules_loaded_at).total_seconds()
        if elapsed > RULES_RELOAD_INTERVAL_SEC:
            self._rules_cache     = await load_active_rules(self.pg_pool)
            self._rules_loaded_at = datetime.now()

    async def _evaluate_all(self) -> int:
        """
        Évalue toutes les règles du cache et traite les alertes.
        Retourne le nombre d'alertes créées ce cycle.
        """
        alerts_created = 0

        for rule in self._rules_cache:
            candidates = await _dispatch(rule, self.es)

            for candidate in candidates:
                alert_id = await self.alert_manager.process(candidate)
                if alert_id:
                    alerts_created += 1

        return alerts_created

    async def run(self):
        """Boucle principale — tourne indéfiniment jusqu'à Ctrl+C."""
        log.info(f"[START] Moteur démarré (intervalle: {WORKER_INTERVAL_SEC}s)")

        while True:
            start = time.monotonic()

            try:
                await self._reload_rules_if_needed()

                if self._rules_cache:
                    count = await self._evaluate_all()
                    if count:
                        log.info(f"[CYCLE] {count} alerte(s) créée(s)")

            except Exception as e:
                log.error(f"Erreur boucle principale : {e}", exc_info=True)

            elapsed    = time.monotonic() - start
            sleep_time = max(0, WORKER_INTERVAL_SEC - elapsed)
            await asyncio.sleep(sleep_time)

    async def close(self):
        """Fermeture propre des connexions."""
        if self.es:
            await self.es.close()
        if self.pg_pool:
            await self.pg_pool.close()


async def main():
    """Point d'entrée de l'application."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    engine = CorrelationEngine()
    await engine.initialize()
    try:
        await engine.run()
    except KeyboardInterrupt:
        log.info("Arrêt demandé (Ctrl+C)")
    finally:
        await engine.close()


if __name__ == "__main__":
    asyncio.run(main())