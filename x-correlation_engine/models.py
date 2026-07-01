"""
correlation_engine/models.py
─────────────────────────────
Rôle unique : définir les structures de données partagées entre tous les modules.

Ces dataclasses sont les "contrats d'interface" du système.
Aucun module ne devrait définir ses propres structures — tout passe par ici.
"""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CorrelationRule:
    """
    Représentation d'une règle de corrélation chargée depuis PostgreSQL.

    Tous les champs correspondent exactement aux colonnes de la table
    correlation_rules. Le rule_loader.py est le seul responsable de
    la conversion Row PostgreSQL → CorrelationRule.
    """
    id:                  str            # UUID PG — identifiant unique de la règle
    name:                str            # Nom lisible affiché dans les alertes
    rule_type:           str            # "threshold" | "pattern" | "composite" | "behavioral"
    conditions:          dict           # Paramètres JSONB — interprétés par l'évaluateur
    time_window_seconds: int            # Durée de la fenêtre d'analyse en secondes
    threshold_count:     Optional[int]  # Seuil de déclenchement (threshold uniquement)
    sources_required:    Optional[list] # Sources nécessaires (composite uniquement)
    alert_level:         str            # "INFO" | "WARNING" | "HIGH" | "CRITICAL"
    confidence_score:    int            # Score de confiance 0–100
    mitre_tactic:        Optional[str]  # Ex: "TA0001" — pour le reporting MITRE
    mitre_technique:     Optional[str]  # Ex: "T1110" — pour le reporting MITRE
    playbook_id:         Optional[str]  # UUID du playbook SOAR à déclencher

    # ── Propriétés calculées ──────────────────────────────────────────────────

    @property
    def event_action(self) -> Optional[str]:
        """
        Retourne l'event_action depuis les conditions.
        Propriété calculée pour éviter de répéter conditions.get("event_action")
        dans chaque évaluateur.
        """
        return self.conditions.get("event_action")

    @property
    def group_by(self) -> str:
        """
        Retourne le champ de groupement (défaut: source_ip).
        Toutes les règles DOIVENT spécifier ce champ dans leur YAML.
        Le défaut source_ip est conservé pour la compatibilité.
        """
        return self.conditions.get("group_by", "source_ip")

    @property
    def sequence(self) -> list:
        """Retourne la séquence pour les règles pattern."""
        return self.conditions.get("sequence", [])

    @property
    def use_eql(self) -> bool:
        """
        Indique si cette règle pattern doit utiliser EQL natif (plus performant)
        ou le FSM Python (plus flexible).
        Par défaut True pour les nouvelles règles.
        """
        return self.conditions.get("use_eql", True)


@dataclass
class AlertCandidate:
    """
    Représentation d'une alerte en attente d'insertion dans PostgreSQL.

    Structure intermédiaire entre la détection (évaluateurs) et la persistance
    (alert_manager). Cette séparation permet de dédupliquer avant d'écrire en BDD.

    Contrat : tout évaluateur retourne une liste[AlertCandidate].
    AlertManager est le seul à écrire dans PostgreSQL.
    """
    rule_id:              str          # UUID de la règle qui a déclenché
    rule_name:            str          # Nom de la règle (dénormalisé pour l'affichage)
    level:                str          # Niveau d'alerte hérité de la règle
    title:                str          # Description humaine générée par l'évaluateur
    correlated_event_ids: list         # IDs des documents ES qui constituent les preuves
    source_ips:           list         # IPs impliquées (dénormalisé pour le dashboard)
    affected_hosts:       list         # Machines touchées
    usernames:            list         # Comptes impliqués
    mitre_tactic:         Optional[str]
    confidence_score:     int

    def dedup_key(self) -> str:
        """
        Clé unique pour la déduplication.
        Format : "rule_id::entité_principale"
        Deux alertes avec la même clé dans la fenêtre DEDUP_WINDOW_SEC = doublon.
        """
        entities = self.source_ips + self.usernames
        entity = entities[0] if entities else "unknown"
        return f"{self.rule_id}::{entity}"