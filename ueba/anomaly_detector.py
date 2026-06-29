#!/usr/bin/env python3
"""
================================================================================
ueba/anomaly_detector.py — Détection des anomalies et scoring 0–100
================================================================================
Rôle unique : prendre les features du jour courant et le profil de baseline,
              appliquer deux modèles (Isolation Forest + Z-Score),
              et calculer un score de risque final entre 0 et 100.

Architecture à deux couches :
  Couche 1 — Z-Score (statistique)
    Mesure combien d'écarts-types chaque feature s'éloigne de sa moyenne.
    Avantage : 100% explicable ("le volume de données est 4.2x la moyenne")
    Limite   : ne détecte pas les interactions entre features

  Couche 2 — Isolation Forest (machine learning)
    Modèle non-supervisé qui apprend la "forme" du comportement normal.
    Détecte les combinaisons inhabituelles même si chaque feature prise
    séparément semble normale.
    Avantage : détecte les patterns complexes
    Limite   : moins explicable que le Z-Score

  Score final = 60% Isolation Forest + 40% Z-Score (configurable dans config.py)

Sources :
  - Liu, F.T. et al., "Isolation Forest", IEEE ICDM 2008
  - Aggarwal, C.C., "Outlier Analysis", Springer 2013 (Z-Score pour logs)
  - Elastic ML anomaly detection documentation (inspiration de l'architecture)
================================================================================
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from config import FEATURES_CONFIG, DETECTION_CONFIG


# Noms des features dans l'ordre fixe utilisé par le modèle
# L'ordre DOIT être identique entre l'entraînement et l'inférence
FEATURE_NAMES = list(FEATURES_CONFIG.keys())


def features_dict_to_vector(features: dict) -> np.ndarray:
    """
    Convertit un dictionnaire de features en vecteur numpy.
    L'ordre est défini par FEATURE_NAMES (constant entre entraînement et inférence).

    Paramètres :
      features : dict {feature_name: float_value}

    Retourne :
      numpy array de shape (len(FEATURE_NAMES),)
    """
    return np.array([
        float(features.get(fname, 0.0))
        for fname in FEATURE_NAMES
    ], dtype=float)


def compute_zscore_anomaly_score(
    today_features: dict,
    baseline_stats: dict,
) -> tuple[float, list[dict]]:
    """
    Calcule le score d'anomalie Z-Score et identifie les features anormales.

    Le Z-Score d'une feature = (valeur_aujourd'hui - moyenne_baseline) / std_baseline
    Un Z-Score absolu > zscore_threshold (config) = anomalie pour cette feature.

    Le score de risque Z = moyenne pondérée des Z-Scores anormaux.
    Les poids viennent de FEATURES_CONFIG[feature]["weight"].

    Retourne :
      (score_0_100, liste_features_anormales_avec_explication)

    La liste d'explication est CRUCIALE pour l'explicabilité :
    elle permet à l'analyste de comprendre POURQUOI une alerte a été générée.
    """
    anomalous_features = []   # features qui ont déclenché une anomalie
    weighted_scores    = []   # scores pondérés pour le calcul du score final

    for fname in FEATURE_NAMES:
        config  = FEATURES_CONFIG[fname]
        stats   = baseline_stats.get(fname, {})

        # Si les stats ne sont pas suffisantes, ignorer cette feature
        if not stats.get("sufficient", False):
            continue

        # Valeur observée aujourd'hui
        today_val = float(today_features.get(fname, 0.0))

        # Statistiques de référence
        mean = stats["mean"]
        std  = stats["std"]  # déjà protégé contre zéro dans baseline.py

        # Calcul du Z-Score (nombre d'écarts-types)
        z_score = abs(today_val - mean) / std

        # Seuil de déclenchement pour cette feature
        threshold = config["zscore_threshold"]

        # Direction de l'anomalie
        direction = config["anomaly_direction"]
        signed_z  = (today_val - mean) / std  # Z signé (avant abs())

        # Vérifier si l'anomalie est dans la direction surveillée
        is_anomalous = False
        if direction == "high"  and signed_z >  threshold:
            is_anomalous = True
        elif direction == "low" and signed_z < -threshold:
            is_anomalous = True
        elif direction == "both" and z_score > threshold:
            is_anomalous = True

        if is_anomalous:
            # Normaliser le Z-Score en score 0–100
            # z = threshold → score = 0, z = threshold+5 → score ≈ 100
            # Formule : min(100, (z - threshold) / 5 * 100)
            feature_score = min(100.0, (z_score - threshold) / 5.0 * 100.0)
            weighted_score = feature_score * config["weight"]
            weighted_scores.append(weighted_score)

            # Construire l'explication lisible par l'analyste
            anomalous_features.append({
                "feature":     fname,
                "description": config["description"],
                "today_value": round(today_val, 3),
                "mean":        round(mean, 3),
                "std":         round(std, 3),
                "z_score":     round(z_score, 2),
                "threshold":   threshold,
                "delta":       round(today_val - mean, 3),
                "explanation": (
                    f"{config['description']} : valeur={today_val:.2f} "
                    f"(moyenne={mean:.2f}, z={z_score:.1f}σ — "
                    f"seuil={threshold}σ)"
                ),
            })

    # Score Z-Score global = somme des scores pondérés, normalisée sur 100
    # Division par sum(weights_of_anomalous) pour garder l'échelle 0–100
    if weighted_scores:
        max_possible = sum(FEATURES_CONFIG[f]["weight"] for f in FEATURE_NAMES) * 100
        raw_score    = sum(weighted_scores)
        zscore_score = min(100.0, raw_score / max_possible * 100.0 * 3)  # ×3 pour amplifier
    else:
        zscore_score = 0.0

    return zscore_score, anomalous_features


def train_isolation_forest(
    features_list: list[dict],
) -> tuple:
    """
    Entraîne un modèle Isolation Forest sur l'historique de features.

    Isolation Forest (Liu et al. 2008) :
    - Construit N arbres de décision aléatoires sur des sous-échantillons
    - Un point normal est difficile à isoler → nécessite beaucoup de coupures
    - Un point anormal est facile à isoler → nécessite peu de coupures
    - Le score = profondeur moyenne d'isolation (normalisé)

    Pourquoi entraîner sur 30 jours de données ?
    Le modèle apprend la FORME GLOBALE du comportement normal, pas juste
    des seuils sur des features individuelles. Il peut donc détecter des
    combinaisons inhabituelles (ex: connexion à 14h depuis une nouvelle IP
    avec un volume normal → chaque feature semble ok, mais la combinaison est suspecte).

    Paramètres :
      features_list : liste de dicts de features (historique 30 jours)

    Retourne :
      (modèle_entraîné, scaler_entraîné) ou (None, None) si données insuffisantes
    """
    # Besoin d'au moins 7 points pour un entraînement minimal
    if len(features_list) < 7:
        return None, None

    # Convertir les features en matrice numpy : shape (n_jours, n_features)
    X = np.array([
        features_dict_to_vector(f)
        for f in features_list
        if not any(np.isnan(v) for v in features_dict_to_vector(f))
    ])

    if X.shape[0] < 7:
        return None, None

    # Standardisation des features : ramener chaque feature à mean=0, std=1
    # Nécessaire car les features ont des échelles très différentes
    # (login_hour: 0–23, data_volume: 0–1000 Mo)
    # Sans standardisation, les features à grande échelle domineraient le modèle
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Entraînement de l'Isolation Forest
    model = IsolationForest(
        n_estimators=DETECTION_CONFIG["isolation_forest_n_estimators"],
        contamination=DETECTION_CONFIG["isolation_forest_contamination"],
        random_state=DETECTION_CONFIG["isolation_forest_random_state"],
        n_jobs=-1,   # utiliser tous les CPUs disponibles
    )
    model.fit(X_scaled)

    return model, scaler


def compute_if_score(
    model,
    scaler,
    today_features: dict,
) -> float:
    """
    Calcule le score d'anomalie Isolation Forest pour les features du jour.

    L'Isolation Forest retourne un score entre -1 (très anormal) et 0.5 (normal).
    On le convertit en score 0–100 pour cohérence avec le Z-Score.

    Mapping :
      score IF ≥ 0      → risque = 0  (comportement normal ou moins anormal que la contamination)
      score IF = -0.5   → risque ≈ 50
      score IF = -1     → risque = 100 (très anormal)

    Paramètres :
      model            : modèle Isolation Forest entraîné
      scaler           : StandardScaler entraîné sur les mêmes données
      today_features   : dict des features du jour à évaluer

    Retourne :
      score de risque IF entre 0.0 et 100.0
    """
    if model is None or scaler is None:
        return 0.0

    # Vecteur de features du jour courant
    x = features_dict_to_vector(today_features).reshape(1, -1)

    # Appliquer la même standardisation qu'à l'entraînement
    x_scaled = scaler.transform(x)

    # Score brut de l'Isolation Forest
    # score_samples() retourne le log de la densité négative estimée
    # Plus le score est bas (négatif), plus le point est anormal
    raw_score = model.score_samples(x_scaled)[0]

    # Conversion en score 0–100
    # raw_score est typiquement entre -0.8 (anormal) et 0.2 (normal)
    # On mappe [-0.8, 0.2] → [100, 0]
    if_score_100 = max(0.0, min(100.0, (-raw_score - 0.0) * 200.0))

    return if_score_100


def compute_final_risk_score(
    if_score: float,
    zscore_score: float,
    anomalous_features: list,
) -> tuple[int, str]:
    """
    Calcule le score de risque final (0–100) et son niveau d'alerte.

    Score final = pondération configurable entre IF et Z-Score.
    Depuis config.py :
      if_score_weight  = 0.6  (60% Isolation Forest)
      zscore_weight    = 0.4  (40% Z-Score)

    Pourquoi cette pondération ?
    - L'IF est meilleur pour détecter les patterns complexes
    - Le Z-Score est meilleur pour l'explicabilité
    - 60/40 est un compromis empirique standard dans la littérature
      (ajustable en fonction des résultats sur ton dataset)

    Retourne :
      (score_entier_0_100, niveau_alerte_string)
    """
    w_if = DETECTION_CONFIG["if_score_weight"]      # 0.6
    w_z  = DETECTION_CONFIG["zscore_weight"]         # 0.4

    final_score = w_if * if_score + w_z * zscore_score

    # Amplifier si plusieurs features anormales en même temps
    # (signal que l'anomalie est systémique, pas ponctuelle)
    if len(anomalous_features) >= 3:
        final_score = min(100.0, final_score * 1.2)   # +20% si 3+ features anormales
    elif len(anomalous_features) >= 2:
        final_score = min(100.0, final_score * 1.1)   # +10% si 2 features anormales

    score_int = int(round(final_score))

    # Niveau d'alerte selon le score
    if score_int >= 90:
        level = "CRITICAL"
    elif score_int >= 75:
        level = "HIGH"
    elif score_int >= DETECTION_CONFIG["alert_threshold"]:
        level = "WARNING"
    else:
        level = "NORMAL"

    return score_int, level


def explain_anomaly(
    anomalous_features: list,
    entity_id: str,
    score: int,
) -> str:
    """
    Génère une explication textuelle lisible pour l'analyste SOC.
    Cette explication apparaîtra dans les alertes UEBA et les dashboards.

    Principe d'explicabilité (XAI — Explainable AI) :
    Toute alerte doit pouvoir répondre à "POURQUOI ce score ?"
    sans que l'analyste doive comprendre le modèle ML.

    Paramètres :
      anomalous_features : liste des features anormales avec leurs explications
      entity_id          : identifiant de l'entité (username ou hostname)
      score              : score de risque final

    Retourne :
      Texte d'explication structuré
    """
    if not anomalous_features:
        return f"Comportement normal pour {entity_id} (score={score})"

    explanations = [f["explanation"] for f in anomalous_features]
    features_str = " | ".join(explanations[:3])   # limiter à 3 pour la lisibilité

    return (
        f"Anomalie comportementale détectée pour {entity_id} (score={score}/100). "
        f"Features anormales ({len(anomalous_features)}) : {features_str}"
    )