#!/usr/bin/env python3
"""
================================================================================
SMART SIEM — Initialisation des règles de corrélation dans PostgreSQL
================================================================================
Rôle        : Insérer les 5 règles de corrélation minimum dans la table
              correlation_rules de PostgreSQL.
Quand       : À exécuter UNE SEULE FOIS après avoir lancé 01_postgres_schema.sql.
Idempotent  : Si une règle existe déjà (même nom), elle est ignorée.
              On peut relancer ce script sans dupliquer les règles.

Pourquoi stocker les règles en base de données et non dans le code ?
→ Un analyste peut modifier les règles (seuil, fenêtre temporelle) via l'interface
  sans modifier le code et sans redémarrer le worker.
→ Traçabilité : chaque règle a un created_by et un historique de déclenchements.
================================================================================
"""

import os       # variables d'environnement
import json     # sérialisation des conditions en JSON (stockées en JSONB dans PG)
import asyncio  # pour les fonctions asynchrones (await asyncpg)
import asyncpg  # client PostgreSQL asynchrone

# bcrypt : algorithme de hachage sécurisé des mots de passe
# On ne stocke JAMAIS un mot de passe en clair dans la base de données.
# bcrypt applique un "coût" (rounds) qui rend le bruteforce très lent.
# coût 12 = ~250ms par vérification → acceptable pour l'authentification,
# très pénalisant pour un attaquant qui essaie des millions de mots de passe.
from passlib.context import CryptContext

# pyotp : génération de clés secrètes TOTP pour le MFA (Multi-Factor Authentication)
# Chaque utilisateur a une clé secrète unique qui, combinée avec l'heure actuelle,
# génère un code à 6 chiffres valable 30 secondes (standard RFC 6238).
import pyotp

# Chaîne de connexion PostgreSQL
# Lue depuis l'environnement ou valeur par défaut pour le développement
PG_DSN = os.environ.get("PG_DSN",
    "postgresql://postgres:felicia@localhost:5432/nafeh")

# ── Contexte de hachage bcrypt ────────────────────────────────────────────────
# CryptContext configure l'algorithme et le coût de hachage.
# "bcrypt" est le standard industriel pour les mots de passe (recommandé OWASP).
# deprecated="auto" → les anciens hashes sont automatiquement mis à jour.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ── Données de l'administrateur initial ──────────────────────────────────────
# Ces valeurs peuvent être surchargées via les variables d'environnement.
# En production, TOUJOURS changer ces valeurs par défaut.
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_EMAIL    = os.environ.get("ADMIN_EMAIL",    "admin@ctu-siem.int")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "Admin@SIEM2026!")
# Périmètre organisationnel de l'admin : accès à TOUT le système (pas de restriction)
ADMIN_ORG_SCOPE = "global"

# ── Définition des 5 règles ───────────────────────────────────────────────────
# Chaque règle est un dictionnaire Python qui correspond exactement
# aux colonnes de la table correlation_rules dans PostgreSQL.

RULES = [

    # ════════════════════════════════════════════════════════════════════════
    # RÈGLE 1 — Brute Force SSH
    # Type     : threshold (seuil)
    # Tactique : TA0001 Initial Access / T1110 Brute Force
    # Logique  : Si 5+ login_failed depuis la même IP en 60s → alerte HIGH
    # ════════════════════════════════════════════════════════════════════════
    {
        # Nom unique de la règle — doit correspondre à ce que le worker attend
        "name": "SSH Brute Force Detection",

        # Description humaine — affichée dans l'interface et dans les emails d'alerte
        "description": (
            "Détecte les attaques brute force SSH : "
            "5 tentatives d'authentification échouées ou plus "
            "depuis la même adresse IP en 60 secondes."
        ),

        # rule_type détermine quel évaluateur sera utilisé dans correlation_engine.py
        # "threshold" → ThresholdEvaluator (comptage dans une fenêtre)
        "rule_type": "threshold",

        # conditions : paramètres de la règle sérialisés en JSON
        # Seront désérialisés par le worker avec json.loads()
        # event_action : l'action à surveiller dans les logs ES
        # group_by     : le champ qui identifie l'attaquant (même IP = même attaquant)
        "conditions": json.dumps({
            "event_action": "login_failed",  # surveiller les échecs d'authentification
            "group_by":     "source_ip",     # grouper par IP source
        }),

        # Fenêtre temporelle : combien de secondes en arrière on regarde
        # 60 secondes = une attaque brute force typique Hydra/Medusa dure ~30s
        "time_window_seconds": 60,

        # Seuil de déclenchement : nombre minimum d'occurrences pour alerter
        # 5 tentatives en 60s est le standard industriel pour la détection SSH brute force
        # Trop bas (ex: 2) → trop de faux positifs (erreurs de frappe)
        # Trop haut (ex: 20) → les attaques lentes passent inaperçues
        "threshold_count": 5,

        # Pas de sources multiples requises pour cette règle (règle single-source)
        "sources_required": None,

        # Niveau d'alerte : HIGH car brute force = tentative d'accès non autorisé active
        # Pas CRITICAL car on n'a pas encore de preuve de compromission réussie
        "alert_level": "HIGH",

        # Score de confiance : probabilité que cette alerte soit un vrai positif
        # 85% car 5 echecs en 60s est très rarement une erreur humaine légitime
        "confidence_score": 85,

        # Mapping MITRE ATT&CK pour la conformité et le reporting
        "mitre_tactic":    "TA0001",  # Initial Access
        "mitre_technique": "T1110",   # Brute Force
    },

    # ════════════════════════════════════════════════════════════════════════
    # RÈGLE 2 — Scan de ports réseau
    # Type     : threshold (seuil)
    # Tactique : TA0007 Discovery / T1046 Network Service Scanning
    # Logique  : 50+ connexions bloquées depuis la même IP en 10s → alerte HIGH
    # ════════════════════════════════════════════════════════════════════════
    {
        "name": "Network Port Scan Detection",
        "description": (
            "Détecte les scans de ports réseau : "
            "50 connexions bloquées ou plus depuis la même adresse IP "
            "en 10 secondes. Signature typique d'un scan Nmap."
        ),
        "rule_type": "threshold",

        # connection_blocked : événement généré par le firewall quand il bloque une connexion
        # C'est la signature d'un scan : l'attaquant envoie des SYN, le firewall les rejette
        "conditions": json.dumps({
            "event_action": "connection_blocked",
            "group_by":     "source_ip",
        }),

        # Fenêtre très courte : 10 secondes
        # Un scan Nmap par défaut envoie ~1000 paquets/seconde
        # 10s est suffisant pour détecter une rafale sans être trop sensible
        "time_window_seconds": 10,

        # Seuil élevé : 50 connexions en 10s
        # Évite les faux positifs sur des applications légitimes qui font beaucoup
        # de connexions (ex: scanners de vulnérabilités internes autorisés)
        "threshold_count": 50,

        "sources_required": None,
        "alert_level": "HIGH",

        # 90% de confiance : 50 connexions en 10s est presque impossible autrement
        # qu'avec un outil de scan automatisé
        "confidence_score": 90,

        "mitre_tactic":    "TA0007",  # Discovery
        "mitre_technique": "T1046",   # Network Service Scanning
    },

    # ════════════════════════════════════════════════════════════════════════
    # RÈGLE 3 — Mouvement latéral (kill-chain séquentielle)
    # Type     : pattern (séquentiel / FSM)
    # Tactique : TA0008 Lateral Movement / T1021 Remote Services
    # Logique  : login_success PUIS file_read (même IP, dans les 5 min) → CRITICAL
    # ════════════════════════════════════════════════════════════════════════
    {
        "name": "Lateral Movement Kill-Chain",
        "description": (
            "Détecte un mouvement latéral : connexion SSH réussie depuis un hôte "
            "inattendu, suivie d'un accès à des fichiers sensibles "
            "(ex: /etc/shadow) par la même entité en moins de 5 minutes."
        ),

        # "pattern" → PatternEvaluator avec FSM (automate à états finis)
        # DIFFÉRENCE clé avec threshold :
        # Threshold compte des occurrences identiques
        # Pattern vérifie une SÉQUENCE d'actions différentes dans l'ordre
        "rule_type": "pattern",

        "conditions": json.dumps({
            # sequence : liste ordonnée des event_actions attendus
            # L'ordre EST important : login_success DOIT précéder file_read
            # Si on voit file_read AVANT login_success → pas d'alerte (comportement différent)
            "sequence": ["login_success", "file_read"],

            # group_by source_ip : les deux événements doivent venir de la même IP
            # C'est ce qui garantit que c'est le même acteur dans toute la séquence
            "group_by": "source_ip",
        }),

        # 300 secondes = 5 minutes
        # Après un login réussi, un attaquant met généralement quelques minutes
        # avant de commencer à explorer le système
        "time_window_seconds": 300,

        # Pas de threshold_count pour les règles pattern
        # (la séquence elle-même suffit à déclencher l'alerte)
        "threshold_count": None,

        "sources_required": None,

        # CRITICAL : une kill-chain complète = compromission probable avec accès aux credentials
        "alert_level": "CRITICAL",

        # 80% de confiance : possible que ce soit un admin légitime qui fait la même chose
        # Moins de certitude qu'une règle threshold sur une action clairement malveillante
        "confidence_score": 80,

        "mitre_tactic":    "TA0008",  # Lateral Movement
        "mitre_technique": "T1021",   # Remote Services
    },

    # ════════════════════════════════════════════════════════════════════════
    # RÈGLE 4 — Exfiltration de données
    # Type     : threshold (seuil sur volume de transferts)
    # Tactique : TA0010 Exfiltration / T1041 Exfiltration Over C2 Channel
    # Logique  : 3+ transferts volumineux vers même IP externe en 1h → CRITICAL
    # ════════════════════════════════════════════════════════════════════════
    {
        "name": "Data Exfiltration Pattern",
        "description": (
            "Détecte une exfiltration de données : "
            "3 transferts sortants volumineux ou plus vers la même adresse IP "
            "externe inconnue en 1 heure."
        ),

        # "threshold" car on compte des occurrences d'un même type d'événement
        # L'event_action "large_outbound_transfer" est défini par convention
        # (le pipeline de normalisation taguera ainsi les transferts > seuil)
        "rule_type": "threshold",

        "conditions": json.dumps({
            "event_action": "large_outbound_transfer",
            "group_by":     "source_ip",  # grouper par IP source interne
        }),

        # 1 heure : les exfiltrations sont souvent lentes pour éviter la détection
        # (l'attaquant fractionne en plusieurs petits transferts)
        "time_window_seconds": 3600,

        # Seuil bas de 3 : même 3 gros transferts vers une IP inconnue est suspect
        "threshold_count": 3,

        "sources_required": None,

        # CRITICAL : exfiltration = vol de données = impact direct sur la confidentialité
        "alert_level": "CRITICAL",

        # 75% de confiance : des sauvegardes légitimes vers le cloud peuvent ressembler
        # à de l'exfiltration si le domaine de destination n'est pas whitelist
        "confidence_score": 75,

        "mitre_tactic":    "TA0010",  # Exfiltration
        "mitre_technique": "T1041",   # Exfiltration Over C2 Channel
    },

    # ════════════════════════════════════════════════════════════════════════
    # RÈGLE 5 — Corrélation inter-sources : Firewall + Active Directory
    # Type     : cross_source (corrélation entre deux sources distinctes)
    # Tactique : TA0001 Initial Access + TA0005 Defense Evasion
    # Logique  : IP bloquée (firewall) ET tentative d'auth (AD) en 5 min → HIGH
    # ════════════════════════════════════════════════════════════════════════
    {
        "name": "Firewall Block then AD Auth Attempt",
        "description": (
            "Corrélation inter-sources : une adresse IP bloquée par le pare-feu "
            "qui tente ensuite une authentification sur l'Active Directory "
            "dans les 5 minutes suivantes. Indicateur d'évasion de contrôle périmétrique."
        ),

        # "cross_source" → CrossSourceEvaluator (intersection d'ensembles entre sources)
        # C'est le type de règle le plus complexe car il corrèle DEUX sources différentes
        # Un SIEM basique ne peut pas faire ça — c'est une valeur ajoutée clé
        "rule_type": "cross_source",

        "conditions": json.dumps({
            # sources : types de sources qui doivent TOUTES être impliquées
            # Ces valeurs correspondent au champ source_type dans log_sources (PG)
            "sources": ["firewall", "active_directory"],

            # events : pour chaque source, l'event_action à surveiller
            # Le worker vérifiera que CHAQUE source a produit SON event_action respectif
            "events": {
                "firewall":          "connection_blocked",  # IP rejetée par le firewall
                "active_directory":  "login_failed"         # même IP essaie sur l'AD
            },

            # group_by source_ip : l'IP est la clé de jointure entre les deux sources
            # C'est ce qui relie le blocage firewall et la tentative AD
            "group_by": "source_ip",
        }),

        # 300 secondes : 5 minutes entre le blocage firewall et la tentative AD
        # Un attaquant réagi généralement rapidement quand un vecteur est bloqué
        "time_window_seconds": 300,

        # Pas de seuil numérique pour les règles cross_source
        # L'apparition dans les DEUX sources suffit
        "threshold_count": None,

        # sources_required : copie de la liste des sources (stockée en JSONB dans PG)
        # Utilisée pour la documentation et l'affichage dans l'interface
        "sources_required": json.dumps(["firewall", "active_directory"]),

        "alert_level": "HIGH",

        # 70% de confiance : légèrement moins certain car l'IP peut être réutilisée
        # par différents utilisateurs (NAT, proxy) → possible faux positif
        "confidence_score": 70,

        "mitre_tactic":    "TA0001",  # Initial Access (via l'AD)
        "mitre_technique": "T1078",   # Valid Accounts (tentative d'utilisation de credentials)
    },
]


async def create_admin_if_missing(conn: asyncpg.Connection) -> str:
    """
    Crée le compte administrateur initial si aucun admin n'existe.
    Retourne l'UUID de l'admin (existant ou nouvellement créé).

    IDEMPOTENT : si un admin existe déjà, on ne crée rien et on retourne son ID.
    On peut relancer ce script autant de fois que nécessaire sans dupliquer le compte.

    Pourquoi créer l'admin ici et pas manuellement ?
    → Automatiser l'initialisation complète du système en un seul script.
    → Garantir que les contraintes de sécurité (bcrypt, MFA) sont respectées dès le départ.
    """

    # Vérification : un admin existe-t-il déjà dans la table users ?
    # fetchval() retourne la valeur de la première colonne de la première ligne
    # Si aucune ligne → retourne None
    existing_id = await conn.fetchval(
        "SELECT id FROM users WHERE role = 'admin' LIMIT 1"
    )

    if existing_id:
        # Un admin existe déjà → on l'utilise sans rien créer
        print(f"[SKIP] Administrateur déjà existant (id={existing_id})")
        return str(existing_id)

    # ── Hachage du mot de passe ───────────────────────────────────────────────
    # pwd_context.hash() applique bcrypt avec le coût configuré (12 rounds).
    # Le résultat ressemble à : "$2b$12$XXX..." — jamais le mot de passe en clair.
    # Chaque appel produit un hash DIFFÉRENT même pour le même mot de passe
    # (grâce au salt aléatoire intégré dans bcrypt) → pas de rainbow table possible.
    password_bytes  = ADMIN_PASSWORD.encode("utf-8")          # str → bytes
    password_safe   = password_bytes[:72].decode("utf-8", errors="ignore")  # tronque à 72 bytes
    hashed_password = pwd_context.hash(password_safe)          # hash bcrypt
    # hashed_password = pwd_context.hash(ADMIN_PASSWORD)

    # ── Génération de la clé secrète TOTP ────────────────────────────────────
    # pyotp.random_base32() génère une clé secrète aléatoire de 32 caractères Base32.
    # Cette clé est stockée en base et partagée avec l'application d'authentification
    # (Google Authenticator, Authy, etc.) via un QR code.
    # En production, cette clé doit être chiffrée avant stockage (AES-256 applicatif).
    mfa_secret = pyotp.random_base32()

    # ── Insertion de l'administrateur dans PostgreSQL ─────────────────────────
    # On utilise INSERT ... RETURNING id pour récupérer l'UUID généré automatiquement
    # (DEFAULT gen_random_uuid() dans le schéma PG).
    admin_id = await conn.fetchval(
        """
        INSERT INTO users (
            username,           -- identifiant de connexion unique
            email,              -- adresse email (canal de notification + récupération)
            hashed_password,    -- mot de passe haché bcrypt (jamais en clair)
            role,               -- 'admin' = accès complet au système
            mfa_secret,         -- clé secrète TOTP pour Google Authenticator
            mfa_enabled,        -- MFA activé par défaut (obligatoire selon EF-26)
            org_scope,          -- périmètre 'global' = pas de restriction d'accès
            is_active,          -- compte actif immédiatement
            must_change_password -- l'admin doit changer son mdp à la première connexion
        ) VALUES (
            $1,                -- username
            $2,                -- email
            $3,                -- hashed_password
            'admin'::user_role, -- cast explicite vers l'ENUM user_role défini dans le schéma
            $4,                -- mfa_secret
            TRUE,              -- mfa_enabled = toujours TRUE pour un admin
            $5,                -- org_scope
            TRUE,              -- is_active
            TRUE               -- must_change_password = sécurité : forcer le changement
        )
        RETURNING id           -- récupère l'UUID généré automatiquement par gen_random_uuid()
        """,
        ADMIN_USERNAME,
        ADMIN_EMAIL,
        hashed_password,
        mfa_secret,
        ADMIN_ORG_SCOPE,
    )

    print(f"\n{'='*60}")
    print(f"  COMPTE ADMINISTRATEUR CRÉÉ")
    print(f"{'='*60}")
    print(f"  Identifiant  : {ADMIN_USERNAME}")
    print(f"  Email        : {ADMIN_EMAIL}")
    print(f"  Mot de passe : {ADMIN_PASSWORD}")
    print(f"  UUID         : {admin_id}")
    print(f"  MFA Secret   : {mfa_secret}")
    print(f"\n  ⚠ IMPORTANT — Configurer Google Authenticator :")
    print(f"  1. Ouvrir Google Authenticator sur votre téléphone")
    print(f"  2. Ajouter un compte → Saisir une clé de configuration")
    print(f"  3. Nom du compte : Smart SIEM Admin")
    print(f"  4. Clé secrète   : {mfa_secret}")
    print(f"  5. Type : Basé sur le temps (TOTP)")
    print(f"\n  ⚠ Changer le mot de passe à la première connexion !")
    print(f"  ⚠ Sauvegarder la clé MFA Secret en lieu sûr !")
    print(f"{'='*60}\n")

    return str(admin_id)


async def init_rules():
    """
    Fonction principale : connexion à PG, création de l'admin, insertion des règles.
    async car asyncpg est asynchrone.

    Ordre d'exécution :
    Étape 1 → Créer l'admin si absent  (prérequis FK pour les règles)
    Étape 2 → Insérer les 5 règles     (avec created_by = admin_id)
    """
    # Création du pool de connexions PostgreSQL
    pool = await asyncpg.create_pool(dsn=PG_DSN, min_size=1, max_size=3)

    async with pool.acquire() as conn:

        # ── ÉTAPE 1 : Créer l'administrateur si absent ────────────────────────
        # Cette étape doit IMPÉRATIVEMENT précéder l'insertion des règles
        # car les règles ont une contrainte FK created_by → users.id.
        # Sans admin, l'INSERT dans correlation_rules lèverait une ForeignKeyViolationError.
        print("[1/2] Vérification / création du compte administrateur...")
        admin_id = await create_admin_if_missing(conn)

        # ── ÉTAPE 2 : Insérer les règles de corrélation ───────────────────────
        print("[2/2] Insertion des règles de corrélation...")

        # Insertion de chaque règle
        for rule in RULES:
            # Vérification d'idempotence : la règle existe-t-elle déjà ?
            # On identifie les règles par leur nom (contrainte UNIQUE dans le schéma PG)
            exists = await conn.fetchval(
                "SELECT id FROM correlation_rules WHERE name = $1",
                rule["name"]  # $1 = paramètre positionnel (protection contre SQL injection)
            )

            if exists:
                # Règle déjà présente → on skip sans erreur
                print(f"[SKIP] Déjà existante : {rule['name']}")
                continue

            # Insertion de la règle avec tous ses paramètres
            await conn.execute(
                """
                INSERT INTO correlation_rules (
                    name, description, rule_type, conditions,
                    time_window_seconds, threshold_count, sources_required,
                    alert_level, confidence_score, mitre_tactic, mitre_technique,
                    is_active, created_by
                ) VALUES (
                    $1,              -- name
                    $2,              -- description
                    $3,              -- rule_type : threshold | pattern | cross_source
                    $4::jsonb,       -- conditions : cast explicite vers JSONB PostgreSQL
                    $5,              -- time_window_seconds
                    $6,              -- threshold_count (peut être NULL pour pattern/cross_source)
                    $7::jsonb,       -- sources_required (peut être NULL)
                    $8::alert_level, -- cast vers l'ENUM alert_level défini dans le schéma
                    $9,              -- confidence_score : 0-100
                    $10,             -- mitre_tactic (ex: "TA0001")
                    $11,             -- mitre_technique (ex: "T1110")
                    TRUE,            -- is_active : activée immédiatement à la création
                    $12::uuid        -- created_by : FK vers users.id (l'admin)
                )
                """,
                rule["name"],
                rule.get("description", ""),
                rule["rule_type"],
                rule["conditions"],              # déjà sérialisé en JSON par json.dumps()
                rule.get("time_window_seconds"),
                rule.get("threshold_count"),     # None → NULL en PG
                rule.get("sources_required"),    # None → NULL en PG
                rule["alert_level"],
                rule["confidence_score"],
                rule.get("mitre_tactic"),
                rule.get("mitre_technique"),
                str(admin_id),                   # UUID converti en string pour asyncpg
            )
            print(f"[OK] Insérée : {rule['name']} ({rule['alert_level']})")

    # Vérification finale : compter les règles actives
    async with pool.acquire() as conn:
        count = await conn.fetchval(
            "SELECT COUNT(*) FROM correlation_rules WHERE is_active = TRUE"
        )
    print(f"\n[RÉSULTAT] {count} règles actives dans PostgreSQL")
    print("  → Si count >= 5 : exigences EF-09 à EF-12 satisfaites")

    # Fermeture du pool de connexions
    await pool.close()


if __name__ == "__main__":
    # asyncio.run() : démarre la boucle asyncio et exécute init_rules()
    asyncio.run(init_rules())