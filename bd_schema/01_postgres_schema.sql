-- Active: 1771814035244@@127.0.0.1@5432@nafeh
01_postgres_schema.sql
-- ============================================================
--  SMART SIEM — Schéma PostgreSQL complet
--  Rôle : stockage des données relationnelles et transactionnelles
--  Version : 1.0 | UCAC/ULC-ICAM 2026
-- ============================================================
 
-- ─── Extensions requises ─────────────────────────────────────
-- pgcrypto : génération UUID v4 et hashing
-- pg_trgm  : index trigramme pour la recherche dans raw_content
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
 
-- ─── Enumérations (types contrôlés) ──────────────────────────
-- Avantage : intégrité sans table de référence, plus lisible que VARCHAR
 
CREATE TYPE log_severity    AS ENUM ('info', 'warning', 'high', 'critical');
CREATE TYPE log_type_enum   AS ENUM ('auth', 'network', 'system', 'application', 'audit');
CREATE TYPE source_protocol AS ENUM ('syslog-udp', 'syslog-tcp', 'filebeat', 'rest-api');
CREATE TYPE source_env      AS ENUM ('production', 'staging', 'development', 'test');
CREATE TYPE proc_status     AS ENUM ('pending', 'processing', 'normalized', 'error');
CREATE TYPE alert_level     AS ENUM ('INFO', 'WARNING', 'HIGH', 'CRITICAL');
CREATE TYPE alert_status    AS ENUM ('open', 'investigating', 'false_positive', 'confirmed', 'escalated', 'closed');
CREATE TYPE incident_status AS ENUM ('open', 'in_progress', 'pending_action', 'resolved', 'closed');
CREATE TYPE exec_mode       AS ENUM ('AUTO', 'CONFIRM');
CREATE TYPE user_role       AS ENUM ('reader', 'analyst', 'rssi', 'auditor', 'admin');
CREATE TYPE audit_action    AS ENUM (
    'user_login', 'user_logout', 'user_created', 'user_deleted',
    'role_changed', 'password_changed', 'mfa_enrolled',
    'alert_acknowledged', 'alert_closed', 'alert_escalated',
    'incident_created', 'incident_assigned', 'incident_resolved',
    'rule_created', 'rule_modified', 'rule_deleted', 'rule_toggled',
    'playbook_executed', 'playbook_created',
    'log_exported', 'report_generated',
    'config_changed', 'api_key_created'
);
CREATE TYPE action_result   AS ENUM ('success', 'failure', 'denied');
CREATE TYPE entity_type     AS ENUM ('user', 'machine', 'service');
 
 
-- ============================================================
-- TABLE 1 : raw_logs
-- Rôle : réception et mise en tampon des logs bruts
--        AVANT normalisation et envoi vers Elasticsearch.
--        C'est le point d'entrée unique du pipeline.
-- ============================================================
CREATE TABLE raw_logs (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    received_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    raw_content      TEXT         NOT NULL,
    source_protocol  source_protocol NOT NULL,
    source_ip        INET         NOT NULL,
    processing_status proc_status NOT NULL DEFAULT 'pending',
    normalized_at    TIMESTAMPTZ,
    error_message    TEXT,
    retry_count      SMALLINT     NOT NULL DEFAULT 0,
    es_document_id   VARCHAR(100),
    es_index_name    VARCHAR(100),
    hash_sha256      CHAR(64),    -- hash du raw_content, calculé à la réception
 
    CONSTRAINT chk_retry CHECK (retry_count >= 0),
    CONSTRAINT chk_hash  CHECK (hash_sha256 ~ '^[a-f0-9]{64}$' OR hash_sha256 IS NULL)
);
 
COMMENT ON TABLE  raw_logs IS 'Table tampon pour les logs bruts avant normalisation. Ne jamais supprimer les entrées manuellement.';
COMMENT ON COLUMN raw_logs.hash_sha256 IS 'SHA-256 du raw_content calculé à la réception — valeur probatoire (chaîne de custody).';
COMMENT ON COLUMN raw_logs.es_document_id IS 'ID du document Elasticsearch créé après normalisation réussie.';
 
-- INDEX raw_logs
-- 1. Recherche par statut de traitement (pipeline monitoring)
CREATE INDEX idx_raw_logs_status     ON raw_logs (processing_status);
-- 2. Recherche par horodatage (monitoring des retards)
CREATE INDEX idx_raw_logs_received   ON raw_logs (received_at DESC);
-- 3. Recherche par IP source (incident investigation)
CREATE INDEX idx_raw_logs_source_ip  ON raw_logs USING HASH (source_ip);
-- 4. Logs non traités récents (worker de normalisation)
CREATE INDEX idx_raw_logs_pending    ON raw_logs (received_at DESC)
    WHERE processing_status = 'pending';
-- 5. Logs en erreur (monitoring pipeline)
CREATE INDEX idx_raw_logs_errors     ON raw_logs (received_at DESC)
    WHERE processing_status = 'error';
 
 
-- ============================================================
-- TABLE 2 : log_sources
-- Rôle : référentiel des sources de logs déclarées.
--        Toute source non déclarée qui envoie des logs
--        doit lever une alerte de sécurité.
-- ============================================================
CREATE TABLE log_sources (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    name              VARCHAR(150) NOT NULL,
    source_type       VARCHAR(60)  NOT NULL,
    ip_address        INET         NOT NULL,
    hostname          VARCHAR(250),
    collection_protocol source_protocol NOT NULL,
    collection_port   INTEGER      NOT NULL DEFAULT 514,
    environment       source_env   NOT NULL DEFAULT 'production',
    org_unit          VARCHAR(100),          -- unité organisationnelle (RBAC)
    is_active         BOOLEAN      NOT NULL DEFAULT TRUE,
    last_seen_at      TIMESTAMPTZ,
    silent_alert_after_minutes INTEGER DEFAULT 60,  -- alerte si silencieux plus longtemps
    metadata          JSONB        NOT NULL DEFAULT '{}',
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
 
    CONSTRAINT uq_log_sources_name    UNIQUE (name),
    CONSTRAINT uq_log_sources_ip_port UNIQUE (ip_address, collection_port),
    CONSTRAINT chk_port               CHECK (collection_port BETWEEN 1 AND 65535)
);
 
COMMENT ON TABLE  log_sources IS 'Référentiel des sources de logs autorisées. Une source inconnue = anomalie.';
COMMENT ON COLUMN log_sources.silent_alert_after_minutes IS 'Durée de silence (min) avant déclenchement d alerte de disponibilité.';
 
-- INDEX log_sources
CREATE UNIQUE INDEX idx_log_sources_ip   ON log_sources (ip_address);
CREATE INDEX idx_log_sources_active      ON log_sources (is_active, environment);
CREATE INDEX idx_log_sources_last_seen   ON log_sources (last_seen_at DESC)
    WHERE is_active = TRUE;
 
 
-- ============================================================
-- TABLE 3 : users
-- Rôle : gestion des identités, authentification MFA,
--        et contrôle d'accès basé sur les rôles (RBAC).
--        Données sensibles — hashées et chiffrées.
-- ============================================================
CREATE TABLE users (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    username            VARCHAR(100) NOT NULL,
    email               VARCHAR(200) NOT NULL,
    hashed_password     VARCHAR(255) NOT NULL,  -- bcrypt, coût >= 12
    role                user_role   NOT NULL DEFAULT 'reader',
    mfa_secret          VARCHAR(100) NOT NULL,  -- clé TOTP chiffrée (AES-256 applicatif)
    mfa_enabled         BOOLEAN     NOT NULL DEFAULT TRUE,
    org_scope           VARCHAR(100),            -- périmètre organisationnel (RBAC)
    is_active           BOOLEAN     NOT NULL DEFAULT TRUE,
    last_login_at       TIMESTAMPTZ,
    failed_login_count  SMALLINT    NOT NULL DEFAULT 0,
    locked_until        TIMESTAMPTZ,
    password_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    must_change_password BOOLEAN    NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by          UUID        REFERENCES users(id) ON DELETE SET NULL,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 
    CONSTRAINT uq_users_username UNIQUE (username),
    CONSTRAINT uq_users_email    UNIQUE (email),
    CONSTRAINT chk_email_format  CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    CONSTRAINT chk_failed_logins CHECK (failed_login_count >= 0)
);
 
COMMENT ON TABLE  users IS 'Identités et accès. MFA obligatoire. Jamais stocker le mot de passe en clair.';
COMMENT ON COLUMN users.mfa_secret IS 'Clé TOTP (RFC 6238) chiffrée au niveau applicatif avant stockage.';
COMMENT ON COLUMN users.org_scope  IS 'Périmètre RBAC : limite la visibilité aux ressources de son périmètre.';
 
-- INDEX users
CREATE UNIQUE INDEX idx_users_username ON users (username);
CREATE UNIQUE INDEX idx_users_email    ON users (LOWER(email));  -- insensible à la casse
CREATE INDEX idx_users_role_active     ON users (role, is_active);
CREATE INDEX idx_users_locked          ON users (locked_until)
    WHERE locked_until IS NOT NULL;
 
 
-- ============================================================
-- TABLE 4 : correlation_rules
-- Rôle : base de connaissances du moteur de corrélation.
--        Chaque règle encode un scénario d'attaque connu.
--        C'est la valeur métier principale du SIEM.
-- ============================================================
CREATE TABLE correlation_rules (
    id                   UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    name                 VARCHAR(200) NOT NULL,
    description          TEXT,
    rule_type            VARCHAR(30)  NOT NULL,       -- threshold | pattern | behavioral | composite
    conditions           JSONB        NOT NULL,       -- conditions d'évaluation encodées
    time_window_seconds  INTEGER,                     -- fenêtre temporelle (NULL = sans limite)
    threshold_count      INTEGER,                     -- N occurrences pour déclencher (threshold)
    sources_required     JSONB,                       -- sources impliquées pour corrélation inter-sources
    alert_level          alert_level  NOT NULL DEFAULT 'WARNING',
    confidence_score     SMALLINT     NOT NULL DEFAULT 80 CHECK (confidence_score BETWEEN 0 AND 100),
    mitre_tactic         VARCHAR(100),
    mitre_technique      VARCHAR(100),
    mitre_subtechnique   VARCHAR(100),
    playbook_id          UUID,                        -- FK vers playbooks (ajoutée après)
    is_active            BOOLEAN      NOT NULL DEFAULT TRUE,
    false_positive_count INTEGER      NOT NULL DEFAULT 0,
    trigger_count        INTEGER      NOT NULL DEFAULT 0,
    last_triggered_at    TIMESTAMPTZ,
    created_by           UUID         REFERENCES users(id) ON DELETE SET NULL,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
 
    CONSTRAINT uq_rule_name          UNIQUE (name),
    CONSTRAINT chk_rule_type         CHECK (rule_type IN ('threshold','pattern','behavioral','composite','cross_source')),
    CONSTRAINT chk_threshold_logic   CHECK (
        (rule_type = 'threshold' AND threshold_count IS NOT NULL AND time_window_seconds IS NOT NULL)
        OR rule_type != 'threshold'
    )
);

-- ALTER TABLE correlation_rules DROP CONSTRAINT chk_rule_type;
-- ALTER TABLE correlation_rules ADD CONSTRAINT chk_rule_type 
--     CHECK (rule_type IN ('threshold','pattern','behavioral','composite','cross_source'));
 
COMMENT ON TABLE  correlation_rules IS 'Règles de détection du moteur de corrélation. La base de connaissance du SIEM.';
COMMENT ON COLUMN correlation_rules.conditions IS 'Conditions JSON. Ex: [{"field":"event_action","op":"eq","value":"login_failed"}]';
 
-- INDEX correlation_rules
CREATE INDEX idx_rules_active_level   ON correlation_rules (is_active, alert_level);
CREATE INDEX idx_rules_mitre          ON correlation_rules (mitre_tactic, mitre_technique)
    WHERE mitre_tactic IS NOT NULL;
CREATE INDEX idx_rules_type           ON correlation_rules (rule_type) WHERE is_active = TRUE;
 
 
-- ============================================================
-- TABLE 5 : playbooks
-- Rôle : procédures de réponse automatisées (SOAR).
--        Encode les actions de remédiation avec leur mode
--        d'exécution (AUTO vs CONFIRM).
-- ============================================================
CREATE TABLE playbooks (
    id                          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    name                        VARCHAR(200) NOT NULL,
    description                 TEXT         NOT NULL,
    action_type                 VARCHAR(60)  NOT NULL,  -- block_ip | disable_account | isolate_machine | notify_escalation
    execution_mode              exec_mode    NOT NULL DEFAULT 'CONFIRM',
    parameters                  JSONB        NOT NULL DEFAULT '{}',
    target_type                 VARCHAR(50),            -- ip_address | user_account | machine | subnet
    confirmation_timeout_seconds INTEGER     NOT NULL DEFAULT 300,
    rollback_supported          BOOLEAN      NOT NULL DEFAULT FALSE,
    rollback_parameters         JSONB,
    is_active                   BOOLEAN      NOT NULL DEFAULT TRUE,
    execution_count             INTEGER      NOT NULL DEFAULT 0,
    last_executed_at            TIMESTAMPTZ,
    created_by                  UUID         REFERENCES users(id) ON DELETE SET NULL,
    created_at                  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
 
    CONSTRAINT uq_playbook_name  UNIQUE (name),
    CONSTRAINT chk_action_type   CHECK (action_type IN (
        'block_ip','disable_account','isolate_machine',
        'notify_escalation','collect_evidence','custom'
    )),
    CONSTRAINT chk_timeout       CHECK (confirmation_timeout_seconds > 0)
);
 
-- Ajout de la FK playbook → rule maintenant que les deux tables existent
ALTER TABLE correlation_rules
    ADD CONSTRAINT fk_rule_playbook
    FOREIGN KEY (playbook_id) REFERENCES playbooks(id) ON DELETE SET NULL;
 
-- INDEX playbooks
CREATE INDEX idx_playbooks_active_type ON playbooks (is_active, action_type);
 
 
-- ============================================================
-- TABLE 6 : alerts
-- Rôle : enregistrement de chaque alerte générée par
--        le moteur de corrélation. Pont entre la détection
--        (Elasticsearch) et la réponse (incidents, playbooks).
-- ============================================================
CREATE TABLE alerts (
    id                   UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id              UUID         NOT NULL REFERENCES correlation_rules(id) ON DELETE RESTRICT,
    title                VARCHAR(350) NOT NULL,
    level                alert_level  NOT NULL,
    status               alert_status NOT NULL DEFAULT 'open',
    triggered_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    acknowledged_at      TIMESTAMPTZ,
    resolved_at          TIMESTAMPTZ,
    acknowledged_by      UUID         REFERENCES users(id) ON DELETE SET NULL,
    correlated_event_ids JSONB,       -- IDs des documents ES ayant déclenché la règle
    source_ips           JSONB,       -- IPs impliquées (dénormalisé pour perf dashboard)
    dest_ips             JSONB,
    affected_hosts       JSONB,
    usernames            JSONB,       -- comptes impliqués
    mitre_tactic         VARCHAR(100),
    confidence_score     SMALLINT     CHECK (confidence_score BETWEEN 0 AND 100),
    is_false_positive    BOOLEAN      NOT NULL DEFAULT FALSE,
    notes                TEXT,
 
    CONSTRAINT chk_ack_after_trigger CHECK (acknowledged_at IS NULL OR acknowledged_at >= triggered_at),
    CONSTRAINT chk_res_after_ack     CHECK (resolved_at IS NULL OR resolved_at >= triggered_at)
);
 
COMMENT ON TABLE  alerts IS 'Alertes générées par le moteur de corrélation. Cycle de vie complet.';
COMMENT ON COLUMN alerts.correlated_event_ids IS 'Liste des _id Elasticsearch des événements déclencheurs.';
COMMENT ON COLUMN alerts.source_ips IS 'IPs sources impliquées — dénormalisé pour perf affichage dashboard.';
 
-- INDEX alerts — critiques pour les SLA (CRITICAL < 30s)
CREATE INDEX idx_alerts_status_level  ON alerts (status, level);
CREATE INDEX idx_alerts_triggered_at  ON alerts (triggered_at DESC);
CREATE INDEX idx_alerts_open_critical ON alerts (triggered_at DESC)
    WHERE status = 'open' AND level = 'CRITICAL';
CREATE INDEX idx_alerts_rule_id       ON alerts (rule_id);
CREATE INDEX idx_alerts_acknowledged  ON alerts (acknowledged_by, acknowledged_at DESC)
    WHERE acknowledged_by IS NOT NULL;
-- Recherche dans les IPs JSON (GIN pour JSONB)
CREATE INDEX idx_alerts_source_ips    ON alerts USING GIN (source_ips);
CREATE INDEX idx_alerts_hosts         ON alerts USING GIN (affected_hosts);
 
 
-- ============================================================
-- TABLE 7 : incidents
-- Rôle : cycle de vie complet d'un incident de sécurité
--        confirmé nécessitant une réponse active.
--        Table de travail principale des analystes.
-- ============================================================
CREATE TABLE incidents (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id          UUID         NOT NULL REFERENCES alerts(id) ON DELETE RESTRICT,
    title             VARCHAR(350) NOT NULL,
    severity          alert_level  NOT NULL,
    status            incident_status NOT NULL DEFAULT 'open',
    assigned_to       UUID         REFERENCES users(id) ON DELETE SET NULL,
    opened_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    resolved_at       TIMESTAMPTZ,
    response_actions  JSONB        NOT NULL DEFAULT '[]',  -- historique des actions
    affected_assets   JSONB        NOT NULL DEFAULT '{}',
    ioc_indicators    JSONB        NOT NULL DEFAULT '[]',  -- indicateurs de compromission
    root_cause        TEXT,
    lessons_learned   TEXT,
    tlp_level         VARCHAR(10)  NOT NULL DEFAULT 'AMBER', -- Traffic Light Protocol
 
    CONSTRAINT uq_incident_alert UNIQUE (alert_id),  -- 1 alerte → 1 incident max
    CONSTRAINT chk_resolved_after_open CHECK (resolved_at IS NULL OR resolved_at >= opened_at),
    CONSTRAINT chk_tlp CHECK (tlp_level IN ('WHITE','GREEN','AMBER','RED'))
);
 
COMMENT ON TABLE  incidents IS 'Incidents confirmés. Chaque incident est lié à exactement une alerte.';
COMMENT ON COLUMN incidents.response_actions IS 'JSON array d actions effectuées: [{action,target,by,at,result}]';
COMMENT ON COLUMN incidents.tlp_level IS 'Traffic Light Protocol — contrôle la diffusion des informations.';
 
-- INDEX incidents
CREATE INDEX idx_incidents_status     ON incidents (status, severity);
CREATE INDEX idx_incidents_assigned   ON incidents (assigned_to, status)
    WHERE assigned_to IS NOT NULL;
CREATE INDEX idx_incidents_opened_at  ON incidents (opened_at DESC);
CREATE INDEX idx_incidents_open       ON incidents (severity, opened_at DESC)
    WHERE status IN ('open', 'in_progress');
 
 
-- ============================================================
-- TABLE 8 : playbook_executions
-- Rôle : journal de chaque exécution de playbook.
--        Séparé de la table playbooks pour ne pas mélanger
--        définition et historique (Single Responsibility).
-- ============================================================
CREATE TABLE playbook_executions (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    playbook_id     UUID         NOT NULL REFERENCES playbooks(id) ON DELETE RESTRICT,
    incident_id     UUID         REFERENCES incidents(id) ON DELETE SET NULL,
    alert_id        UUID         REFERENCES alerts(id) ON DELETE SET NULL,
    triggered_by    UUID         REFERENCES users(id) ON DELETE SET NULL,
    execution_mode  exec_mode    NOT NULL,
    target_value    VARCHAR(500) NOT NULL,  -- IP, username ou hostname ciblé
    parameters_used JSONB        NOT NULL DEFAULT '{}',
    status          VARCHAR(30)  NOT NULL DEFAULT 'pending',
    result          JSONB,                  -- résultat de l'exécution
    started_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    confirmed_at    TIMESTAMPTZ,            -- pour mode CONFIRM
    confirmed_by    UUID         REFERENCES users(id) ON DELETE SET NULL,
    completed_at    TIMESTAMPTZ,
    error_message   TEXT,
 
    CONSTRAINT chk_exec_status CHECK (status IN ('pending','awaiting_confirm','running','success','failed','cancelled','rolled_back'))
);
 
-- INDEX playbook_executions
CREATE INDEX idx_pe_playbook_id   ON playbook_executions (playbook_id, started_at DESC);
CREATE INDEX idx_pe_incident_id   ON playbook_executions (incident_id) WHERE incident_id IS NOT NULL;
CREATE INDEX idx_pe_pending       ON playbook_executions (started_at DESC)
    WHERE status IN ('pending', 'awaiting_confirm');
 
 
-- ============================================================
-- TABLE 9 : audit_logs
-- Rôle : journal IMMUABLE de toutes les actions utilisateurs.
--        Base de la conformité RGPD et ISO 27001.
--        Valeur probatoire — aucune UPDATE ou DELETE permise.
-- ============================================================
CREATE TABLE audit_logs (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID         REFERENCES users(id) ON DELETE SET NULL,
    username_snapshot VARCHAR(100) NOT NULL,  -- snapshot au moment de l'action
    role_snapshot     user_role   NOT NULL,   -- rôle au moment de l'action
    action           audit_action NOT NULL,
    resource_type    VARCHAR(60),
    resource_id      VARCHAR(100),
    performed_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    ip_address       INET,
    user_agent       VARCHAR(500),
    result           action_result NOT NULL DEFAULT 'success',
    metadata         JSONB        NOT NULL DEFAULT '{}'
);
 
COMMENT ON TABLE  audit_logs IS 'Journal d audit immuable. Aucune UPDATE/DELETE autorisée (Row Security + trigger).';
COMMENT ON COLUMN audit_logs.username_snapshot IS 'Snapshot du username — conservé même si le compte est supprimé.';
 
-- INDEX audit_logs — optimisés pour les requêtes d'audit
CREATE INDEX idx_audit_performed_at  ON audit_logs (performed_at DESC);
CREATE INDEX idx_audit_user_id       ON audit_logs (user_id, performed_at DESC)
    WHERE user_id IS NOT NULL;
CREATE INDEX idx_audit_action        ON audit_logs (action, performed_at DESC);
CREATE INDEX idx_audit_resource      ON audit_logs (resource_type, resource_id)
    WHERE resource_type IS NOT NULL;
CREATE INDEX idx_audit_failures      ON audit_logs (performed_at DESC)
    WHERE result IN ('failure', 'denied');
 
 
-- ============================================================
-- TABLE 10 : ueba_profiles (résumé PostgreSQL)
-- Rôle : profils comportementaux persistants.
--        Les détails de série temporelle vivent dans ES.
--        Ce résumé sert aux dashboards et à la corrélation rapide.
-- ============================================================
CREATE TABLE ueba_profiles (
    id                     UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_id              VARCHAR(200) NOT NULL,  -- username ou hostname
    entity_type            entity_type NOT NULL,
    profile_period_start   DATE        NOT NULL,
    profile_period_end     DATE        NOT NULL,
    typical_login_hours    JSONB,      -- distribution horaire des connexions
    typical_source_ips     JSONB,      -- IPs sources habituelles
    avg_daily_events       FLOAT,
    avg_daily_data_mb      FLOAT,
    typical_accessed_systems        JSONB,      -- systèmes habituellement accédés
    risk_score_current     SMALLINT    NOT NULL DEFAULT 0 CHECK (risk_score_current BETWEEN 0 AND 100),
    risk_score_previous    SMALLINT    CHECK (risk_score_previous BETWEEN 0 AND 100),
    anomaly_count_7d       INTEGER     NOT NULL DEFAULT 0,
    last_anomaly_at        TIMESTAMPTZ,
    last_updated           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    es_profile_id          VARCHAR(100)  -- référence vers le profil complet dans ES
 );
    -- CONSTRAINT uq_ueba_entity UNIQUE (entity_id, entity_type, profile_period_start)

 
-- INDEX ueba_profiles
CREATE INDEX idx_ueba_entity_type  ON ueba_profiles (entity_type, entity_id);
CREATE INDEX idx_ueba_risk_score   ON ueba_profiles (risk_score_current DESC)
    WHERE risk_score_current > 50;  -- index partiel : seulement les profils à risque
CREATE INDEX idx_ueba_last_updated ON ueba_profiles (last_updated DESC);
 
 
-- ============================================================
-- TABLE 11 : retention_policies
-- Rôle : définition des politiques de rétention des données.
--        Permet une configuration sans modifier le code.
--        Chaque politique s'applique à un type de données.
-- ============================================================
CREATE TABLE retention_policies (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_name     VARCHAR(100) NOT NULL,
    data_type       VARCHAR(60)  NOT NULL,      -- raw_logs | es_logs | alerts | incidents | audit_logs
    retention_days  INTEGER      NOT NULL CHECK (retention_days > 0),
    archive_before_delete BOOLEAN NOT NULL DEFAULT TRUE,
    archive_location      VARCHAR(300),          -- chemin ou bucket S3
    is_active       BOOLEAN     NOT NULL DEFAULT TRUE,
    last_applied_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 
    CONSTRAINT uq_policy_data_type UNIQUE (data_type),
    CONSTRAINT chk_data_type CHECK (data_type IN (
        'raw_logs', 'es_logs', 'alerts', 'incidents', 'audit_logs', 'ueba_profiles'
    ))
);
 
-- Données initiales des politiques de rétention
INSERT INTO retention_policies (policy_name, data_type, retention_days, archive_before_delete) VALUES
    ('Rétention logs bruts',       'raw_logs',       30,   TRUE),
    ('Rétention logs ES',          'es_logs',        180,  TRUE),
    ('Rétention alertes',          'alerts',         365,  TRUE),
    ('Rétention incidents',        'incidents',      730,  TRUE),   -- 2 ans
    ('Rétention journal d audit',  'audit_logs',     1095, FALSE),  -- 3 ans (RGPD/ISO 27001)
    ('Rétention profils UEBA',     'ueba_profiles',  90,   FALSE);
 
 
-- ============================================================
-- TRIGGERS
-- ============================================================
 
-- Trigger : updated_at automatique
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
 
CREATE TRIGGER trg_users_updated_at          BEFORE UPDATE ON users           FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_log_sources_updated_at    BEFORE UPDATE ON log_sources     FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_rules_updated_at          BEFORE UPDATE ON correlation_rules FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_playbooks_updated_at      BEFORE UPDATE ON playbooks        FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_retention_updated_at      BEFORE UPDATE ON retention_policies FOR EACH ROW EXECUTE FUNCTION update_updated_at();
 
-- Trigger : protection de l'immuabilité de audit_logs
CREATE OR REPLACE FUNCTION deny_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'SECURITY: La table audit_logs est immuable. Aucune modification autorisée. (action: %)', TG_OP;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
 
CREATE TRIGGER trg_audit_no_update BEFORE UPDATE ON audit_logs FOR EACH ROW EXECUTE FUNCTION deny_audit_modification();
CREATE TRIGGER trg_audit_no_delete BEFORE DELETE ON audit_logs FOR EACH ROW EXECUTE FUNCTION deny_audit_modification();
 
-- Trigger : incrémentation automatique du compteur d'alertes sur les règles
CREATE OR REPLACE FUNCTION increment_rule_trigger_count()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE correlation_rules
    SET trigger_count = trigger_count + 1, last_triggered_at = NOW()
    WHERE id = NEW.rule_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
 
CREATE TRIGGER trg_alert_increment_rule AFTER INSERT ON alerts FOR EACH ROW EXECUTE FUNCTION increment_rule_trigger_count();
 
 
-- ============================================================
-- RÉCAPITULATIF DES INDEX CRÉÉS
-- (résumé en bas du fichier)
-- ============================================================
/*
TABLE raw_logs (5 index)
  idx_raw_logs_status    : processing_status — filtre pipeline worker
  idx_raw_logs_received  : received_at DESC — monitoring retards
  idx_raw_logs_source_ip : HASH(source_ip) — recherche exacte d'IP
  idx_raw_logs_pending   : (partiel) received_at DESC WHERE pending — worker
  idx_raw_logs_errors    : (partiel) received_at DESC WHERE error — monitoring
 
TABLE log_sources (3 index)
  idx_log_sources_ip       : UNIQUE ip_address — contrainte + recherche
  idx_log_sources_active   : is_active, environment — filtre courant
  idx_log_sources_last_seen: (partiel) last_seen_at WHERE active — monitoring silence
 
TABLE users (4 index)
  idx_users_username   : UNIQUE username — authentification
  idx_users_email      : UNIQUE LOWER(email) — insensible casse
  idx_users_role_active: role, is_active — RBAC
  idx_users_locked     : (partiel) locked_until — déverrouillage auto
 
TABLE correlation_rules (3 index)
  idx_rules_active_level : is_active, alert_level — évaluation moteur
  idx_rules_mitre        : (partiel) mitre_tactic, technique — reporting MITRE
  idx_rules_type         : (partiel) rule_type WHERE active — dispatch moteur
 
TABLE alerts (7 index)
  idx_alerts_status_level  : status, level — dashboard principal
  idx_alerts_triggered_at  : triggered_at DESC — timeline
  idx_alerts_open_critical : (partiel) CRITICAL open — SLA < 30s
  idx_alerts_rule_id       : rule_id — performance des règles
  idx_alerts_acknowledged  : acknowledged_by, at — charge analyste
  idx_alerts_source_ips    : GIN(source_ips) — recherche dans JSONB
  idx_alerts_hosts         : GIN(affected_hosts) — recherche dans JSONB
 
TABLE incidents (4 index)
  idx_incidents_status   : status, severity — vue analyste
  idx_incidents_assigned : assigned_to, status — charge analyste
  idx_incidents_opened_at: opened_at DESC — timeline
  idx_incidents_open     : (partiel) severity, opened_at WHERE open — dashboard
 
TABLE audit_logs (5 index)
  idx_audit_performed_at : performed_at DESC — requêtes chronologiques
  idx_audit_user_id      : user_id, performed_at — activité utilisateur
  idx_audit_action       : action, performed_at — filtres d'audit
  idx_audit_resource     : resource_type, resource_id — pivot sur ressource
  idx_audit_failures     : (partiel) performed_at WHERE failure/denied — sécurité
 
TABLE ueba_profiles (3 index)
  idx_ueba_entity_type  : entity_type, entity_id — profil par entité
  idx_ueba_risk_score   : (partiel) risk_score DESC WHERE > 50 — alertes UEBA
  idx_ueba_last_updated : last_updated DESC — fraîcheur des profils
*/
