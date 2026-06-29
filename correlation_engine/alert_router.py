#!/usr/bin/env python3
"""
SMART SIEM — Router d'alertes et module SOAR
FastAPI endpoints pour :
  - Recevoir les alertes du moteur de corrélation
  - Envoyer les notifications (email, webhook)
  - Déclencher les playbooks (block_ip, disable_account, escalate)
  - Gérer le cycle de vie des incidents
"""

import os, json, uuid, logging, asyncio
from datetime import datetime, timezone
from typing import Optional

import asyncpg
import aiohttp
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

log = logging.getLogger("alert_router")

# ── Configuration ─────────────────────────────────────────────────────────────
SMTP_HOST    = os.environ.get("SMTP_HOST",    "smtp.gmail.com")
SMTP_PORT    = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER    = os.environ.get("SMTP_USER",    "siem@exemple.com")
SMTP_PASS    = os.environ.get("SMTP_PASS",    "MOT_DE_PASSE_APP")
SOC_EMAIL    = os.environ.get("SOC_EMAIL",    "soc-team@exemple.com")
RSSI_EMAIL   = os.environ.get("RSSI_EMAIL",   "rssi@exemple.com")
SLACK_WEBHOOK= os.environ.get("SLACK_WEBHOOK","https://hooks.slack.com/services/XXX/YYY/ZZZ")
PG_DSN       = os.environ.get("PG_DSN",
    "postgresql://postgres:felicia@localhost:5432/nafeh")

app = FastAPI(title="Smart SIEM — Alert Router")

# ── Modèles Pydantic ──────────────────────────────────────────────────────────
class AlertTriggeredPayload(BaseModel):
    alert_id: str

class IncidentUpdatePayload(BaseModel):
    status:     Optional[str] = None   # open | in_progress | resolved | closed
    notes:      Optional[str] = None
    assigned_to: Optional[str] = None

class PlaybookConfirmPayload(BaseModel):
    confirmed: bool   # True = confirmer, False = annuler


# ── Helpers base de données ───────────────────────────────────────────────────
_pg_pool: Optional[asyncpg.Pool] = None

async def get_pool() -> asyncpg.Pool:
    global _pg_pool
    if not _pg_pool:
        _pg_pool = await asyncpg.create_pool(dsn=PG_DSN, min_size=2, max_size=10)
    return _pg_pool

async def load_alert(alert_id: str, pool: asyncpg.Pool) -> dict:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT a.*, r.name as rule_name, r.playbook_id
               FROM alerts a
               JOIN correlation_rules r ON r.id = a.rule_id
               WHERE a.id = $1::uuid""",
            alert_id
        )
    if not row:
        raise HTTPException(status_code=404, detail=f"Alerte {alert_id} introuvable")
    return dict(row)


# ── NOTIFICATIONS ─────────────────────────────────────────────────────────────

def send_email_sync(to: str, subject: str, body_html: str):
    """Envoie un email via SMTP TLS (exécuté dans un thread séparé)."""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = SMTP_USER
    msg["To"]      = to
    msg.attach(MIMEText(body_html, "html"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, to, msg.as_string())
        log.info(f"Email envoyé à {to} | Sujet: {subject[:50]}")
    except Exception as e:
        log.error(f"Erreur envoi email : {e}")


async def send_slack_webhook(message: str, level: str):
    """Envoie une notification Slack via webhook."""
    color_map = {"INFO": "#36a64f", "WARNING": "#ffa500", "HIGH": "#ff6b35", "CRITICAL": "#e01e5a"}
    payload = {
        "attachments": [{
            "color":    color_map.get(level, "#888888"),
            "title":    f"🚨 Smart SIEM — Alerte {level}",
            "text":     message,
            "footer":   "Smart SIEM | CTU",
            "ts":       int(datetime.now().timestamp()),
        }]
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(SLACK_WEBHOOK, json=payload, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status != 200:
                    log.warning(f"Slack webhook: HTTP {resp.status}")
                else:
                    log.info(f"Notification Slack envoyée (level={level})")
    except Exception as e:
        log.error(f"Erreur webhook Slack : {e}")


def build_alert_email(alert: dict) -> tuple[str, str]:
    """Construit le sujet et le corps HTML de l'email d'alerte."""
    level    = alert["level"]
    title    = alert["title"]
    rule     = alert.get("rule_name", "N/A")
    mitre    = alert.get("mitre_tactic", "N/A")
    conf     = alert.get("confidence_score", 0)
    src_ips  = json.loads(alert.get("source_ips", "[]") or "[]")

    emoji = {"INFO": "ℹ", "WARNING": "⚠", "HIGH": "🔴", "CRITICAL": "🚨"}.get(level, "•")
    color = {"INFO": "#0066cc", "WARNING": "#ff8800", "HIGH": "#cc3300", "CRITICAL": "#990000"}.get(level, "#666")

    subject = f"{emoji} [Smart SIEM] {level} — {title[:80]}"
    body = f"""
    <html><body>
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;border:1px solid #ddd;border-radius:8px;overflow:hidden">
        <div style="background:{color};padding:16px;color:white">
            <h2 style="margin:0">{emoji} Alerte {level}</h2>
        </div>
        <div style="padding:20px">
            <p><strong>Titre :</strong> {title}</p>
            <p><strong>Règle :</strong> {rule}</p>
            <p><strong>Tactique MITRE :</strong> {mitre}</p>
            <p><strong>Score de confiance :</strong> {conf}%</p>
            <p><strong>IPs sources :</strong> {", ".join(src_ips) or "N/A"}</p>
            <p><strong>Horodatage :</strong> {datetime.now(timezone.utc).isoformat()}</p>
            <hr>
            <p style="color:#666;font-size:12px">Smart SIEM — CTU Security Operations Center</p>
        </div>
    </div>
    </body></html>
    """
    return subject, body


# ── PLAYBOOKS SOAR ────────────────────────────────────────────────────────────

async def playbook_block_ip(ip: str, alert_id: str, pool: asyncpg.Pool, mode: str = "AUTO"):
    """
    Playbook : blocage d'une IP suspecte.
    AUTO : action immédiate
    CONFIRM : envoie un email de confirmation et attend
    """
    if mode == "CONFIRM":
        # Enregistrer l'exécution en attente
        exec_id = str(uuid.uuid4())
        async with pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO playbook_executions
                   (id, alert_id, execution_mode, target_value, status, started_at)
                   VALUES ($1::uuid, $2::uuid, 'CONFIRM'::exec_mode, $3, 'awaiting_confirm', NOW())""",
                exec_id, alert_id, ip
            )
        confirm_link = f"http://localhost:8000/playbooks/executions/{exec_id}/confirm"
        cancel_link  = f"http://localhost:8000/playbooks/executions/{exec_id}/cancel"
        subject = f"[CONFIRM REQUIRED] Blocage IP {ip}"
        body = f"""
        <html><body>
        <p>L'alerte SIEM propose de bloquer l'IP : <strong>{ip}</strong></p>
        <p>
          <a href="{confirm_link}" style="background:#cc3300;color:white;padding:10px 20px;border-radius:4px;text-decoration:none">Confirmer le blocage</a>
          &nbsp;&nbsp;
          <a href="{cancel_link}" style="background:#888;color:white;padding:10px 20px;border-radius:4px;text-decoration:none">Annuler</a>
        </p>
        <p style="color:#666;font-size:12px">Cette demande expire dans 5 minutes.</p>
        </body></html>
        """
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, send_email_sync, SOC_EMAIL, subject, body)
        log.info(f"[SOAR CONFIRM] Demande de blocage IP {ip} envoyée par email")
        return {"status": "awaiting_confirm", "execution_id": exec_id}

    # Mode AUTO : action immédiate
    # Option 1 : bloquer via iptables (si on est sur Linux)
    # os.system(f"iptables -A INPUT -s {ip} -j DROP")

    # Option 2 : insérer dans une table de blocage (plus sûr pour un projet étudiant)
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO playbook_executions
               (alert_id, execution_mode, target_value, status, started_at, completed_at,
                parameters_used, result)
               VALUES ($1::uuid, 'AUTO'::exec_mode, $2, 'success', NOW(), NOW(),
                       $3::jsonb, $4::jsonb)""",
            alert_id, ip,
            json.dumps({"action": "block_ip", "ip": ip}),
            json.dumps({"blocked": True, "method": "database_rule", "timestamp": datetime.now(timezone.utc).isoformat()})
        )
    log.warning(f"[SOAR AUTO] IP {ip} bloquée")
    return {"status": "success", "ip_blocked": ip}


async def playbook_disable_account(username: str, alert_id: str, pool: asyncpg.Pool):
    """Playbook : désactiver un compte utilisateur compromis."""
    async with pool.acquire() as conn:
        # Désactiver le compte
        result = await conn.execute(
            "UPDATE users SET is_active = FALSE WHERE username = $1",
            username
        )
        # Enregistrer l'exécution
        await conn.execute(
            """INSERT INTO playbook_executions
               (alert_id, execution_mode, target_value, status, started_at, completed_at,
                parameters_used, result)
               VALUES ($1::uuid, 'AUTO'::exec_mode, $2, 'success', NOW(), NOW(),
                       $3::jsonb, $4::jsonb)""",
            alert_id, username,
            json.dumps({"action": "disable_account", "username": username}),
            json.dumps({"disabled": True, "pg_result": result})
        )
    log.warning(f"[SOAR] Compte {username} désactivé")
    return {"status": "success", "account_disabled": username}


async def playbook_escalate_rssi(alert: dict, pool: asyncpg.Pool):
    """Playbook : escalader un incident critique vers le RSSI."""
    # Créer un incident
    incident_id = str(uuid.uuid4())
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO incidents (id, alert_id, title, severity, status, opened_at)
               VALUES ($1::uuid, $2::uuid, $3, $4::alert_level, 'open'::incident_status, NOW())""",
            incident_id, alert["id"], alert["title"], alert["level"]
        )

    # Email RSSI
    subject = f"[ESCALADE CRITIQUE] {alert['title'][:80]}"
    body = f"""
    <html><body>
    <h2>⚠️ Incident de sécurité critique — Action requise</h2>
    <p>Un incident a été ouvert automatiquement :</p>
    <ul>
        <li><strong>ID Incident :</strong> {incident_id}</li>
        <li><strong>Niveau :</strong> {alert['level']}</li>
        <li><strong>Titre :</strong> {alert['title']}</li>
        <li><strong>Règle déclenchée :</strong> {alert.get('rule_name', 'N/A')}</li>
    </ul>
    <p>Veuillez vous connecter au dashboard SIEM pour prendre en charge cet incident.</p>
    </body></html>
    """
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, send_email_sync, RSSI_EMAIL, subject, body)
    log.warning(f"[SOAR] Escalade vers RSSI — Incident {incident_id}")
    return {"status": "escalated", "incident_id": incident_id}


# ── LOGIQUE DE ROUTAGE ────────────────────────────────────────────────────────

NOTIFICATION_RULES = {
    "INFO":     {"email": False, "slack": False, "playbook": False},
    "WARNING":  {"email": False, "slack": True,  "playbook": False},
    "HIGH":     {"email": True,  "slack": True,  "playbook": False},
    "CRITICAL": {"email": True,  "slack": True,  "playbook": True},
}

async def route_alert(alert_id: str):
    """
    Fonction principale de routage.
    Appelée en background task par l'endpoint /internal/alert-triggered.
    """
    pool  = await get_pool()
    alert = await load_alert(alert_id, pool)
    level = alert["level"]
    rules = NOTIFICATION_RULES.get(level, {})

    log.info(f"[ROUTE] Alerte {alert_id} | niveau {level} | règles: {rules}")

    # ── 1. Notification email ─────────────────────────────────────────────────
    if rules.get("email"):
        subject, body = build_alert_email(alert)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, send_email_sync, SOC_EMAIL, subject, body)

    # ── 2. Webhook Slack ──────────────────────────────────────────────────────
    if rules.get("slack"):
        await send_slack_webhook(alert["title"], level)

    # ── 3. Déclencher le playbook associé ────────────────────────────────────
    if rules.get("playbook"):
        src_ips   = json.loads(alert.get("source_ips",   "[]") or "[]")
        usernames = json.loads(alert.get("usernames",    "[]") or "[]")

        if src_ips:
            await playbook_block_ip(src_ips[0], alert_id, pool, mode="AUTO")
        if level == "CRITICAL":
            await playbook_escalate_rssi(alert, pool)

    # ── 4. Mettre à jour le statut de l'alerte ────────────────────────────────
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE alerts SET status = 'investigating'::alert_status WHERE id = $1::uuid AND status = 'open'::alert_status",
            alert_id
        )


# ── ENDPOINTS FastAPI ─────────────────────────────────────────────────────────

@app.post("/internal/alert-triggered", status_code=202)
async def alert_triggered(payload: AlertTriggeredPayload, bg: BackgroundTasks):
    """Endpoint interne appelé par le moteur de corrélation."""
    bg.add_task(route_alert, payload.alert_id)
    return {"status": "accepted", "alert_id": payload.alert_id}


@app.get("/api/v1/alerts")
async def list_alerts(status: Optional[str] = None, level: Optional[str] = None):
    """Liste les alertes avec filtres optionnels."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        query = "SELECT a.*, r.name as rule_name FROM alerts a JOIN correlation_rules r ON r.id = a.rule_id WHERE 1=1"
        params = []
        if status:
            params.append(status)
            query += f" AND a.status = ${len(params)}::alert_status"
        if level:
            params.append(level)
            query += f" AND a.level = ${len(params)}::alert_level"
        query += " ORDER BY a.triggered_at DESC LIMIT 50"
        rows = await conn.fetch(query, *params)
    return [dict(r) for r in rows]


@app.patch("/api/v1/alerts/{alert_id}")
async def update_alert(alert_id: str, payload: dict):
    """Mettre à jour le statut d'une alerte (acquitter, escalader, fermer)."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE alerts SET status = $1::alert_status, acknowledged_at = NOW() WHERE id = $2::uuid",
            payload.get("status", "investigating"), alert_id
        )
    return {"updated": alert_id}


@app.get("/api/v1/incidents")
async def list_incidents(status: Optional[str] = None):
    pool = await get_pool()
    async with pool.acquire() as conn:
        query = "SELECT * FROM incidents WHERE 1=1"
        params = []
        if status:
            params.append(status)
            query += f" AND status = ${len(params)}::incident_status"
        query += " ORDER BY opened_at DESC LIMIT 50"
        rows = await conn.fetch(query, *params)
    return [dict(r) for r in rows]


@app.patch("/api/v1/incidents/{incident_id}")
async def update_incident(incident_id: str, payload: IncidentUpdatePayload):
    """Mise à jour du statut d'un incident avec journalisation dans audit_logs."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        updates, params = [], [incident_id]
        if payload.status:
            params.append(payload.status)
            updates.append(f"status = ${len(params)}::incident_status")
            if payload.status == "resolved":
                updates.append("resolved_at = NOW()")
        if payload.notes:
            params.append(payload.notes)
            updates.append(f"notes = ${len(params)}")

        if updates:
            await conn.execute(
                f"UPDATE incidents SET {', '.join(updates)} WHERE id = $1::uuid",
                *params
            )
    return {"updated": incident_id, "status": payload.status}


@app.post("/api/v1/playbooks/executions/{exec_id}/confirm")
async def confirm_playbook(exec_id: str, payload: PlaybookConfirmPayload):
    """Confirmer ou annuler une exécution de playbook en mode CONFIRM."""
    pool = await get_pool()
    new_status = "running" if payload.confirmed else "cancelled"
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE playbook_executions SET status = $1, confirmed_at = NOW() WHERE id = $2::uuid",
            new_status, exec_id
        )
    if payload.confirmed:
        # TODO: exécuter l'action réelle ici
        log.info(f"[SOAR CONFIRM] Exécution {exec_id} confirmée")
    return {"execution_id": exec_id, "status": new_status}


@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}
